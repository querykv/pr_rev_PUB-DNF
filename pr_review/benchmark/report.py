"""The scorecard (`plan/benchmark.md` §4, `report.py`).

A deterministic markdown render of a `CorpusRun` — no LLM, the same contract
`report/markdown.py` holds for findings.

§7 is titled "Target & honesty" and the honesty half is the harder one, because
every incentive in a benchmark points at a bigger number. Five things are
therefore rendered as part of the document body rather than as footnotes anyone
can strip when quoting it:

1. **Scope.** These are 3a-only numbers — deterministic detectors plus the
   sentinel. Not the §7 headline (~P90/R93), which is a whole-pipeline figure
   needing Phase 3b and 3c, and not comparable to Gemini's self-reported number,
   which §7 already flags as a different and easier bar.
2. **n, next to every rate.** `metrics.Rate` renders the denominator with the
   ratio so it cannot be dropped in transit.
3. **The upper bound.** "Known clean" is false in the small: a merged PR from a
   healthy repository may still carry a vulnerability nobody has found. Every
   false-positive number here is therefore an upper bound.
4. **Which detectors actually ran.** A false-positive rate over a corpus where
   `semgrep` reported `missing_tool` every time is a rate for a tool that never
   ran, and no other line in the document would say so.
5. **Cost: UNMEASURED.** No model is called in this package. `M1_STATUS.md` §4 is
   explicit that a zero in a token-economy report reads as "cheap" when it means
   "we did not look", so the word is printed and the number is not.

A sixth was added after the first measure->fix->measure cycle: the **commit under
measurement**, because on a pinned corpus the code is the only thing that varies
between two runs, and `write_scorecard` refuses to overwrite one run with
another.

A seventh arrived with `rescore`: a document produced by replaying a stored run
**says so, and names the run it replayed**. The numbers in a rescored card were
produced by the pipeline at `code_sha` and by the scoring rules of whatever
commit did the rescoring, and a reader comparing two cards has to be able to
tell which of the two moved.
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from pr_review.benchmark.metrics import (
    AblationMetrics,
    LabelledMetrics,
    NegativeMetrics,
    PairMetrics,
    ablation_metrics,
    labelled_metrics,
    negative_metrics,
    pair_metrics,
)
from pr_review.benchmark.runner import CorpusRun, head_sha
from pr_review.models.claude_cli import (
    TRANSPORT_FLOOR_TOKENS,
    TRANSPORT_FLOOR_CLI_VERSION,
    measured_floor,
    floor_for,
)

_SCOPE = (
    "**Scope: 3a only.** These numbers cover the deterministic detectors "
    "(secrets, structural CPG, semgrep, sca, iac) plus the injection sentinel. "
    "Phase 3b agentic families and the 3c verifier are not built and are not "
    "measured here, so this is **not** the `PR_Rev_0620.md` §13.7 / "
    "`benchmark.md` §7 headline (~P90/R93 on a post-cutoff CVE holdout), and it "
    "is not comparable to the Gemini extension's self-reported figure — §7 "
    "already records that ours is a harder, not-directly-comparable bar."
)

_SCOPE_LLM = (
    "**Scope: one model call per case, and no pipeline.** These numbers come "
    "from a single-prompt LLM arm: **no detector ran**, and neither did the "
    "noise filter, delta scoping or the injection sentinel. Everything reported "
    "is `introduced_by_pr` by construction, because the model never saw a "
    "baseline to attribute anything to. Scored by the same `score_case` as "
    "every other arm, which is the only thing the arms share."
)

_SCOPE_UNKNOWN = (
    "**Scope: UNSTATED.** This run records the arm `{arm}`, which this renderer "
    "does not have a scope note for. Rather than print one that may be false, "
    "it says so — see errata §14.58 for why that is the rule here."
)


def render_scope(run) -> str:
    """What actually ran, from the run — not from a constant.

    `_SCOPE` WAS PRINTED UNCONDITIONALLY, and on every LLM-arm scorecard it said
    the numbers covered "the deterministic detectors (secrets, structural CPG,
    semgrep, sca, iac) plus the injection sentinel" for a run in which **not one
    detector executed**. Eight stored scorecards carry that sentence.

    This is `render_cost`'s bug, one constant over. That one printed "no model is
    invoked anywhere in this harness" across a run that made 33 model calls and
    cost $0.95; it was fixed on 2026-08-21 and its twin, four lines above it in
    the same file, was not. A hardcoded honesty notice is only honest until the
    thing it describes changes — and the second time that lesson arrives it is
    not a slip, it is a shape (errata §14.58).

    So the default is not the pipeline note. An arm this function does not know
    prints that it does not know, because the failure being prevented is
    precisely a confident sentence about a run nobody checked.
    """
    arm = (getattr(run, "arm", "") or "").strip()
    # "" is every run written before 2026-08-21, and all of them were the
    # pipeline: the arm field did not exist because there was only one arm.
    if arm in ("", "deterministic") or arm.startswith("triage-"):
        return _SCOPE
    if arm.startswith("llm-"):
        return _SCOPE_LLM
    return _SCOPE_UNKNOWN.format(arm=arm)


_COST = (
    "**Cost / tokens: UNMEASURED.** No model is invoked anywhere in this "
    "harness, so there is nothing to count. This is not a claim that the tool is "
    "cheap; per `M1_STATUS.md` §4 the token accounting itself is still "
    "unverified against a real provider."
)


def _tokens(acct: dict) -> tuple[int, int]:
    """`(uncached, cached)` from an accounting dict of either vintage.

    Dumps written before 2026-08-22 carry `content_tokens` /
    `transport_overhead_tokens`. The *numbers* were always right — they were
    always uncached and cached — so this is a rename, not a migration, and the
    five stored runs stay readable without a `_DUMP_VERSION` bump.
    """
    uncached = acct.get("uncached_tokens", acct.get("content_tokens", 0))
    cached = acct.get("cached_tokens", acct.get("transport_overhead_tokens", 0))
    return int(uncached), int(cached)


def render_cost(run) -> str:
    """The cost line, from what the run actually spent.

    `_COST` was a constant, and on 2026-08-21 it printed "no model is invoked
    anywhere in this harness" across a scorecard for a run that made 33 model
    calls and cost $0.95. A hardcoded honesty notice is only honest until the
    thing it describes changes, and this one outlived its truth by exactly one
    commit -- the same shape as §14.42, where a claim nobody re-checked kept
    being quoted.

    THE SPLIT THIS USED TO PRINT WAS WRONG. It reported `content_tokens` as
    "ours (prompt + answer)" and the rest as "CLI transport overhead". Claude
    Code caches through the last user message, so our prompt is in the *cached*
    bucket and the "ours" figure was the uncached remainder -- 2 tokens for a
    23 KB prompt (§14.44). Replacing one mislabelled pair with another would
    repeat the error, so the buckets are now named for what the CLI reports, and
    the ours-vs-theirs split is printed separately and marked **derived**,
    because it rests on a calibration constant rather than on this run.
    """
    acct = getattr(run, "model_accounting", None) or {}
    if not acct or not acct.get("calls"):
        return _COST
    models = ", ".join(acct.get("models") or []) or "unknown"
    effort = ", ".join(acct.get("effort") or []) or "unstated"
    calls = int(acct["calls"])
    uncached, cached = _tokens(acct)
    total = uncached + cached
    per_case = acct["cost_usd"] / max(1, sum(1 for r in run.runs if r.ok))
    # Priced by the floor measured for THIS run's CLI, or the constant when the
    # run does not say which CLI it used (§21). The floor is cached by
    # construction, so it cannot exceed the cached bucket.
    floor = floor_for(acct)
    harness = min(cached, calls * floor)
    ours = max(0, total - harness)
    return (
        f"**Cost / tokens: MEASURED.** {calls} model call(s) via the "
        f"`claude` CLI (`{models}`, effort `{effort}`): "
        f"**${acct['cost_usd']:.4f}** total, **${per_case:.4f}** per completed "
        f"case.\n\n"
        f"Tokens, as the CLI reports them: **{cached:,}** cached "
        f"(`cache_creation + cache_read`) plus **{uncached:,}** uncached "
        f"(`input + output`), **{total:,}** in all. Those two buckets are "
        f"**not** our-content and their-overhead. Claude Code caches its own "
        f"system prompt and, when our prompt clears the model's minimum "
        f"cacheable length, our prompt with it — so which bucket our tokens "
        f"land in varies by prompt size and model, and neither bucket alone "
        f"names a party (§14.44).\n\n"
        f"**Derived, not measured here:** at a calibrated floor of "
        f"{floor:,} tokens per call for the CLI's own system "
        f"prompt, ~**{harness:,}** of the total is harness and ~**{ours:,}** is "
        f"ours. The subtraction is taken from the *total* rather than from the "
        f"cached bucket, because doing the latter reported 0 tokens of our own "
        f"content for a run that had plainly sent some. It rests on a "
        f"calibration against one CLI build, not on this run. Neither figure is "
        f"an API price."
        + floor_provenance(acct)
    )


def floor_provenance(acct: dict) -> str:
    """Say which CLI produced a run, and flag it when that is not the build
    `TRANSPORT_FLOOR_TOKENS` was calibrated against.

    `OPEN_ITEMS.md` §21: the floor has no second source, so a CLI upgrade that
    grows the system prompt re-attributes harness tokens to our content and
    **nothing in the suite can notice**. This is the second source -- not of the
    number, but of the conditions it was measured under.

    Three states, and the third is the one worth the code: matching (silent),
    differing (say so), and *unrecorded* (say that too). A run stored before the
    version was captured must not read as agreement.
    """
    seen = acct.get("cli_version")
    if seen == TRANSPORT_FLOOR_CLI_VERSION:
        return ""
    if not seen:
        return (
            f"\n\n**Floor provenance: UNRECORDED.** This run does not say which "
            f"`claude` build produced it, so the {TRANSPORT_FLOOR_TOKENS:,}-token "
            f"floor cannot be checked against it. Runs stored before 2026-08-24 "
            f"predate that field; treat the derived split as unverified rather "
            f"than as agreeing."
        )
    known = measured_floor(seen)
    if known is None:
        return (
            f"\n\n**Floor provenance: RECORDED, never calibrated.** This run used "
            f"`claude` **{seen}**, which has never been measured, so the split "
            f"above falls back to the **{TRANSPORT_FLOOR_TOKENS:,}** calibrated "
            f"against **{TRANSPORT_FLOOR_CLI_VERSION}**. That makes it an "
            f"extrapolation: whatever this build's system prompt actually costs, "
            f"the difference is being attributed to our content. The fallback is "
            f"deliberate — an interpolated floor would be a number with no "
            f"measurement behind it and no way to tell the two apart. Measure "
            f"this build per `OPEN_ITEMS.md` §21 before quoting the split; the "
            f"totals and the cost are unaffected."
        )
    # The split above ALREADY used `known` -- `floor_for` selected it. So there
    # is no gap to report, and saying there was one would be this project's
    # commonest defect: a sentence that was true before the arithmetic under it
    # changed (Plan 2 §L5).
    return (
        f"\n\n**Floor provenance: MEASURED for this build.** This run recorded "
        f"`claude` **{seen}**, whose floor was measured at **{known:,}** tokens "
        f"per call, and the split above uses that rather than the "
        f"**{TRANSPORT_FLOOR_TOKENS:,}** calibrated against "
        f"**{TRANSPORT_FLOOR_CLI_VERSION}**. Runs on different builds are "
        f"therefore priced by different floors — correct per run, and worth "
        f"knowing before comparing two arms' *ours* columns."
    )


def calls_of(acct: dict) -> int:
    try:
        return int(acct.get("calls") or 0)
    except (TypeError, ValueError):
        return 0


def _table(rows: list[tuple[str, str]], headers: tuple[str, str]) -> list[str]:
    if not rows:
        return ["_(none)_", ""]
    out = [f"| {headers[0]} | {headers[1]} |", "|---|---|"]
    out += [f"| {a} | {b} |" for a, b in rows]
    out.append("")
    return out


def _counts_table(counts: dict[str, int], total: int,
                  headers: tuple[str, str]) -> list[str]:
    rows = [
        (name, f"{n} ({n / total:.0%})" if total else str(n))
        for name, n in counts.items()
    ]
    return _table(rows, headers)


def render_delta_scoping(neg: NegativeMetrics | None,
                         lab: LabelledMetrics | None) -> list[str]:
    """What the baseline pass removed — the pipeline's largest measured effect.

    IT WAS UNREPORTED UNTIL 2026-08-22, and the reason is worth stating where it
    can be read: every metric in this harness was aimed at recall, and recall is
    the axis this tool is worst at. Delta scoping removes 86% of the detectors'
    raw output on the negative corpus and 97% on the labelled one, and the only
    trace of it in a scorecard was one line saying how many findings were
    "excluded from scoring" — phrasing that reads like bookkeeping rather than
    like the mechanism most responsible for the false-positive rate. §14.46.
    """
    m = neg or lab
    if m is None or not m.raw_findings:
        return []

    out = [
        "## Delta scoping — what the baseline pass removes",
        "",
        f"- **Raw findings the detectors produced:** {m.raw_findings}",
        f"- **Attributed to the base tree and dropped:** {m.suppression.render(3)}",
    ]
    if neg is not None:
        out += [
            f"- **False positives per PR, as shipped:** {neg.fp_per_pr.render(2)}",
            f"- **...if every raw finding were reported:** "
            f"{neg.fp_per_pr_unscoped.render(2)}",
        ]
    out += [
        "",
        "> `findings/delta.py` runs the same detectors over the base commit and "
        "drops anything that was already there. This is the single largest "
        "effect any stage in this pipeline has on the reported numbers, and it "
        "is the capability a diff-only reviewer cannot have: **a tool that "
        "never sees the base tree cannot tell an introduced defect from one the "
        "PR merely walked past.**",
        "",
        "### Three tiers, and only two of them are measured",
        "",
        "| tier | what it is | this run |",
        "|---|---|---|",
        f"| no scoping | every raw finding reported | "
        f"{neg.fp_per_pr_unscoped.render(2) if neg else '—'} · **derived** |",
        "| hunk-based | no base checkout; a finding counts as introduced when "
        "it sits in an edited region | *measured 2026-08-22: 0.32/PR on the "
        "negative corpus — and it lost the one gate-relevant finding, §14.48* |",
        f"| baseline | the base tree scanned and subtracted | "
        f"{neg.fp_per_pr.render(2) if neg else '—'} · measured |",
        "",
        "> **The top row is arithmetic, not a run.** It is what this run's own "
        "counts imply if nothing were dropped. A genuinely unscoped run would "
        "also lose Semgrep's `--baseline-commit` scoping, so the real figure is "
        "that one or worse. The middle row *was* run, and it is the tool's real "
        "behaviour whenever checkouts are unavailable — `--no-checkout`, an "
        "offline `--diff-file`, the whole M0 thread.",
        "",
        "> **The middle tier is not the bottom tier with less noise.** It "
        "over-reports inside edited hunks and under-reports outside them. On "
        "the negative corpus it gained five medium alarms and lost one HIGH — "
        "the only gate-relevant finding there, and a correct one. Its "
        "gate-relevant rate is therefore *better* than the full pipeline's "
        "while its gating is worse. **When a false-alarm rate improves, diff "
        "the finding sets before believing it**: an aggregate cannot tell you "
        "whether noise or evidence was removed. §14.48.",
        "",
        "> **A raw-LLM arm's zero here is the prompt's doing, not the model's.** "
        "`llm-diff-baseline.md` asks for vulnerabilities the diff *\"introduces "
        "or leaves present in the code shown\"* — it was told to include "
        "pre-existing ones and then scored as wrong for each. **Asked the other "
        "way it does the job**: `llm-diff-introduced-only.md` changes that one "
        "instruction and took control-PR false alarms to **0 · 0 · 1 of 26 across "
        "three passes**, against the baseline prompt's 3 · 5 · 4 — at or below "
        "this pipeline's 1 of 26 — while leaving vulnerable-half output inside "
        "its own run-to-run range. So the suppression figures above are a real "
        "property of this pipeline and **not** a capability only it can have. "
        "§14.47, replicated and narrowed to this range in §14.51.",
        "",
    ]
    return out


def render_negative(m: NegativeMetrics) -> list[str]:
    out = [
        "## False positives on known-clean PRs",
        "",
        f"- **False positives per PR:** {m.fp_per_pr.render(2)}",
        f"- **Gate-relevant (high/critical) per PR:** {m.gate_relevant_per_pr.render(2)}",
        f"- **PRs with no findings at all:** {m.clean_rate.render(2)}",
        f"- Pre-existing findings excluded from scoring: {m.skipped_pre_existing}",
        "",
        "> Every finding attributed to the PR on known-clean code is counted "
        "against the tool. **This is an upper bound on the false-positive "
        "rate**, not a point estimate: a merged PR from a healthy repository "
        "can still contain a real vulnerability that nobody has found, and any "
        "such finding is counted here as a false alarm. It also says nothing "
        "about recall — a detector that reports nothing scores perfectly on "
        "this set.",
        "",
        "### The endpoint stratum",
        "",
        f"- PRs where the structural detector saw at least one endpoint: "
        f"**{m.endpoint_cases}** of {m.cases}",
        f"- Endpoints seen across those PRs: **{m.endpoints_seen}**",
        f"- **False positives per endpoint-touching PR:** "
        f"{m.fp_per_endpoint_pr.render(2)}",
        f"- **`BAC-MISSING-AUTHZ` alarms per endpoint seen:** "
        f"{m.missing_authz_per_endpoint.render(3)}",
        "",
        "> `M2_STATUS.md` §3.2's named worry is that `BAC-MISSING-AUTHZ` fires "
        "on every unguarded endpoint in a changed file, including deliberately "
        "public ones. Most merged PRs touch no endpoint at all, so that rule "
        "cannot fire in them and the corpus-wide average prices it at near-zero "
        "— arithmetically true, and an answer to a different question. This "
        "stratum is the one that addresses it. The split is derived from what "
        "the detector actually saw, not from how the corpus was picked, so "
        "neither number is biased by the other's needs.",
        "",
        "### Which rules produce the noise",
        "",
        "The aggregate above is not actionable on its own; this table is the "
        "output that is.",
        "",
    ]
    out += _counts_table(m.by_internal, m.findings, ("Taxonomy id", "False positives"))
    out += ["### By detector", ""]
    out += _counts_table(m.by_detector, m.findings, ("Detector", "False positives"))
    out += ["### By severity", ""]
    out += _counts_table(m.by_severity, m.findings, ("Severity", "False positives"))
    noisiest = sorted(m.per_case.items(), key=lambda kv: -kv[1])[:5]
    if noisiest:
        out += ["### Noisiest cases", ""]
        out += _table([(c, str(n)) for c, n in noisiest], ("Case", "False positives"))
    return out


def render_labelled(m: LabelledMetrics) -> list[str]:
    f1 = f"{m.f1:.3f}" if m.f1 is not None else "n/a"
    out = [
        "## Precision and recall on labelled cases",
        "",
        f"- **Precision:** {m.precision.render()}",
        f"- **Recall:** {m.recall.render()}",
        f"- **Recall ignoring the CWE label** (did anything point at the "
        f"vulnerable lines?): {m.recall_ignoring_cwe.render()}",
        f"- **F1:** {f1}",
        f"- **Localization** (matched a label *and* the lines): {m.localization.render()}",
        f"- Near misses (right file, wrong lines): {m.near_miss}",
        f"- **True positives owed to the CWE relation table:** "
        f"{m.relation_table_share.render(2)}",
        "",
        "> **Recall is understated by design and must not be read flat.** The 3a "
        "detectors cover a deliberate subset of the taxonomy: Broken Access "
        "Control is the M3 agent flagship, and Privacy/PII and Insecure Design "
        "are agent families with no deterministic detector at all. A miss in "
        "those classes is a milestone boundary, not a detector defect. The "
        "per-family breakdown below is the honest reading.",
        "",
        "> The relation-table share matters because "
        "`benchmark/scoring.py:_CWE_GROUPS` decides which CWE ids count as the "
        "same defect. Widening it raises precision and recall without changing "
        "the tool. If most true positives arrive through it rather than through "
        "an exact CWE match, the headline is a property of that table.",
        "",
        "> **The two recalls above are the same question asked with and without "
        "the taxonomy**, and the gap between them is this measurement's own "
        "vocabulary error rather than anything the tool did. `_CWE_GROUPS` is a "
        "hand-list of ~9 families against a taxonomy of some 940 ids, so an "
        "advisory that labels a defect one level up or down from where a tool "
        "would is a silent false positive. An arm that emits fixed internal ids "
        "shows no gap at all — the pipeline's two numbers are equal by "
        "construction — while an arm that names CWEs freely can show a large "
        "one. Read the gap as a property of the arm's vocabulary, never as "
        "recall it deserves credit for: locating a defect and classifying it "
        "are different achievements, and only the second is `recall`. "
        "`OPEN_ITEMS.md` §27.",
        "",
        "### True positives by family",
        "",
    ]
    out += _counts_table(m.by_family_tp, m.tp, ("Family", "True positives"))
    out += ["### Misses by ground-truth CWE", ""]
    out += _counts_table(m.by_family_fn, m.fn, ("CWE", "Missed"))

    out += [
        "### Blind, or mis-aimed?",
        "",
        f"- **Ground truth some finding named, scored or not:** "
        f"{m.reached_the_right_file.render(3)}",
        f"- ...found, but attributed to the base tree **on the vulnerable "
        f"lines**: {m.baseline_overlapping}",
        f"- ...found, but attributed to the base tree **elsewhere in the file**: "
        f"{m.baseline_file_only}",
        "",
        "> A missed row fails in two ways that `recall` prices identically at "
        "zero: no detector ever produced a finding for it, or a detector "
        "produced the right finding and `findings/delta.py` attributed it to "
        "the baseline, so scoring never saw it. Different causes, different "
        "fixes. The first row above is the union, and it is **not a quality "
        "claim** — naming a file is not naming a defect. It is here because "
        "when recall is low the useful question is whether the detectors are "
        "blind or merely mis-aimed.",
        "",
        "> The split matters for what to do next. A row found **on the "
        "vulnerable lines** would have been a true positive but for delta "
        "scoping, and argues about attribution. A row found **elsewhere in the "
        "file** would only ever have been a near miss, and argues about "
        "localization — a taint detector reports at the sink, while a fixing "
        "commit's ground truth sits where the missing validation went, and "
        "those are different lines by construction.",
        "",
        "### The in-scope stratum",
        "",
        f"- **Recall over ground truth a 3a detector could name:** "
        f"{m.in_scope_recall.render()}",
        f"- Misses in classes **no detector models at all**: {m.out_of_scope_fn}",
        "",
        "> This is the honest reading of the flat recall above. Roughly half a "
        "recent advisory sample is CWE-400, CWE-1333, CWE-834, CWE-455, "
        "CWE-200, CWE-59 and CWE-61 — resource consumption, ReDoS, symlinks — "
        "which no deterministic detector in this milestone emits. Counting "
        "those against the tool measures the roadmap.",
        "",
        "> **The stratum is derived, never selected for.** The corpus was not "
        "filtered to CWEs the tool covers; that would be the corpus-flattering "
        "failure `Corpus.selection_criteria` exists to expose, and errata "
        "§14.20 already ruled on the same question from the other side. The "
        "set comes from `benchmark/scope.py`, which reads the detectors' own "
        "dispatch tables rather than a hand-maintained list — a list would let "
        "a one-line edit raise recall without changing the tool.",
        "",
    ]
    if m.out_of_scope_cwes:
        out += ["#### Missed CWEs with no detector", ""]
        out += _counts_table(m.out_of_scope_cwes, m.out_of_scope_fn,
                             ("CWE", "Missed"))
    return out


def render_pairs(m: PairMetrics) -> list[str]:
    out = [
        "## Paired controls — did it find the vulnerability, or the file?",
        "",
        f"- **Pairs where the vulnerable side was flagged and the fixed side "
        f"was silent:** {m.discriminated.render(2)}",
        f"- Flagged the vulnerable side, but also flagged the fix: "
        f"{m.detected_but_control_also_flagged}",
        f"- Missed the vulnerable side entirely: {m.missed}",
        "",
        "> **This is the number that makes a reverted fix worth scoring, and it "
        "belongs next to recall rather than under it.** A labelled case here is "
        "a fixing commit run backwards, so the vulnerable lines are essentially "
        "the whole diff — the easiest possible presentation of the defect. "
        "Recall alone cannot separate *found the vulnerability* from *always "
        "fires on this file*, and the second scores identically while being "
        "worthless. The control is the same file with only the vulnerability "
        "removed, so the pair separates them and neither half does.",
        "",
    ]
    if m.unpaired:
        out += [f"> {m.unpaired} advisory/advisories had only one side complete "
                f"and are excluded from the rate above.", ""]
    if m.examples:
        out += ["### Per advisory", ""]
        out += _table([(f"`{pid}`", outcome) for pid, outcome in m.examples],
                      ("Advisory", "Outcome"))
    return out


def render_ablation(m: AblationMetrics) -> list[str]:
    out = [
        "## Phase-2 noise filter — recall ablation",
        "",
        f"- **Recall after filter:** {m.recall_after_filter.render(3)} "
        f"ground-truth files survived",
        f"- Dropped ground-truth files: {m.dropped}",
        f"- ...of which the guardrail never considered: {m.dropped_without_guardrail}",
        "",
        "> **At M2 this stage does not gate what the detectors see.** "
        "`pipeline.py` builds the detect stage from the manifest and every "
        "parsed file, not from the filter's kept set, so a dropped file is "
        "still scanned and a finding in it still reaches the report. The "
        "filter's drops decide what Phase-3b agents are routed to, which "
        "arrives at M3. This measurement is therefore a **baseline taken "
        "before the stage becomes load-bearing** — it is not evidence that a "
        "live leak was found or closed.",
        "",
        "> A drop the guardrail never considered is the more serious of the two: "
        "`DropRecord.guardrail_considered` separates \"the CPG said this file is "
        "inert\" from \"we never asked\".",
        "",
    ]
    if m.examples:
        out += ["### Dropped ground-truth files", ""]
        out += _table([(f"`{p}`", f"{r} ({c})") for c, p, r in m.examples[:20]],
                      ("Path", "Reason (case)"))
    return out


def render_scorecard(run: CorpusRun) -> str:
    negatives = [s for s in run.scores if not s.labelled]
    labelled = [s for s in run.scores if s.labelled]

    out = [
        f"# Detector scorecard — {run.corpus_name}",
        "",
        f"**Run:** {run.started_at} · **cases attempted:** {len(run.runs)} · "
        f"**completed:** {run.completed} · **wall clock:** {run.wall_s:.0f}s",
        "",
        # Two runs of a pinned corpus differ only by the code, so the code is
        # the one thing a reader needs in order to tell them apart.
        f"**Code under measurement:** `{run.code_sha or head_sha()}`"
        + ("  ·  **profile cache: isolated per case** (`--cold-profiles`), so "
           "no case reused or patched another's profile"
           if run.cold_profiles else ""),
        "",
        render_scope(run),
        "",
        render_cost(run),
        "",
        "---",
        "",
        "## Corpus",
        "",
        "**Selection criteria, verbatim from the pinned corpus:**",
        "",
        f"> {run.selection_criteria}",
        "",
        "A corpus chosen to flatter the tool is the classic benchmark failure, "
        "and printing how it was picked is the only defense a reader has. Cases "
        "are pinned by repo, PR number and both shas, so every number below can "
        "be re-derived.",
        "",
    ]

    if run.rescored_at:
        out[5:5] = [
            f"**Rescored:** {run.rescored_at} by `{head_sha()}`, replaying the "
            f"stored run above. The pipeline was not re-executed — every "
            f"finding below is the one `{run.code_sha or 'the original run'}` "
            f"produced, re-judged by this commit's scoring rules. If two "
            f"scorecards disagree, this line says which of the two things moved.",
            "",
        ]

    if run.detector_status:
        out += ["## Detectors actually exercised", "",
                "A detector that found nothing and a detector whose binary is "
                "absent produce the same empty list. These are the "
                "`AdapterRun.status` counts across the corpus; anything not "
                "mostly `ran` means the numbers below do not cover that "
                "detector.", ""]
        rows = [
            (name, " · ".join(f"{s}: {n}" for s, n in sorted(statuses.items())))
            for name, statuses in sorted(run.detector_status.items())
        ]
        out += _table(rows, ("Detector", "Status counts"))

    neg_m = negative_metrics(negatives) if negatives else None
    lab_m = labelled_metrics(labelled) if labelled else None
    # Before the false-positive section, because it is the explanation for the
    # number that section reports.
    out += render_delta_scoping(neg_m, lab_m)
    if neg_m is not None:
        out += render_negative(neg_m)
    if lab_m is not None:
        out += render_labelled(lab_m)
        pair_of = {r.case.id: r.case.pair_id for r in run.runs if r.case.pair_id}
        if pair_of:
            labelled_of = {r.case.id: r.case.labelled for r in run.runs}
            out += render_pairs(pair_metrics(run.scores, pair_of, labelled_of))
    if run.ablations:
        out += render_ablation(ablation_metrics(run.ablations))

    if run.errors:
        out += [
            "## Cases that did not complete",
            "",
            f"{len(run.errors)} of {len(run.runs)} cases failed and are excluded "
            f"from every number above. They are listed so the denominator stays "
            f"honest rather than silently shrinking.",
            "",
        ]
        out += _table([(c, f"`{e}`") for c, e in run.errors[:20]], ("Case", "Error"))

    out += [
        "---",
        "",
        "<sub>Generated by `pr_review.benchmark`. Deterministic render of a "
        "corpus run — no model involved in producing these numbers or this "
        "document.</sub>",
    ]
    return "\n".join(out)


def scorecard_target(corpus_name: str, root: str | Path = "benchmark/results",
                     *, label: str | None = None) -> tuple[Path, Path]:
    """Where `write_scorecard` would put this corpus's scorecard and dump.

    Split out so the collision can be checked **before** a run rather than after
    it -- see `precheck_scorecard`.
    """
    out_dir = Path(root) / (f"{date.today().isoformat()}-{label}" if label
                            else date.today().isoformat())
    return out_dir / f"{corpus_name}.md", out_dir / "run.json"


def precheck_scorecard(corpus_name: str, root: str | Path = "benchmark/results",
                       *, label: str | None = None, dump: bool = True) -> None:
    """Raise now if the write at the end of the run would collide (§4).

    `run.json` is written at a fixed path per directory while the markdown is
    named per corpus, so running both corpora under one `--label` collides on
    the dump even though the scorecards would not. The refusal is correct; its
    TIMING was not. It fired after `run_corpus` returned, which on 2026-08-08
    meant 844 seconds of work produced a scorecard on stdout and no dump.
    Nothing about this needs a whole run to discover.

    **This is a pre-flight, not a lock.** The directory is keyed on today's date,
    so a run that starts at 23:58 and ends at 00:03 writes somewhere this check
    never looked, and a concurrent run can take the name in between. Both leave
    the original post-write refusal as the thing that actually protects the
    file; this only makes the common case cheap to discover.
    """
    for existing in [p for p in scorecard_target(corpus_name, root, label=label)
                     if dump or p.suffix == ".md"]:
        if existing.exists():
            raise FileExistsError(
                f"{existing} already exists, and this run would collide with it "
                f"at the END of the run rather than now. Pass a different "
                f"`--label` (the two corpora need different ones -- `run.json` "
                f"is one per directory), or `--overwrite` to replace it."
            )


def write_scorecard(run: CorpusRun, root: str | Path = "benchmark/results",
                    *, label: str | None = None, overwrite: bool = False,
                    dump: bool = True) -> Path:
    """Write the scorecard, and the run it was rendered from, under
    `benchmark/results/<date>[-<label>]/`.

    Dated and committed, because a measurement nobody can find again is not a
    measurement. The run directories themselves are disposable; this is not.

    Refuses to clobber an existing scorecard. The whole point of pinning a
    corpus is measure -> fix -> measure, and the second run of that loop happens
    on the same day as the first — so keying only on the date would silently
    delete the baseline at the exact moment it became worth keeping. `label`
    separates the runs; `overwrite` is for re-rendering one you meant to replace.

    `run.json` lands beside it under the same rule. The scorecard is a *render*
    of a run and the run is the expensive part; keeping only the render is what
    made blind spot #9 true, where a result older than the code that scored it
    could not be regenerated at all. `dump=False` is for a rescore that is
    deliberately not re-pinning its source.
    """
    out_dir = Path(root) / (f"{date.today().isoformat()}-{label}" if label
                            else date.today().isoformat())
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{run.corpus_name}.md"
    dump_path = out_dir / "run.json"
    if not overwrite:
        for existing in (path, dump_path if dump else None):
            if existing is not None and existing.exists():
                raise FileExistsError(
                    f"{existing} already exists. Pass a label to keep both runs "
                    f"(`--label after-fix` -> {out_dir}-after-fix/), or "
                    f"`--overwrite` to replace it."
                )
    path.write_text(render_scorecard(run))
    if dump:
        dump_path.write_text(json.dumps(run.to_dict(), indent=2))
    return path
