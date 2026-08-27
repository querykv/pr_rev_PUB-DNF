"""ARM 3 — the raw single-prompt LLM baseline (`plan/benchmark.md` §3).

WHAT THIS IS FOR

The comparison's headline question is not "is the pipeline good" but "is it
worth more than the obvious alternative". `plan/benchmark.md` §3 names that
alternative — a raw single-prompt LLM over the same cases — and
`benchmark/__init__.py` has listed it as deliberately absent since M2 because
it needed a model. `claude -p` supplies one without Bedrock.

WHY IT IS A PRODUCER AND NOT A DETECTOR

Slotting this into `detect/runner.py` would have been less code and would have
been wrong. A `Detector` inherits the noise filter and delta scoping, and a
baseline that inherits the pipeline's machinery is not a baseline — it is the
pipeline with a different detector. So this produces `list[Finding]` directly
and hands it to the same `score_case`, which is the only thing the two arms
share.

THE FAIRNESS LEDGER, STATED RATHER THAN BURIED

Every asymmetry between this arm and the pipeline, in both directions:

  * The model sees the diff and nothing else — no repository, no tools, no
    ground truth, and not the advisory summary (`AdvisoryRef.summary` never
    reaches `PRTask`). The pipeline sees two full checkouts. **Favours the
    pipeline**, and it is the honest framing: a reviewer with the repo is arm
    4, which was cut.
  * Everything the model reports is `introduced_by_pr=True` by construction,
    because it only ever saw the diff. The pipeline runs `findings/delta.py`
    against a baseline and can say "this was already there". **Favours the
    model on recall and penalises it on false positives**, and there is no way
    to remove the asymmetry without giving the model the baseline, which would
    make it a different arm.
  * A CWE this project's taxonomy cannot map is kept as `Unmapped`, never
    dropped. Dropping would quietly improve the model's false-positive rate and
    quietly hurt its recall, and the direction of a silent correction is not
    something a comparison gets to choose.

DETERMINISM

There is none. The CLI exposes no temperature, so this arm is run several times
and the spread is reported. The pipeline produced identical numbers twice; if
this does not, that is a property of the product, not noise to average away.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from pr_review.benchmark.schema import BenchCase
from pr_review.benchmark.scoring import _CWE_GROUPS, _norm_cwe
from pr_review.detect.normalize import make_finding
from pr_review.schema import DetectorKind, Finding, Severity
from pr_review.taxonomy.registry import _TABLE

PROMPTS_DIR = (Path(__file__).resolve().parent.parent.parent
               / "benchmark" / "prompts")
PROMPT_PATH = PROMPTS_DIR / "llm-diff-baseline.md"

TOOL = "llm-diff-baseline"

# The largest user message either LLM arm will send, in characters (~150k tokens
# at 4 chars/token, leaving headroom under a 200k context for the CLI's own
# system prompt and the reply).
#
# WHY A STATED CONSTANT RATHER THAN LETTING THE API REFUSE. Reproducibility. A
# third party re-running these arms must get the same partition of the corpus
# regardless of what any model's context window happened to be that month, and
# an arm whose corpus coverage drifts with a vendor's release notes is not a
# baseline. Same reasoning as `TRANSPORT_FLOOR_TOKENS`: a calibrated number that
# is wrong in a knowable way beats an invisible one that moves.
#
# WHY REFUSE RATHER THAN TRUNCATE. A truncated diff is a different experiment
# wearing this one's name, and the failure is silent in the worst direction: the
# model would review the first 14% of a pull request, find nothing, and be
# scored as correctly reporting a clean PR.
#
# WHY REFUSE RATHER THAN DROP THE CASE. `PIVOT_PLAN.md` §1.4 requires the same
# corpora unmodified. The case stays in, the refusal is recorded against it, and
# **the inability to review it is the result** -- on the negative corpus two of
# fifty PRs exceed this, and the pipeline reviews both, because it works file by
# file and never assembles the whole diff into one payload. That is a real
# difference between the approaches and it should appear in the numbers rather
# than in a footnote about excluded cases.
MAX_MESSAGE_CHARS = 600_000


def oversized(chars: int) -> str | None:
    """The note to record for a payload no LLM arm will send, or None.

    Shared by both arms deliberately: a ceiling that differed between them would
    partition the corpus differently and the pair would stop being comparable.
    """
    if chars <= MAX_MESSAGE_CHARS:
        return None
    return (f"payload is {chars:,} characters (~{chars // 4:,} tokens), over the "
            f"{MAX_MESSAGE_CHARS:,}-character ceiling this arm sends; not "
            f"reviewable in one call")

_SEVERITIES = {s.value: s for s in Severity}

# CWE -> internal id, built from the one table that already maps them. The model
# answers in CWE because that is public vocabulary it can be expected to know;
# making a baseline learn this project's private ids would handicap it for a
# reason that has nothing to do with finding vulnerabilities.
def _cwe_index() -> dict[str, str]:
    """CWE -> internal id, preferring the id the CWE is *primary* for.

    Several internal ids list the same CWE. `INTEG-HIDDEN-TEXT` carries
    `["CWE-1007", "CWE-94"]` because hidden-text attacks are a code-injection
    delivery mechanism, while `INJ-CODE` carries `CWE-94` first because that is
    what it *is*. A naive first-wins index resolves CWE-94 by table order, and
    table order is not a judgement.

    Scoring survives either way -- `cwe_match` reads `taxonomy.cwe`, and the
    mapped id's list contains the reported CWE by construction, so a correct
    CWE still matches ground truth. What first-wins breaks is the **family
    label**, which is what the comparison table shows a reader. A code
    injection filed under Integrity is a misleading row in a document whose
    whole purpose is to be believed.

    Position in the list is the tie-break: index 0 means the id is that CWE's
    natural home.
    """
    best: dict[str, tuple[int, str]] = {}
    for internal, row in _TABLE.items():
        for rank, cwe in enumerate(row.get("cwe", ())):
            key = cwe.upper()
            if key not in best or rank < best[key][0]:
                best[key] = (rank, internal)
    return {cwe: internal for cwe, (_rank, internal) in best.items()}


_CWE_TO_INTERNAL = _cwe_index()

# Every CWE the pipeline's detectors can ever put on a finding.
_EMITTABLE_CWES = {c.upper() for row in _TABLE.values() for c in row.get("cwe", ())}


def load_prompt(path: str | Path | None = None) -> str:
    """Read the committed prompt. Absent is fatal, not defaulted: an arm that
    silently ran a different prompt than the repository records is unauditable,
    which is the one thing this arm cannot be.

    `path` selects a variant -- `llm-diff-introduced-only.md` is arm 3b. It is a
    parameter rather than a module constant because **changing the prompt
    changes the arm**, so which file ran has to travel with the run (it lands in
    `CorpusRun.arm`) instead of being whatever the file system held that day.
    """
    p = Path(path) if path else PROMPT_PATH
    if not p.exists():
        raise FileNotFoundError(
            f"the arm-3 prompt is missing at {p}. It is a committed "
            f"artifact — the claim that this arm is reproducible rests on it.")
    return p.read_text()


def _extract_json(text: str) -> dict:
    """Pull the JSON object out of a reply that may be fenced or prefaced."""
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def to_findings(reply: str, case: BenchCase,
                tool: str = TOOL) -> tuple[list[Finding], list[str]]:
    """Convert one reply into `Finding`s, plus notes on what could not be read.

    Notes are returned rather than logged because an arm that quietly discarded
    a third of the model's output would report a false-positive rate for a
    different experiment.

    `tool` is a parameter, defaulted to arm 3's own name so arm 3 is unchanged,
    because arm 3c (`context_arm.py`) shares this parser deliberately: two arms
    that read replies differently would differ by more than context, which is
    the one variable the pair exists to isolate. It cannot share the *label* —
    `ScoredFinding.detector` reads `provenance.tool`, so a scorecard that called
    both arms `llm-diff-baseline` could not tell them apart.
    """
    data = _extract_json(reply)
    rows = data.get("findings")
    if not isinstance(rows, list):
        return [], ["reply carried no `findings` list"]

    findings, notes = [], []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            notes.append(f"row {i} was not an object")
            continue
        path = str(row.get("file") or "").strip()
        if not path:
            notes.append(f"row {i} named no file")
            continue
        try:
            start = int(row.get("start_line") or 0)
        except (TypeError, ValueError):
            start = 0
        if start <= 0:
            notes.append(f"row {i} ({path}) gave no usable start_line")
            continue
        try:
            end = int(row.get("end_line") or start)
        except (TypeError, ValueError):
            end = start

        cwe = _norm_cwe(str(row.get("cwe") or ""))
        internal = _CWE_TO_INTERNAL.get(cwe)
        if internal is None:
            # `TOOL-UNMAPPED`, not a made-up id: `lookup()` raises on anything
            # absent from the registry, so inventing one crashes the arm.
            internal = "TOOL-UNMAPPED"
            notes.append(f"row {i} ({path}) cwe {cwe or '(none)'} is outside the taxonomy")

        severity = _SEVERITIES.get(str(row.get("severity") or "").strip().lower(),
                                   Severity.MEDIUM)
        finding = make_finding(
            internal=internal,
            title=str(row.get("title") or "unnamed finding")[:200],
            severity=severity,
            # A single fixed confidence. The model is not asked for one: a
            # self-reported confidence is exactly what M4's calibration work
            # exists to test, and taking one on trust here would smuggle an
            # untested signal into a baseline.
            confidence=5,
            detector=DetectorKind.AGENT,
            tool=tool,
            rule_id=cwe or None,
            path=path,
            start_line=start,
            end_line=max(end, start),
            why=str(row.get("why") or "")[:1000],
        )
        # PRESERVE THE REPORTED CWE. `TOOL-UNMAPPED` carries `cwe: []`, and
        # `scoring.cwe_match` reads exactly that list -- so without this a model
        # that correctly answered CWE-400 on a CWE-400 case scores as a FALSE
        # POSITIVE. 21 of this corpus's 33 ground-truth rows are outside the
        # taxonomy, so discarding would cap this arm at 36% recall by
        # construction and measure our table's coverage rather than the model.
        #
        # This IS an asymmetry and it is declared, not hidden: the pipeline's
        # detectors map a fired rule to a fixed id and genuinely cannot emit
        # CWE-400, while the model names a CWE directly. That is a real
        # capability difference, so the comparison reports recall twice -- over
        # all ground truth, and over the taxonomy-reachable stratum where both
        # arms can actually compete. See `reachable_ground_truth()`.
        if cwe and cwe not in finding.taxonomy.cwe:
            finding = finding.model_copy(update={
                "taxonomy": finding.taxonomy.model_copy(
                    update={"cwe": [cwe, *finding.taxonomy.cwe]})})
        findings.append(finding)
    return findings, notes


def reachable_ground_truth(gt_cwe: str) -> bool:
    """Could ANY pipeline detector ever match this ground-truth CWE?

    The stratum that makes the head-to-head fair. A detector emits a fixed
    internal id, so the set of CWEs the pipeline can express is the union of
    the registry's lists, widened by `scoring._CWE_GROUPS`. Ground truth
    outside that union is unreachable by construction -- a vocabulary gap, not
    a detection failure -- and on the labelled corpus that is 27 of 36 rows,
    leaving a recall ceiling of 0.250.

    That count is `ground_truth` rows, which is what `recall` divides by. This
    docstring said "21 of 33" until 2026-08-24: `BenchCase.cwe` advisory tags
    are a different population (33 tags, 12 in scope) that is close enough to
    look interchangeable and is not. Errata §14.45; pinned by
    `test_the_ceiling_is_derived_from_the_rows_recall_divides_by`, which
    asserts both populations so the two can never be confused silently again.
    """
    gt = _norm_cwe(gt_cwe)
    if gt in _EMITTABLE_CWES:
        return True
    return any(gt in group and (group & _EMITTABLE_CWES) for group in _CWE_GROUPS)


def review_case(case: BenchCase, provider, model_id: str | None = None,
                effort: str = "low",
                prompt_path: str | Path | None = None
                ) -> tuple[list[Finding], list[str]]:
    """One case, one call, blind. The provider decides which model."""
    diff = case.pr_task.diff_text
    if not diff.strip():
        return [], ["case carried no diff text"]
    too_big = oversized(len(diff))
    if too_big:
        return [], [too_big]
    reply = provider.complete(
        [{"role": "system", "content": load_prompt(prompt_path)},
         {"role": "user", "content": diff}],
        model_id=model_id,
        effort=effort,
    )
    return to_findings(reply, case)


def run_llm_arm(corpus, provider, limit: int | None = None,
                model_id: str | None = None, progress: bool = True,
                effort: str = "low", prompt_path: str | Path | None = None):
    """Run arm 3 over a corpus and return a `CorpusRun` the normal machinery reads.

    Deliberately not `runner.run_corpus` with a flag. That function builds
    checkouts, runs six detectors, reads a changeset and computes a filter
    ablation, and none of it applies here -- a baseline that borrowed the
    pipeline's plumbing would be measuring the plumbing. What the two share is
    `_score_all`, which is the only thing that must be identical for the
    comparison to mean anything.
    """
    import time

    from pr_review.benchmark.runner import CaseRun, CorpusRun, _score_all, head_sha

    cases = corpus.cases[:limit] if limit else corpus.cases
    result = CorpusRun(corpus_name=corpus.name,
                       selection_criteria=corpus.selection_criteria,
                       started_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                       code_sha=head_sha(),
                       # The prompt file is part of the arm's identity, not a
                       # setting: two runs of "arm 3" with different prompts are
                       # different experiments and a scorecard has to say which.
                       arm=f"llm-diff:{effort}:{Path(prompt_path or PROMPT_PATH).stem}")
    started = time.monotonic()
    try:
        for i, case in enumerate(cases, start=1):
            if progress:
                print(f"[{i}/{len(cases)}] {case.id}", flush=True)
            mark = len(getattr(provider, "calls", ()) or ())
            case_started = time.monotonic()
            run = CaseRun(case=case)
            try:
                findings, notes = review_case(case, provider, model_id=model_id,
                                              effort=effort,
                                              prompt_path=prompt_path)
                run.findings = findings
                # A baseline sees only the diff, so it cannot attribute anything
                # to a baseline commit. Everything it says is about this PR.
                run.pre_existing = 0
                if notes and progress:
                    for n in notes[:3]:
                        print(f"    note: {n}", flush=True)
            except Exception as exc:                 # noqa: BLE001
                run.error = f"{type(exc).__name__}: {exc}"
                if progress:
                    print(f"    ERROR {run.error}", flush=True)
                result.errors.append((case.id, run.error))
            run.wall_s = time.monotonic() - case_started
            try:
                run.model_cost = provider.accounting(since=mark)
            except (AttributeError, TypeError):
                run.model_cost = {}
            result.runs.append(run)
            if progress and run.ok:
                print(f"    {len(run.findings)} finding(s) · {run.wall_s:.1f}s", flush=True)
    finally:
        result.wall_s = time.monotonic() - started
        try:
            result.model_accounting = provider.accounting()
        except (AttributeError, TypeError):
            result.model_accounting = {}
    _score_all(result)
    return result
