# Benchmark — Build Status & Handoff

**Last updated:** 2026-08-22 · **Scope:** the measurement harness (`plan/benchmark.md`, built
narrow at 3a scope), the first real precision measurement, the four defect fixes it drove, the
labelled GHSA corpus that measured recall, and the taint-engine defect that acting on it exposed.
**State:** **pass 1 and pass 2 both complete, and pass 2 acted on.** Pass 1: five defects, four
fixed and re-measured (1.96 → **0.22** false positives per PR, 0.00 gate-relevant throughout), one
deferred to M3. Pass 2: 26 advisories × 2 cases, **recall 0.028 (1/36)**, **0.111 in scope**.
Acting on it found a dual-role source/sink defect in the taint engine and took the labelled corpus
from **0.42 → 0.04 false positives per PR with every signal number unchanged** (§4c); the
localization gap was accepted as Phase-3b work with a measured argument (errata §14.30).

**2026-08-26 — the arm that tested this project's premise (§4x).** `ContextBundle`, the payload
Phase 3b was specified to receive, was captured and handed to a model alongside the diff. Three
passes on each of two corpora. **It did not review any better than from the diff alone** — recall
15–20 of 36 against 17–18, precision 0.50 against 0.51 — though it demonstrably changed *what* the
model attended to. §7.1 of `REPORT.md` lists the four measured reasons that is a floor rather than a
verdict. Two defects in the **apparatus** came out of the same day and both are worse than anything
found in the tool: §14.59 and §14.60.

**2026-08-21 — the four-arm comparison (§4i).** The baseline columns `benchmark.md` §3 asks for are
no longer blocked: semgrep-alone, the pipeline, pipeline + live tier-3 triage, and a **raw diff-only
LLM**, all scored by the same `score_case` on the same corpus, which is a **post-cutoff temporal
holdout**. Headline: the LLM out-recalls the pipeline **13×** overall and **5× on the stratum the
pipeline can express**, at **$0.014/case**, and discriminates pairs 0.35–0.42 against 0.04. Four of
five pre-registered predictions held; the two that did not both moved *against* the tool. Three
errata came out of it (§14.42–§14.44), two of them defects in numbers this document had published.

> Detail record for the benchmark work, in the same role `M1_STATUS.md` and `M2_STATUS.md` play
> for their milestones. `CONTINUATION.md` is the short "where are we"; §9 there summarizes pass 1
> and §10 pass 2. Design intent: `plan/benchmark.md`. Working plans:
> `~/.claude/plans/linked-sauteeing-lollipop.md` (pass 1) and
> `~/.claude/plans/resuming-work-on-the-twinkly-fiddle.md` (pass 2). Errata this produced:
> `PR_Rev_0620.md` §14.19–§14.31.

---

## 1. Where it stands

**894 tests pass**, plus CAP's own 4 — 454 before any benchmark work, +29 for the harness, +31 for
pass 1's defects, +42 for pass 2 (20 in `tests/test_ghsa.py`, 22 for serialization, scope, pairs
and baseline attribution), +8 for acting on pass 2 (5 in `tests/test_cpg_selfloop.py`, 3 for
`is_generated` and the endpoint count), +24 for the five new lockfile formats (§4d), then +28 for
the two design decisions and the gate (§4e), +31 for the FastAPI `dependencies=` forms (§4f),
+19 for the receiver narrowing (§4g) and +3 for the IaC corpus's defects (§4h), then **+56 for the
four-arm comparison (§4i)**: 21 in `tests/test_claude_cli.py`, 14 in `tests/test_llm_arm.py`, +10 in
`test_benchmark.py` (cost line, arm wiring, the recall unit, the token labels), +6 in
`test_checkout.py` and +5 in `test_change_filter.py`, then **+20 in `tests/test_report_html.py`**
for the HTML comparison scorecard — escaping, the ceiling, and the honesty carries; and **+27** for
the delta-scoping work (§4j, §4k): the suppression metric, the catalog loader's duplicate-key guard,
the container-privilege id's ceiling invariance, and the baseline cache's two staleness guards.
Then **+27 for the Plan-2 execution of 2026-08-24 and the publication audit that followed it**, counted per file rather than by subtracting one
total from another: **+10** in `tests/test_rendered.py` (the publication-drift ledger, §24, plus the two
declaration tests and the two ledger-key portability tests §14.52 added to it), **+7** in `tests/test_m0.py` (generated-header reading and
its blind spot, §4n), **+3** in `tests/test_claude_cli.py` (the CLI version probe, §4l.3), **+3** in
`tests/test_report_html.py` (the conditional `Floor` column), **+2** in `tests/test_deps.py` (§5's
single source for lockfile names) and **+2** in `tests/test_benchmark.py` (§4's results-name
pre-flight).
Then **+12 for Plan 3's Step 0**, 2026-08-25: **+1** in `tests/test_benchmark.py`
for the total-spend guard, which landed at `e7615f1` and was never counted here — every
document said 799 against a suite of 800 for a day (§14.54); **+9** in
`tests/test_render_report.py`, where the report page's tab title, eyebrow and `<h1>` stopped
being literals in the generator and became things `REPORT.md` decides; and **+2** in
`tests/test_doc_claims.py`, which is why this paragraph can no longer drift quietly — a commit
that moves the count and not the documents is now a red suite.
Then **+2 for Plan 3's Step 1**: `tests/test_benchmark.py` gains the `--keep-runs` collision
guard and the odd second test that asserts the collision is **still present in the pinned
corpus**, so a rebuilt corpus retires the guard loudly instead of leaving it green for a reason
that stopped being true (§14.55). Then **+1 at Step 1b's consolidation**: the same drift, one
directory over — `tests/test_doc_claims.py` now ties the published *stored-run* count to
`benchmark/results/*/run.json`, the same glob the total-spend guard sums, so the two
definitions cannot drift apart.
Then **+12 for Plan 3's Step 2**: **+8** in
`tests/test_context_capture.py` (the capture carries no ground truth, its case entries are an
allow-list rather than a deny-list, a failed case is recorded rather than dropped, and
`case_run_dir` is checked against `pipeline._run_dir` so §14.55 cannot recur silently) and
**+5** in `tests/test_change_context.py` for the three orderings §14.57 found unstable —
neighbours, the profile slice's lists, and taint paths, the last of which orders *paths* while
leaving each flow's source→sanitizer→sink sequence alone. A further **+4** guard the
**committed capture** itself — that its provenance names a clean commit, that its
`analyzer_version` still matches this build (a bump invalidates it, because the profile decides
the CPG the bundles are cut from), that it covers every labelled case, and that every list in it
is actually ordered.
Then **+27 for Plan 3's Step 3**, all in `tests/test_context_arm.py`: the arm-3c prompt and its
producer. Four of them are the ones the comparison actually rests on — that the message *opens with
the exact bytes arm 3 would have sent*, that the two prompts' output contracts are word for word
identical, that neither `PRTask.title` nor `PRTask.body` reaches the model, and that a slice cannot
close the untrusted fence from inside. Every one of the 23 guards was falsified (§14.29), and the
first sweep found one that falsified **green** — the fixture diff had no trailing whitespace, so
`.strip()` was a no-op on it and the guard could not discriminate (§14.57's lesson, arriving in the
step that followed it).
Then **+16 for Plan 3's Step 4**, again all in `tests/test_context_arm.py`: the pre-flight that
refuses a capture before any model call (coverage and `ANALYZER_VERSION`, each falsified by removing
the check), `CaseRun.payload` surviving a dump and an *older* dump without one, the CLI routing
`--arm llm-context` to the context runner rather than parsing it and dispatching elsewhere — with the
neutral cwd and the tool-free assertion both checked at the dispatch — and **3 that close §14.58**:
an LLM arm's scorecard must not claim detectors ran, the pipeline arm's note must not have moved, and
an unrecognised arm must print UNSTATED rather than inherit the most common one. Splitting
`build_parser()` out of `main()` is what made the CLI testable at all; `run` carries fourteen flags
and until 2026-08-26 not one of them had a test that it parsed.
Then **+11 for §4u's two scoring changes**, in the new `tests/test_cwe_relations.py`. Four cover
the `{CWE-59, CWE-61}` pair and five the label-agnostic recall, but the two worth naming are neither:
`test_neither_id_in_the_new_pair_is_emittable_by_any_detector` pins **the rule that let the pair in**,
so a future detector emitting either id turns the decision red instead of silently moving arm 2's
ceiling; and `test_the_rejected_group_would_have_moved_the_ceiling` pins why `{CWE-77, 78, 88}` was
kept out, so the reasoning survives without the probe being re-run.
A final **+4** for the shared payload ceiling (§4v), two of which are the pair that matters: that
the ceiling touches **no** labelled case, so no stored arm-3 result moved when it was added, and that
it **does** bite on exactly two negative-corpus cases — a limit nothing reaches is a limit that has
not been tested.
`cap_engine/`'s working tree is clean — the harness never touches it, and
`pr_review/benchmark/` imports no CAP module at all.

| `benchmark.md` | Deliverable | Status |
|---|---|---|
| §4 | `pr_review/benchmark/schema.py` — `BenchCase`, `GTVuln`, `PRTask`, `CaseRef`, `Corpus`, `AdvisoryRef` | ✅ |
| §4 `loaders/` | `pr_review/benchmark/corpus.py` — GitHub merged PRs → pinned negative corpus | ✅ |
| §4 `loaders/` | `pr_review/benchmark/ghsa.py` — advisories → reverted fixes + post-fix controls | ✅ |
| §4 `runner.py` | `pr_review/benchmark/runner.py` — drives the real `pipeline.run_review()`; serializes a run | ✅ |
| §4 `scoring.py` | `pr_review/benchmark/scoring.py` — FP rule, TP matching, filter ablation, baseline attribution | ✅ ablation now run against real labels |
| §4 `metrics.py` | `pr_review/benchmark/metrics.py` — rates with denominators, strata, pairs | ✅ |
| §4 `report.py` | `pr_review/benchmark/report.py` — markdown scorecard + `run.json` | ✅ markdown; HTML **comparison** scorecard `2026-08-22` (`report_html.py`). The per-PR finding dashboard four plan docs ask for stays unbuilt — `PIVOT_PLAN.md` §3 |
| §3 ablation | Recall after the Phase-2 noise filter | ✅ **36/36**, first run 2026-08-07 |
| §6 | `pr_review/benchmark/gate.py` — CI regression gate | ✅ **2026-08-08**, gates on counts not rates; no CI to wire it into yet |
| §3 | Baseline columns (Semgrep-alone / CodeQL-alone / raw-LLM) | ✅ **2026-08-21**, §4i — semgrep-alone and raw-LLM run; **CodeQL still blocked** (`detect/codeql.py` never built). Raw-LLM unblocked by `models/claude_cli.py`, not by Bedrock |
| §1 | Calibration / ECE | ❌ needs a model |
| §5 | Threshold tuning | ❌ M6 |

**Not a milestone.** This is M6 work pulled forward, sanctioned by `benchmark.md`'s own preamble
("built in M6 but stubbed earlier so each milestone can measure itself"). §8's acceptance is
deliberately **not** met and is not claimed.

---

## 2. What was built, and the reasoning that isn't obvious from the code

### It drives `run_review()`, and that is the whole design

The tempting shortcut is calling `detect_stage()` directly — faster, no run directory, no report
to parse. It would also measure something we do not ship. Errata §14.18 records the general form
("a fixture validates a parser; only the binary validates an adapter"); a harness that
reimplements the pipeline is the same error one level up, validating the harness author's model of
the pipeline instead of the pipeline.

So each case runs the real entry point with the real config, and the harness reads back the
artifacts the real run wrote: `03d_findings.normalized.json`, `02_changeset.json`,
`telemetry.json`. This is also why the run picked up things a synthetic driver would have missed —
the `semgrep --baseline-commit` fallback note and the SCA exit-127 both arrived through
`detect_notes`.

### The corpus pins the merge base, not the base branch tip

A PR's `.diff` is the three-dot diff: `merge-base(base, head) → head`. The GitHub API's `base.sha`
is the base *branch*, which on a PR merged days after it opened has moved on. Materializing that
as `--base-dir` hands `findings/delta.py` a tree the diff was never computed against: the baseline
pass scans content that does not correspond to the diff's "before" side, no fingerprint matches,
and **every pre-existing finding scores as introduced**.

That failure is silent and in the noisy direction — the same shape as errata §14.17's base-side
source reader — and it would have landed directly on the false-positive number this corpus exists
to produce. `corpus.materialize()` computes the merge base with git in the mirror `GitCheckout`
already maintains. This is the one change outside the new package: `GitCheckout.mirror_dir()` is
now public, because a PR's diff is a question only git can answer.

Evidence it works: **158 pre-existing findings were correctly excluded** on the baseline run.
Without delta scoping the measured rate would have been 5.1/PR instead of 1.96. (That count is 91
after defect 2 — 67 of the 158 were themselves phantom-endpoint findings, generated on the base
side and discarded. §3 has the reasoning for why a *smaller* count is the improvement.)

### The endpoint stratum is derived, not selected

Recorded as errata §14.20. Most merged PRs touch no endpoint, so `BAC-MISSING-AUTHZ` cannot fire
in them, and a corpus-wide average prices it at 0.22/PR — arithmetically true and an answer to a
question nobody asked. Restricted to the 5 PRs where the structural detector actually saw an
endpoint it is 2.2/PR.

Two ways to get that number, and only one is honest. Selecting endpoint-heavy PRs into the corpus
would make the *headline* unrepresentative. Deriving the stratum afterwards from
`telemetry.detect.structural.endpoints` leaves both numbers intact. The general rule: **a rule's
false-positive rate must be reported against the population where that rule can fire, and the
denominator has to come from the run rather than from the sampling.**

### `Rate` refuses to be quoted without its denominator

A precision of 0.83 over 6 findings and one over 600 are different claims. `metrics.Rate` keeps
numerator and denominator together and renders them together (`0.750 (3/4)`), so no call site can
drop the n by accident, and an empty denominator renders `n/a (0 cases)` rather than `0.000`.
"We did not look" and "we looked and found none" must not print the same.

### The CWE relation table reports its own influence

`benchmark.md` §3 requires "compatible taxonomy (same CWE family)" and leaves "family" undefined.
Defined widely enough, every finding matches every label and precision goes to 1.0 without a line
of detector work. So `scoring._CWE_GROUPS` is explicit, small, justified per group from MITRE's own
parent/child relations, and exact match is tried first — and `LabelledMetrics.relation_table_share`
reports what fraction of true positives the table bought. If most of them arrive through it, the
headline is a property of that table and the reader can see so.

### Negative-set scoring excludes pre-existing findings

`findings/delta.py` already separates what a PR is answerable for from what it inherited. Counting
inherited findings as false positives would price the repository's backlog rather than the tool's
noise, and would make the tool score worse on an old repo than a new one for reasons having
nothing to do with the detectors.

### The ablation reads an artifact; it does not set a flag

`scoring.ablate_filter()` queries `02_changeset.json`'s existing `DropRecord`s rather than
re-running the pipeline with the filter disabled. That keeps the ablation from perturbing what it
measures, and it is why the verifier ablation at M4 will cost almost nothing: same shape, different
artifact. `DropRecord.guardrail_considered` already existed for exactly this, and separates "the
CPG said this file is inert" from "we never asked".

### Cost prints UNMEASURED, never 0

No model is invoked anywhere in this package. `telemetry.json` carries `tokens: {input: 0,
output: 0}`, and `M1_STATUS.md` §4 is explicit that a zero in a token-economy report reads as
"cheap" when it means "we did not look". The scorecard prints the word.

---

## 3. The measurement — 2026-08-07

**Corpus:** 50 merged PRs, 5 each from 10 Python repositories, pinned in
`benchmark/corpus/negative.json` (7 MB, committed). Zero case errors in either run.
Two runs of the **same** corpus, the second after fixing defects 1, 3 and 5:

| Metric | Baseline | After fixes 1/3/5 |
|---|---|---|
| False positives per PR | 1.96 (98/50) | **0.24** (12/50) — **−88%** |
| **Gate-relevant** (high/critical) per PR | 0.00 (0/50) | **0.00** (0/50) |
| PRs with no findings at all | 86% (43/50) | **94%** (47/50) |
| Pre-existing findings excluded by the baseline | 158 | 158 |
| `sca` adapter status | `error: 2 · not_applicable: 48` | `not_applicable: 50` |
| Endpoint stratum | 10 PRs · 142 endpoints · 6.40 FP/PR | 10 PRs · 142 endpoints · 1.20 FP/PR |
| Wall clock | 1244 s | 1128 s |

- Baseline: `benchmark/results/2026-08-07/` — `negative.md` (generated) + `analysis.md` (hand
  verification, the five defects in full).
- After fixes: `benchmark/results/2026-08-07-after-fixes/` — same pair.

**The fixed classes went to exactly zero and the deferred class did not move**: `INTEG-HIDDEN-TEXT`
85 → 0, `INJ-CODE-EXEC` 1 → 0, `BAC-MISSING-AUTHZ` 12 → 12. That is the shape a targeted fix should
have; a change in the third number would have meant a side effect nobody asked for.

Three readings matter more than the headline. **Nothing either run produced could have failed a
build** — every FP was MEDIUM and `policy.gate()` fires on `validated` at HIGH+, partly by
construction (M2 emits `candidate`, `M2_STATUS.md` §3.3), so re-measure after M4. **The noise was
concentrated, not spread**: 3 PRs produced 85 of the baseline's 98. And **a falling FP rate on a
negative set is not evidence of quality by itself** — breaking a detector produces the same curve.
Both fixes were argued from mechanism and pinned by tests asserting the *surviving* behaviour;
pass 2 is still the real check.

**In-sample.** The fixes were derived from this corpus and measured on it. The −88% is not an
out-of-sample claim.

### Defect 2, measured — and the FP column was the wrong place to look

Third run, `benchmark/results/2026-08-07-defect2/` (scorecard + analysis), code `a6e0226`, every
profile rebuilt from scratch under `ANALYZER_VERSION` 3.

| Metric | Baseline | Fixes 1/3/5 | + defect 2 |
|---|---|---|---|
| False positives per PR | 1.96 | 0.24 | **0.22** (11/50) |
| PRs with no findings | 86% | 94% | **96%** |
| Pre-existing findings excluded | 158 | 158 | **91** |
| PRs where a detector saw an endpoint | 10 | 10 | **5** |
| Endpoints seen | 142 | 142 | **74** |
| `missing-authz` per endpoint | 0.085 | 0.085 | **0.149** |

**The prediction written here before the run held exactly**: 12 → 11 false positives, Saleor's
`@patch` case gone, the 11 Wagtail hits untouched (9 on `#14453`, 2 on `#14452`, same file). The
stated falsification criterion — `BAC-MISSING-AUTHZ` below 11, meaning the rule had taken genuine
endpoints with it — did not trigger.

**One false positive removed, and that was never the point.** Three other numbers moved:

- **The endpoint denominator halved, 142 → 74.** Five of the ten PRs that appeared to touch
  endpoints touched none — they qualified purely on `@patch` decorators in test files.
- **`missing-authz` per endpoint rose 75%, 0.085 → 0.149.** The only number any fix made *worse*,
  and the one most worth trusting: errata §14.20's corollary predicted the phantom denominator was
  understating the rule's own false-positive rate. Blind spot 4 guessed "roughly a factor of two";
  measured, 1.75.
- **67 fewer pre-existing findings, 158 → 91.** Phantom endpoints existed on both sides of every
  diff, so the baseline pass was generating ~67 spurious findings per corpus and `delta.py` was
  dutifully excluding them. They never reached a report and no earlier scorecard showed them.
  A *smaller* count is the improvement here — had the baseline weakened, introduced would have
  risen, and it fell.

---

## 3b. Pass 2 — the labelled GHSA corpus (2026-08-07)

**Corpus:** 26 advisories × 2 cases = 52, over 18 repositories, from the 80 most recent
GitHub-reviewed `pip` advisories. Pinned in `benchmark/corpus/labelled.json` with its generated
build log (`labelled.md`), its hand verification (`labelled-verification.md`) and its reproducible
hand exclusions (`labelled-excluded.txt`). Run: `benchmark/results/2026-08-07-labelled/`,
scorecard + `run.json` + `analysis.md`. **Zero case errors, 878 s, run twice with identical
numbers.**

| Metric | Value |
|---|---|
| **Recall** (span-level, all ground truth) | **0.028** (1/36) |
| Recall over CWEs a 3a detector can name | **0.111** (1/9) |
| Ground truth some finding named, scored or not | **0.139** (5/36) |
| **Pairs discriminated** (vuln flagged, fix silent) | **0.04** (1/26) |
| Precision on labelled cases | 1.000 (1/1) |
| False positives per control PR | 0.42 (11/26) |
| **Gate-relevant false positives** | **0.00** (0/26) |
| **Recall after the Phase-2 noise filter** | **1.000** (36/36) |

### Each case is a fix run backwards, with the fix itself as its control

`benchmark.md` §2a says the pre-fix state is vulnerable ground truth and the post-fix state is the
clean control. Making that reviewable needs a *PR*, since every detector here is diff- and
delta-scoped. So each advisory becomes two cases from the fixing commit F and its parent P:
**A** `base=tree(F) head=tree(P)`, the fix reverted — a PR that *introduces* the vulnerability, so
`delta.py` marks it introduced and scoring can see it; **B** `base=tree(P) head=tree(F)`, the real
fixing PR, `ground_truth=[]`.

**A alone is not worth scoring, and B is why.** In a reverted fix the vulnerable lines are
essentially the whole diff — the easiest possible presentation of the defect — and recall cannot
separate *found the vulnerability* from *always fires on this file*. The control holds the file
constant and removes only the vulnerability, so the **pair** answers that and neither half does.
Hence `metrics.PairMetrics`, and hence 0.04 being the number to quote rather than 0.028.

### The three things worth knowing

**1. Half the corpus is outside this milestone by construction.** 27 of 36 ground-truth rows are
CWEs no 3a detector emits — CWE-1333, CWE-400, CWE-200, CWE-61, CWE-444, CWE-20, CWE-59, CWE-668,
CWE-834, CWE-74, CWE-455. The corpus was **not** filtered to fix that; `pr_review/benchmark/scope.py` derives
the stratum from the detectors' own dispatch tables after selection, the same discipline §14.20
imposed from the other side. **One asymmetry to state:** scope is decided through
`scoring.cwe_match`, so a *narrow* `_CWE_GROUPS` shrinks the in-scope denominator and **flatters**
in-scope recall — the reverse of its effect on TP matching. CWE-88 and CWE-74 (3 rows) are arguably
nameable by `INJ-CMD` and are not in the table; in scope they would make it 1/12. **0.111 is itself
an upper bound**, and widening the table to improve it is precisely what `relation_table_share`
exists to expose.

**2. The detectors are mis-aimed, not blind — and delta scoping costs nothing.** The going-in
hypothesis was that `delta.py` was eating detections: on a reverse-fix case the base is the *fixed*
tree, and a file still carrying same-class taint after the fix would fingerprint-match on both sides
and be demoted to `pre_existing` before scoring saw it. Pass 1 could never have caught that — on a
negative corpus delta scoping only removes false positives, which reads as pure gain. Measured:

- found but attributed to the base **on the vulnerable lines**: **0**
- found but attributed to the base **elsewhere in the file**: **4**

Nothing was lost to attribution; every suppressed same-CWE finding was outside the span anyway, so
it would have been a near miss regardless. What the 4 show is the real gap, and it is structural
rather than a defect: **a taint detector reports at the sink, and a fixing commit's ground truth
sits where the missing validation went.** Different lines by construction. Thumbor is the clearest —
finding at `file_loader.py:40`, ground truth at 19–25 and 37. Same function, same CWE, three lines
apart. `scoring.BaselineAttribution` exists to keep these two failures apart, because `recall`
prices them identically at zero and they have different fixes.

**3. A false-positive class the negative corpus structurally could not surface.** All 11 false
positives are on control cases, all MEDIUM, all `cpg-structural`, and **10 of 11 are in test
files** — the security regression tests the fixes ship with. A path-traversal fix's regression test
is by construction full of traversal-shaped code. Not a construction artifact: the control *is* the
real fixing PR, so a maintainer would really have seen these. `cap_for_test()` is why they are all
MEDIUM and why gate-relevant is 0.00, so the existing mitigation works — and 91% of the corpus's
noise is still one class it only demotes. Deciding it belongs with `suppress.py` (`M2_STATUS.md`
§4.8), not a patch: suppressing test files trades measured noise for unmeasured recall.

### First-time exercises

- **The filter ablation ran at last.** `scoring.ablate_filter` was built and unit-tested at pass 1
  with no labelled cases. **36/36 ground-truth files survived the filter.** Read with the caveat the
  scorecard prints: at M2 the filter does not gate what the detectors see, so this is a baseline
  taken before the stage becomes load-bearing at M3, not a live leak check.
- **SCA ran successfully for the first time in any corpus** (`not_applicable: 51 · ran: 1`). Pass 1
  was `error: 2` before the defect-5 fix and `not_applicable: 50` after. One invocation narrows
  blind spot #3; it does not close it.
- **The one true positive** is `GHSA-f42x-p2mx-hm8r` — `tar.extractall(local_download_folder)` at
  `penelope.py:3418`, exact CWE-22 match, control silent. The only discriminated pair in 26.

### What pass 2 says about the four pass-1 fixes

It was meant to be their out-of-sample check and is a **weak** one. `BAC-MISSING-AUTHZ` fired 0
times across 16 endpoints (vs 0.149/endpoint on the negative corpus) — consistent with the defect-2
fix not having broken endpoint extraction, but 16 endpoints in 3 PRs is thin. The sentinel produced
nothing, so §14.21 was neither exercised nor contradicted. `INJ-CODE-EXEC` still fires, so removing
`compile` did not disable the class. **Honest statement: pass 2 measured the detector suite's
recall and found nothing that contradicts the four fixes.**

---

## 4. The five defects

Full mechanisms and evidence in `benchmark/results/2026-08-07/analysis.md`. Summarized here with
the fix each one needs, because **they are not equally safe to fix.**

| # | Defect | FPs | Fix risk (as rated) | Outcome |
|---|---|---|---|---|
| 1 | Sentinel `hidden-text` fires on GitHub's `@<ZWSP>` convention | 85 (87%) | **Safe** | ✅ fixed → 0 |
| 2 | `_suffix()` makes any `patch`/`get`/… decorator a route | 1 (+ inflates denominator) | **Recall risk** | ✅ fixed — **the rating was wrong**, see below |
| 3 | `re.compile` matches the bare `compile` code-exec sink | 1 | **Safe** | ✅ fixed → 0 |
| 4 | Guard model sees decorators/DI, not imperative authz | 11 | **Design decision** | ⏭ deferred to M3 |
| 5 | SCA feeds `pyproject.toml` to osv-scanner (exit 127) | 0 (2 errors) | **Safe** | ✅ fixed — **worse than measured**, see below |

**Two of the five ratings did not survive contact with the fix**, both in the same direction: the
scorecard understated the defect. #5's failure turned out to be per-invocation rather than
per-file, and #2's "unknown denominator inflation" turned out to be 46% of the entire
access-control matrix. The FP column is a poor proxy for severity because **a defect is only
counted here when it lands inside a diff** — profile-wide corruption is nearly invisible to it.
Worth remembering the next time this table is used to prioritize.

### 1 — the sentinel's invisible-character set conflates two different threats — ✅ FIXED

`sentinel.py:218` `_INVISIBLE` mixes zero-width characters (ZWSP, ZWNJ, ZWJ, BOM, WJ, MVS) with
bidirectional controls (LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI). Only the second group is the
Trojan Source vector (CVE-2021-42574). The first group has legitimate everyday uses — GitHub
escapes `@` as `@<ZWSP>` in generated release notes so changelogs do not notify hundreds of
people, and **ZWJ is required in emoji sequences and Indic scripts**.

**Proposed:** split the set — zero-width characters stop reporting on the non-source surfaces
(`pr:body`, `pr:title`) where platform conventions dominate.

**Implemented instead:** `sentinel._MENTION_ESCAPE` exempts the exact convention — ZWSP only, only
immediately after a visible `@`, only before a word character — on **every** surface. Two reasons
the proposal was worse:

- **It gave up a real capability.** A hidden instruction in a PR body is a genuine vector, and the
  body is the surface a fork PR actually uses (errata §14.13). Turning zero-width detection off
  there to silence one convention trades a detection for a suppression.
- **It fixed the wrong scope.** The convention appears in generated `CHANGELOG.md` files as
  readily as in `pr:body`, so a surface-based rule would have kept firing on source files while
  having stopped watching the surface that matters more.

The measured signature justified the narrow shape: **106 of 106** invisible characters in the
corpus were `@<ZWSP>`+word — unanimous, so nothing wider was needed. Errata §14.21.

**Still open, and deliberately not fixed:** the ZWJ-in-emoji/Indic-script case above. It did not
occur once in the corpus, so fixing it now would be writing an unmeasured rule to solve a
hypothetical — the same mistake the module docstring already refuses for multi-line payloads.

### 2 — route-verb matching discards the receiver — ✅ FIXED, after measuring it properly

`promote.py:87` `_suffix()` keeps only the last dotted segment and `promote.py:204` tests it
against `_ROUTE_VERBS`, so `@patch(...)` from `unittest.mock` becomes a PATCH endpoint. The
catalog spells these `app.patch` / `router.patch`; the receiver is thrown away.

**It was rated "1 FP + unknown denominator inflation" and deferred pending a recall number. That
rating was wrong, and the way it was wrong is the lesson.** Reading the cached Phase-1 profiles
directly instead of the scorecard:

| Access-control matrix rows, all cached profiles | Count | Share |
|---|---|---|
| Real URL paths | 8,685 | 48.5% |
| **`@patch(...)` mock targets** | **8,297** | **46.3%** |
| Unresolved markers (`(unresolved:HomeView)`, Django) | 925 | 5.2% |
| **Total** | **17,907** | |

8,292 of the 8,297 are in test files. **Saleor is 99.8% phantom** (8,018 of 8,038 rows). The
access-control matrix is the artifact phase-3 §3b's BAC agent reads, so this was never a cosmetic
miscount — and the scorecard priced it at **one false positive**, because a phantom endpoint only
produces a finding when its file is in the diff. Errata §14.24.

**Implemented:** `promote._is_route_decorator()`. The discriminator is the **argument, not the
receiver** — a route path starts with `/`, a `mock.patch` target is a dotted attribute path with no
slash — so the rule rejects only on positive evidence of *not* being a route. Verified against the
same 17,907 rows: it removes the 8,297 and touches neither of the other two buckets.

The two rejected alternatives, recorded because both look tidier:

- **Require a dotted receiver** (`@app.get` over `@get`) — still admits `@mock.patch`, which is at
  least as common as the bare form, and drops frameworks exporting module-level route decorators.
- **Require the path to start with `/`** — drops `@app.route()` with the path in a variable and
  Django's `(unresolved:…)` markers. Recall here lands on Broken Access Control, the M3 flagship,
  so the rule is shaped to give ground rather than take it.

Thirteen parametrized cases pin both directions in `tests/test_promote.py`, including the four
unreadable-route shapes that must survive.

**It took two attempts, and the second is the one worth reading.** The first rule required a
complete attribute path — a name after the final dot. Re-running showed Saleor's matrix down from
1,608 rows to 72, of which **68 were still phantom**. Long patch targets are written as
implicitly-concatenated literals:

```python
@patch(
    "saleor.graphql.product.bulk_mutations."
    "product_bulk_delete.get_webhooks_for_event"
)
```

`_first_string()` returns only `"saleor.graphql.product.bulk_mutations."`, which ends at a dot, so
the strict rule kept it. A *prefix* of an attribute path is no more a URL than a whole one — both
still have to pass the no-slash guard to get there — so the trailing segment is now optional.
Re-verified against every cached row: the corrected rule rejects **2,123 of 2,123** remaining mock
targets and **0 of 8,685** URL paths and **0 of 925** unresolved markers.

Two things this cost nothing to learn and would have been expensive to miss:

- **The strict rule looked like a success.** 1,608 → 72 rows is a 96% reduction and every test
  passed. Only counting what *survived* showed 94% of the remainder was still wrong. A big
  improvement is not evidence of a correct rule.
- **`ANALYZER_VERSION` paid for itself within the hour.** The profiles written by the first attempt
  carried `analyzer_version: 2`, so bumping to 3 was the whole of what it took to re-measure
  honestly. Without that key (added the same afternoon, errata §14.25) the second attempt would
  have loaded the first attempt's profiles and reported that the correction changed nothing.

**A dead-catalog finding fell out of this.** `python.yaml` spells route decorators with receivers
under `frameworks.<fw>.endpoints.decorators` — and `promote.py` never reads that key, nor
`method_kwarg`, `path_arg` or `route_table_calls`. Only `endpoints.view_bases` is read. The
hardcoded `_ROUTE_VERBS` exists because the catalog list cannot enumerate every name someone binds
a router to (`bp`, `blueprint`, `api`, `v1`), which is a real constraint — but the catalog header
promises "DATA, NOT CODE … adding a framework should never require touching Python", and for the
single most important extraction it is neither. Listed in §6.

**Resolved 2026-08-08** — §4e, errata §14.33. The constraint above is real but it does not require
hardcoding: the catalog matches decorators by dotted *suffix*, so the receivers were always
decorative and the derived set equals `_ROUTE_VERBS` exactly. `decorators` and `method_kwarg` are
read; the keys describing machinery nobody built are deleted.

### 3 — dotless catalog patterns match any receiver — ✅ FIXED (differently)

`cpg.py:262` `_matches()` is a documented dotted-suffix match; `python.yaml:136` lists `compile`
(the builtin) in `code_exec`. `re.compile` ends with `.compile`, so it matches. Compiling a regex
is not evaluating code.

**Proposed:** a catalog convention — a pattern with no dot matches only a bare call. **Rejected
after checking what else it would hit.** Seven single-segment patterns are single-segment *on
purpose* — `text` (sqlalchemy), `RawSQL`, `render_template_string`, `from_string`, `mark_safe`,
`format_html`, `extractall` — and all are commonly called as `module.name(...)`. The rule would
have silently traded unmeasured recall on six sink classes for one measured false positive, and
recall is exactly what pass 2 has not measured yet.

**Implemented instead:** `compile` was removed from the `code_exec` sink list, because it does not
belong there. **`compile` is a compiler, not an executor** — a code object does nothing until
`eval` or `exec` runs it, and both remain sinks — so this costs no reachable coverage at all. The
test asserts the property against the loaded catalog rather than the removed line, and asserts
`eval`/`exec` survive so a catalog edit cannot pass it by deleting more.

The residual gap the proposal named is unchanged and still real: `from re import compile` followed
by a bare `compile(...)` is indistinguishable without import resolution — but it no longer matters
here, since `compile` is not a sink at all.

**The class is not fixed, only this instance.** Every remaining single-segment pattern still
carries the wildcard, and defect #2 is the same shape from the decorator side. Errata §14.22
records why a blanket guard is the tempting wrong answer.

### 4 — the guard model is partial, and that is a design question

All 11 remaining `BAC-MISSING-AUTHZ` hits are on one Wagtail router file. Inspecting the source
shows the detector was *correct* not to flag the two endpoints carrying
`@require_any_permission(...)`, and the flagged handlers do enforce authorization — imperatively,
via `action_class(page, user=request.user)`, with the check living in another module.
`cpg._resolve_callee` is local-file-first **by design** (`M2_STATUS.md` §2), so the detector
structurally cannot follow it. A few flagged endpoints (`list_pages`, `find_page`) are plausibly
meant to be public — §3.2's "including deliberately public ones", verbatim.

**Not a bug fix.** Adding decorator names would not touch it. The real options are: demote to INFO
when the handler references `request.user`; leave the class to the M3 BAC agent, which is what
phase-3 §3b exists for; or accept the rate. **This should wait for M3** rather than be patched now.

### 5 — SCA hands osv-scanner a file it cannot read — ✅ FIXED, and it was worse than measured

`sca.py:182` passes every changed dependency manifest to `--lockfile`. osv-scanner 2.4.0 has no
extractor for `pyproject.toml` and exits **127**. Recorded honestly as `status=error` with the
message in `detect_notes` — `AdapterRun.status` working as designed — but the effect is that
**SCA contributed no coverage anywhere in this corpus** (`error: 2 · not_applicable: 48`).

**Found while fixing it:** the rejection is **per invocation, not per file**. Probing the real
binary showed osv-scanner extracting `requirements.txt` successfully, then hitting
`pyproject.toml`, exiting 127 and discarding what it had already extracted. So the blast radius
was never "pyproject-only repositories" — *any* PR touching a manifest alongside a real lockfile
lost SCA coverage for both. Errata §14.23.

**Implemented:** `sca._OSV_LOCKFILES` + `_osv_supports()`, probed one file at a time against
osv-scanner 2.4.0 / osv-scalibr 0.4.5 on 2026-08-07 and pinned by a parametrized test that fails
if an upgrade widens support. Unsupported files are filtered before the call; when some remain the
run proceeds and names the skipped ones in `AdapterRun.notes`; when none remain the status is
`not_applicable`, not `error` — a coverage gap rather than a broken tool.

Supported, measured not assumed: `poetry.lock`, `Pipfile.lock`, `package-lock.json`, `yarn.lock`,
`go.mod`, `requirements*.txt`. Rejected: `pyproject.toml`, `package.json`, `Pipfile`, `setup.py`,
`setup.cfg`, `go.sum`, `constraints*.txt`.

**A second gap this exposed, upstream and not fixed.** The proposed fix listed `uv.lock` and
`pdm.lock` — but `extract/deps.py:_FORMATS` does not recognize either, nor `Cargo.lock`,
`composer.lock` or `Gemfile.lock`. A repository pinning with `uv.lock` produces no `DepDelta` at
all, so SCA never sees it regardless of what osv-scanner supports. That is a Phase-0 parser gap,
it is invisible from the scorecard (it renders as `not_applicable`, indistinguishable from "this
PR changed no dependency"), and `uv` is now common enough that it matters. Listed in §6.

---

## 4b. The three small items pass 2 left behind (2026-08-07)

Done after pass 2, in one batch, because two of the three came out of reading a single run
artifact by hand and the third had been open since pass 1.

### The endpoint denominator, validated at last — blind spot #4

Two complementary checks, because neither alone closes it.

**A hand count on real code.** Four Prefect FastAPI routers (`admin.py`, `block_capabilities.py`,
`collections.py`, `block_documents.py`), read by hand and compared with `promote()`:

| File | Hand | Profiled |
|---|---|---|
| `admin.py` | 5 | 5 |
| `block_capabilities.py` | 1 | 1 |
| `block_documents.py` | 6 | 6 |
| `collections.py` | 1 | 1 |
| **Total** | **13** | **13** |

Exact on count, and also on every verb and route path. No extra files, no missed routes.

**A regression test that reproduces the defect.** `test_a_mock_heavy_test_module_adds_no_endpoints`
profiles the fixture with a `@patch`-heavy module added and asserts the count stays 11.
`_is_route_decorator` was already unit-tested on decorator *strings*; what was missing — and what
blind spot #4 actually named — was an assertion on the resulting **count**.

**The first draft of that test was inert, and only the falsification check caught it.** Written
with a module importing just `unittest.mock`, it passed identically with the fix neutralized:
`extract_frameworks` skips any file `_detect_framework` finds no framework in, so the module was
never examined. Adding one `from fastapi.testclient import TestClient` made it bite — 11 endpoints
with the fix, **16 and five phantom rows without it**. Real test modules import the framework they
exercise, which is exactly why Saleor's were 99.8% phantom.

That is §4's lesson recurring at one more level: *a big improvement is not evidence of a correct
rule*, and **a passing test is not evidence of a live assertion**. Neutralize the fix and watch the
test fail, or the guard is decorative.

### `classify.is_generated` did not recognize build output

`extract/classify.py` covered `.min.js`, `_pb2.py`, `/migrations/`, `/vendor/`, `/node_modules/`
and `/.generated/` — but not sourcemaps or `dist/`. So
`netbox/project-static/dist/netbox.js.map`, a minified sourcemap, was scanned like source and
produced a **HIGH `SEC-PASSWORD`** finding on a base64 blob.

Consequential rather than cosmetic: `secrets.py` and `sast_semgrep.py` both skip a generated file
outright and `change/filter.py` drops it, so this is the switch that decides whether a bundle gets
scanned at all. Added: `.js.map`, `.css.map`, `.min.css`, `/dist/`. **`build/` deliberately not** —
it was never observed and, unlike `dist/`, routinely holds hand-written tooling, so adding it would
trade unmeasured coverage for a hypothetical.

Latent in pass 1 in the way §4 warns about: the finding was pre-existing on all 50 cases, so
`delta.py` excluded it and **no scorecard ever showed it**. First sight of it was reading a
`run.json` by hand while sizing the serialization dump.

**Re-measured, both corpora, and the prediction written before the run held exactly.** The
prediction was: introduced findings unchanged on the negative corpus (all 11 are Wagtail
`BAC-MISSING-AUTHZ`, not secrets) with the *pre-existing* count falling by the sourcemap; and
every labelled number unchanged, since those 18 library repos carry no `dist/` or sourcemaps.
Falsification criterion: any movement in introduced findings would mean the rule was broader than
intended.

| | Before (`-defect2`) | After (`-generated-fix`) |
|---|---|---|
| False positives per PR | 0.22 (11/50) | **0.22 (11/50)** |
| Gate-relevant per PR | 0.00 | **0.00** |
| PRs with no findings | 0.96 | **0.96** |
| Endpoint stratum · `missing-authz`/endpoint | 2.20 · 0.149 (11/74) | **2.20 · 0.149 (11/74)** |
| **Pre-existing findings excluded** | **91** | **90** |

Exactly one finding removed, and it is the sourcemap. Nothing else moved on either corpus — the
labelled scorecard is identical line for line. `benchmark/results/2026-08-07-generated-fix/` and
`-labelled-generated-fix/`, both with `run.json`.

A rule that removes one specific known-bad finding and touches nothing else is the shape a targeted
fix should have — the same test §3 applied to the pass-1 fixes, where the fixed classes went to
zero and the deferred one did not move.

### `secrets.py` bypassed `MAX_SNIPPET_CHARS`

`normalize.make_finding` bounds evidence snippets at 400 characters; `secrets.py` built its
`Evidence` directly and did not. On the sourcemap above that is a **1.25 MB** snippet inside the
finding, the run artifact, and — had it been introduced rather than pre-existing — a code fence in
`report.md`. It alone made a three-case `run.json` 1.3 MB.

**Safe to land without re-measuring, and checked rather than assumed:** `secrets.py` calls
`fingerprint(path, internal, None, secret)` — the *secret*, not the evidence line — so truncation
cannot move a fingerprint, a baseline match, or any count. (`normalize.make_finding` does hash its
snippet, but truncates *before* hashing, so it was already consistent.)

---

## 4c. Acting on pass 2 — the dual-role taint defect (2026-08-08)

Pass 2's two open questions were posed as design decisions. Measuring them turned one into a
defect with a mechanism-level fix and the other into a deliberate acceptance.

### The false positives were never about test files

Pass 2 read as "10 of 11 false positives are in security regression tests". Inspecting the flows
showed something else: `source` and `sink` were **the same node**.

Three `python.yaml` patterns are legitimately both — `open` (filesystem/path), `requests.get` and
`httpx.get` (network/http_outbound) — and each classification is correct on its own terms:
`open(p)`'s **argument** is a path sink, `open(f).read()`'s **return value** is untrusted data. The
node builder does not distinguish argument position from return position, so every `open(x)` emits
a source node *and* a sink node and `_taint`'s cross product pairs them. Test code merely calls
`open()` more often; 42 of the same shape were sitting in non-test code in the same corpus.

Fixed in two steps, each measured on both corpora, because their blast radii differ.

**A — the degenerate case.** A path whose source and sink are the same call site is not a path.
**B — the general case.** A dual-role pattern never pairs with *itself* at any distance: pairing
`open`@29 with `open`@38 claims the contents read at 29 reach the path argument at 38, which
`_taint` does not establish — it pairs by co-location in a call tree, not by dataflow.

B is compared on the matched **pattern**, not the call text, so `open` and `f.open` count as one
entry. `CPGNode.attrs["pattern"]` was added to carry it (`ANALYZER_VERSION` 3 → 4 → 5).

**What B deliberately keeps**, and what four tests pin: `open` still seeds taint into *other* sinks
(`os.system(open(cfg).read())`), still receives taint from *other* sources
(`open(request.args["f"])`), and two different patterns still pair — which is what pass 2's only
true positive is.

### Measured, both corpora, four runs

| Labelled (pass 2) | Original | +`is_generated` | +A | +B |
|---|---|---|---|---|
| **False positives per PR** | 0.42 (11/26) | 0.42 | 0.31 (8/26) | **0.04 (1/26)** |
| Control PRs with no findings | 0.88 | 0.88 | 0.92 | **0.96** |
| **Recall** | 0.028 (1/36) | 0.028 | 0.028 | **0.028** |
| **Recall, in scope** | 0.111 (1/9) | 0.111 | 0.111 | **0.111** |
| **Pairs discriminated** | 0.04 (1/26) | 0.04 | 0.04 | **0.04** |
| Pre-existing excluded | 149 | 149 | 109 | **80** |

| Negative (pass 1) | After defect 2 | +`is_generated` | +A | +B |
|---|---|---|---|---|
| False positives per PR | 0.22 (11/50) | 0.22 | 0.22 | **0.22** |
| Gate-relevant | 0.00 | 0.00 | 0.00 | **0.00** |
| `missing-authz` per endpoint | 0.149 (11/74) | 0.149 | 0.149 | **0.149** |
| Pre-existing excluded | 91 | 90 | 81 | **75** |

**A 90% cut in false positives with every signal number bit-identical.** Recall, in-scope recall,
pair discrimination, precision and localization did not move on the labelled corpus, and the
negative corpus did not move at all except in the pre-existing count. That is the shape §3 demands
of a targeted fix, and it is the strongest form available: the classes aimed at collapsed and
nothing else did.

### Two predictions that were wrong, and why that was useful

**"A will remove 6 findings."** It removed 3. Six self-loop *paths* went, but `Finding.fingerprint`
excludes line numbers (cross-cutting §6), so removing the 29→29 path merely re-attributed the same
finding to the 38→29 pairing. **Paths are not findings; the mapping is many-to-one.** Worth
remembering whenever a graph-level fix is priced against a finding-level number.

**"B will take the remaining 8 to 0."** It took them to 1. The survivor is `BAC-SSRF` in a test
file, source `open`@292 → sink `requests.post`@294 — **two different patterns**, so B correctly
leaves it alone. It is a genuine cross-pattern path that happens to be in test code, which is the
residue of the original "test-file" question and is now a single finding rather than a class.

### The other question was accepted, not fixed

The localization gap is recorded as errata **§14.30** and **deliberately not patched**. The four
in-scope misses with a finding in the right file are cases where the detector emits *identical*
findings on the vulnerable and fixed trees (12 of 12 fingerprints), because the vulnerability is a
change of operation order — thumbor moves percent-decoding above its containment check, and both
versions satisfy `abspath` + `requires_containment_check`. Widening the location window is
provably inert here (near misses are 0; every candidate is `pre_existing`), and scoring at file
level would move recall 0.028 → ~0.14 without touching the tool. The class belongs to Phase 3b,
which now has a measured argument rather than a design intuition.

---

## 4d. Five more lockfile formats, and the first SCA findings (2026-08-08)

`extract/deps.py` gained `uv.lock`, `pdm.lock`, `Cargo.lock`, `composer.lock` and `Gemfile.lock`.
Agenda item 2, picked up because pass 2 made it interesting: SCA had run **once** in 102 cases.

Poetry, uv, pdm and Cargo turn out to be one format — `[[package]]` blocks keyed `name` then
`version` — so they share `_parse_toml_lock`. composer.lock and Gemfile.lock each needed their own.
`_OSV_LOCKFILES` was re-probed against osv-scanner 2.4.0 rather than reasoned about, the same way
the entry above it was earned: all five extract, in one multi-`--lockfile` invocation.

### It was measured because it was not inert

10 of the 50 negative cases and one labelled pair touch these files. The 11 deltas were computed
offline from the pinned diffs **before** the run, so the input was known exactly and only the
pipeline's response to it was open (`scratchpad/lockfile-prediction.md`).

| | Before (`-selfpair`) | After (`-lockfiles`) |
|---|---|---|
| `sca` adapter status, negative | `not_applicable: 50` | **`ran: 10 · not_applicable: 40`** |
| `sca` adapter status, labelled | `ran: 1 · not_applicable: 51` | **`ran: 3 · not_applicable: 49`** |
| False positives per PR, negative | 0.22 (11/50) | **0.24 (12/50)** |
| Gate-relevant per PR, negative | 0.00 | **0.02 (1/50)** |
| False positives per PR, labelled | 0.04 (1/26) | **0.08 (2/26)** |
| Gate-relevant per PR, labelled | 0.00 | **0.04 (1/26)** |
| Pre-existing excluded | 75 · 80 | **75 · 80 — unchanged** |
| `BAC-MISSING-AUTHZ` · endpoints · per endpoint | 11 · 74 · 0.149 | **identical** |
| Recall · in-scope · pairs | 0.028 · 0.111 · 0.04 | **identical** |

The falsification criterion held exactly: this change touches dependency files, and no
source-code number moved by anything.

### Two predictions wrong again, and both worth the ink

**"Gate-relevant stays 0.00."** It went to 0.02 and 0.04, one HIGH on each corpus, and **both
findings are correct**. fastapi#16141 bumps `gitpython 3.1.54 → 3.1.57`; 3.1.57 is affected by six
advisories and fixed in 3.1.58. The PR upgraded, but not far enough. Blind spot 2 has said since
pass 1 that a merged PR can carry a real vulnerability and the corpus will score it as a false
alarm — this is the first time that stopped being hypothetical, and **the number should not be
tuned back down**. What it costs is the clean 0.00 gate-relevant line; what it buys is the first
evidence any part of this tool finds a real defect in code nobody flagged.

**"Pre-existing falls."** It did not move: 75 and 80, both unchanged. The reasoning was that those
lockfiles had been scanned as ordinary files and would now be dropped as `lockfile_captured`. True,
and worthless — they were producing **no findings** to drop. `uv.lock`'s `hash = "sha256:…"` lines
never matched a secrets rule. So the value of this change is not noise removal; it is that SCA sees
a dependency delta at all. Assuming a newly-silenced input was noisy is the same shape of error as
§14.31's "10 of 11 are in test files".

### The labelled corpus's SCA finding is an artifact, and a real one

`GHSA-29w2-fq35-v728:control` — the *fixing* side of the pair — reports the project against **its
own advisory**. `uv.lock` carries an editable self-entry, `awslabs-aws-api-mcp-server`, and the fix
commit's tree declares 1.3.46 while OSV says 1.3.46 is vulnerable and 1.3.47 fixes it. The code fix
is present; the version bump that announces it landed in a later commit.

Checked against the git graph rather than assumed: `ab1bbeb` is the fix and declares 1.3.46,
`70d8c4c` is its parent and declares 1.3.47. The version string in this monorepo's lockfile does
not order with its commits, so both cases' `base_sha`/`head_sha` and `diff_text` agree and the
corpus is sound — the inversion is in the version numbering, not the construction. Recorded as
errata **§14.32**, with the open code question (should SCA skip a lockfile's editable self-entry?)
left for the next session rather than patched here.

---

## 4e. Two design decisions and a gate (2026-08-08)

Agenda items 1–3. Both decisions were argued from mechanism and **the predictions below were
written into this file before the run**, which is the only arrangement under which "the number
moved the way I expected" carries information.

### The predictions, pre-registered

Computed offline from the pinned diffs and head checkouts of all 13 SCA-invoking cases, before
anything was run. The first-party marker is present in **every** `uv.lock` (saleor is `virtual`, the
rest `editable`) and in `pydantic-core/Cargo.lock`; it is *in the delta* in **5 of 13** cases and
produces a finding in exactly **one**.

| | Predicted |
|---|---|
| negative — every scored number | **unchanged**: FP/PR 0.24, gate-relevant 0.02, 74 endpoints, missing-authz 0.149 |
| negative — `sca` status | **unchanged** at `ran: 10 / not_applicable: 40` |
| negative — `first_party_skipped` | appears on saleor#19616, saleor#19613, pydantic#13597 **and nowhere else** |
| labelled — findings | exactly **one** disappears, on `GHSA-29w2-fq35-v728:control` |
| labelled — FP/PR · gate-relevant | 0.08 → **0.04** · 0.04 → **0.00** |
| both — recall · in-scope · pairs · precision · localization | **unchanged** |

**Falsification criterion:** anything else moving means the rule is too wide. Specifically the
negative corpus must not lose a finding and `sca` must not lose an invocation.

One run adjudicates both changes because they name **disjoint** numbers — the endpoint change may
move endpoints/missing-authz/recall and is predicted to move nothing, the SCA change may move `sca`
findings only.

The endpoint side was settled independently and more cheaply first, and that is the part worth
copying: 39 of the 41 cached profiles were rebuilt from their checkouts and their endpoints and
access-control matrices compared **whole** against the stored artifacts — **8,576 endpoints and
9,610 matrix rows, zero differences**, in 20 minutes rather than an hour. A change predicted to be
inert should be falsified by the cheapest instrument that can do it, not by the headline one.

### Measured

| | Before (`-lockfiles`) | After (`-decisions`) | Predicted? |
|---|---|---|---|
| FP per PR, negative | 0.24 (12/50) | **0.24 (12/50)** | ✅ |
| Gate-relevant, negative | 0.02 (1/50) | **0.02 (1/50)** | ✅ |
| `sca` status, negative | `ran: 10 · n/a: 40` | **identical** | ✅ |
| Endpoints · missing-authz, negative | 74 · 0.149 (11/74) | **identical** | ✅ |
| Pre-existing, negative · labelled | 75 · 80 | **75 · 80** | ✅ |
| FP per PR, labelled | 0.08 (2/26) | **0.04 (1/26)** | ✅ |
| Gate-relevant, labelled | 0.04 (1/26) | **0.00 (0/26)** | ✅ |
| `sca` status, labelled | `ran: 3 · n/a: 49` | **identical** | ✅ |
| Recall · in-scope · pairs | 0.028 · 0.111 · 0.04 | **identical** | ✅ |
| Precision · localization · filter ablation | 1.000 · 1.000 · 36/36 | **identical** | ✅ |
| `first_party_skipped` on the negative corpus | — | **0 cases** | ❌ predicted 3 |

Zero case errors on both. Exactly one finding disappeared, on `GHSA-29w2-fq35-v728:control`, and
nothing else moved on either corpus — including the negative corpus's endpoint numbers, which is the
second and independent confirmation that the catalog change was inert.

### The wrong prediction, which is the useful part

**`first_party_skipped` fired on nothing.** It was predicted to appear on saleor#19616,
saleor#19613 and pydantic#13597 — the three negative cases whose delta *is* the first-party entry.
It did not, and the code is right: the counter sits after `if not vulns: continue`, so it counts
self-entries that would otherwise have produced a **finding**, not self-entries that exist. Saleor
and pydantic-core carry no advisories against themselves, so there was nothing suppressed and
nothing to state. Counting them would have inflated a "what did we hide from you" number with
non-events, which is the opposite of what it is for.

**This is the same error as last session's "pre-existing falls"** (§4d), one level down: assuming a
newly-handled input was doing something, when the reason it was quiet is that it had nothing to say.
Twice now the mistake has been to predict a counter would move because the *input* reached it,
rather than because the *event it counts* occurred.

It also makes the negative-corpus result stronger than predicted rather than weaker: the SCA change
is not merely score-neutral there, it is completely invisible — no finding, no counter, no note.

### A harness wrinkle found in passing

Both runs were first launched with `--label decisions`. `write_scorecard` names the markdown per
corpus (`negative.md`, `labelled.md`) but `run.json` is **fixed per directory**, so the second run
refused to clobber the first's dump — correctly, and after 844s of work. The scorecard survived in
stdout; the dump did not. Prior sessions avoided this by convention (`-lockfiles` /
`-labelled-lockfiles`) rather than by anything enforcing it. Noted in `OPEN_ITEMS.md`.

### What made the endpoint decision decidable

The catalog's own header (`python.yaml`, MATCHING CONTRACT) says decorators are matched by **dotted
suffix**. Under that contract the receivers in `app.route` / `bp.route` were always decorative, and
the suffix set the catalog implies *is* the hardcoded `_ROUTE_VERBS` — once `add_url_rule`, which is
a call and not a decorator, comes out. So the design question "the hardcoded verb set exists for a
real reason" dissolved: the reason (a catalog cannot enumerate every name a router is bound to,
`bp`/`blueprint`/`api`/`v1`) is satisfied by suffix matching, not by hardcoding. Full detail in
errata §14.33.

### The gate gates on counts

`pr_review/benchmark/gate.py`, and the reason it is not what §6 specified. §6 asks for tolerances on P/R/FP,
which assumes rates stable enough for a tolerance to mean something. Recall is **1/36** carried by
one true positive; a single finding moves negative FP/PR by 0.02, the same distance as the entire
gate-relevant number. A tolerance wide enough to survive normal variation would be wider than the
signal. So: **integer ratchets against a pinned `run.json`, and every rate printed without gating on
it.** Ranked above all of them are the invariants — a case error, a detector's `ran` count dropping,
the filter eating ground truth — because every expensive lesson on this branch was a detector going
quiet rather than a number going bad.

It caught itself first. The first draft loaded runs with `CorpusRun.from_dict`, which does not
re-derive `scores`, and printed **"PASS — 7 checks"** on two real corpora it had never scored: every
ratchet is an inequality, so zero against zero satisfies all of them at once. Errata §14.33.

Run across this session's two pairs it **passes both, 12 checks each**. The labelled pair is the one
worth reading: `false positives 2 → 1` and `gate-relevant 1 → 0` pass as improvements while
`true positives 1 → 1`, `in-scope 1 → 1` and `discriminated pairs 1 → 1` hold — noise down, signal
flat, stated as five integers none of which a tolerance on a rate could have expressed.

Run across the *lockfile* change instead it **fails**, correctly, on `gate-relevant 0 → 1` — the
gitpython finding. A true positive still moves the number a baseline pins, and the answer is
re-pinning the baseline, not tuning the finding away.

---

## 4f. FastAPI `dependencies=` guards — and the premise that was wrong (2026-08-08)

Agenda item 3's first entry. The stated reason to do it was: FastAPI router-level guards read as
unguarded and **inflate `missing-authz` (0.149, 11/74)** — "the one that corrupts a published
number." That reason is **false**, and finding out cost less than implementing it would have.

### The premise, falsified before any code was written

All 11 `missing-authz` findings — 92% of the negative corpus's 12 false positives — are in **one
file**, `wagtail/api/v3/routers/pages.py`, across two PRs (#14452, #14453). That file is
**django-ninja** (`from ninja import Router`; promoted as `django` only because of its `django.http`
imports) and contains **zero `dependencies=`**. The 11 decompose as:

| Count | Endpoints | Actual cause | Owner |
|---|---|---|---|
| 9 | `publish`, `unpublish`, `copy`, `move`, `delete`, `revert`, `convert_alias`, `create_alias`, `copy_for_translation` — all on `actions_router` | authz enforced **imperatively in the body**: `if not page.permissions_for_user(request.user).can_publish(): raise PublishPagePermissionError` | **defect 4**, deferred to M3 with the BAC agent |
| 2 | `list_pages`, `find_page` | deliberately-public reads over a tier-filtered queryset | §3.2's named worry, and blind spot 2 |

So `router_kwarg` moves `missing-authz` by **exactly 0**. This is the **third** instance of one
error: predicting a counter moves because *the input reached it*, rather than because *the event it
counts happened* — after `first_party_skipped` (§4e) and "pre-existing falls" (§4c).

### What the corpora actually contain

Paren-balanced scan of 138,691 Python files across every checkout:

| Form | Sites | Where | Same-file? |
|---|---|---|---|
| `@router.post(…, dependencies=[…])` — route decorator | 240 | flyto-core **20 (production)**, fastapi tests 220 | yes |
| `APIRouter(dependencies=[…])` — constructor, i.e. `router_kwarg` | 308 | fastapi tests **only** | yes |
| `include_router(…, dependencies=[…])` | 209 | Prefect **9 (production)**, fastapi tests 200 | **no** |

Two things fall out. The decorator form — where the corpus's only production usage outside Prefect
lives — **was not a catalog key at all**; the audit that found nine inert keys could not find a key
that was never written. And `router_kwarg`'s entire measurable population here is test code in one
repo. Both same-file forms are now read; `include_router` is deferred on the splice-violation and
partial-cache argument (`OPEN_ITEMS.md` §8).

### The prediction, pre-registered

Against the 41 cached profiles, 7,908 of 9,610 access-control matrix rows are unguarded. Of those,
**220** carry a decorator-level `dependencies=` and **≤400** sit in a file containing a
constructor-level one (an upper bound: "in a file with" is not "bound to").

| | Predicted |
|---|---|
| Matrix rows | **unchanged at 9,610** |
| `enforcement` flips `none → enforced` | **≤620 rows, every one inside `fastapi__fastapi`** |
| Flips in wagtail · flask · netbox · DRF · Prefect · saleor | **zero** |
| Every scored number, both corpora | **unchanged** — negative FP 12, gate-relevant 1, missing-authz 11/74 |

**Falsification criterion:** any flip outside `fastapi__fastapi`, or any change to the row count.
Either means receiver attribution is wrong. Note the prediction is *not* that the change is inert —
it is that the change is confined to an artifact no scored number reads, which is a different claim
and the reason the cheap instrument can settle it.

### Measured

39 of 41 cached profiles rebuilt and their matrices compared whole, twice, ~9.5 min each. (The two
skipped are `o__r` fixtures with no checkout — the same 39 §4e compared. The pre-registered "9,610"
counted all 41; the comparable population is **9,606**, and that four-row difference is bookkeeping,
not movement.)

| | Predicted | Measured | |
|---|---|---|---|
| Matrix rows | unchanged | **9,606 → 9,606**, 0 added, 0 removed | ✅ |
| Flips confined to `fastapi__fastapi` | yes | **180 of 180** | ✅ |
| Flips in wagtail · flask · netbox · DRF · Prefect · saleor | zero | **zero** | ✅ |
| `none → enforced` | ≤620 | **170** (110 `route_dependency`, 60 `router_dependency`) | ✅ |
| Every scored number, both corpora | unchanged | wagtail's rows did not move, so no `missing-authz` finding can | ✅ |

The 620 was an upper bound and behaved like one: it counted rows *in a file containing* a
constructor-level `dependencies=`, which is not the same as rows *bound to* that router.

### The prediction held, and holding was not sufficient

**Reading the 370 rows of the first pass — rather than checking the count against the bound — found
a defect in the change itself.** The first `_router_guards` walked every `assignment` in a file and
pooled them by name. `fastapi/tests/test_dependency_yield_scope.py` binds a module-level
`app = FastAPI()` with **no** guard and two *function-local* `app = FastAPI(dependencies=[...])`
inside test bodies, so endpoints on the real `app` came back **enforced** on the strength of a
variable in another scope. A false `guarded` is the dangerous direction: it silently removes a
`missing-authz` finding rather than adding noise.

Three narrowings, each independently falsified: syntactically module-level bindings only, names
assigned exactly once, and a name already recorded is not recorded again. They removed **half the
movement** — 74 changed rows per fastapi profile became 36, and 345 `none → enforced` became 170.

This is §4c's "check the artifact, not just the metric" one level further down: **check the rows,
not the count of rows**. The count agreed with the prediction in both passes. Only the rows said
which of the two was right.

Getting a *test* for the scope rule took three attempts, and both failures were inert rather than
wrong. The first fixture gave the function-local router a name no decorator referenced, so removing
the check changed nothing. The second gave it a name that *was* referenced — and the assigned-once
rule then caught the same shape, so the check still could not be falsified alone. Only a conditional
module-level binding (`if FLAG: router = APIRouter(dependencies=[...])`) isolates it. The overlap is
now stated in the docstring, per the standard §14.29 sets and `OPEN_ITEMS.md` §7 applies.

### The labelled corpus, pre-registered before running

The negative corpus was not re-run: zero wagtail rows moved, so no `missing-authz` finding can
change, and every flip is in `fastapi__fastapi`'s test suite where no case fires. The labelled
corpus **was**, because it is the one containing flyto-core — the only production usage of the
route-decorator form in either corpus, where 5 of 22 FastAPI endpoints go from unguarded to
`route_dependency`.

| | Predicted |
|---|---|
| Every scored number | **unchanged**: FP/PR 0.04 (1/26), gate-relevant 0.00, recall 0.028 (1/36) · in-scope 0.111 (1/9) · pairs 0.038 (1/26), endpoints 16 · missing-authz 0.000 (0/16), `sca ran: 3` |
| Case errors | **zero** |
| Gate vs `2026-08-08-labelled-decisions` | **PASS**, 12 checks |

Two mechanisms, not one, and stating both is the point — a guard change can move these numbers by
exactly two routes and both are closed:

- `missing-authz` is **already 0 of 16** on this corpus. Guards can only hold it at zero; there is
  no finding there to remove.
- `guard-removed` fires when an endpoint is guarded in base and unguarded in head, so a PR *deleting*
  a `dependencies=[...]` would newly produce one. **No case's diff touches a `dependencies=` line** —
  checked across all 52 before the run, rather than assumed from the fact that flyto-core is present.
  That is the §12 error stated as a positive test: the input reaching the code is not the event.

**Falsification criterion:** any scored number moving at all.

**Measured** — `benchmark/results/2026-08-09-labelled-deps/`, 52/52 cases, 782s, zero case errors.
**Every scored number identical to the baseline**, and the gate against
`2026-08-08-labelled-decisions` returns **PASS — 12 checks, exit 0**:

| | Baseline | This run |
|---|---|---|
| False positives per PR | 1/26 | **1/26** |
| Gate-relevant per PR | 0/26 | **0/26** |
| Recall · in-scope · pairs | 1/36 · 1/9 · 1/26 | **1/36 · 1/9 · 1/26** |
| Endpoints · missing-authz | 16 · 0/16 | **16 · 0/16** |
| `sca` · `structural` · `secrets` · `semgrep` · `iac` invocations | 3 · 52 · 52 · 52 · 0 | **identical** |
| Filter ablation | 0 dropped of 36 | **0 dropped of 36** |

The interesting part is that this was predicted from *two* named mechanisms rather than from the
change looking small — `missing-authz` is already zero here so guards cannot lower it, and no case's
diff touches a `dependencies=` line so `guard-removed` cannot newly fire. Both were checked before
running. flyto-core's 5 newly-guarded endpoints are real and change the profile; they change nothing
scored, because nothing scored was reading them.

### The ten rows that were not flips

The remaining 10 are `enforced → enforced` with the guard list **reordered**:
`['get_user', 'get_db'] → ['get_db', 'get_user']`, moving `auth_pattern` from `dependency:get_user`
to `dependency:get_db`. That is the `_dep_names` refactor, and it is a fix rather than a change: the
loop it replaced iterated a **set** of call names, and Python randomizes string hashes per process,
so an endpoint carrying both `Depends` and `Security` could put either into `guards[0]` — the value
`security_profile._auth_pattern` writes into the matrix. Those rows were not stable before; they are
now, in source order.

It also exposes something pre-existing that this change does not fix: `dependency:get_db` names a
database session as the endpoint's authorization mechanism, because **any** `Depends` counts as a
guard. `OPEN_ITEMS.md` §9.

---

## 4g. Four catalog patterns that matched the wrong receivers (2026-08-09)

Agenda item 3's remaining entries were `sources.param_annotations` and the
`danger_kwarg`/`conditional_calls` pair. Neither was done, and the reason is the same shape as §4f:
**the population was measured before the work was planned, and it was not the population the agenda
assumed.**

### The scorecard cannot see the taint engine

This is the number to carry forward, and it applies to every taint item on the agenda, not only to
what was built:

| | taint paths | taint findings | reported | **scored** |
|---|---|---|---|---|
| negative, 50 merged PRs | 29 | 9 | 0 | **0** |
| labelled, 52 cases | 2,938 | 457 | 76 | **1 TP + 1 FP** |

80 of the labelled corpus's 82 findings are `pre_existing`, because the reverse-fix construction
makes the fixed tree the base and anything present on both sides is excluded before scoring. The
negative corpus's merged PRs rarely touch a taint site at all. So **no taint-precision change can
move either published FP number** — not this one, and not `param_annotations` or the argument
pair behind it. Asking "which of these moves a number" is the wrong question for all three, and it
would have consumed the session.

What *can* be read is the artifact: the reported finding set, and the node census under it.

### What the reported findings actually are

Read, not inferred, from `2026-08-09-labelled-deps/run.json`:

- **40 of the 42 `INJ-CODE-EXEC` findings are `self.exec` / `session.exec` / `self.control_session.exec`.**
  `penelope.py:2625` defines `def exec(self, ...)` — the scanned project's own method for running a
  command on a remote session. The catalog's bare `exec` matched it by dotted suffix.
- 5 more are `request.text` and `part.text` reported as **SQL sinks** — HTTP response bodies and a
  Qt widget accessor, via `sinks.sql.calls: [… text …]`.
- Both `INJ-CMD` findings are `subprocess.check_output`, one of them
  `subprocess.check_output(['ifconfig'])` — a literal list, with the "source" an `open` 4,600 lines
  away in a different function.

### The census, from the pipeline's own output

The 41 cached `cpg.json` files hold the node set ANALYZER_VERSION 7 built, so the before side cost
nothing to obtain:

| pattern | role | nodes | correct receivers | colliding receivers |
|---|---|---|---|---|
| `escape` | **sanitizer** | 1,344 | `html.escape` 31 (listed separately) | **`re.escape` 1,036**, `CSS.escape` 20 |
| `eval` | sink | 340 | none | `c.eval` 199, `cs.eval` 125 |
| `text` | sink | 1,632 | **`sa.text` 1,557** | `st` 20, `strategies` 12, `eavesdropper` 9 |
| `exec` | sink | 20 | none | `session.exec` 20 (SQLModel) |
| `poll` | source | 27 | none | `Popen.poll()`, every one |
| `consume` | source | 27 | none | `self.consume` 15 |

### Two conclusions from `rg` that the cached CPGs corrected

Worth recording because both would have produced a worse fix:

1. **`text` is mostly *correct*.** A corpus-wide `rg` said 495 bare against 6,859 dotted and read as
   a disaster. The CPGs say 1,557 of 1,632 nodes are `sa.text` — SQLAlchemy, exactly right. A
   blanket "single-segment patterns are unsafe" rule would have deleted them. The collision rate is
   **repo-dependent**: low here, high in the labelled corpus's Qt and HTTP code.
2. **`exec` is small here and dominant there.** 20 nodes on the negative corpus, 40 of 42 reported
   findings on the labelled one, because penelope has no cached profile in the negative set.

So the fix is not a rule about segment counts. `urlparse` (51 × `urllib.parse.urlparse`),
`bindparam` (69 × `sa.bindparam`), `from_string` (`app.jinja_env.from_string`) and `extractall` are
single-segment too and their dotted forms are **correct**; exact-matching them would have cut real
coverage. The shortlist is a measurement, and it is recorded next to each pattern in the catalog.

### The asymmetry that decided the ordering

`escape` is a **sanitizer**, and `detect/structural.py:200` drops any path with `sanitized_by`
outright. `re.escape` therefore **deletes** findings, silently, with no verifier downstream to
restore them. The catalog header's standing trade — "recall matters more than precision here, these
only *seed* candidates and Phase 3c verifies" — is an argument about **sinks**. It is not an
argument for a loose sanitizer, which is loose in the opposite direction. That paragraph now says so.

The second reason to do this before `param_annotations`: `_taint` is a source×sink cross product,
and of the sink matches inside the 169 FastAPI functions `param_annotations` would seed, **68 of 239
are collisions**. Seeding new sources first multiplies them.

### The prediction, pre-registered

Written into the approved plan before any census was run:

| node class | before | predicted after |
|---|---|---|
| `escape` sanitizer | 1,344 | 308 — all 1,036 `re.escape` gone |
| `eval` sink | 340 | 0 |
| `text` sink | 1,632 | 1,587 — `sa` 1,557 + bare 30 kept, 45 collisions gone |
| `exec` sink | 20 | 0 |
| `poll` source | 27 | 0 |
| `consume` source | 27 | 12 |
| **every other pattern** | — | **unchanged** |

**Falsification criterion:** movement in any pattern not on that list, or any drop in `sa.text`,
`urlparse`, `bindparam`, `from_string` or `extractall`. Either means the exactness is applied to the
wrong set. Net ~1,483 nodes removed.

**And the honest risk, pre-registered with it.** Removing 1,036 sanitizer nodes should *increase*
findings, because paths marked `sanitized_by` become reportable. But a sanitizer only neutralizes
**its own class** (`cpg.py`'s `_taint`), so this can only surface **template** sinks — and neither
corpus reports a single `INJ-SSTI`. If the census produces zero newly-unsanitized paths, **the
sanitizer half is inert on these corpora and this section says so** rather than claiming a win from
the node count. That is §4f's lesson applied to my own proposal instead of the agenda's.

### Measured — the census

39 of 41 cached profiles rebuilt, 819s, zero errors. (The two skipped are the `o__r` fixtures with
no checkout, the same two §4e and §4f skipped.)

| kind | pattern | before | after | delta |
|---|---|---|---|---|
| sanitizer | `escape` | 1,344 | 308 | **−1,036** |
| sink | `eval` | 383 | 43 | **−340** |
| sink | `exec` | 80 | 60 | **−20** |
| sink | `text` | 1,632 | 30 | −1,602 |
| sink | **`sa.text`** | 0 | 1,557 | **+1,557** |
| source | `consume` | 27 | 12 | −15 |
| source | `poll` | 27 | 0 | −27 |
| **72 other patterns** | | | | **unchanged** |
| **total nodes** | | 37,466 | 35,983 | **−1,483** |

**The falsification criterion was not tripped**: nothing moved outside the shortlist, and
`urlparse`, `bindparam`, `from_string` and `extractall` are all in the 72 unchanged. The net is
−1,483 against a predicted −1,483, and every individual **delta** matches.

**Three of the predicted absolute numbers were wrong, for two clerical reasons.** Both are worth
recording, because neither is about the change and both would recur:

1. **`eval` was 383, not 340; `exec` was 80, not 20.** I took those from the *receiver* subtotal of
   the first census and wrote them down as the *node* total. The difference is the bare calls — 43
   real `eval(...)` and 60 real `exec(...)` — which are the actual builtins and are **supposed** to
   survive. Predicting "0" was predicting that the fix would delete the thing it exists to keep.
2. **`text` went to 30, not 1,587, because `sa.text` became its own row.** The census keys on the
   catalog pattern, and the alias is now a pattern in its own right, so one row split into two.
   30 + 1,557 = **1,587**, exactly the predicted total. The population was right; the shape of the
   table it would land in was not.

### The census could not see the findings this was about — so a second instrument

Zero overlap: all 41 cached profiles are negative-corpus repos, and **every reported taint finding
lives in a labelled-corpus repo with no cached profile.** The census can show the narrowing behaves
as predicted; it structurally cannot show the 40 `self.exec` findings going away.

So each labelled checkout was built twice against the same source, once with `_matches` forced back
to the old suffix rule:

| pattern | call text | before | after |
|---|---|---|---|
| `text` | `resp.text` | 822 | 0 |
| `exec` | **`self.exec`** | 118 | 0 |
| `text` | `request.text` | 108 | 0 |
| `text` | `r.text` | 90 | 0 |
| `text` | `response.text` | 60 | 0 |
| `escape` | `re.escape` (sanitizer) | 51 | 0 |
| `exec` | `session.exec` | 28 | 0 |
| `text` | Qt accessors — `server_status_label`, `title_lineedit`, `clipboard`, `webhook_url_lineedit` … | 90 | 0 |
| `exec` | `self.close_dialog.exec` (a Qt modal dialog) | 6 | 0 |
| `poll` | `self.tor_proc.poll`, `self.meek_proc.poll` | 15 | 0 |

**Nodes 11,625 → 10,138. Taint paths 49,607 → 47,368 (−2,239, −4.5%).**

### The direction check: the sanitizer half is inert, on both corpora

This was pre-registered as the honest risk, and it is what happened.

Negative corpus: **sanitized paths 116 → 116, +0.** The mechanism is exact — of the 1,344 `escape`
sanitizer nodes, the ones actually appearing in a path's `sanitized_by` were **all bare `escape`**,
which still matches. The 1,036 `re.escape` nodes were in the graph and on no path at all.

Labelled checkouts: sanitized 82 → 76, and the −6 decomposes as **0 surfaced, 6 deleted**. Every one
of those six was a path whose *sink* was itself a collision node, removed with it. Not one
suppressed finding came back.

So: **1,087 false sanitizer nodes removed, and zero findings recovered anywhere.** The fix closes a
real recall hole — `re.escape` next to a template sink would delete a genuine finding, and
`structural.py:200` would never say so — but on these two corpora that hole was never stepped in.
The node count is not the win it looks like, and this paragraph exists so nobody quotes it as one.

### The labelled corpus, pre-registered before running

Predicted, from named mechanisms rather than from the change looking small:

- **Reported findings fall sharply**, from 76, concentrated in penelope (48 today, ~40 of them
  `.exec`) and onionshare.
- **Every scored number is identical.** FP 1/26 is `taint-http_outbound` on `requests.post` with an
  `open` source; recall 1/36 is `taint-path` on `tar.extractall`. All three patterns are in the 72
  the census left unchanged, and `extractall` carries an explicit must-not-regress test.
- Gate against `2026-08-08-labelled-decisions/run.json`: **PASS**.

**Falsified by**: any movement in FP, recall, in-scope recall, pairs discriminated, or the endpoint
count. Any of those means the narrowing reached a pattern that was carrying a real finding.

### Measured — the labelled corpus

`benchmark/results/2026-08-09-labelled-receivers/`, 52/52 cases, 855s, **zero case errors**.

| | before (`-labelled-deps`) | after | |
|---|---|---|---|
| `cpg-structural` findings reported | 76 | **31** | **−59%** |
| of which taint | 71 | **26** | |
| `INJ-CODE-EXEC` | 42 | **2** | the 40 `.exec` collisions, gone; both real `exec` kept |
| `INJ-SQLI` | 5 | **0** | all five were `request.text` / `part.text` |
| taint findings generated | 457 | **145** | |
| taint paths | 2,938 | 2,626 | |
| semgrep findings | 6 | 6 | untouched, as it should be |

By repo, the taint findings: penelope **48 → 8**, aiohttp 8 → 3, onionshare 6 → 6,
proot-distro 6 → 6, datamodel-code-generator 3 → 3.

**Every scored number identical.** FP 1/26, gate-relevant 0/26, TP 1, in-scope 1/9, pairs 1/26,
recall 1/36, endpoints 16, missing-authz 0/16, recall-after-filter 36/36.
**Gate vs `2026-08-08-labelled-decisions`: PASS — 12 checks, exit 0.**

The prediction held, and this time holding was the whole point: **45 of 76 reported findings
removed with not one scored number moving** is the shape a precision fix is supposed to have, and
the reason it is legible at all is that §4g measured which patterns carried real findings *before*
narrowing anything. `taint-command` stayed at 2 and `taint-path` at 17 because those patterns were
never in the shortlist.

### What this does not say

The 31 that remain are not therefore correct. 17 are `taint-path`, mostly `open`-sourced paths
through the same cross-product that produced the 45, and `open` is item 11 in `OPEN_ITEMS.md`
precisely because its receivers are ambiguous rather than wrong. The change removed a class that
was **provably** wrong; it did not audit what is left.

And the FP/PR number is unchanged at 1/26 — as predicted, and as §4g's opening table says it had to
be. **A 59% cut in what a reviewer reads is invisible to every published metric this harness has.**
That is the finding to carry, not the 59%.

---

## 4h. The IaC corpus — `iac.py` on real input for the first time (2026-08-09)

Not a defect fix and not a precision claim. `iac.py` reported `not_applicable` on **all 102 cases**
of the negative and labelled corpora, because both are Python-only by construction. So one of M2's
five adapters had never seen a real PR, and "the deterministic detector suite works" rested, for
that fifth, on `tests/fixtures/iac_sample/main.tf`. This closes that.

### The corpus, and the screen that chose it

`benchmark/corpus/iac.json` — **20 cases, 4 repositories**: two Terraform module repos
(`terraform-aws-modules/terraform-aws-vpc`, `-eks`) for checkov's HCL checks and two Docker image
repos (`docker-library/postgres`, `-python`) for its Dockerfile checks, a different code path.

**Repositories were screened; pull requests were not.** Recent merged PRs in each candidate were
sampled and the fraction touching a `classify.is_iac` file counted, because a Terraform module
repo's PR stream turns out to be substantially GitHub Actions and pre-commit churn.
`terraform-aws-modules/terraform-aws-security-group` was rejected at **1 of 4**. Within each chosen
repo the rule is the negative corpus's rule verbatim — most recent merged PRs in listing order, no
filtering on size, content, files touched or outcome.

Measured on the pinned corpus before running: **16 of 20 cases carry at least one IaC file**. The
other four are kept deliberately — an adapter reporting `not_applicable` when there is nothing to
scan is the `AdapterRun` contract being exercised (§2's "absence is a state"), not a wasted case.

**Helm and Kubernetes chart repos were deliberately excluded.** `classify.is_iac` matches yaml only
on a literal `/k8s/` or `/helm/` path segment, so the `charts/<name>/templates/*.yaml` layout those
repos actually use would not classify. Such a corpus would have measured the classifier, not the
adapter. The gap is real — phase-0 §3 says "`*.yaml` under k8s/helm" — and is now `OPEN_ITEMS.md`.

One builder change was needed: `corpus.build_negative_corpus` hardcoded `language="python"`. It is
metadata only — the pipeline reads `config.languages`, never the case — but a scorecard calling
this corpus Python would be wrong about the thing it measures. Now `--language`.

### Pre-registered, before the run

| | Predicted |
|---|---|
| `iac` status `ran` | **≥16 of 20 cases** — the first time in this project |
| Findings **generated** | **high** — checkov's defaults flag policy choices (unencrypted bucket, open egress) that a *module* deliberately leaves to its caller |
| Findings **introduced** | **low** — the resources predate the PR, so `delta.py`'s baseline pass should demote most to `pre_existing` |
| The measurement that matters | **the introduced/generated ratio** — this is delta scoping tested against a detector it has never been tested on, on a file type it has never seen |

**Falsification.** If `iac` comes back `not_applicable` on the majority, **the corpus selection
failed and the adapter is not implicated** — check `is_iac` against the actual changed paths before
concluding anything. If *introduced* is high, either delta scoping does not work for checkov
fingerprints or checkov is genuinely reporting on added lines, and the two are distinguishable by
reading the findings.

**Adapter defects are expected and are not a failure of the exercise.** §5 validated checkov against
one recorded fixture, and the same "one version, one fixture" caveat broke all three external
adapters on first contact (errata §14.18). Finding some here is the point.

### Measured

`benchmark/results/2026-08-19-iac-secretsfix/`, 20/20 cases, 105s, **zero case errors**.

| | Predicted | Measured |
|---|---|---|
| `iac` status `ran` | ≥16 of 20 | **16 of 20** — and the 4 `not_applicable` are exactly the 4 cases with no IaC file |
| Findings generated | high | **204** |
| Findings introduced | low | **32** |
| **introduced / generated** | **low ratio** | **32 / 204 = 16%** — delta scoping demoted 172 |

**The prediction held on every line, and the adapter works.** `iac.py` executes on real PRs, checkov
parses, findings normalize, and `delta.py`'s baseline pass — never before tested against this
detector or this file type — demoted 84% of them as pre-existing, which is the correct answer: the
resources predate the PRs.

The 32 that remain are `CKV_DOCKER_2` (no HEALTHCHECK) and `CKV_DOCKER_3` (runs as root), 16 each,
one pair per changed Dockerfile. Both are checkov's defaults firing on official Docker images, which
is checkov being checkov rather than a defect on our side.

### Three defects, one fixed and two recorded — which is what running it was for

**1. A false secret that failed a gate.** `docker-library/postgres`'s `docker-entrypoint.sh:76`
assigns `NSS_WRAPPER_PASSWD="$(mktemp)"` — a temp **file path**. `secrets.py` reported it HIGH, and
because secrets still carry the M0 `status=validated` simplification they are the one class that can
reach the gate: case `postgres#1415` came back **FLAGGED**. `_PLACEHOLDER_RE` already excluded
`${...}` and did not exclude `$(...)`, though a value computed at run time is not a hardcoded one
either way. **Fixed**, falsified, and the run redone: 36 → 32 reported, verdicts 19 approved + 1
flagged → **20 approved**. Backticks were deliberately not added — the legacy form was not observed,
and `is_generated`'s docstring records the standing trade against unmeasured coverage.

**2. `CKV_DOCKER_3` is filed under the wrong family, and correcting it deletes findings.** Its title
says "Container runs as root"; its internal id said `CFG-DEFAULT-CREDS`. Retargeting to `CFG-IAC`
was tried — and **silently deleted 16 findings**, because the fingerprint is
`(path, internal, symbol, snippet)` and `CKV_DOCKER_2` reports on the same Dockerfile at the same
line, so only the differing taxonomy id was keeping the pair apart. The run showed 36 → 16 where 32
was correct. **Reverted**: a visible wrong label beats an invisible lost finding, the same asymmetry
as §4f's false `guarded` and §4g's false sanitizer. `OPEN_ITEMS.md` §18, pinned by
`test_two_rules_on_one_line_collapse_if_they_share_a_taxonomy_id`.

**3. `is_generated` cannot see header markers.** 12 of the reported findings are on Dockerfiles
whose first lines read *"THIS DOCKERFILE IS GENERATED VIA apply-templates.sh / PLEASE DO NOT EDIT
IT"*. `plan/phase-0-extraction.md` §3 specifies `is_generated` as "**header markers**, `*_pb2.py`,
…" and only the path half exists — the signature is `is_generated(path: str)`, so it structurally
cannot read a header. **Not fixed**: it is an interface change, and `is_generated` suppresses
`secrets.py`, `sast_semgrep.py` and `change/filter.py`, so a false positive there is silent lost
coverage on three detectors at once. `OPEN_ITEMS.md` §17.

### What this does and does not say

It says the adapter works on real input, that delta scoping generalizes to a detector and a file
type it had never seen, and that first contact with a real corpus found three defects in an adapter
that had passed every unit test — the fourth time that has happened (errata §14.18 took all three
external adapters at once).

It is **not** a precision measurement. Four repositories across two organisations, chosen for IaC
content, is enough to answer "does this work" and not enough to support a false-positive rate. The
32 remaining findings are checkov policy defaults on generated files; whether they are *useful* is a
different question, and the honest answer today is that nobody has asked a Docker maintainer.

## 4i. The four-arm comparison — what the pipeline is worth against a raw LLM (2026-08-21)

The measurement `plan/benchmark.md` §3 asks for and `BENCHMARK_STATUS.md` §1 recorded as blocked:
**"Baseline columns (Semgrep-alone / CodeQL-alone / raw-LLM) — ❌ blocked."** Three of the four are
now run. CodeQL stays blocked (`detect/codeql.py` was never built); the raw-LLM arm is unblocked not
by Bedrock but by `models/claude_cli.py`, which fills the `ModelProvider` seam over `claude -p`
(`PIVOT_PLAN.md` §1.0).

### Why this corpus can carry the comparison

**It is a clean temporal holdout, by accident.** Every advisory in the labelled corpus was published
**2026-07-24 → 2026-08-07**; the model's training cutoff is **May 2026**. `plan/benchmark.md` §3
demands exactly this ("prefer a temporal holdout: CVEs published after the model's cutoff") and
treats it as the hard part of evaluating an LLM honestly. It exists here only because the corpus was
built from "the 80 most recently published advisories" for unrelated reasons. Also load-bearing:
`AdvisoryRef.summary` is deliberately withheld from `PRTask`, so the task cannot leak its own answer.

### The arms

| arm | what runs | corpus | result dir |
|---|---|---|---|
| 1 | semgrep only, every other detector disabled | labelled | `2026-08-21-arm1-semgrep-only` |
| 2 | pipeline, deterministic | labelled | `2026-08-09-labelled-receivers` |
| 2b | pipeline + live tier-3 triage | negative | `2026-08-21-triage-live-negative` |
| 3 | raw LLM, diff only, sonnet, `--effort low`, ×3 | labelled | `2026-08-21-arm3-llm-p{1,2,3}` |

Arm 3 is a **producer**, not a second harness: it emits `Finding`-shaped output and is scored by the
same `score_case` the pipeline is (`benchmark/llm_arm.py`). It runs tool-free (`--disallowedTools`)
from a `tempfile.mkdtemp()` cwd, and `assert_no_tool_use()` is called after — belt and braces,
because a model that could read the checkout would silently be answering a different question.

### Measured

All figures rescored by `eff62ba` from the stored runs, so the recall unit is the fixed one (§14.43).

| arm | recall (36 rows) | reachable stratum (9 rows) | precision | pairs discriminated | FP/PR on controls | cost |
|---|---|---|---|---|---|---|
| 1 semgrep alone | 0.000 (0/36) | 0.000 (0/9) | n/a (0 findings) | 0.00 (0/26) | 0.00 (0/26) | $0 |
| 2 pipeline | 0.028 (1/36) | 0.111 (1/9) | 1.000 (1/1) | 0.04 (1/26) | 0.04 (1/26) | $0 |
| 3 LLM pass 1 | 0.361 (13/36) | 0.556 (5/9) | 0.375 (18/48) | 0.35 (9/26) | 0.12 (3/26) | $2.5611 |
| 3 LLM pass 2 | 0.361 (13/36) | 0.667 (6/9) | 0.390 (16/41) | 0.42 (11/26) | 0.19 (5/26) | $0.7716 |
| 3 LLM pass 3 | 0.333 (12/36) | 0.556 (5/9) | 0.341 (14/41) | 0.38 (10/26) | 0.15 (4/26) | $0.7231 |

**Read every recall figure against the ceiling.** 27 of the 36 ground-truth rows are outside the
taxonomy entirely, so a *perfect* pipeline scores **0.250** here (§14.42, `OPEN_ITEMS.md` §19). Arm
3's 0.361 is therefore **above** the pipeline's vocabulary ceiling — not because it is a better
detector of the same things, but because it answers in CWE directly and is not confined to the
taxonomy at all. That is why the reachable-stratum column exists, and it is the honest place to
compare the two.

> **The ceiling was published as 0.364 on 2026-08-21 and corrected to 0.250 on 2026-08-22.** The
> first figure counted `BenchCase.cwe` advisory tags (33, 12 in scope); recall divides by
> `ground_truth` rows (36, 9 in scope). Errata **§14.45**. In-scope recall was never affected —
> `metrics.py` derives `in_scope_rows` from the rows themselves — so every number in the table above
> stands as printed. Found by the HTML comparison page, which computes the ceiling from the same
> metrics object rather than quoting the documented constant.

**Arm 1's anti-vacuity check passed:** `semgrep | ran: 52`. A zero from a detector that never
executed and a zero from a detector that found nothing are the same empty list, and this corpus has
produced the first before (§2, "Which detectors actually ran"). It ran on all 52 and found nothing.

### Arm 2b is a cost measurement and nothing else

50 negative-corpus PRs, 33 of them reaching tier 3, one haiku call each: **$0.9537 total, $0.019 per
PR**, 34 min wall clock. Every scored number came out **identical to the deterministic baseline**.

That is not a null result to bury — it is §14.40, confirmed at n=50. `pipeline.py` builds the detect
stage from the manifest and every parsed file, **not** from the filter's kept set, so what tier 3
decides routes Phase-3b agents and Phase 3b does not exist. The pre-registration predicted this arm
would move every scored number on both corpora. It moves none. **Do not put arm 2b in a findings
column**; it belongs only in a cost column, and it retroactively vindicates the v6→v8 re-runs that
were skipped on the same reasoning.

Two caveats on its cost figure, both in the direction of *overstating*: the run predates
`--effort` being wired through, so those 33 calls ran at haiku's default effort while the config asks
for `low` (`dropped_effort: ["low"]` in the stored accounting is the record of it); and the harness
floor eats essentially all of its cached tokens (§14.44). Current code would cost the same or less.

### The pre-registered predictions

Written before any full arm ran (`benchmark/results/PREREGISTRATION-2026-08-21.md`).

| | prediction | outcome |
|---|---|---|
| P1 | arm 1 at or near zero recall | ✅ 0.000, and semgrep verifiably ran |
| P2 | arm 3 out-recalls the pipeline | ✅ by **13×** on the headline, **5×** on the reachable stratum |
| P3 | arm 3's false positives *much* higher, mostly on controls | ❌ **wrong in the useful direction** |
| P4 | arm 3 varies run to run | ✅ recall 0.361/0.361/0.333, FP 3/5/4, pairs 9/11/10 |
| P5 | most of arm 3's hits land on unreachable ground truth | ⚠️ **split** |

**P3 was wrong, and it is the most informative wrong.** 3–5 false positives per 26 control PRs
against the pipeline's 1 is 3–5×, not the order of magnitude "much higher" implied — and the
prediction's *reasoning* was that a model with no baseline cannot tell introduced from pre-existing,
so it should fire on post-fix controls constantly. It does not. Pair discrimination came out
**0.35–0.42 against the pipeline's 0.04**: the model is not merely finding more, it is separating
the vulnerable side from its fix roughly ten times more often. The expected failure mode of the
naive baseline did not materialise, and the argument for the unbuilt 3c verifier is correspondingly
weaker than pre-registered.

**P5 split.** The first half held: 8–10 of each pass's true positives are `Unmapped` — CWEs the
pipeline has no word for. The second half failed. The arms were predicted to look *much closer* on
the reachable stratum, and they do not: **0.556–0.667 against 0.111**, still 5×. The gap is not an
artifact of vocabulary. On the ground truth this pipeline was built to express, a diff-only LLM at
`--effort low` finds five times as much.

### What this says, and what it does not

It says the **agent layer is where the value is**, and prices it. The deterministic detectors are a
floor, and on this corpus a low one: `Y − X` at `M − N` is what M3 would have to earn, and the
measurement now exists to hold it to. It also says the LLM's cost is real but small at this effort —
~$0.75/pass over 52 cases once the prompt cache is warm, $0.014/case.

It does **not** say the pipeline is worthless or that the LLM should replace it. Four limits, all
load-bearing:

1. **n = 26 advisories, one numerator for the pipeline.** The pipeline's entire recall is one
   `taint-path` finding. Nothing here has the resolution to rank two tools that both score near zero.
2. **A labelled case is a fixing commit run backwards**, so the vulnerable lines are essentially the
   whole diff — the easiest possible presentation, and one that favours a reader of diffs.
3. **The pipeline was measured at 3a scope**, which is what it is, but the design's own answer to
   this comparison (Phase 3b agents, the 3c verifier) is exactly the part that does not exist.
4. **Cost is measured through a harness that taxes it.** Arm 3's ~250k tokens of content carry
   ~380k of CLI system prompt; an API caller pays neither the same tokens nor the same price
   (§14.44).

## 4j. Delta scoping, and the prompt that did the same job (2026-08-22)

Two arms, run because of one gap: **the harness had no metric for the stage most responsible for the
false-positive rate.**

### The gap

`plan/benchmark.md` asks for precision, recall, calibration and ablations, so `metrics.py` answers
those — and every one of them scores what the tool *reported*. `findings/delta.py` scans the base
commit with the same detectors and drops what was already there; its entire effect is on what the
tool did **not** report, and nothing in the module could see it. The only trace in any scorecard was
one line under the false-positive heading — *"Pre-existing findings excluded from scoring: 75"* —
phrased as bookkeeping about a denominator.

Derived from stored dumps, no re-run needed:

| corpus | raw findings | dropped as pre-existing | reported | FP/PR as shipped | FP/PR unscoped |
|---|---|---|---|---|---|
| negative (50 PRs) | 87 | **75 (86.2%)** | 12 | 0.24 | **1.74** *(derived)* |
| labelled (52 cases) | 72 | **70 (97.2%)** | 2 | 0.04 | 1.38 *(derived)* |

**7.25× on the negative corpus.** The unscoped column is arithmetic, not a run: a genuinely unscoped
pipeline would also lose Semgrep's own `--baseline-commit` scoping, so it is that figure or worse.
Errata §14.46.

### Arm 2c — the middle tier, and the improvement that was a loss

`benchmark/configs/no-baseline.yaml` sets `baseline.enabled: false`, so `delta.py` falls back to
hunk overlap. Not a hypothetical: it is what the tool does on `--no-checkout`, on an offline
`--diff-file` run, and throughout the M0 thread.

| tier | raw | dropped | reported | FP/PR | gate-relevant/PR |
|---|---|---|---|---|---|
| no scoping *(derived)* | 87 | 0 | 87 | **1.74** | — |
| **hunk-based** *(measured)* | 87 | 71 | 16 | **0.32** | **0.00** |
| baseline *(measured)* | 87 | 75 | 12 | **0.24** | **0.02** |

**P1 held in direction and missed in size:** predicted 0.4–0.8, measured 0.32. Hunk overlap recovers
most of what the base-tree scan does *on rate*.

**P2 was wrong, and the way it was wrong is the finding.** Gate-relevant alarms were predicted to
rise; they fell to zero, which reads as the degraded mode being *safer*. The set difference says
otherwise. Hunk scoping gained five medium `BAC-MISSING-AUTHZ` alarms in edited files and lost
exactly one finding: `SC-VULN-DEP` at `uv.lock:906` in `fastapi/fastapi#16141` — the gitpython
under-upgrade, a **correct HIGH** this corpus scores as a false alarm by construction and which
`OPEN_ITEMS.md` carries a standing instruction never to tune away. The SCA finding sits at a
lockfile line the PR did not literally edit, so hunk overlap calls it pre-existing.

So the degraded path is **not the full path plus noise**; it is differently wrong in both directions,
and the thing it lost here is the only finding on this corpus that would fail a build. Errata
§14.48. The operational consequence is for `--no-checkout` and the offline path, which
`cli.py` already warns about — the warning now has a measured cost attached.

### Arm 3b — the prompt that had been confounding the comparison

`benchmark/prompts/llm-diff-baseline.md` had always instructed the model to report vulnerabilities
the diff *"introduces **or leaves present in the code shown**"*. Arm 3 was **told** to report
pre-existing findings, and then every one it produced on a post-fix control was scored as a false
alarm. Its `pre_existing = 0` was the prompt's doing.

`llm-diff-introduced-only.md` changes that one instruction and adds a paragraph on context lines.
Same model, same effort, same corpus, same producer, same scorer.

| | vuln-half findings | control-half findings | FP/control PR | recall | reachable | cost |
|---|---|---|---|---|---|---|
| baseline prompt, pass 1 | 51 | 3 | 0.12 | 0.361 | 0.556 | $2.5611 |
| baseline prompt, pass 2 | 41 | 5 | 0.19 | 0.361 | 0.667 | $0.7716 |
| baseline prompt, pass 3 | 45 | 4 | 0.15 | 0.333 | 0.556 | $0.7231 |
| **3b introduced-only** | **40** | **0** | **0.00** | **0.306** | **0.333** | $1.7645 |

**Zero false alarms on 26 control PRs — below this pipeline's one.** It is selective rather than
timid: the vulnerable half stayed at 40, inside the baseline prompt's own 41–51 range, while the
control half went to nothing. Under uniform thinning at the observed rate the control half would
land near 2–3, and the three baseline passes produced 3, 4 and 5.

It cost real detections. Headline recall fell 15% (13 rows → 11) and **reachable-stratum recall fell
by half** (5–6 of 9 → 3). The instruction that removes a false alarm on a fixed file also removes a
true positive whose evidence sat on a context line.

### The pre-registered predictions, and three of five wrong

`benchmark/results/PREREGISTRATION-2026-08-22.md`, written before either arm ran.

| | prediction | outcome |
|---|---|---|
| P3 | 3b's control false alarms fall, but not to the pipeline's 0.04 — guess 0.06–0.12 | ❌ **0.00**, below the pipeline |
| P4 | 3b's recall drops by more than its false alarms do | ❌ recall −15%, false alarms −100% |
| P5 | pair discrimination rises | ❌ **fell**, 0.35–0.42 → 0.31 |

**P4 was the diagnostic and it failed usefully.** Its purpose was to catch "the model is not
distinguishing anything, it is just reporting less". If that were what happened, recall and false
alarms would have fallen together. They did not — one fell 15% and the other 100%.

**P5 fell because the model also flagged fewer vulnerable sides.** Pair discrimination requires
*both* a flagged vulnerable side and a silent control. The control half went perfectly silent; the
vulnerable half lost detections at the same time, and the second effect was larger. So the arm is
better at not crying wolf and worse at finding the wolf, which is the trade the instruction buys.

### What survives, precisely

- **The suppression numbers are real** — 7.25× on the negative corpus, and mechanical: the pipeline
  names the base-commit finding that matched. The model's version is a judgement with no artifact.
- **The pipeline's costs $0.** Arm 3b's run cost $1.76.
- **The word "cannot" does not survive.** §14.46's first draft called delta scoping "the capability a
  diff-only reviewer cannot have". It was falsified 33 minutes after it was committed. Errata
  §14.47.

### What is still open

> **Closed 2026-08-24 — the passes ran; see §4l.2.** The suppression replicated (0 · 0 · 1 against
> 3 · 5 · 4) but the recall cost did not, and "below the pipeline's 1" became "at or below". The
> commands below are kept because they are the reproduction recipe, not because the question is open.

Arm 3b is **one pass** against the baseline prompt's three, and arm 3 is known to vary run to run.
0/26 is outside the baseline's 3–5 spread, which is why it is believed; two more passes at ~$0.75
each would settle it (`OPEN_ITEMS.md` §22):

```bash
.venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/labelled.json \
    --arm llm-diff --arm-prompt benchmark/prompts/llm-diff-introduced-only.md \
    --arm-effort low --label arm3b-introduced-only-p2
```


## 4k. `CKV_DOCKER_3`'s family, and the cache defect the verification run found (2026-08-22)

`OPEN_ITEMS.md` §18: 16 IaC-corpus findings titled *"Container runs as root"* were mapped to
`CFG-DEFAULT-CREDS` — a privilege misconfiguration filed as a default credential, so every one
carried a family that would route it to the wrong agent. It had stood for three weeks because
correcting it to `CFG-IAC` collapsed the pair with `CKV_DOCKER_2` in dedup and **silently deleted 16
findings**.

### What unblocked it

§18's remaining route was a new taxonomy id, blocked on an argument: *"any new id has to be checked
against `scoring._CWE_GROUPS` and `benchmark/scope.py`, which read the same table and must not be
widened casually."* §14.42's work turned that argument into a measurement — the labelled corpus has
36 ground-truth rows over 17 CWEs, 9 in scope — and a number is testable where an argument is not.

`CFG-CONTAINER-PRIVILEGE` carries CWE-250/269. Neither appears in the corpus's 17, neither is in any
`_CWE_GROUPS` group. They now enter `in_scope_cwes()` — correctly; a detector can emit them — while
the corpus's in-scope row count stays **9/36**, asserted by
`test_the_new_id_does_not_move_the_benchmark_recall_ceiling`. The falsification pass confirms the
guard bites: adding CWE-668, which *is* in the corpus, turns it red. **That is the difference
between widening a vocabulary because a detector grew and widening it to move a number.**

### The verification run found something else

| IaC corpus run | raw | reported | `CKV_DOCKER_3` findings |
|---|---|---|---|
| 2026-08-19, old id, warm baseline | 202 | 32 | 16 |
| 2026-08-22, new id, **stale** baseline | 202 | **112** | **96** |
| 2026-08-22, new id, **fresh** baseline | 202 | **32** | **16** |

The taxonomy change is exactly neutral — the fresh-baseline run reproduces the pre-change numbers to
the finding. The 112 was a **stale cache**: `Finding.fingerprint` hashes the taxonomy `internal` id,
`BaselineCache` was keyed on `base_sha` alone with no version of any kind, and a baseline built
before the remap held hashes nothing could match. 80 pre-existing findings were reported as
introduced.

Fixed with a manual `BASELINE_VERSION` and an automatic `normalize.mapping_digest()` — derived from
the tables, because a remap is the edit somebody makes without thinking about caches, which is the
one a manual constant misses. Errata §14.49.

**It also puts a second asterisk on every stored false-positive rate.** Staleness only ever moves a
finding from pre-existing to introduced, so it inflates false positives and never deflates them; no
stored number was flattered. How much each historical run carries is unmeasured, and
`OPEN_ITEMS.md` §23 records what settling it would cost (about 70 minutes, no model spend).

---

---

## 4l. The two questions §4j and §4k left open, both settled (2026-08-24)

Neither was new work. Both were named in `OPEN_ITEMS.md` with a price attached, and both were bought
because a figure that had already been published depended on them.

### 4l.1 The retroactive staleness question — §23, and the answer is nil

§4k's `BaselineCache` fix (errata §14.49) measured **32 reported findings becoming 112** on the IaC
corpus once a stale baseline was invalidated: a 3.5× inflation from the cache alone. That left a
retroactive question it could not answer — *how much of the same inflation does every stored run
carry?*

**Method.** All 17 `.pr_review/cache/*/baseline/` directories were archived and deleted at 13:58, and
the negative and labelled corpora re-run from cold baselines with distinct `--label`s
(`negative-freshbaseline`, `labelled-freshbaseline`; the labelled run keeps `--cold-profiles` as §7
requires). Ten baseline directories rebuilt between 14:01 and 14:20, every mtime after the deletion —
checked, because a re-run that silently found a cache it was supposed to have lost would report
"no change" for the wrong reason.

**Result: identical on both corpora, not approximately.**

| | stored | fresh baseline |
|---|---|---|
| negative — raw findings | 87 | 87 |
| negative — attributed to base tree | 0.862 (75/87) | 0.862 (75/87) |
| negative — **FP/PR** | **0.24 (12/50)** | **0.24 (12/50)** |
| negative — gate-relevant | 0.02 (1/50) | 0.02 (1/50) |
| labelled — raw findings | 36 | 36 |
| labelled — attributed to base tree | 0.972 (35/36) | 0.972 (35/36) |
| labelled — recall | 0.028 (1/36) | 0.028 (1/36) |
| labelled — reachable | 0.111 (1/9) | 0.111 (1/9) |
| labelled — pairs discriminated | 0.04 (1/26) | 0.04 (1/26) |

Compared on **finding identity** — `(case, path, line, taxonomy id, rule id)` — not on counts, because
two runs can agree on a total while disagreeing about what is in it. 12/12 negative and 37/37
labelled matched exactly. Stored runs compared against: `2026-08-21-triage-live-negative` and
`2026-08-09-labelled-receivers`, the latter chosen because it is the pipeline arm on the comparison
page *and* sits inside the 2026-08-07→09 churn window §23 named as the suspect one.

**Why nil here when it was 3.5× there, stated so the result is not over-read.** The IaC inflation came
from remapping `CKV_DOCKER_3` to a new taxonomy id, and the id is part of the fingerprint — so every
cached baseline fingerprint stopped matching at once. The negative and labelled baselines were built
against detector output whose fingerprints have not moved since. **The mechanism is real and the
exposure here was zero.** This does not retire the trap; it prices this instance of it.

The direction argument in §23 held: staleness only ever moves a finding from pre-existing to
introduced, so no stored number was ever flattered by it. That is now measured rather than reasoned.

### 4l.2 Arm 3b at n=3 — §22, and two published claims do not survive

§4j reported arm 3b (`llm-diff-introduced-only.md`) as **0 false alarms on 26 control PRs**, from a
single pass, and §22 recorded that this was the weakest evidence the project accepts anywhere — the
baseline prompt was run three times *precisely because the arm varies*. Two more passes, `--effort
low`, same prompt, same corpus.

| pass | vuln-half | control | recall | reachable | precision | cost |
|---|---|---|---|---|---|---|
| 3b p1 (2026-08-22) | 40 | **0** | 0.306 (11/36) | 0.333 (3/9) | 0.342 (13/38) | $1.7645 |
| 3b p2 (2026-08-24) | 40 | **0** | 0.333 (12/36) | 0.667 (6/9) | 0.342 (13/38) | $1.7963 |
| 3b p3 (2026-08-24) | 45 | **1** | 0.444 (16/36) | 0.556 (5/9) | 0.442 (19/43) | $0.4665 |
| *baseline prompt ×3* | *51 · 41 · 45* | *3 · 5 · 4* | *0.361 · 0.361 · 0.333* | *0.556 · 0.667 · 0.556* | | |

**What survives, and it is the finding.** Control-half output is **3, 4, 5** under the baseline prompt
against **0, 0, 1** under introduced-only. The ranges do not overlap at n=3 each. The suppression is
real and it replicates.

**What does not survive — 1: "below this pipeline's 1" becomes "at or below".** p3 produced one
control-half finding. The arm's range is 0–1 and the pipeline scores 1, so arm 3b ties it in the
worst pass rather than beating it in every pass.

**What does not survive — 2: the recall cost.** §4j and `REPORT.md` (in its 2026-08-24 shape, since
rewritten) said the prompt change
"was not free" — headline recall down 15%, reachable-stratum recall halved. Both figures came from
p1 alone:

- Headline recall spans **0.306–0.444** against the baseline's **0.333–0.361**. Arm 3b's best pass is
  higher than *every* baseline pass.
- Reachable-stratum recall spans **0.333–0.667** against the baseline's **0.556–0.667** — overlapping,
  same best value. There is a downward tendency across the spreads; "halved" was p1 drawing the
  bottom of its own range.

Reported as spreads and never as means, per §4i's rule that variance in this arm is a product
difference rather than noise.

**§22 predicted which number would move, and why.** It wrote: *"the reachable-recall drop (0.333
against 0.556–0.667) is the figure most likely to move, because it has the smallest denominator on
the page."* It moved from a point estimate to a spread covering the baseline's. **A denominator of 9
was doing the work of an argument** — the same shape as §14.43's "a denominator that never moves is
not thereby correct", one layer up.

**Cost.** $1.7963 + $0.4665 = **$2.26**, against §22's estimate of ~$1.50 for the pair. The gap is
prompt-cache warmth, not work: p2 ran cold at $1.80 where p3 ran warm at $0.47, the same
$2.56-then-$0.75 pattern §4i measured for arm 3. **An estimate quoted per-pass is wrong whenever the
cache state differs between passes**, which is most of the time.

**Runs:** `2026-08-24-negative-freshbaseline`, `2026-08-24-labelled-freshbaseline`,
`2026-08-24-arm3b-introduced-only-p2`, `2026-08-24-arm3b-introduced-only-p3`.

### 4l.4 Which CLI produced each stored run — recovered, and the published figures are safe

§4l.3 said no stored run records its CLI, so the older splits were "unverified rather than wrong".
That was true of the *runs*. It was not true of the *machine*: `~/.local/share/claude/versions/`
keeps every installed build with its install time, and `CorpusRun.started_at` is already stored. The
two together attribute every run we have.

| installed | version |
|---|---|
| 2026-08-19 15:12 | 2.1.235 ← the floor's calibration |
| 2026-08-21 23:34 | 2.1.239 |
| 2026-08-22 17:49 | 2.1.240 |
| 2026-08-24 13:29 | 2.1.241 ← measured at 7,777 |

| run | started | CLI | floor that applies |
|---|---|---|---|
| `2026-08-21-triage-cost-sample` | 08-21 15:41 | **2.1.235** | 7,300 ✅ |
| `2026-08-21-triage-live-negative` (arm 2b) | 08-21 15:48 | **2.1.235** | 7,300 ✅ *and clamped, so the floor does not enter* |
| `2026-08-21-smoke-llm` | 08-21 16:10 | **2.1.235** | 7,300 ✅ |
| `2026-08-21-arm3-llm-p1 / p2 / p3` | 08-21 16:32–16:41 | **2.1.235** | 7,300 ✅ |
| `2026-08-22-arm3b-introduced-only` (p1) | 08-22 13:32 | 2.1.239 | **unmeasured** |
| `2026-08-24-arm3b-introduced-only-p2 / p3` | 08-24 14:06–14:11 | **2.1.241** | 7,777 — currently computed at 7,300 |

**The conclusion that matters: every published floor-derived figure is correct.** `REPORT.md` §4's
*"~380k tokens of harness riding along with ~250k of content"* and the scorecard's **249,665** are
all **arm 3**, which ran on **2.1.235** — the exact build 7,300 was calibrated against. So the
constant is right for everything that has been published, and **moving it to 7,777 would make
correct published numbers wrong by ~10%.**

Where 7,300 *is* currently wrong is arm 3b p2/p3 — content overstated by 24,804 tokens each — and
their splits appear in no published page. Arm 3b p1 ran on 2.1.239, which has never been measured.

**The readers now consume what this table documents.** As of 2026-08-24 `claude_cli.floor_for()`
prices each run with the floor measured for *its own* CLI, falling back to the constant when the run
records no version — which is every run above, so nothing here re-prices and the regenerated
scorecard is byte-identical. What changes is the future: a run from today forward carries its
version and is priced correctly without anyone consulting this table. `OPEN_ITEMS.md` §21.

**Method note.** The attribution is derived from file mtimes plus run timestamps, not observed by
the runs themselves. It is evidence, not telemetry: a build installed but not activated, or a run
launched from a shell holding an older path, would break it. Runs from 2026-08-24 onward record
their own version and need none of this. The table is kept because it is the only thing that can
speak for the runs that predate the field.

### 4l.3 The transport floor had already gone stale — §21, found by the check that was built for it

`OPEN_ITEMS.md` §21 said the floor "will go stale silently" and asked for a mechanism rather than a
reminder. The mechanism went in on 2026-08-24 — the provider records `claude --version` into
`model_accounting`, and the readers compare it against the build the floor was calibrated on. **It
fired on its first execution.**

| CLI | measured floor | when |
|---|---|---|
| 2.1.235 | 7,263 cold / 7,445 warm | 2026-08-21, `--model sonnet` |
| **2.1.241** | **7,777** (cold and warm alike) | 2026-08-24, same method, `--effort low` |

Method, identical to the original so the two are comparable: a one-line system prompt (so
`--system-prompt` + `--exclude-dynamic-system-prompt-sections` are passed, which **every** real arm
does — both `llm_arm.py:251` and `change/filter.py:250` send a system message, checked) and a
one-word user prompt, twice, so the second call reads the cache the first one wrote. Cost **$0.0328**.

**The constant was NOT changed, and that is the finding worth carrying.** `TRANSPORT_FLOOR_TOKENS`
still reads 7,300. Moving it to 7,777 would re-derive the harness/ours split of every **stored** run
— including runs the older CLI produced, for which 7,300 is right — and that split is published
(`REPORT.md` §4: ~380k harness against ~250k content on arm 3). Per §L4's rule, that is a two-hour
landing, not a one-line edit. So the measurement is recorded per version in
`claude_cli._FLOOR_BY_VERSION` and the readers quantify the gap instead of hiding it: on a 52-call
pass, *"understates harness by ~477 tokens per call — ~24,804 across this run"*.

**What is still not known, and cannot be recovered.** No stored run records which CLI produced it,
because the field did not exist until now. So the arm-3 and arm-3b passes of 2026-08-21/22/24 cannot
be attributed to 2.1.235 or 2.1.241 after the fact, and their derived splits are **unverified rather
than wrong**. The reader now says exactly that — `UNRECORDED`, distinct from a match — because
silence there would read as agreement. Every run from 2026-08-24 forward carries its version.

**PENDING, with the expected outcome stated.** If the constant is ever moved to a version-aware
lookup, arm 3's harness figure rises by ~477/call and its "ours" figure falls by the same, i.e.
~380k → ~405k harness and ~250k → ~225k content at 52 calls. Nothing about cost, recall or precision
moves; only the derived split does. That prediction is here so it cannot be quietly restated later.

---

## 4m. The five patterns §10 named next — censused, and all five are correct (2026-08-24)

`OPEN_ITEMS.md` §10 named five patterns as "most worth doing next": the ones whose sink class is
actually reported and whose receiver could be anything. All five were censused by the §4g method —
**from the cached CPGs, not from source** — and none of them collides with anything.

Population: 61 cached `cpg.json` files across 35 repositories, the negative corpus. Labelled-corpus
repos mostly have no cached profile (§4g records the same limit), so the one labelled-corpus site
that matters is named explicitly below rather than counted here.

| pattern | list | nodes | receivers seen | collisions |
|---|---|---|---|---|
| `extractall` | `sinks.path.calls` | 53 | `extractall` 30 · `archive.` 15 · `zf.` 6 · `z.` 2 | **0** |
| `from_string` | `sinks.template.calls` | 123 | `self.engine.` 50 · `template_environment.` 42 · `app.jinja_env.` 8 · 6 more | **0** |
| `mark_safe` | `sinks.template.calls` | 546 | `mark_safe` 546 | **0** |
| `format_html` | `sinks.template.calls` | 194 | `format_html` 194 | **0** |
| `urlopen` | `sources.calls` | 30 | `urllib.request.` 11 · `urllib_request.` 10 · bare 8 · `conn.` 1 | **0** |

**946 nodes, zero collisions.** Against `text`'s 45 collisions in 1,632 nodes, this is a different
regime, and it is the direct vindication of §4g's standing warning: *do not assume a single-segment
pattern is wrong because it is single-segment.*

Reading each verdict, because "0 collisions" is a summary and the argument is what generalises:

- **`extractall` — correct, and narrowing it would be destructive.** Every receiver is a *local
  variable* holding an archive object (`tar`, `zf`, `z`, `archive`), plus poetry's own module-level
  `extractall()` wrapper (`src/poetry/utils/helpers.py:410`) around `zipfile.ZipFile` and
  `tarfile.open`. All 12 unique call sites were read: every one is genuine archive extraction. There
  is **no dotted form to narrow to** — the method name is the whole signal, since `extractall`
  exists on `TarFile` and `ZipFile` and essentially nowhere else. And the sink behind this project's
  **only scored true positive** is one of those local-variable receivers:
  `tar.extractall(local_download_folder)` at `penelope.py:3418`, CWE-22, source `tarfile.open` two
  lines earlier. Any narrowing that demanded a dotted receiver would delete it.
  `tests/test_cpg.py:283` pins exactly this and is the guard to read first.
- **`from_string` — correct.** Nine distinct receivers, every one a template environment
  (`self.engine`, `template_environment`, `app.jinja_env`, `engines['django']`, `env`, …). This is
  the case §4g flagged as *correct in its dotted forms*, confirmed.
- **`mark_safe`, `format_html` — correct, trivially.** 740 nodes between them and exactly one
  receiver each: bare. Django imports both directly, so there is no dotted spelling in the wild to
  collide with.
- **`urlopen` as a source — correct.** Includes urllib3's `conn.urlopen`, which is a real network
  read and belongs at `trust: high` with the rest. The dotted `urllib.request.urlopen` separately
  exists as an `http_outbound` *sink* at `python.yaml:270`; the two entries are not duplicates,
  they are the two ends of a flow.

**Nothing was changed.** No pattern narrowed, no `ANALYZER_VERSION` bump, no corpus re-run, no
published number moved. That is the outcome a census is *allowed* to have, and saying so is the
point: §4g's four patterns were narrowed because the census said to, and these five are left alone
because the census said that instead. The measurement is the deliverable either way.

**Method, so it need not be re-derived.** Sink and source nodes in a cached CPG carry
`attrs.pattern` — the catalog entry that matched — and `name`, the receiver expression as written.
Group by the first, count the second. `rg` over source is explicitly *not* this measurement (§4g:
it read `text` as a disaster when the CPGs said 1,557 of its 1,632 nodes were right).

### 4m.1 The one census that must come from source, and why that is not a contradiction

`OPEN_ITEMS.md` §13 (`redis.eval`) was censused the same day and could **not** use the method above.
The reason is worth stating, because it looks like a violation of §4g and is the opposite of one.

A CPG records the calls that **matched a pattern**. That makes it the right instrument for asking
*"is this pattern matching the wrong things?"* — the narrowing question §4g asked — and a useless
one for asking *"what would a pattern we do not have match?"*, because the unmatched calls were
never recorded. For a **coverage addition** the graph is silent by construction, so the population
has to come from source.

The rule that survives, and it is the one §4g actually meant: **use the graph to judge what the
detector did, and source to find what it never saw.** Reaching for source to second-guess something
the graph already knows is the error §4g recorded; reaching for it where the graph holds nothing is
just the only available measurement.

Result, over 34 source trees and 138,858 Python files, deduplicated to distinct `(repo, file, line)`:
**5 genuine `.eval(` code-execution sites against 85 false ones.** The three §13 named are confirmed
and are all `self.redis.eval`. Full table and the disposition are in `OPEN_ITEMS.md` §13.

**A method note that cost twenty minutes.** Two earlier passes of this census returned zero and were
believed for longer than they should have been. `find .pr_review/cache/*/src -name "*.py"` and
`xargs -a roots.txt find -name "*.py"` both report **0 files** — the second because `xargs` appends
its arguments *after* the command's, producing `find -name "*.py" <roots>`. A per-root loop reports
138,858. A search whose population is zero is not a finding, it is a broken search; check the
denominator before believing an empty result.

---

## 4n. Header markers: the rule was measured before it shipped, and the findings did not move (2026-08-24)

`OPEN_ITEMS.md` §17 — `classify.is_generated` reads header markers now. Two results, and the second
is the one that matters.

### The marker rule, measured over 305,861 files before it was written

§17's standing warning is that a false positive here is **silent lost coverage**, so the rule was
calibrated against the corpus trees rather than chosen. New suppressions, excluding files the path
rules already suppress — that exclusion is the whole measurement, and leaving it out inflates every
number by ~15,500 Django migrations that were already gone:

| rule | newly suppressed | what it wrongly catches |
|---|---|---|
| any marker, first 2 KB — **the shape §17 sketched** | **11,073 (3.62%)** | `apply-templates.sh`, `generate-stackbrew-library.sh` — the hand-written scripts that DO the generating, whose text contains the header they emit |
| first 10 lines, comments only, minus "generated by" | 1,128 (0.37%) | `.github/workflows/*.yml`, which say "automatically generated" while *describing* GitHub's dependency graph |
| **two signals — "generated" AND "do not edit", first 10 comment lines** | **803 (0.26%)** | nothing found; **640 of the 803 are Dockerfiles**, the intended target |

One signal matches prose *about* generation; two matches a file announcing itself as output. The
comment-only clause is what keeps a generator's own source out, where these phrases are string
literals. `_HEADER_LINES = 10` is what keeps `apply-templates.sh` out, since its heredoc sits far
below — pinned, along with the blind spot that a generator emitting its template *within* its first
ten lines would still be caught. Zero such files exist in the corpus; the test says so out loud
rather than letting the measurement read as proof the rule is sound in general.

### The findings did not move, and the reason is structural

`2026-08-24-iac-generated-headers` against `2026-08-22-iac-container-privilege-freshbaseline`:
**32 findings before, 32 after, identical case for case.** The pre-registered prediction was that
all 32 would disappear. It was wrong, and usefully.

The header reader works: on `docker-library__python#1123`, **6 of 6** Dockerfiles are flagged
`is_generated` when a checkout is present. Nothing consumes the flag. `is_generated` gates
`detect/secrets.py:118`, `detect/sast_semgrep.py:57` and `change/filter.py:147` — **`detect/iac.py`
is not among them and never asks.** Every one of the 32 findings is a checkov check.

This is errata §14.40's shape again, one layer over: **the stage that decides is not the stage that
gates.** §17's evidence — "12 reported findings on machine-written files" — described the problem
correctly and implied a fix that would not have worked, because the reader was only ever half of it.

### The half that is left is a decision, not an omission

Making `detect/iac.py` respect the flag would take one line, and **it would take the IaC corpus from
32 findings to 0** — every finding it has is a checkov check on a generated Dockerfile. That corpus
exists to prove `iac.py` runs on real input (§4h). A corpus with no findings proves nothing, and
§18 already records what happens when the obvious fix deletes findings.

**Decided 2026-08-24: not suppressing them.** The recommendation below was put to the project owner
and accepted. Stated so it can still be argued with: **do not suppress these.** "Container runs as
root" on a generated Dockerfile is a **true** finding with the **wrong address** — the fix belongs
in `apply-templates.sh`, not in the output. Suppression destroys the information; what the finding
needs is to be *annotated* with the generator, so the reader is sent to the template. That is a
different and larger change, and it is not this one.

### A note on the diff fallback, which is weaker than it looks

With no checkout, content comes from the diff's first hunk, padded so line numbers stay true. It
finds the marker only when **both** signals are inside the hunk. On `python#1123` the first hunk
begins at line 4 — inside the header, but below the "GENERATED VIA" line — so only the "DO NOT EDIT"
half is visible and the two-signal rule correctly declines: **0 of 8**. On `postgres#1415`, whose
diff *adds* the NOTE line, **4 of 13**. So the content half depends on a checkout in practice, and
the fallback is a bonus in the minority case rather than a substitute. That also means arm 2c
(`--no-checkout`) keeps very nearly its present behaviour, which is the safe direction.

---

## 4o. The recall numerator, audited at last (2026-08-24)

**Every recall figure this project publishes divides by, or rests on, one finding.** 0.028 (1/36),
0.111 (1/9), and the "a diff-only LLM finds five times as much" headline that prices the whole
unbuilt agent layer. `CONTINUATION.md`'s review block had nominated it as the claim carrying the most
weight on the least verification: **if that one finding is wrong, pipeline recall is 0.000 and the
ratio in `REPORT.md` §6 is undefined.** Nobody had opened the case. This is that audit.

**The finding.**

| | |
|---|---|
| case | `GHSA-f42x-p2mx-hm8r:vuln`, `brightio/penelope`, reverse-fix |
| advisory | **CVE-2026-50558** — *"Penelope unsafe tar extraction allows arbitrary local file write via crafted session archive"* |
| ground truth | `CWE-22`, `penelope.py`, spans `[3407,3413]` + `[3415,3421]` — the lines the fix removed |
| reported | `BAC-PATH-TRAVERSAL` (`CWE-22`), `penelope.py:3418`, confidence 6, `introduced_by_pr: true` |
| taint edge | source `tarfile.open` @3402 → sink `tar.extractall` @3418 |

**It is on the right line.** The fix at `a040afb` replaces

```python
with warnings.catch_warnings():
    warnings.simplefilter("ignore", category=DeprecationWarning)
    try:
        tar.extractall(local_download_folder)
```

with `safe_tar_extractall(tar, local_download_folder)`. The flagged call *is* the vulnerability the
CVE describes; `safe_tar_extractall` occurs 0 times in the vulnerable tree and twice in the fixed
one. Line 3418 sits inside ground-truth span `[3415,3421]`, and `CWE-22` matches `CWE-22` exactly, so
the score is earned on both axes `score_case` tests.

**And it is not the coincidence the construction invites.** `REPORT.md` §7 limit 2 warns that a
labelled case is a fixing commit run backwards, so the vulnerable lines are nearly the whole diff and
almost anything landing in the changed region would score. That objection does not survive contact
with this case:

- Ground truth is **14 lines of a 5,911-line file** — 0.24%. The diff is 64 changed lines.
- The **same detector fired four times in this same file**. Delta scoping dropped three as
  pre-existing (`penelope.py:3483`, `:3736`, `:3741`, all `os.remove` cleanup callbacks present
  identically in both trees) and kept exactly the one the fix rewrote.

That second point is the load-bearing one. The true positive is not "a path-traversal finding landed
somewhere in a path-traversal case" — it is the stage under §4j selecting one of four same-family
hits in one file and choosing the right one. **The corpus's one true positive and the suppression
mechanism are the same result seen from two directions.**

**One imprecision, recorded because it is in a reader-visible string.** The evidence reads *"tarfile
.open is untrusted input and reaches tar.extractall with no path sanitizer on the path."* The taint
edge is right and the conclusion is right — the fix is literally the addition of a sanitizer — but
"on the path" reads as though `local_download_folder` were the tainted value. It is not; the
untrusted data is the **archive member names** inside `tar`, which is what makes this CWE-22 rather
than a destination-directory bug. The mechanism the detector recorded (untrusted archive object
reaching an extraction sink) is the correct one. No number moves; the sentence is loose where the
analysis is not.

**What this discharges.** Recall 0.028 and 0.111 are now *verified* rather than *asserted*, and so is
everything downstream: the five-times ratio, `REPORT.md` §6's pricing of the agent layer, and §7's
limit 1 — which stays true (a numerator of one is still a numerator of one) but is no longer
accompanied by the worry that the one might be wrong. Blind spot #1 in `CONTINUATION.md` §5 can be
read as measured.

**What it does not discharge.** n=1 is n=1. This audit says the finding is real, not that the
pipeline would find the next one.

## 4p. The bundle census — what a context-fed arm could see (2026-08-25)

Plan 3, Step 1. A kill gate: the thresholds below were written down before the number existed.

**The question.** `build_bundles()` builds from the filter's kept set (`_change_stage`:
`filter_changes` → `classify_changes` → `build_bundles`). A model fed those bundles never sees a
hunk the filter dropped, so the filter's recall bounds any such arm the way the 0.250 taxonomy
ceiling bounds arm 2. §14.40 said the filter's recall ablation *"becomes meaningful for the first
time"* once something consumes tier-3 routing; this is that something.

> **A coarser version of this number already existed, and the first draft of this section said it
> did not.** Corrected 2026-08-25 during consolidation. `scoring.ablate_filter` reads
> `02_changeset.json`'s drop records and asks whether any of them names a ground-truth **file**;
> pass 2 reported **36/36 ground-truth files survived** (`CONTINUATION.md` §5). That is a real
> measurement, it is printed under every labelled run, and this census **reproduces it
> independently** — none of the seven drop records names a ground-truth file.
>
> What it cannot answer is the question an arm depends on. `ablate_filter` never opens
> `02_context_bundles.json`: a file can survive the filter and still produce no group, a group can
> be bundled without its bundle covering the vulnerable lines, and neither shows up in a drop
> record. The census below is that finer question, and its agreement with the coarser one at file
> level is a cross-check rather than a repetition.

**Method.** Labelled corpus, 26 vulnerable cases, deterministic arm, `--keep-runs`. **Zero model
calls, $0.** The two coordinate systems line up without translation and that was checked rather than
assumed: `context._span` reads `hunk.new_range` and `context._to_slice` reads
`sources(file, "after")`, both head-tree, and the corpus's ground-truth spans are head-tree too
because `head_sha` is the vuln commit under `reverse_fix`.

**Result.** Thresholds committed in advance: ≥ 6 of 9 proceed · 3–5 of 9 proceed with the ceiling as
the headline · ≤ 2 of 9 stop.

| rows | n | covered | spans | in a hunk | in a slice | **slice-only** |
|---|---|---|---|---|---|---|
| in scope (the 0.250 ceiling's 9) | 9 | **9 (1.000)** | 29 | 29 | 23 | **0** |
| out of scope | 27 | 27 (1.000) | 83 | 83 | 52 | **0** |
| all ground-truth rows | 36 | **36 (1.000)** | 112 | 112 | 75 | **0** |

**The filter is not the bottleneck.** Seven `DropRecord`s across the 26 vulnerable runs — six
changelog or docs files (`docs_only`) and one captured lockfile. Not one names a ground-truth file.
The gate is passed at its top threshold.

**And the arm's most obvious selling point is dead before a dollar was spent.** `slice-only = 0`:
not one ground-truth span is reachable through assembled context but not through the diff. Every
vulnerable line is inside a hunk, so it is inside `pr_task.diff_text`, so **arm 3 already sees all
112 of them.** This arm cannot win by showing a model lines the raw diff hides.

**That is a property of the corpus and has to be published as one.** These are `reverse_fix`
constructions: the ground truth is *"lines the fix removed"* and the diff is the fix reversed, so the
vulnerable lines **are** the diff, by construction. §3b already says a reverted fix is "the easiest
possible presentation of the defect"; this is the same limit, arriving at a different measurement.
In a real pull request the vulnerable sink is frequently pre-existing and outside the diff, which is
precisely the case where assembled context would be the only way to see it — and this corpus cannot
contain that case.

**What the arm does add, and what its hypothesis therefore has to be.** 288,803 characters of
surrounding code across 26 cases (min 597, median 7,176, max 36,600), plus the profile slice, the
reachability hints and the escalation tier. Enclosing symbols and 1-hop neighbours cover 75 of the
112 spans *redundantly* — the same lines the hunks already carry, with their definitions around
them. So the question this arm asks is not **"can the model see it"** but **"does surrounding a line
the model can already see with its enclosing symbol, its callers and callees, and the repository's
own access-control and sensitive-field rows change what the model concludes about it."** Harder to
win, cleaner to interpret, and the pre-registration at Step 5 must predict against *that* question.

**Escalation is advisory, and nothing acts on it.** 58 of 83 bundles escalate to `full_file`, 22 to
`none`, 3 to `multi_hop` — but `build_bundles` records the tier without changing what it puts in the
bundle. Phase-2 §5's acceptance check ("minimal context bundles, no full files unless the escalation
rule fires") is therefore satisfied trivially: no bundle holds a full file whichever tier fired. This
is §14.40's lesson in a second place — *a stage that runs is not a stage that gates* — and Step 3 has
to decide explicitly whether the producer honours the tier or ignores it, and record which.

**The census also found a defect in the harness, and found it by disagreeing with itself.** The first
pass reported three rows unreachable. All three were `--keep-runs` directory collisions, not filter
drops. Errata **§14.55**; fixed in `runner._case_slug`.

### 4p.1 What the context costs — and why "cheaper" is the wrong hypothesis

The project's stated vision for a pipeline-fed model arm was that processing might improve findings,
reduce cost, or both. The second half is answerable from the census, for $0, before any arm exists.

Payload the model would receive, all 26 vulnerable cases:

| | raw diff (arm 3) | bundles as built | bundles, profile slice deduped |
|---|---|---|---|
| characters | 229,184 | 556,735 | 490,906 |
| ratio | 1.00× | **2.43×** | **2.14×** |
| ~tokens (chars/4) | 57,296 | 139,183 | 122,726 |

Per case: median **1.70×**, min 0.57×, max 16.10×.

~~**The structural reason outlives the number.** A diff is already the minimal representation of a
change. Phase 1's token economy (Principle #4) was designed to beat *whole-file and whole-repo*
review, and against that baseline it wins by a wide margin. Against a **diff** it cannot: every
element a bundle adds — the enclosing symbol, the 1-hop callers and callees, the profile rows, the
reachability hints — is by definition something the diff did not contain. **There is no
configuration of this arm in which sending more context costs less than sending less context.** So
"cheaper" was never an open outcome for a per-PR context arm, and the report must say so rather than
leave a reader to hope for it.~~

> **Struck the same day, 2026-08-25, by §4p.2 — the measurement this paragraph itself called for.**
> The numbers in the table above are correct and stand. The *generalisation* drawn from them is
> false: on ordinary pull requests the bundles are **half** the raw diff, not 2.43× it. A diff is
> the minimal representation of a change only when the change is small and entirely relevant, which
> is what an advisory-derived corpus is made of. Kept, struck rather than deleted, per §14's rule —
> and written up as errata **§14.56**, because publishing a structural claim from one corpus while
> the other corpus sat unmeasured is the §14.42 pattern exactly.

**Where a cost win could still be real, and it is not this measurement.** The filter's other job is
deciding that a change needs no model at all. On this corpus it drops almost nothing — 7 records, all
`docs_only` or a captured lockfile — because advisory-derived PRs are wall-to-wall significant. On
ordinary pull requests most changes are not, and *"the pipeline never called the model"* is a saving
no raw-LLM arm can have. That is a separate measurement on the negative corpus and it is the only
place the cost half of the vision can still land.

**One scale observation, stated precisely because the loose version is wrong.** `_profile_slice`
selects rows *"by the group's files, not by keyword similarity, so the selection is explainable and
stable"* — and it does exactly that. But file granularity degenerates when the file is the program:
`penelope.py` is a 5,911-line single-file tool, so "the sinks in this group's files" is **323 sink
nodes, 34,700 characters**, against a 2,954-character diff. The same slice is then emitted once per
group in the same file, which is why 13 of 26 cases carry a byte-identical profile slice in more than
one bundle. Neither is a bug against the documented rule; both are the rule meeting a shape it was
not sized for. Deduplication recovers 2.43× → 2.14×, so it is **not** the main cost story and must not
be sold as one — the bundles are simply larger than the diff.

### 4p.2 The same question on ordinary PRs — and it answers differently (2026-08-25)

Plan 3, Step 1b. Negative corpus, 50 ordinary pull requests, deterministic run, `--keep-runs`, **zero
model calls, $0**. One case (`netbox-community__netbox#22764`) carries a 4,371,608-character diff and
dominates every aggregate, so both views are given and the outlier-excluded one is the honest
headline.

| configuration | chars | aggregate | median per PR |
|---|---|---|---|
| raw diff (arm 3) | 2,429,552 | 1.00× | 1.00× |
| **bundles only** | 1,270,580 | **0.52×** | **0.50×** |
| filtered diff only | 1,908,709 | 0.79× | 1.00× |
| filtered diff + bundles | 3,179,289 | 1.31× | 1.46× |
| raw diff + bundles | 3,700,132 | 1.52× | 1.50× |

*(All 50 including netbox: 0.19× / 0.28× / 0.47× / 1.19× against a 6,801,160-character raw diff.)*

**Bundles are smaller than the diff on 39 of 50 ordinary PRs.** That is the opposite of the labelled
corpus, where they are 2.43× larger, and the reason is corpus shape rather than anything about the
pipeline: an advisory-derived PR is small, focused and entirely relevant, so context is purely
additive; an ordinary PR is large and mostly irrelevant, so a bundle carrying symbol slices around
the changes is a **reduction**. §4p.1's struck paragraph generalised from the first shape without
measuring the second. Errata **§14.56**.

**The filter is not the lever, and this is the surprise.** 328 of 406 files kept. The filtered diff
alone is 0.79× aggregate and **1.00× median** — the filter drops changelogs, docs and lockfiles, not
code. The saving in "bundles only" does not come from dropping files; it comes from the bundle
carrying *slices around the changed symbols* instead of *complete unified diffs of large files*.

**Where the pipeline does refuse to spend anything.** 8 of 50 PRs produce no group and therefore no
bundle — the pipeline would never have called a model at all. 34 of 50 have no group marked
`significant`, which is what a router reading that flag would additionally skip; nothing reads it
today, which is §14.40 for the third time. The 8 are only 2.5% of diff bytes, so this is a
*call-count* saving, not a token saving.

**What survives from §4p.1, and it is the part that decides the arm.** Any configuration retaining
the diff is arithmetically dearer than the diff alone: raw diff + bundles is **1.52×** here and
**3.43×** on the labelled corpus. The configuration chosen for the findings comparison is the
expensive one, deliberately, because it is the only one that isolates the variable.

> **Realized 2026-08-26, §4r.** The 3.43× above is arithmetic on bundle JSON and stands as what it
> was. The producer that actually sends the payload weighs **3.21×** on the same 26 cases — the
> renderer's prose costs less than the three dedupes it makes possible. Neither number supersedes the
> other; they measure different objects, and §4r says which is which.

**So "cheaper" and "better" are in tension, and that tension is the interesting result.** The only
configuration cheaper than arm 3 is bundles-only, and bundles-only is cheaper *because it drops the
diff* — `ContextBundle.hunks` carry line numbers with no text, so a model given bundles alone cannot
see a deleted line. Removing a guard is a primary way a pull request introduces a vulnerability, so
that arm would be blind on a core case. **Cheap by omission is not the same as cheap by processing**,
and only a findings measurement can tell them apart. The ladder that does:

| | question | cost vs arm 3 |
|---|---|---|
| arm 3 | baseline | 1.00× |
| **this arm** — raw diff + bundles | does the context *add* anything? | 1.5–3.4× |
| bundles only, *only if the above wins* | can the context *replace* the diff at half the cost? | 0.50× |

The second rung is worth nothing until the first one answers, which is why it is not being built now.


## 4q. The context, pinned — and it was not the same twice (2026-08-25)

Plan 3, Step 2. `pr_review/benchmark/context_capture.py` and
`python -m pr_review.benchmark capture-context`. **Zero model calls, $0.**

**Why the context is captured rather than rebuilt per pass.** The arm has two halves and only one is
being measured. The pipeline half is deterministic; the model half is not, which is why the arm runs
three passes at all (§14.51). If every pass rebuilt its own bundles, a difference between passes
could be the model *or* the pipeline and nothing in the result would say which. Capturing once fixes
the pipeline half at a known value, so the spread across passes measures the thing spread is for. It
also makes the arm replayable by someone without 30 GB of checkouts and a warm profile cache.

**The step's exit criterion was "re-running capture twice produces identical bytes." It failed on the
first attempt**, and then twice more as each fix uncovered the next one. Three fields had an order
nobody had stated:

| field | ordered by | why it varied |
|---|---|---|
| `neighbors` | `cpg.edges("calls")` | graph edge order |
| `profile_slice`'s node lists | `cpg.nodes_of_kind()` | graph node insertion order |
| `reachability_hints` | `cpg.taint_paths` | path order |

**One mechanism under all three, and it was already written down.** A *freshly built* CPG is stable:
building the sample-app profile in three separate processes gives byte-identical node and edge
orderings. The cached path is not. `runner._isolated` records that `ProfileCache` is stateful across
cases and `drift.decide()` reads the latest fingerprint for a repository rather than one matching the
case — so the first case in a repository builds cold and the rest patch its profile incrementally, and
a patched graph does not carry a built graph's insertion order. Which branch a case takes depends on
what the capture run inherited. The evidence matches: of pypdf's four cases the one that ran **first**
was identical between captures, and the ones that differed were later cases in the same repository.

**The fixes are three sorts, and one of them is a distinction rather than a sort.** Neighbours and
the profile slice's node lists are put in source order, `(file, line, name)`. Taint paths order the
**paths** and leave each path's flow alone — `TaintPath.to_flow()` emits source, then sanitizers, then
sink, and sorting inside a path would turn a data-flow trace into a list of coordinates.

**Verification.** The four cases known to be unstable, run with their whole repositories so the
incremental branch fires as it did originally: **10 cases, 35 bundles, 126,494 slice chars,
byte-identical across two captures.** Concentrating on the known-unstable cases is the stronger test,
not the cheaper one — the full corpus dilutes four unstable cases in 52. **Stated as a limit rather
than glossed: full-corpus byte-identity was not re-verified after the last two sorts landed.** Two
10-minute captures would settle it and the concentrated run is the better evidence per minute, but
the claim above is about 10 cases, not 52.

**The artifact.** `benchmark/context/labelled.json` — 1,751,536 bytes, **52 cases, 175 bundles,
649,269 slice chars, analyzer v8, captured at `53be1ef`**. Committed, because an arm that replays a
capture is only reproducible if the capture is in version control. Four guards ride on it: its
provenance must name a **clean** commit (a `-dirty` sha is an artifact nobody can rebuild), its
`analyzer_version` must match the build reading it (a bump changes the profile, the profile decides
the CPG, and the CPG is what the bundles are cut from), it must cover every labelled case, and every
list in it must actually be ordered — §14.57 checked against the artifact and not only the code path.

**No published number moved, and the reason it could not is worth stating.** `neighbors`,
`profile_slice` and `reachability_hints` are read by `bundle_stats`, which sums them, and by the
serializer. No detector, no score, no scorecard. **But ordering was never cosmetic for the arm**: a
prompt whose sections shuffle between runs is a confound in an experiment whose entire output is a
spread across three passes, and it defeats prompt caching, which every cost figure in §4p.1 and
§4p.2 assumes. And for `neighbors` specifically it was not cosmetic at all — `_neighbors` truncates
at `MAX_NEIGHBORS = 6`, so where the cap bound, the unstable order was choosing *which* neighbours a
model would see. Errata **§14.57**; the selection rule itself is `OPEN_ITEMS.md` §25.

## 4r. The arm's prompt and producer — and what building the consumer revealed (2026-08-26)

Plan 3 Step 3. `benchmark/prompts/llm-context-bundles.md` and
`pr_review/benchmark/context_arm.py`: the diff, then the pipeline's own context, then the same JSON
answer arm 3 is asked for. `$0` — nothing here calls a model.

**The two decisions that were not the code's to make quietly**, both written into the prompt file's
header where a third party audits them, not only into the plan:

- **The diff is raw; the slices are wrapped.** The message *begins with the exact bytes arm 3 would
  have sent* — that is an assertion, not an intention, and it is the single guarantee the whole
  comparison rests on. Slice `content` goes through `safety/wrap.py:wrap_many`, because it is marked
  UNTRUSTED at `change/schema.py:92` and arm 3 never receives it, so wrapping it introduces no
  asymmetry in anything the two arms share. Residual, stated rather than fixed: the diff is untrusted
  text outside a fence, so this prompt already admits untrusted content in its body — wrapping the
  slices marks the far larger payload, it does not close that.
- **The escalation tier is not honoured; its reason is.** 113 of 175 bundles say `full_file`.
  Honouring it means shipping whole files, which the capture does not carry and which would move the
  cost figures the arm is priced against. So **this arm's result is a lower bound** on a
  tier-honouring implementation, and the write-up owes that sentence. The reason string is still
  sent: the `multi_hop` reasons name the concrete taint path (*"a taint-lite path spans 3 functions
  (a -> b -> c)"*), which is the most specific thing in the bundle and costs nothing. Silence here
  would have been §14.40 a third time.

**What the payload actually costs, measured on the built producer over the same 26 vulnerable cases
§4p.1's table uses** — not estimated from bundle JSON size:

| | raw diff (arm 3) | §4p.1, bundles as built | §4p.1, profile deduped | **as this producer renders it** |
|---|---|---|---|---|
| context characters | — | 556,735 | 490,906 | **507,089** |
| ratio to the diff | — | 2.43× | 2.14× | **2.21×** |
| whole message | 229,184 (1.00×) | — | — | **736,273 (3.21×)** |

Per case the message is a median **2.92×** the diff, min 1.74×, max 11.15×. Over all 52 cases it is
2.36× context and 3.36× message.

**§4p.2's 3.43× was arithmetic on bundle JSON and stands as what it was; 3.21× is what the artifact
that actually gets sent weighs.** The renderer adds prose the raw bundles do not have and still comes
in under, because it emits the project-level `auth_summary` once per case instead of once per group
(identical across every bundle in all 52 cases, checked, with a per-group fallback if a future
capture ever disagrees), dedupes repeated diff section headers, and replaces a byte-identical profile
slice with *"identical to group N"* — 23 such back-references across the corpus, none dangling.

### 4r.1 Three limits the build surfaced, all of which the write-up owes

Building the consumer answered questions the producer never had to. All three are measured on the
pinned capture, and all three narrow what the arm may claim.

1. **34 of 175 bundles carry no source at all** — no enclosing symbol, no neighbour; 32 of them with
   hunks and 2 with none. For those groups this arm is arm 3 plus a profile slice. No case degenerates
   completely — all 52 have at least one bundle with source — but **18 of 52 have a mix**, so the arm
   must not be described as uniformly context-fed.
2. **Only 26 of 36 ground-truth rows (72.2%), and 75 of 112 spans (67.0%), have source in the context
   that covers the vulnerable lines.** Split by stratum: **7 of the 9 taxonomy-reachable rows**, and
   19 of 27 outside it. This is the sharper companion to §4p's `slice-only = 0`: every span is in a
   hunk, so arm 3 sees all 112 and the arm cannot win on visibility — and now we also know that on
   **10 of 36 rows the added context contains no source covering the vulnerability at all**, so on
   those rows the two arms differ only by surrounding metadata. The arm's upside is bounded by 26/36
   before a single call is made.
3. **A `ContextBundle` does not carry the path of its own hunks.** `Hunk.id` is `<file_id>:h<n>` with
   `file_id` a hash, and `group.files` lives on `ChangeGroup`, which the bundle does not embed. The
   path is recoverable only from `enclosing_symbols[].file`, which exists for 141 of 175 bundles; for
   the other 34 the renderer says the file is not carried rather than guessing. Every bundle's hunks
   do lie in exactly one file — 0 of 175 span two file ids — so this is a schema gap, not an
   ambiguity. **A Phase-3b agent would have hit the same wall**, which is the argument for building a
   consumer before building the agent. `OPEN_ITEMS.md` §26.

### 4r.2 A guard that falsified green, in the step after the one that named the lesson

All 23 guards were falsified per §14.29 — neutralize, require red, restore. The first sweep came back
22 of 23, and the one that stayed green was the most important test in the file: the assertion that
the message opens with the exact bytes arm 3 would have sent. Neutralized by stripping the diff, it
**passed anyway**, because the fixture diff had no leading or trailing whitespace for `.strip()` to
remove and the joining newline happened to restore the one it did.

The guard was correct; the fixture could not discriminate. §14.57 recorded that lesson one step
earlier and it recurred immediately, which is the argument for running the falsification sweep as a
script rather than by eye. The fixture now ends with `" \n"` — a context line for a blank source
line, which is what unified diff format actually emits — and the neutralization goes red.
## 4s. The arm, wired — and the scorecard that described a different one (2026-08-26)

Plan 3 Step 4. `--arm llm-context` runs end to end: `$0`, no model called, exercised over the real
corpus and the real capture with a stub provider — **52/52 cases, 52 scores, payload recorded on
every one**, and 175 bundles with 34 source-free groups, which reproduces §4r's figures through a
different code path.

**Structurally it is the first arm that needs both halves.** Arm 2 bypasses the model; arm 3 bypasses
the pipeline. This one wants the pipeline's context *and* a model, and takes the pipeline half from
the committed capture — so it still builds no checkout, runs no detector, and gets arm 3's neutral
`tempfile.mkdtemp()` cwd plus `--disallowedTools`, because `claude -p` rooted in a corpus checkout
could read the source and quietly become the repo-access arm that was cut.

**`CaseRun.payload` records what each case sent** — diff chars, context chars, bundles, slices,
source-free groups. Outside `_DUMP_VERSION` for the same reason `model_cost` is: scoring does not
read it, so the eighteen stored runs stay readable and an absent `payload` means "this arm did not
measure its payload" rather than zero.

**A pre-flight that refuses before spending anything.** Two ways to waste a paid pass, both free to
rule out first, both modelled on `precheck_scorecard` — which exists because a naming collision found
*after* a run cost 844 seconds on 2026-08-08:

| refused | because |
|---|---|
| a capture that does not cover the corpus | a shorter experiment that still writes a scorecard is a recall denominator quietly reduced to whatever happened to be captured — §14.45's shape |
| a capture from another `ANALYZER_VERSION` | a bump invalidates every profile, and the profile decides the CPG the bundles are cut from, so the run would price context this build no longer produces |

`code_sha` is deliberately **not** checked: it is provenance and legitimately differs from HEAD after
any commit that does not touch the pipeline.

**Measured, for Step 5 to price against:** one pass over the labelled corpus sends **~1.87 M
characters (~468 K tokens)** of system-plus-user content across 52 calls. Step 5 recomputes the
dollar figure — that is its job, and §14.53's money rule means the number and the run land together.

### 4s.1 The scorecard said five detectors produced numbers no detector produced

Rendering a scorecard for the new arm printed *"these numbers cover the deterministic detectors
(secrets, structural CPG, semgrep, sca, iac) plus the injection sentinel"* — for a run in which not
one detector executed. **Eight stored scorecards already carried that sentence**, going back to the
first arm-3 run on 2026-08-21.

It is `render_cost`'s bug one constant over. That one printed *"no model is invoked anywhere in this
harness"* across a run that made 33 model calls and cost $0.95; it was found and fixed the same week,
and its twin four lines above it in the same file — broken by the same commit — was not, for five
days. **Fixing an instance is not fixing a class.** Errata §14.58.

`render_scope(run)` now branches on `CorpusRun.arm`, and an arm it does not recognise prints
**UNSTATED** naming the arm rather than inheriting the most common one — because the failure being
prevented is exactly a confident sentence about a run nobody checked.

**The eight files were re-rendered from their stored `run.json`** with `rescore`: $0, no pipeline
re-executed, **no number moved in any of them**, verified line by line. The only changes are the
scope paragraph, the `Rescored:` timestamp, the floor-provenance notice §21 added on 2026-08-24, and
§14.51's narrowing of the arm-3b claim — the last two being corrections those files should already
have carried. The published pages never contained the sentence.
## 4t. Pre-registered, then smoked — and the first smoke could not tell a working arm from a broken one (2026-08-26)

Plan 3 Step 5, the kill gate. **$0.4524 spent**, against a plan estimate of ~$0.10 — two smoke runs,
because the first one proved nothing.

**Predictions committed before the arm saw a model**, at `439373b`:
`benchmark/results/PREREGISTRATION-2026-08-26.md`. Six predictions, each checkable against the three
stored arm-3 passes rather than against memory. Two outcomes are recorded there as **known false in
advance** so they cannot be claimed afterwards: higher recall from seeing more (`slice-only = 0`),
and cheaper (3.41× the payload by construction).

### 4t.1 A smoke on cases the baseline is quiet on cannot discriminate — the same lesson, a third time

The first smoke used `--limit 2`, which takes the corpus's first two cases. Both are halves of
`GHSA-fp3f-mc75-235c`, and **arm 3 found 0 findings on it in pass 1 and 1 in pass 2.** Arm 3c
returned 0 and 0, at 22 output tokens.

Read one way that is a passing smoke; read honestly it is **no evidence at all** — the pre-registered
falsification condition is *"near-zero findings means the prompt is too restrictive or the parse
broke"*, and a case where the baseline is also near-zero cannot separate those from a working arm.
Assertion (a), *"output parses into `Finding`"*, was satisfied **vacuously**: nothing was parsed.

This is §14.57's lesson for the third time in three days — §14.57 itself (a fixture yielding one
neighbour), §4r.2 (a fixture diff with no whitespace to strip), and now a smoke corpus with no
findings to find. **The shape is always the same: the check ran, it came back green, and the green
meant the input had no power to produce red.** The rule that follows is worth more than any of the
three instances: *before trusting a green check, ask what input would have made it red, and confirm
the input you used could have been that.*

The second smoke used a three-case subset chosen **because arm 3 found findings on all three in all
three stored passes** (3/3/3 and 3/2/3) — `.claude/handoff/smoke-3c-corpus.json`, whose
`selection_criteria` records that reasoning in the artifact rather than in a commit message.

### 4t.2 The gate, on a corpus that could fail it

| `PIVOT_PLAN.md` §4 assertion | result |
|---|---|
| (a) output parses into `Finding` | **pass** — 6 findings across 3 cases, including three CWEs correctly noted as outside the taxonomy rather than dropped |
| (b) `score_case` runs | **pass** — 3 scores, 1 tp, 5 fp |
| (c) usage tokens non-zero | **pass** — 81,364 cached + 2,583 uncached. Not the guessed-key zero |
| (d) no tool calls | **pass** — `tool_denials: 0`, and `assert_no_tool_use()` at the dispatch |

Three pieces of Step 4 machinery also fired correctly on live data: `render_scope` printed the LLM-arm
note (§4s.1), `payload` was recorded per case, and **§21's floor-provenance check fired** — the run
used `claude` 2.1.246, never calibrated, so the derived split is marked an extrapolation.

### 4t.3 The early signal, which is n=3 and must not be read as a result

On the three smoke cases, against arm 3's three stored passes over **the same three cases**:

| | arm 3 p1 | p2 | p3 | **arm 3c** |
|---|---|---|---|---|
| ground-truth rows matched | 1/3 | 1/3 | 1/3 | **1/3** |
| true positives | 2 | 2 | 2 | **1** |
| false positives | 4 | 4 | 4 | **5** |
| reached the right file | 3/5 | 2/4 | 3/5 | **1/3** |

~~**This points against P2 and P4**, the two predictions the arm was most expected to win. It is three
cases. Arm 3's own spread across three passes on these three cases is *zero*, which is itself
unusual and makes the sample look steadier than the corpus is. **Nothing here is reportable**, and it
is written down only so that a full pass agreeing with it cannot later be presented as expected, and
a full pass disagreeing with it cannot be presented as a surprise.~~

> **Struck the same day, 2026-08-26, on reading the findings instead of the metrics.** The table
> above is arithmetically correct and stands; the sentence drawn from it was wrong, and it was wrong
> in the direction of over-reading a sample I had just finished calling worthless.
>
> **On two of the three cases neither arm can score a true positive at all.** Ground truth for
> `GHSA-22p9-r2f5-22mf` is **CWE-59**; arm 3 and arm 3c *both* answer **CWE-61**, its child, on every
> symlink finding they make — and `cwe_match` does not relate them, so every one of those findings is
> a false positive by construction, for both arms. Arm 3 reported three, arm 3c reported four and was
> charged one more false positive for the extra one.
>
> Reading the findings rather than the totals, the two arms agree far more than the metrics suggest:
>
> | case | arm 3 (p2) | arm 3c | who actually found it |
> |---|---|---|---|
> | `cj54:vuln` | 2 findings, both overlapping the one gt span | 1 finding overlapping the other gt span | **both** — recall 1/1 each |
> | `22p9:vuln` | 3 symlink findings, all CWE-61, all unscoreable | 4 symlink findings, all CWE-61, all unscoreable | **both**, and neither can score |
> | `22p9:control` | 1 false alarm | 1 false alarm | tie |
>
> So this sample **cannot measure precision**, because two thirds of it is unwinnable for reasons
> that have nothing to do with either arm. That is the *third* distinct way this smoke turned out to
> have no power to discriminate, after §4t.1's two — and it is what led to §4u, which is a much
> larger finding than anything the smoke was run to check.
## 4u. The scorer calls a child CWE a false positive, and it costs the LLM arms a third of their recall (2026-08-26)

Found by reading three smoke findings that the metrics had already written off. **This is not a
finding about the context arm.** It is a finding about the instrument every arm is measured with, and
it was sitting in six stored passes.

`scoring.cwe_match` accepts an exact id, or a **hand-listed** relation from `_CWE_GROUPS`. That table
already encodes five parent/child families — CWE-77/78, CWE-94/95, CWE-22's directional children,
CWE-285/862/863/639, CWE-798/259. **CWE-59 → CWE-61 is the same relationship and is not in it.**

### 4u.1 What it costs, measured across the six stored LLM passes

Findings that land in the **right file**, on **overlapping lines**, and are scored **false positive
solely because the CWE ids are not related**: **124**. The distribution is not a long tail:

| n | ground truth | model said | relationship |
|---|---|---|---|
| **32** | CWE-61 | CWE-59 | parent |
| **12** | CWE-59 | CWE-61 | child — **44 on this pair alone, in both directions** |
| 11 | CWE-200 | CWE-89 | none — a real model error |
| 8 | CWE-88 | CWE-78 | siblings under CWE-77 |
| 6 | CWE-834 | CWE-770 | adjacent, arguable |
| 5 | CWE-287 | CWE-306 | child |
| 5 | CWE-668 | CWE-284 | adjacent, arguable |
| 4 | CWE-200 | CWE-CORRUPTION | not a CWE — a real model error |

Roughly half are defensible hierarchy, half are genuine mistakes. **The pair that matters is
CWE-59/61**, which is the corpus's most common vulnerability class and which both LLM arms label the
same way as each other and differently from the advisory.

### 4u.2 The effect on arm 3's published recall, and on arm 2's ceiling

Recomputed over the three stored arm-3 passes. **The scorer was not modified** — this is a diagnostic
overlay, saved as `.claude/handoff/cwe-relation-probe.py` so it can be re-derived rather than trusted.

| group added | **arm 2's ceiling** | arm 3 recall, p1/p2/p3 |
|---|---|---|
| none (today) | 9/36 | **13 / 13 / 12** |
| **{CWE-59, CWE-61}** | **9/36 — unchanged** | **18 / 18 / 17** |
| {CWE-77, 78, 88} | **11/36 — MOVES** | 14 / 14 / 13 |
| {CWE-287, CWE-306} | 9/36 — unchanged | 14 / 13 / 13 |

> **This table was measured on 2026-08-26 *before* `{CWE-59, CWE-61}` was added**, which is why its
> first row reads 13/13/12. It is the evidence the decision was taken on and is left as it stood.
> Re-running `.claude/handoff/cwe-relation-probe.py` today reports the current table as the baseline
> and 18/18/17, because the pair is now in it.

**Arm 3's headline recall is 0.33–0.36 as published and would be 0.47–0.50** with one pair added —
a 40% relative change to the number the entire comparison is defined against.

**Why {CWE-59, CWE-61} specifically does not trip the standing constraint.** The rule is *do not
widen `_CWE_GROUPS` to flatter an arm*, and its stated mechanism is that `benchmark/scope.py` reads
the same table, so widening *"moves recall both ways"*. Measured: **neither CWE-59 nor CWE-61 is
emittable by any detector**, so `reachable_ground_truth` cannot change and arm 2's ceiling stays at
9/36. {CWE-77, 78, 88} *does* move it — 9 to 11 — because CWE-78 **is** emittable. **The constraint is
working exactly as designed; it separates the two cases rather than forbidding both.**

And the direction matters: adding the pair raises the **LLM arms** from 0.35 to ~0.49 while the
pipeline stays at 1/36. It makes this project's own tool look *worse* by comparison. Whatever else it
is, it is not self-flattery.

### 4u.3 Why this blocks Step 6 rather than following it

Three paid passes of arm 3c would be scored by this instrument, against an arm 3 baseline scored by
it too. The comparison would survive — the error is symmetric — but **every absolute number in the
write-up would be understated by the same third**, and the corpus's most common class would be
invisible in both arms' results.

Fixing it after the passes means re-deriving three scorecards and the report from stored runs, which
`rescore` makes free. Fixing it before means the numbers are right the first time. **The reason to
decide now is that it is the owner's call and not mine** — `_CWE_GROUPS` is under a standing "do not
widen" constraint, and §4u.2 is the measurement that constraint asked for, not permission to ignore it.

### 4u.4 Decided and done, 2026-08-26 — both halves

Owner's decision: **add the measured pair, and add a label-agnostic recall alongside it.** Errata
§14.59 carries the reasoning; what landed:

- `_CWE_GROUPS` gained `{CWE-59, CWE-61}` — **the only entry in that table added from a measurement
  rather than from reading the taxonomy**, and the comment says so. Two tests pin *the rule that
  admitted it*, not just the entry: that neither id is emittable (so the ceiling cannot move, and a
  future detector emitting one turns the decision red), and that CWE-78 **is** emittable, which is
  why `{CWE-77, 78, 88}` stayed out.
- `metrics.recall_ignoring_cwe` — rows some finding pointed at, taxonomy ignored. Reported **beside**
  `recall` in every labelled scorecard, never instead of it.

**All 36 stored scorecards re-scored.** Audited line by line: **no pipeline recall moved anywhere**,
every LLM arm moved up, and the 2026-08-26 smoke went **1/3 → 3/3**, which confirms §4t.3's corrected
reading — the arm had found all three rows and was being charged for its vocabulary.

| | recall | **ignoring the CWE label** | precision |
|---|---|---|---|
| arm 3 p1 / p2 / p3 | 18 / 18 / 17 of 36 | **29 / 27 / 28** | 0.53 / 0.52 / 0.49 |
| arm 3b ×3 | 16 / 16 / 20 | 25 / 26 / 28 | 0.58 / 0.56 / 0.60 |
| pipeline | 1 of 36 | **1 of 36 — no gap at all** | 0.50 |

**The last column of that table is the finding.** An arm that emits fixed ids shows no gap by
construction; an arm that names CWEs freely shows 9–11 rows of it. The gap is not recall anyone
deserves credit for — **locating a defect and classifying it are different achievements** — but it is
the first number in this project that can tell whether added context helped a model *find* something
or *name* it, and that is exactly the distinction Plan 3 exists to make.
## 4v. Two pull requests no single-prompt arm can review, and that is a result (2026-08-26)

Found while sizing the negative corpus for Step 6, before spending anything on it.

| corpus | cases | diff total | ~tokens |
|---|---|---|---|
| labelled | 52 | 458,374 chars | 114,593 |
| negative | 50 | **6,801,160 chars** | **1,700,290** |
| negative, less two outliers | 48 | 1,680,083 chars | 420,020 |

**One pull request is 4.37 MB — 64% of the whole corpus in a single PR**, about 1.09 M tokens, which
no current context window holds. A second is 749 KB. The other 48 are ordinary; the negative corpus's
*median* diff (7,947 chars) is slightly **smaller** than the labelled corpus's (8,282).

**Both LLM arms now refuse a payload over `MAX_MESSAGE_CHARS = 600_000`** (~150 K tokens) and record
the refusal against the case. Three choices, and the reasoning for each is in the constant's own
comment:

- **A stated constant, not the API's rejection.** A third party re-running must get the same
  partition of the corpus regardless of what any vendor's context window was that month. Same
  argument as `TRANSPORT_FLOOR_TOKENS`.
- **Refuse, not truncate.** A truncated diff is a different experiment wearing this one's name, and
  it fails in the worst direction — the model reviews 14% of a PR, finds nothing, and is scored as
  correctly reporting a clean one.
- **Refuse, not drop.** `PIVOT_PLAN.md` §1.4 requires the same corpora unmodified. The case stays in
  and the refusal is the datum.

**Because that datum is the point.** The pipeline reviews both PRs — it works file by file and never
assembles the whole diff into one payload. A single-prompt arm has a maximum pull-request size and
the pipeline does not. **That is a difference in kind rather than in score**, it costs nothing to
measure, and it is the strongest argument yet for §4.2's bundles-only rung: bundles are bounded by
`MAX_SLICE_LINES` and `MAX_NEIGHBORS`, so a bundles-only arm would review the 4.37 MB PR that neither
current LLM arm can open.

### 4v.1 A cost estimate I gave the owner was wrong by 3.7×, and it informed a decision

When the owner chose to run both corpora I estimated the negative half at **"~$3–6, and cheaper per
case since the payload is smaller there."** The second clause was wrong. It came from §4p.2's
*ratio* — bundles are 0.52× the diff on ordinary PRs — applied without checking the **absolute**
size. The runnable negative payload is **3.7× the labelled corpus's**, not smaller.

§4p.2's ratio is correct and unchanged; what was wrong was reading a ratio as a magnitude. **A ratio
says how two things compare, never how big either is** — and this is the second time in three days
that a ratio measured on one corpus was carried somewhere it did not describe (§14.56 was the first,
and it was struck for the same reason).

### 4v.2 The negative corpus's context, captured and measured — the corrected figures

`benchmark/context/negative.json`, 50 cases, 337 bundles, 568,053 slice chars, analyzer v8 at
`ff3eba3`. The committed-capture guards were **parametrized over every file in `benchmark/context/`**
rather than naming `labelled.json`, so this artifact arrived guarded instead of arriving unguarded
and being noticed later.

Measured over the **48 runnable cases**, against the labelled corpus:

| | labelled (52) | **negative (48 runnable)** |
|---|---|---|
| context vs the diff | 2.36× | **0.39×** |
| whole message vs the diff | 3.36× | **1.39×** |
| per case, median | 3.07× | **1.49×** |
| bundles · source-free groups | 175 · 34 (19%) | 209 · **83 (40%)** |

**§4p.2 is confirmed and sharpened.** Context on ordinary pull requests really is cheap relative to
the diff — 0.39×, better even than §4p.2's 0.52×, because the renderer's three dedupes pay for
themselves. The arm is still dearer than arm 3 anywhere it also carries the diff, but **1.39× is a
different proposition from 3.41×**, and it is the configuration a deployment would actually face.

**Two of five bundles on this corpus carry no source at all**, against one in five on the labelled
corpus. Ordinary PRs touch configuration, docs and tests, where the CPG has no symbol to slice — so
on this corpus the arm degenerates toward arm 3 far more often, and the write-up owes that beside any
false-alarm result.

**Cost, measured rather than extrapolated**, priced against arm 3's own stored accounting:

| pass | ~tokens | warm | cold |
|---|---|---|---|
| arm 3, negative | 791,360 | ~$0.91 | ~$3.22 |
| arm 3c, negative | 1,012,881 | ~$1.16 | ~$4.12 |
| arm 3c, labelled | 1,230,600 | ~$1.41 | ~$5.01 |

**Step 6 as scoped is therefore $10–20, not $4–8** — three passes of arm 3c on both corpora plus
three of arm 3 on the negative corpus, which has no arm-3 baseline at all.
## 4w. Step 6 — four passes of nine survived, and the guard that ate the other five (2026-08-26)

Nine passes launched, sequential, 40 minutes. **Four completed and are on disk. Five made every model
call, were billed, and wrote nothing.** Errata §14.60 has the full anatomy; the short version is that
`assert_no_tool_use()` ran **after** the corpus run and **before** `write_scorecard`, so it raised
and discarded the record with the money already spent — and the inference it raised on was wrong
anyway.

| pass | outcome |
|---|---|
| `arm3c-labelled` p1 · p2 · p3 | **all three lost** — the headline of the entire plan |
| `arm3-negative` p1 | lost |
| `arm3-negative` p2 · p3 | **stored** — $1.4922 · $0.8610 |
| `arm3c-negative` p1 | lost |
| `arm3c-negative` p2 · p3 | **stored** — $1.9793 · $2.0472 |

**What is left is two passes each of the two negative-corpus arms, and nothing at all on the labelled
corpus** — which is the comparison Step 6 exists to produce. Two passes is also one short of the
three §14.51 established as the minimum for telling a result from run-to-run variance: with two you
can see disagreement but cannot tell which of them is the outlier.

**The money is bracketed, not known.** 252 paid calls have no stored run. Priced between the warmest
and coldest passes measured the same day — a 3.5× spread on identical work — the lost spend is
**$4.30 to $22.37**, and it cannot be derived from disk.

### 4w.2 The project's spend, and the part of it that is not derivable

**This is where the total lives.** `REPORT.md` carried it until 2026-08-26 and no longer does — §4
there is now about what *drives* cost, which is the more useful thing for a reader, and an accounting
total is not a finding. The guards moved with the number rather than being retired:
`test_the_published_total_spend_still_matches_the_stored_runs` reads the table below, and
`test_the_report_still_names_the_spend_that_has_no_stored_run` checks the disclosure under it.

| | |
|---|---|
| 2026-08-21 — arm 3 ×3, arm 2b, smoke, cost sample | $5.4616 |
| 2026-08-22 — arm 3b pass 1, its smoke run | $1.8597 |
| 2026-08-24 — arm 3b passes 2 and 3 | $2.2627 |
| 2026-08-26 — arm 3c's two smokes and Step 6's nine passes, five run twice | $13.5745 |
| **total, derivable from the stored runs** | **$23.16** |
| **spent with no stored run** — §14.60 | **$4.30 – $22.37, not derivable** |

**Recomputed from all 21 paid runs, never incremented** (§14.53). The true project spend is somewhere
in **$27.46–$45.53**; the published figure is the one that can be checked, and writing an estimate
into a table whose caption says it sums the stored runs would make the single unverifiable number
look exactly like the verifiable ones.

### 4w.1 Both defects fixed, and the general form is worth more than either

- **Ordering.** The check now runs after the artifact is durable, on all three exit paths — on-disk,
  `--stdout`, and the naming-collision path. Falsified by restoring the original shape, which is the
  only neutralization that actually removes the property; my first attempt at that falsification came
  back **green** because it moved the check but still left `write_scorecard` ahead of it.
- **The inference.** `--disallowedTools` blocks tool *use*, so an attempted tool is refused into
  `permission_denials` and the refusal forces a second turn. A denial implies multi-turn; **multi-turn
  does not imply a denial.** The guard now treats a denial as fatal and records a bare multi-turn call
  in a new `multi_turn_calls` field. The stored passes report `tool_denials: 0`, so on the available
  evidence nothing was attempted and the denylist and neutral cwd both held.

**The rule this generalises to.** Every other guard in this project prevents a wrong number reaching a
document, and belongs before the artifact. This one prevents a wrong *experiment* — and by the time
it can run, the experiment has already happened and been paid for, so the only thing left for it to
destroy is the evidence. **Guards protecting correctness go before the artifact; guards protecting
interpretation go after it**, and the test for which you are writing is whether the thing it prevents
has already occurred by the time it fires.
## 4x. THE RESULT — the pipeline's context did not make the model better (2026-08-26)

Nine passes, three per arm per corpus. Scored by `score_case`, the same function every arm has always
used, against predictions committed at `439373b` **before the arm saw a model**.

### 4x.1 Labelled corpus — the headline, and it is a null

| | recall | recall ignoring CWE | precision | F1 | findings |
|---|---|---|---|---|---|
| **arm 3** (diff only) | 18 · 18 · 17 of 36 | 29 · 27 · 28 | 0.53 · 0.52 · 0.49 | 0.515 · 0.511 · 0.480 | 54 · 46 · 49 |
| **arm 3c** (diff + context) | **15 · 20 · 15** | **27 · 28 · 24** | **0.44 · 0.58 · 0.49** | **0.428 · 0.566 · 0.449** | 46 · 48 · 40 |

**Mean recall 17.7 → 16.7. Mean precision 0.51 → 0.50.** Arm 3c's spread is *wider* on every measure:
recall 15–20 against 17–18, precision 0.44–0.58 against 0.49–0.53.

**Adding the pipeline's assembled context did not improve the model's findings, and made it less
consistent.** Three passes is exactly enough to say that: arm 3c's best pass (20) beats arm 3's best
(18), and its worst (15) loses to arm 3's worst (17). **A one-pass run of this arm could have been
written up as either a win or a loss**, which is §14.51's entry arriving in the experiment it was
written for.

### 4x.2 P5 — the test that was designed to attribute an improvement, and found none to attribute

§4r.1 split the 36 ground-truth rows: **26 have source in the context, 10 do not.** On the 10, arm 3c
receives nothing arm 3 did not, beyond framing. Mean rows matched over three passes:

| | 26 rows **with** source | 10 rows **without** |
|---|---|---|
| arm 3 | 12.0 | 5.7 |
| arm 3c | **12.3** | **4.3** |

**+0.3 rows where context could help; −1.4 where it could not.** Both differences sit inside
per-pass noise (10/13/13 against 12/13/12; 8/5/4 against 3/7/3). The pre-registered inference was
*"if it improves on the 26 and not the 10, the improvement is attributable to context."* **There is
no improvement to attribute.**

### 4x.3 Negative corpus — and here the context demonstrably changes behaviour

50 merged PRs from healthy repositories; every finding counts against the tool.

| | false alarms | gate-relevant | `BAC-MISSING-AUTHZ` |
|---|---|---|---|
| **arm 3** | 3 · 4 · 3 (mean 3.3) | 0 · 0 · 0 | **0 · 0 · 0** |
| **arm 3c** | **2 · 8 · 5 (mean 5.0)** | 1 · 2 · 1 | **2 · 2 · 1** |
| pipeline | 12 | 1 | 11 |

**False alarms went up, not down** — P8 failed in the opposite direction. But the *mechanism* is
visible and it is the most interesting thing in this whole step: **arm 3c produces five
`BAC-MISSING-AUTHZ` findings across three passes and arm 3 produces none.** Their titles name the
pipeline's own vocabulary — *"New page action endpoints bypass require_any_permission decorator"*,
*"publish endpoint creates a revision before permission check"*. That is `ProfileSlice.access_control_rows`
reaching the model's output.

**So the context works, in the sense that it changes what the model looks at, in exactly the
direction its designers intended.** On a corpus of clean PRs, looking harder at authorization
produces false alarms. On a corpus of known vulnerabilities, it did not produce more true ones.

### 4x.4 Every prediction, scored

| | prediction | outcome |
|---|---|---|
| **P1** | no headline recall win | **HELD** — 16.7 against 17.7, inside noise |
| **P2** | precision > 0.55 to count as a win *(restated in the addendum after the scorer changed)* | **FAILED** — 0.50 against 0.51 |
| **P3** | control-half false alarms fall to 0–2 of 26 | **HELD** — 4 · 2 · 1 against arm 3's 3 · 5 · 4; mean **4.0 → 2.3** |
| **P4** | "reached the right file" rises above 30/44 | **FAILED** — 23/44 · 29/45 · 21/42, flat |
| **P5** | improvement concentrates on the 26 covered rows | **NULL** — no improvement to concentrate |
| **P6** | dilution failure mode: recall < 10 or findings < 30 | **did not trigger** — min 15 and 40 |
| **P7** | negative-corpus payload near 1.5× | **HELD** — measured **1.39×** |
| **P8** | false alarms fall on ordinary PRs | **FAILED, opposite direction** — 3.3 → 5.0 |
| **P9** | gate-relevant stays at or above 0.02 | **HELD for arm 3c** (0.02–0.04) and **failed for arm 3** (0.00) — the context arm matches the pipeline where the raw arm sees nothing |

**Two of nine held on the arm's own merits, one held as a null, one was a restatement that then
failed, and the two cost predictions both held.** P3 is the single clean win: on the control halves —
the *fixed* files, where the sanitizer the fix added is in the profile slice — context cut false
alarms from 4.0 to 2.3.

### 4x.5 What this licenses saying, and what it does not

**Says:** on this corpus, at this effort, with this configuration, feeding a model the context a
Phase-3b agent was specified to receive **did not make it a better reviewer**, and cost 3.41× the
payload to find out. It did make it a *different* reviewer, measurably and explicably.

**Does not say:** that context is worthless. Four limits, all measured earlier today and all pointing
the same way — this is a **lower bound**:

1. `slice-only = 0` (§4p) — arm 3 already sees all 112 ground-truth spans, so the arm could only ever
   win on judgment, never on visibility. **A `reverse_fix` corpus cannot contain the case where
   context matters most**, because the vulnerable lines *are* the diff.
2. Only 26 of 36 rows have source in the context at all (§4r.1).
3. The escalation tier is **not honoured** (§4r) — 113 of 175 bundles asked for the whole file and
   got slices.
4. Neighbour selection is unmeasured (`OPEN_ITEMS.md` §25) — six neighbours chosen by source order.

**The honest headline is that the first configuration of this idea did not pay off, on the one corpus
that could be built for it.** That is a result, it is publishable, and it cost $23.16 to obtain.

## 5. Known blind spots — state these, do not let them read as clean

1. ~~**Recall is unmeasured.**~~ **Measured 2026-08-07: 0.028 (1/36), 0.111 in scope, 0.04 of pairs
   discriminated.** What replaces this blind spot is narrower and sharper: **the measurement rests
   on 26 advisories and one true positive.** A single case carries the entire numerator, so the
   difference between 0.028 and 0.000 is one finding in one repository. It is a first measurement,
   not a baseline, and the same n = 50 caution pass 1 carries applies harder here.
2. **The FP number is an upper bound.** "Known clean" is false in the small — a merged PR from a
   healthy repository can carry a vulnerability nobody has found, and this counts any such finding
   against us.
3. **IaC is unmeasured. SCA is now thinly measured, and that is different.** `iac` is still
   `not_applicable` on all 102 cases across both corpora — nothing prices it. `sca` ran **once**
   in pass 2 and, after §4d added five lockfile formats, **13 times across the two corpora**,
   producing **2 findings**. Both are correct on inspection: one real (gitpython 3.1.57, fixed in
   3.1.58) and one an artifact of a lockfile's editable self-entry (§14.32). 13 invocations and 2
   findings is a first contact with real input, not a false-positive rate — the denominator that
   would price SCA is *dependency-changing PRs*, and there are 10 of them.
4. ~~**`missing-authz per endpoint` is understated**, because defect 2 inflates its denominator.~~
   **Closed 2026-08-07, and quantified**: 0.085 → **0.149**, understated by a factor of **1.75**
   (the guess here was "roughly two"). ~~What replaces this blind spot is narrower: **the endpoint
   denominator has never been validated against a hand count.**~~ **Also closed 2026-08-07**, two
   ways — see §4b. A hand count of four real Prefect FastAPI routers matched the profiler
   **13/13** on routes, verbs and paths; and `test_promote.py` now profiles a `@patch`-heavy test
   module and asserts the endpoint count does not move.
5. **n = 50, and the noise is concentrated.** Baseline: 3 PRs produced 85 of 98 FPs. After the
   fixes it is worse, not better — **all 11 remaining FPs are one file in one repository**,
   so a corpus without Wagtail would report ~0.02 FP/PR and mean nothing. This is a first
   measurement, not a stable baseline.
6. **Gate-relevant FP is 0.00 partly by construction.** M2 emits `candidate`; the gate needs
   `validated`. Re-measure after M4.
7. **The pass-1 fixes were derived from that corpus and measured on it — in-sample.** Each is
   argued from mechanism rather than tuned to the number (a documented platform escape; a compiler
   is not an executor; osv-scanner's own lockfile-vs-manifest distinction; a route path starts with
   `/`), and each is pinned by tests asserting what must *survive*. **Pass 2 was meant to be the
   out-of-sample check and turned out to be a weak one** — see §3b's last section. It contradicts
   none of them and confirms none of them either.
7b. **Both headline numbers are upper bounds, in opposite directions.** Pass 1's false-positive
   rate is an upper bound because a merged PR can carry an undiscovered vulnerability. Pass 2's
   recall is an upper bound because a reverted fix is the easiest possible presentation of a defect
   — the vulnerable lines are essentially the whole diff, where a real vulnerability-introducing PR
   buries them in unrelated change. Neither is a point estimate.
7c. **Pass 2's ground truth is a proxy.** "The lines the fixing commit changed" is not "where the
   vulnerability is", and §3b's second finding is largely a consequence of the gap between them.
   Two spans of 112 are known-unmatchable scaffolding, biasing recall down by ~2%
   (`labelled-verification.md`).
8. **Repo selection is a recorded bias.** Ten repos chosen by one person for detector surface. The
   criteria are printed verbatim in every scorecard so a reader can discount accordingly.
9. ~~**A corpus run cannot be re-scored without re-running it.**~~ **Closed 2026-08-07.**
   `write_scorecard` now writes `run.json` beside the scorecard and
   `python -m pr_review.benchmark rescore --run <path>` re-derives every number from it in seconds.
   It paid for itself inside pass 2: the baseline-attribution metric was added after the corpus had
   already run. What remains is a bounded limitation, stated where it lives — **the dump carries the
   slices scoring reads today** (case, findings, drop records, detect telemetry), so teaching
   scoring to read something new means bumping `_DUMP_VERSION` and paying for one more run. That
   happened once already, v1 → v2, when labelled cases turned out to need their pre-existing
   findings kept.
10. **Only the aggregate is checked by anything.** The scorecard reports per-taxonomy, per-detector
    and per-severity breakdowns, and no test asserts that they sum to the headline. They did in
    both runs, checked by hand.

---

## 6. Next steps

Ordered by measured impact per unit of work. Everything here is **credential-free**;
`models/bedrock.py` and M3 remain blocked and unaffected.

1. ~~Fix defects 1, 3 and 5, then re-run the pinned corpus.~~ **Done 2026-08-07.** 1.96 → 0.22
   FP/PR. The measure→fix→measure loop closed for the first time; §3 has both runs.
2. ~~Decide defect 2.~~ **Done 2026-08-07 — fixed.** Reading the profiles rather than the
   scorecard showed 46% of the access-control matrix was mock targets, which changed the decision
   outright. §4 has the numbers and the two rejected alternatives.
3. ~~**Pass 2: the labelled GHSA corpus.**~~ **Done 2026-08-07** — §3b. Recall measured, the filter
   ablation run for the first time (36/36), and a new false-positive class found that the negative
   corpus structurally could not surface.
4. ~~**Serialize `CorpusRun`.**~~ **Done 2026-08-07** — blind spot #9, `rescore` subcommand.
5. ~~**Localization.**~~ **Resolved 2026-08-08 — accepted, not patched** (§4c, errata §14.30). The
   four in-scope misses emit *identical* findings on the vulnerable and fixed trees, 12/12
   fingerprints, so widening the match window is provably inert. The class is Phase 3b work with a
   measured argument behind it. **Do not** revisit it by widening the window to raise recall.
6. ~~**The test-file false-positive class.**~~ **Resolved 2026-08-08 — it was a detector defect,
   not a policy question** (§4c, errata §14.31). "10 of 11 are in test files" was a population, not
   a cause: a pattern that is both a source and a sink was tainting itself, and 42 of the same
   shape sat in non-test code. Fixed at the mechanism; 0.42 → 0.04 FP/PR with every signal number
   unchanged. `suppress.py` + allowlist is still wanted for its own reasons, but not for this.
7. **Defer defect 4 to M3** with the BAC agent, as a design decision rather than a patch. Pass 2
   adds evidence: its CWE-862/863/287 rows were all missed by the deterministic detectors, which is
   what `M2_STATUS.md` §3.2 predicted.
8. ~~**Assert the endpoint denominator against a hand count.**~~ **Done 2026-08-07**, two ways —
   §4b. A hand count of four real Prefect FastAPI routers matched the profiler 13/13, and
   `test_promote.py` now profiles a `@patch`-heavy module and asserts the count does not move. That
   test was **inert when first written** and had to be repaired before it asserted anything
   (errata §14.29).
9. ~~**Make `python.yaml`'s `endpoints` block live, or delete it.**~~ **Done 2026-08-08** — §4e,
   errata §14.33. `decorators` and `method_kwarg` are read; `method_from_decorator`, `path_arg`,
   `route_table_calls` and `route_files` are deleted with their reasons recorded at the code that
   replaced each. The catalog's own matching contract is what resolved the design question: it
   matches decorators by **dotted suffix**, so the receivers were already decorative and the
   derived set equals the old hardcoded literal exactly — a test asserts that. The coverage test
   written to stop this recurring found **nine more inert keys**, now named in `OPEN_ITEMS.md` §3.
10. ~~**`pr_review/benchmark/gate.py`**~~ **Done 2026-08-08** — §4e. It never got the stable number and was
    built not to need one: it ratchets **integer counts** against a pinned `run.json` and reports
    every rate without gating on it. What is left is that there is no CI in this repository to wire
    it into (no `.github/`, no Makefile), which is M6, and no smoke subset — `--limit` slices the
    corpus in order, which splits the labelled pairs and changes every denominator, so a subset run
    cannot be compared against a full baseline.
11. ~~**Teach `extract/deps.py` the modern lockfiles.**~~ **Done 2026-08-08** — §4d. All five
    landed and both corpora were re-measured. SCA went from 1 invocation in 102 cases to 13, and
    produced the first two SCA findings this tool has made on real input.
12. ~~**Two latent defects found in passing.**~~ **Both done 2026-08-07** — §4b. `is_generated`
    gained `dist/`, `*.js.map`, `*.css.map`, `*.min.css` (and deliberately *not* `build/`); the
    secrets snippet is now bounded by `MAX_SNIPPET_CHARS`, which cannot move a fingerprint because
    `fingerprint()` is given the secret, not the line.
13. ~~**Should SCA skip a lockfile's editable self-entry?**~~ **Decided 2026-08-08: yes** — §4e,
    errata §14.33. Decided on the mechanism, not the number, which is why 10 dependency-changing
    PRs was enough: osv-scanner is asked "is this *dependency* vulnerable" and a first-party entry
    is the subject of that question, so the "Upgrade `<name>`" remediation is addressed to the
    people reading the review. The case the counter-argument wanted kept is kept by the stated
    note, which is where it belongs — it wants different words than an upgrade instruction.
14. **`sources.param_annotations` and the argument-reading group** — two real detector gaps that
    fell out of the catalog coverage test, `OPEN_ITEMS.md` §3. Both need call-*argument* extraction,
    the same ParseCache gap that defers Django route tables, so one fix closes them together.

    > **Corrected 2026-08-24.** This item used to lead with `auth.router_kwarg` and assert that it
    > "makes FastAPI router-level guards read as unguarded, which *inflates* `missing-authz`". That
    > key was **read on 2026-08-08** by `promote._router_guards`, and the inflation claim was
    > **wrong and never true** — §4f is the record. All 11 of those findings are in one django-ninja
    > file with no `dependencies=` anywhere. `OPEN_ITEMS.md` §3 carries the correction; this list
    > repeated the superseded premise for sixteen days. **A counter was predicted to move because
    > the input reached it, rather than because the event it counts happened** — the standing trap in
    > `OPEN_ITEMS.md`, surviving in the document that recorded it.

---

## 7. How to re-run

```bash
# the labelled GHSA corpus -> benchmark/results/<date>-labelled/   (~15 min, 52 cases)
# --cold-profiles is REQUIRED for this corpus: without it the second case in a
# repo patches the first one's profile, so the two halves of a pair are built by
# different code paths (`runner._isolated`).
.venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/labelled.json \
    --cold-profiles --label labelled

# rebuild the labelled corpus from the advisory feed (reproducible: same command,
# same exclusions, same corpus). The spans it produces are CANDIDATES — see
# benchmark/corpus/labelled-verification.md before quoting anything from it.
.venv/bin/python -m pr_review.benchmark build-labelled --advisories 80 --per-repo 2 \
    --exclude benchmark/corpus/labelled-excluded.txt --criteria "..." \
    --out benchmark/corpus/labelled.json

# re-derive a scorecard from a stored run, in seconds instead of the full re-run
.venv/bin/python -m pr_review.benchmark rescore \
    --run benchmark/results/2026-08-07-labelled/run.json --label retaxonomy

# the regression gate: integer ratchets against a pinned baseline, rates reported
# but never gating. Exit 0 pass / 1 regressed / 2 could not compare — and "could
# not compare" is a refusal, not a pass: mismatched corpus, mismatched
# --cold-profiles, a different case set, or a dump this build cannot read.
.venv/bin/python -m pr_review.benchmark gate \
    --baseline benchmark/results/<pinned>/run.json \
    --run      benchmark/results/<new>/run.json
# --max-new-findings N raises the false-positive allowance (default 1)
# --json emits the verdict for a machine instead of a person

# the pinned negative corpus -> benchmark/results/<date>/negative.md   (~20 min, 50 cases)
.venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/negative.json

# re-measuring the SAME day: label it, or the write refuses rather than clobber
# the run you are comparing against -> benchmark/results/<date>-after-fix/
.venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/negative.json \
    --label after-fix

# on a machine without the checkouts, rebuild them from the pinned shas first
.venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/negative.json --rehydrate

# keep the per-case run dirs so a number can be audited back to the run that produced it
.venv/bin/python -m pr_review.benchmark run --corpus benchmark/corpus/negative.json \
    --keep-runs /tmp/bench-runs

# build a new corpus (GH_TOKEN optional; unauthenticated GitHub API is 60 req/hr)
.venv/bin/python -m pr_review.benchmark build --repos o/r,o2/r2 --per-repo 5 \
    --criteria "how these were chosen — printed verbatim in every scorecard" \
    --out benchmark/corpus/negative.json
```

`--criteria` is **required** and `corpus.save()` refuses a blank one: it is printed verbatim in
every scorecard and is the reader's only defense against a corpus picked to flatter the tool.

Checkouts land in the gitignored `.pr_review/cache/` — **4.6 GB** for this corpus, two extracted
trees per case plus mirrors. The corpus and results are committed; the trees are not.

**If you change how a profile is built, bump `profile/cache.py:ANALYZER_VERSION`.** Cached
profiles are keyed on the repo sha and the file layout, neither of which moves when an extraction
rule is fixed, so without a bump a re-run silently measures the old analyzer and reports that your
fix did nothing (errata §14.25). Bumping it forces a full profile rebuild for every repository in
the corpus, which is most of a re-run's cost.
