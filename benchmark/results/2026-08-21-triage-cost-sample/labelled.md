# Detector scorecard — labelled

**Run:** 2026-08-21T15:41:33 · **cases attempted:** 6 · **completed:** 6 · **wall clock:** 148s

**Code under measurement:** `21c7151-dirty`
**Rescored:** 2026-08-26T12:41:36 by `b34cef5-dirty`, replaying the stored run above. The pipeline was not re-executed — every finding below is the one `21c7151-dirty` produced, re-judged by this commit's scoring rules. If two scorecards disagree, this line says which of the two things moved.


**Scope: 3a only.** These numbers cover the deterministic detectors (secrets, structural CPG, semgrep, sca, iac) plus the injection sentinel. Phase 3b agentic families and the 3c verifier are not built and are not measured here, so this is **not** the `PR_Rev_0620.md` §13.7 / `benchmark.md` §7 headline (~P90/R93 on a post-cutoff CVE holdout), and it is not comparable to the Gemini extension's self-reported figure — §7 already records that ours is a harder, not-directly-comparable bar.

**Cost / tokens: MEASURED.** 5 model call(s) via the `claude` CLI (`haiku`, effort `unstated`): **$0.0933** total, **$0.0155** per completed case.

Tokens, as the CLI reports them: **36,725** cached (`cache_creation + cache_read`) plus **10,139** uncached (`input + output`), **46,864** in all. Those two buckets are **not** our-content and their-overhead. Claude Code caches its own system prompt and, when our prompt clears the model's minimum cacheable length, our prompt with it — so which bucket our tokens land in varies by prompt size and model, and neither bucket alone names a party (§14.44).

**Derived, not measured here:** at a calibrated floor of 7,300 tokens per call for the CLI's own system prompt, ~**36,500** of the total is harness and ~**10,364** is ours. The subtraction is taken from the *total* rather than from the cached bucket, because doing the latter reported 0 tokens of our own content for a run that had plainly sent some. It rests on a calibration against one CLI build, not on this run. Neither figure is an API price.

**Floor provenance: UNRECORDED.** This run does not say which `claude` build produced it, so the 7,300-token floor cannot be checked against it. Runs stored before 2026-08-24 predate that field; treat the derived split as unverified rather than as agreeing.

---

## Corpus

**Selection criteria, verbatim from the pinned corpus:**

> The 80 most recently published GitHub-reviewed advisories for the pip ecosystem as of 2026-08-07, capped at 2 per source repository and 1 per fixing commit, restricted to those carrying a CWE and a fixing-commit reference into their own repository whose parent is not a merge, whose fix diff is under 400 KB, and which touch reviewable Python source outside tests and docs. Ground-truth spans are the lines the fix removed, excluding spans that are entirely imports, version bumps or comments. Two fixing commits were then excluded by hand as bulk refactors whose spans mark remediation plumbing rather than the defect; the reasons are in benchmark/corpus/labelled-excluded.txt. NOT filtered by CWE: classes no 3a detector can emit are retained and reported as a stratum. Newest-first sampling makes the set post-cutoff for any model evaluated later.

A corpus chosen to flatter the tool is the classic benchmark failure, and printing how it was picked is the only defense a reader has. Cases are pinned by repo, PR number and both shas, so every number below can be re-derived.

## Detectors actually exercised

A detector that found nothing and a detector whose binary is absent produce the same empty list. These are the `AdapterRun.status` counts across the corpus; anything not mostly `ran` means the numbers below do not cover that detector.

| Detector | Status counts |
|---|---|
| iac | not_applicable: 6 |
| sca | not_applicable: 6 |
| secrets | ran: 6 |
| semgrep | ran: 6 |
| structural | ran: 6 |

## False positives on known-clean PRs

- **False positives per PR:** 0.00 (0/3)
- **Gate-relevant (high/critical) per PR:** 0.00 (0/3)
- **PRs with no findings at all:** 1.00 (3/3)
- Pre-existing findings excluded from scoring: 0

> Every finding attributed to the PR on known-clean code is counted against the tool. **This is an upper bound on the false-positive rate**, not a point estimate: a merged PR from a healthy repository can still contain a real vulnerability that nobody has found, and any such finding is counted here as a false alarm. It also says nothing about recall — a detector that reports nothing scores perfectly on this set.

### The endpoint stratum

- PRs where the structural detector saw at least one endpoint: **0** of 3
- Endpoints seen across those PRs: **0**
- **False positives per endpoint-touching PR:** n/a (0 cases)
- **`BAC-MISSING-AUTHZ` alarms per endpoint seen:** n/a (0 cases)

> `M2_STATUS.md` §3.2's named worry is that `BAC-MISSING-AUTHZ` fires on every unguarded endpoint in a changed file, including deliberately public ones. Most merged PRs touch no endpoint at all, so that rule cannot fire in them and the corpus-wide average prices it at near-zero — arithmetically true, and an answer to a different question. This stratum is the one that addresses it. The split is derived from what the detector actually saw, not from how the corpus was picked, so neither number is biased by the other's needs.

### Which rules produce the noise

The aggregate above is not actionable on its own; this table is the output that is.

_(none)_

### By detector

_(none)_

### By severity

_(none)_

### Noisiest cases

| Case | False positives |
|---|---|
| GHSA-fp3f-mc75-235c:control | 0 |
| GHSA-fwg2-594c-jp42:control | 0 |
| GHSA-gm37-52c6-37mw:control | 0 |

## Precision and recall on labelled cases

- **Precision:** n/a (0 cases)
- **Recall:** 0.000 (0/6)
- **Recall ignoring the CWE label** (did anything point at the vulnerable lines?): 0.000 (0/6)
- **F1:** n/a
- **Localization** (matched a label *and* the lines): n/a (0 cases)
- Near misses (right file, wrong lines): 0
- **True positives owed to the CWE relation table:** n/a (0 cases)

> **Recall is understated by design and must not be read flat.** The 3a detectors cover a deliberate subset of the taxonomy: Broken Access Control is the M3 agent flagship, and Privacy/PII and Insecure Design are agent families with no deterministic detector at all. A miss in those classes is a milestone boundary, not a detector defect. The per-family breakdown below is the honest reading.

> The relation-table share matters because `benchmark/scoring.py:_CWE_GROUPS` decides which CWE ids count as the same defect. Widening it raises precision and recall without changing the tool. If most true positives arrive through it rather than through an exact CWE match, the headline is a property of that table.

> **The two recalls above are the same question asked with and without the taxonomy**, and the gap between them is this measurement's own vocabulary error rather than anything the tool did. `_CWE_GROUPS` is a hand-list of ~9 families against a taxonomy of some 940 ids, so an advisory that labels a defect one level up or down from where a tool would is a silent false positive. An arm that emits fixed internal ids shows no gap at all — the pipeline's two numbers are equal by construction — while an arm that names CWEs freely can show a large one. Read the gap as a property of the arm's vocabulary, never as recall it deserves credit for: locating a defect and classifying it are different achievements, and only the second is `recall`. `OPEN_ITEMS.md` §27.

### True positives by family

_(none)_

### Misses by ground-truth CWE

| CWE | Missed |
|---|---|
| CWE-1333 | 4 (67%) |
| CWE-400 | 1 (17%) |
| CWE-834 | 1 (17%) |

### Blind, or mis-aimed?

- **Ground truth some finding named, scored or not:** 0.000 (0/6)
- ...found, but attributed to the base tree **on the vulnerable lines**: 0
- ...found, but attributed to the base tree **elsewhere in the file**: 0

> A missed row fails in two ways that `recall` prices identically at zero: no detector ever produced a finding for it, or a detector produced the right finding and `findings/delta.py` attributed it to the baseline, so scoring never saw it. Different causes, different fixes. The first row above is the union, and it is **not a quality claim** — naming a file is not naming a defect. It is here because when recall is low the useful question is whether the detectors are blind or merely mis-aimed.

> The split matters for what to do next. A row found **on the vulnerable lines** would have been a true positive but for delta scoping, and argues about attribution. A row found **elsewhere in the file** would only ever have been a near miss, and argues about localization — a taint detector reports at the sink, while a fixing commit's ground truth sits where the missing validation went, and those are different lines by construction.

### The in-scope stratum

- **Recall over ground truth a 3a detector could name:** n/a (0 cases)
- Misses in classes **no detector models at all**: 6

> This is the honest reading of the flat recall above. Roughly half a recent advisory sample is CWE-400, CWE-1333, CWE-834, CWE-455, CWE-200, CWE-59 and CWE-61 — resource consumption, ReDoS, symlinks — which no deterministic detector in this milestone emits. Counting those against the tool measures the roadmap.

> **The stratum is derived, never selected for.** The corpus was not filtered to CWEs the tool covers; that would be the corpus-flattering failure `Corpus.selection_criteria` exists to expose, and errata §14.20 already ruled on the same question from the other side. The set comes from `benchmark/scope.py`, which reads the detectors' own dispatch tables rather than a hand-maintained list — a list would let a one-line edit raise recall without changing the tool.

#### Missed CWEs with no detector

| CWE | Missed |
|---|---|
| CWE-1333 | 4 (67%) |
| CWE-400 | 1 (17%) |
| CWE-834 | 1 (17%) |

## Paired controls — did it find the vulnerability, or the file?

- **Pairs where the vulnerable side was flagged and the fixed side was silent:** 0.00 (0/3)
- Flagged the vulnerable side, but also flagged the fix: 0
- Missed the vulnerable side entirely: 3

> **This is the number that makes a reverted fix worth scoring, and it belongs next to recall rather than under it.** A labelled case here is a fixing commit run backwards, so the vulnerable lines are essentially the whole diff — the easiest possible presentation of the defect. Recall alone cannot separate *found the vulnerability* from *always fires on this file*, and the second scores identically while being worthless. The control is the same file with only the vulnerability removed, so the pair separates them and neither half does.

### Per advisory

| Advisory | Outcome |
|---|---|
| `GHSA-fp3f-mc75-235c` | missed |
| `GHSA-fwg2-594c-jp42` | missed |
| `GHSA-gm37-52c6-37mw` | missed |

## Phase-2 noise filter — recall ablation

- **Recall after filter:** 1.000 (6/6) ground-truth files survived
- Dropped ground-truth files: 0
- ...of which the guardrail never considered: 0

> **At M2 this stage does not gate what the detectors see.** `pipeline.py` builds the detect stage from the manifest and every parsed file, not from the filter's kept set, so a dropped file is still scanned and a finding in it still reaches the report. The filter's drops decide what Phase-3b agents are routed to, which arrives at M3. This measurement is therefore a **baseline taken before the stage becomes load-bearing** — it is not evidence that a live leak was found or closed.

> A drop the guardrail never considered is the more serious of the two: `DropRecord.guardrail_considered` separates "the CPG said this file is inert" from "we never asked".

---

<sub>Generated by `pr_review.benchmark`. Deterministic render of a corpus run — no model involved in producing these numbers or this document.</sub>
