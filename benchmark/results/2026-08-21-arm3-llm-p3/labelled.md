# Detector scorecard — labelled

**Run:** 2026-08-21T16:41:09 · **cases attempted:** 52 · **completed:** 52 · **wall clock:** 261s

**Code under measurement:** `29177aa-dirty`
**Rescored:** 2026-08-26T12:41:35 by `b34cef5-dirty`, replaying the stored run above. The pipeline was not re-executed — every finding below is the one `29177aa-dirty` produced, re-judged by this commit's scoring rules. If two scorecards disagree, this line says which of the two things moved.


**Scope: one model call per case, and no pipeline.** These numbers come from a single-prompt LLM arm: **no detector ran**, and neither did the noise filter, delta scoping or the injection sentinel. Everything reported is `introduced_by_pr` by construction, because the model never saw a baseline to attribute anything to. Scored by the same `score_case` as every other arm, which is the only thing the arms share.

**Cost / tokens: MEASURED.** 52 model call(s) via the `claude` CLI (`sonnet`, effort `low`): **$0.7231** total, **$0.0139** per completed case.

Tokens, as the CLI reports them: **616,562** cached (`cache_creation + cache_read`) plus **12,573** uncached (`input + output`), **629,135** in all. Those two buckets are **not** our-content and their-overhead. Claude Code caches its own system prompt and, when our prompt clears the model's minimum cacheable length, our prompt with it — so which bucket our tokens land in varies by prompt size and model, and neither bucket alone names a party (§14.44).

**Derived, not measured here:** at a calibrated floor of 7,300 tokens per call for the CLI's own system prompt, ~**379,600** of the total is harness and ~**249,535** is ours. The subtraction is taken from the *total* rather than from the cached bucket, because doing the latter reported 0 tokens of our own content for a run that had plainly sent some. It rests on a calibration against one CLI build, not on this run. Neither figure is an API price.

**Floor provenance: UNRECORDED.** This run does not say which `claude` build produced it, so the 7,300-token floor cannot be checked against it. Runs stored before 2026-08-24 predate that field; treat the derived split as unverified rather than as agreeing.

---

## Corpus

**Selection criteria, verbatim from the pinned corpus:**

> The 80 most recently published GitHub-reviewed advisories for the pip ecosystem as of 2026-08-07, capped at 2 per source repository and 1 per fixing commit, restricted to those carrying a CWE and a fixing-commit reference into their own repository whose parent is not a merge, whose fix diff is under 400 KB, and which touch reviewable Python source outside tests and docs. Ground-truth spans are the lines the fix removed, excluding spans that are entirely imports, version bumps or comments. Two fixing commits were then excluded by hand as bulk refactors whose spans mark remediation plumbing rather than the defect; the reasons are in benchmark/corpus/labelled-excluded.txt. NOT filtered by CWE: classes no 3a detector can emit are retained and reported as a stratum. Newest-first sampling makes the set post-cutoff for any model evaluated later.

A corpus chosen to flatter the tool is the classic benchmark failure, and printing how it was picked is the only defense a reader has. Cases are pinned by repo, PR number and both shas, so every number below can be re-derived.

## Delta scoping — what the baseline pass removes

- **Raw findings the detectors produced:** 4
- **Attributed to the base tree and dropped:** 0.000 (0/4)
- **False positives per PR, as shipped:** 0.15 (4/26)
- **...if every raw finding were reported:** 0.15 (4/26)

> `findings/delta.py` runs the same detectors over the base commit and drops anything that was already there. This is the single largest effect any stage in this pipeline has on the reported numbers, and it is the capability a diff-only reviewer cannot have: **a tool that never sees the base tree cannot tell an introduced defect from one the PR merely walked past.**

### Three tiers, and only two of them are measured

| tier | what it is | this run |
|---|---|---|
| no scoping | every raw finding reported | 0.15 (4/26) · **derived** |
| hunk-based | no base checkout; a finding counts as introduced when it sits in an edited region | *measured 2026-08-22: 0.32/PR on the negative corpus — and it lost the one gate-relevant finding, §14.48* |
| baseline | the base tree scanned and subtracted | 0.15 (4/26) · measured |

> **The top row is arithmetic, not a run.** It is what this run's own counts imply if nothing were dropped. A genuinely unscoped run would also lose Semgrep's `--baseline-commit` scoping, so the real figure is that one or worse. The middle row *was* run, and it is the tool's real behaviour whenever checkouts are unavailable — `--no-checkout`, an offline `--diff-file`, the whole M0 thread.

> **The middle tier is not the bottom tier with less noise.** It over-reports inside edited hunks and under-reports outside them. On the negative corpus it gained five medium alarms and lost one HIGH — the only gate-relevant finding there, and a correct one. Its gate-relevant rate is therefore *better* than the full pipeline's while its gating is worse. **When a false-alarm rate improves, diff the finding sets before believing it**: an aggregate cannot tell you whether noise or evidence was removed. §14.48.

> **A raw-LLM arm's zero here is the prompt's doing, not the model's.** `llm-diff-baseline.md` asks for vulnerabilities the diff *"introduces or leaves present in the code shown"* — it was told to include pre-existing ones and then scored as wrong for each. **Asked the other way it does the job**: `llm-diff-introduced-only.md` changes that one instruction and took control-PR false alarms to **0 · 0 · 1 of 26 across three passes**, against the baseline prompt's 3 · 5 · 4 — at or below this pipeline's 1 of 26 — while leaving vulnerable-half output inside its own run-to-run range. So the suppression figures above are a real property of this pipeline and **not** a capability only it can have. §14.47, replicated and narrowed to this range in §14.51.

## False positives on known-clean PRs

- **False positives per PR:** 0.15 (4/26)
- **Gate-relevant (high/critical) per PR:** 0.00 (0/26)
- **PRs with no findings at all:** 0.85 (22/26)
- Pre-existing findings excluded from scoring: 0

> Every finding attributed to the PR on known-clean code is counted against the tool. **This is an upper bound on the false-positive rate**, not a point estimate: a merged PR from a healthy repository can still contain a real vulnerability that nobody has found, and any such finding is counted here as a false alarm. It also says nothing about recall — a detector that reports nothing scores perfectly on this set.

### The endpoint stratum

- PRs where the structural detector saw at least one endpoint: **0** of 26
- Endpoints seen across those PRs: **0**
- **False positives per endpoint-touching PR:** n/a (0 cases)
- **`BAC-MISSING-AUTHZ` alarms per endpoint seen:** n/a (0 cases)

> `M2_STATUS.md` §3.2's named worry is that `BAC-MISSING-AUTHZ` fires on every unguarded endpoint in a changed file, including deliberately public ones. Most merged PRs touch no endpoint at all, so that rule cannot fire in them and the corpus-wide average prices it at near-zero — arithmetically true, and an answer to a different question. This stratum is the one that addresses it. The split is derived from what the detector actually saw, not from how the corpus was picked, so neither number is biased by the other's needs.

### Which rules produce the noise

The aggregate above is not actionable on its own; this table is the output that is.

| Taxonomy id | False positives |
|---|---|
| TOOL-UNMAPPED | 4 (100%) |

### By detector

| Detector | False positives |
|---|---|
| llm-diff-baseline | 4 (100%) |

### By severity

| Severity | False positives |
|---|---|
| medium | 3 (75%) |
| low | 1 (25%) |

### Noisiest cases

| Case | False positives |
|---|---|
| GHSA-wvpp-8hx9-p66j:control | 1 |
| GHSA-22p9-r2f5-22mf:control | 1 |
| GHSA-8359-h9fx-j6v9:control | 1 |
| GHSA-29w2-fq35-v728:control | 1 |
| GHSA-fp3f-mc75-235c:control | 0 |

## Precision and recall on labelled cases

- **Precision:** 0.538 (21/39)
- **Recall:** 0.472 (17/36)
- **Recall ignoring the CWE label** (did anything point at the vulnerable lines?): 0.778 (28/36)
- **F1:** 0.503
- **Localization** (matched a label *and* the lines): 0.778 (21/27)
- Near misses (right file, wrong lines): 6
- **True positives owed to the CWE relation table:** 0.38 (8/21)

> **Recall is understated by design and must not be read flat.** The 3a detectors cover a deliberate subset of the taxonomy: Broken Access Control is the M3 agent flagship, and Privacy/PII and Insecure Design are agent families with no deterministic detector at all. A miss in those classes is a milestone boundary, not a detector defect. The per-family breakdown below is the honest reading.

> The relation-table share matters because `benchmark/scoring.py:_CWE_GROUPS` decides which CWE ids count as the same defect. Widening it raises precision and recall without changing the tool. If most true positives arrive through it rather than through an exact CWE match, the headline is a property of that table.

> **The two recalls above are the same question asked with and without the taxonomy**, and the gap between them is this measurement's own vocabulary error rather than anything the tool did. `_CWE_GROUPS` is a hand-list of ~9 families against a taxonomy of some 940 ids, so an advisory that labels a defect one level up or down from where a tool would is a silent false positive. An arm that emits fixed internal ids shows no gap at all — the pipeline's two numbers are equal by construction — while an arm that names CWEs freely can show a large one. Read the gap as a property of the arm's vocabulary, never as recall it deserves credit for: locating a defect and classifying it are different achievements, and only the second is `recall`. `OPEN_ITEMS.md` §27.

### True positives by family

| Family | True positives |
|---|---|
| Unmapped | 15 (71%) |
| Broken Access Control | 6 (29%) |

### Misses by ground-truth CWE

| CWE | Missed |
|---|---|
| CWE-1333 | 3 (16%) |
| CWE-200 | 3 (16%) |
| CWE-20 | 2 (11%) |
| CWE-668 | 2 (11%) |
| CWE-834 | 1 (5%) |
| CWE-74 | 1 (5%) |
| CWE-22 | 1 (5%) |
| CWE-863 | 1 (5%) |
| CWE-94 | 1 (5%) |
| CWE-287 | 1 (5%) |
| CWE-88 | 1 (5%) |
| CWE-400 | 1 (5%) |
| CWE-455 | 1 (5%) |

### Blind, or mis-aimed?

- **Ground truth some finding named, scored or not:** 0.587 (27/46)
- ...found, but attributed to the base tree **on the vulnerable lines**: 0
- ...found, but attributed to the base tree **elsewhere in the file**: 0

> A missed row fails in two ways that `recall` prices identically at zero: no detector ever produced a finding for it, or a detector produced the right finding and `findings/delta.py` attributed it to the baseline, so scoring never saw it. Different causes, different fixes. The first row above is the union, and it is **not a quality claim** — naming a file is not naming a defect. It is here because when recall is low the useful question is whether the detectors are blind or merely mis-aimed.

> The split matters for what to do next. A row found **on the vulnerable lines** would have been a true positive but for delta scoping, and argues about attribution. A row found **elsewhere in the file** would only ever have been a near miss, and argues about localization — a taint detector reports at the sink, while a fixing commit's ground truth sits where the missing validation went, and those are different lines by construction.

### The in-scope stratum

- **Recall over ground truth a 3a detector could name:** 0.556 (5/9)
- Misses in classes **no detector models at all**: 15

> This is the honest reading of the flat recall above. Roughly half a recent advisory sample is CWE-400, CWE-1333, CWE-834, CWE-455, CWE-200, CWE-59 and CWE-61 — resource consumption, ReDoS, symlinks — which no deterministic detector in this milestone emits. Counting those against the tool measures the roadmap.

> **The stratum is derived, never selected for.** The corpus was not filtered to CWEs the tool covers; that would be the corpus-flattering failure `Corpus.selection_criteria` exists to expose, and errata §14.20 already ruled on the same question from the other side. The set comes from `benchmark/scope.py`, which reads the detectors' own dispatch tables rather than a hand-maintained list — a list would let a one-line edit raise recall without changing the tool.

#### Missed CWEs with no detector

| CWE | Missed |
|---|---|
| CWE-1333 | 3 (20%) |
| CWE-200 | 3 (20%) |
| CWE-20 | 2 (13%) |
| CWE-668 | 2 (13%) |
| CWE-834 | 1 (7%) |
| CWE-74 | 1 (7%) |
| CWE-88 | 1 (7%) |
| CWE-400 | 1 (7%) |
| CWE-455 | 1 (7%) |

## Paired controls — did it find the vulnerability, or the file?

- **Pairs where the vulnerable side was flagged and the fixed side was silent:** 0.42 (11/26)
- Flagged the vulnerable side, but also flagged the fix: 3
- Missed the vulnerable side entirely: 12

> **This is the number that makes a reverted fix worth scoring, and it belongs next to recall rather than under it.** A labelled case here is a fixing commit run backwards, so the vulnerable lines are essentially the whole diff — the easiest possible presentation of the defect. Recall alone cannot separate *found the vulnerability* from *always fires on this file*, and the second scores identically while being worthless. The control is the same file with only the vulnerability removed, so the pair separates them and neither half does.

### Per advisory

| Advisory | Outcome |
|---|---|
| `GHSA-22p9-r2f5-22mf` | detected, but control also flagged |
| `GHSA-29w2-fq35-v728` | missed |
| `GHSA-2f54-p244-32q6` | detected, control clean |
| `GHSA-3cg5-48j3-v4gv` | detected, control clean |
| `GHSA-3fcr-jvgp-7f58` | missed |
| `GHSA-47pj-3jcm-6whg` | missed |
| `GHSA-6hr6-w5qg-qmwg` | detected, control clean |
| `GHSA-7h3g-4w2f-fj2f` | missed |
| `GHSA-8359-h9fx-j6v9` | detected, but control also flagged |
| `GHSA-9xq3-3fqg-4vg7` | detected, control clean |
| `GHSA-c5px-58j2-7fqp` | detected, control clean |
| `GHSA-cj54-hpcc-gj6h` | detected, control clean |
| `GHSA-f42x-p2mx-hm8r` | detected, control clean |
| `GHSA-fp3f-mc75-235c` | detected, control clean |
| `GHSA-fwg2-594c-jp42` | missed |
| `GHSA-gm37-52c6-37mw` | detected, control clean |
| `GHSA-hmj8-5xmh-5573` | missed |
| `GHSA-j6g5-3hh3-pgw8` | missed |
| `GHSA-jm78-9fvv-mhgr` | missed |
| `GHSA-m8wh-29wm-52mv` | missed |
| `GHSA-mfx4-hv73-q22v` | detected, control clean |
| `GHSA-mq44-7p77-q5h7` | missed |
| `GHSA-phj3-59pf-cp83` | detected, control clean |
| `GHSA-v833-3823-cmhp` | missed |
| `GHSA-wjv6-jcfj-mf9r` | missed |
| `GHSA-wvpp-8hx9-p66j` | detected, but control also flagged |

## Phase-2 noise filter — recall ablation

- **Recall after filter:** 1.000 (36/36) ground-truth files survived
- Dropped ground-truth files: 0
- ...of which the guardrail never considered: 0

> **At M2 this stage does not gate what the detectors see.** `pipeline.py` builds the detect stage from the manifest and every parsed file, not from the filter's kept set, so a dropped file is still scanned and a finding in it still reaches the report. The filter's drops decide what Phase-3b agents are routed to, which arrives at M3. This measurement is therefore a **baseline taken before the stage becomes load-bearing** — it is not evidence that a live leak was found or closed.

> A drop the guardrail never considered is the more serious of the two: `DropRecord.guardrail_considered` separates "the CPG said this file is inert" from "we never asked".

---

<sub>Generated by `pr_review.benchmark`. Deterministic render of a corpus run — no model involved in producing these numbers or this document.</sub>
