# Pre-registration — the four-arm comparison, 2026-08-21

> **Outcomes are recorded in `BENCHMARK_STATUS.md` §4i, not here.** This file is deliberately left
> as written: a pre-registration that gets edited after the results are in is not one. P1 ✅ · P2 ✅ ·
> P3 ❌ · P4 ✅ · P5 ⚠️ split — see §4i for what each means.
>
> P5 below cites the recall ceiling as "21 of 33 rows". That figure was corrected to
> **27 of 36, a ceiling of 0.250**, on 2026-08-22 (errata §14.45). The prediction is left
> as written, which is the point of a pre-registration.

Written **before** any full arm ran. Established practice here (§14.29 and the pass-2 work), and
it has already earned its keep three times today: the triage arm was predicted to move every scored
number and moved none (§14.40); the fork-PR break was predicted and does not occur (§14.41); the
arm-3 cost was estimated at $0.015/case and measured $0.179 before `--effort` was found.

## The arms

| arm | what runs | corpus |
|---|---|---|
| 1 | semgrep only, everything else disabled | labelled |
| 2 | pipeline, deterministic (already measured) | labelled |
| 2b | pipeline + live tier-3 triage | negative (cost only — §14.40) |
| 3 | raw LLM, diff only, sonnet, `--effort low`, **3 passes** | labelled |

## Predictions

**P1 — Arm 1 (semgrep-alone) scores at or near zero on recall.** The pipeline's single true positive
is `taint-path` on `tar.extractall`, which comes from the *structural* detector. Arm 1 turns
structural off. If arm 1 finds it anyway, my model of where the pipeline's recall comes from is
wrong.

**P2 — Arm 3 out-recalls the pipeline.** The pipeline scores 1/36. A model reading the whole diff
with a security brief should exceed that. Stated plainly because it is the prediction most likely to
embarrass the tool, and refusing to write it down would be the tell.

**P3 — Arm 3's false-positive count is much higher than the pipeline's**, and mostly on the control
half. The model cannot distinguish introduced from pre-existing — it never sees a baseline — so a
post-fix control looks identical to its vulnerable twin apart from the fix. Pair discrimination is
where I expect it to do worst.

**P4 — Arm 3 varies run to run**, and by more than one finding across the three passes. The
pipeline produced byte-identical scorecards twice. If arm 3 also comes out identical three times,
that is a genuine and surprising result about determinism at `--effort low`.

**P5 — Most of arm 3's true positives, if any, land on ground truth the pipeline cannot express.**
21 of 33 rows are outside the taxonomy (§14.42), and the model answers in CWE directly. The
reachable-stratum recall is therefore the number to compare, and I expect the two arms to look much
closer there than the headline suggests.

## What would falsify the exercise itself

If arm 3 returns zero findings on nearly every case, the prompt or the parse is broken, not the
model. The smoke run on 2 cases returned 1 finding and 0 on the control, which is the right shape
but too small to settle it.

## Cost, predicted

$0.081/case measured at `--effort low` cold; 52 cases x 3 passes = 156 calls. Expect **$6-13**
total, wall clock **~15 min**, depending on how much the 1h prompt cache holds across the run.
