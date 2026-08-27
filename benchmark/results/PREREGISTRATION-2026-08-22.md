# Pre-registration — the delta-scoping tier and the introduced-only prompt, 2026-08-22

Written **before** either arm ran. Established practice here (§14.29), and on 2026-08-21 it caught
three wrong predictions in one day — including one where the arm I predicted would move every number
moved none.

Both arms exist because of §14.46: the pipeline's baseline pass removes 86–97% of the detectors'
raw output, no scorecard reported it, and the LLM baseline was never asked to do the same job.

## The arms

| arm | what changes | corpus |
|---|---|---|
| **2c** | `baseline.enabled: false` — no base-tree scan, so `findings/delta.py` falls back to hunk overlap | negative |
| **3b** | the arm-3 prompt, with "or leaves present in the code shown" replaced by an introduced-only instruction | labelled |

Nothing else moves in either. Arm 2c is config-only, like arm 1. Arm 3b changes one paragraph of a
committed prompt file and nothing in the producer.

## Predictions

**P1 — Arm 2c lands nearer the baseline tier (0.24 FP/PR) than the unscoped one (1.74).** Most
pre-existing findings should sit outside the lines a PR touched, so hunk overlap ought to catch a
large share of what the base-tree scan catches. I will guess **0.4–0.8 FP/PR**. If it lands near
1.74 instead, then hunk scoping is nearly useless and almost all the 7.25× is owed to the base-tree
scan specifically — which would make §14.46's claim *stronger*, not weaker, and would also mean the
`--no-checkout` degraded path is far worse than "Phase 1 skipped" suggests.

**P2 — Arm 2c's gate-relevant rate rises above the current 0.02.** The one gate-relevant finding on
this corpus is a correct HIGH on a real under-upgrade. Hunk scoping over-estimates the introduced
set by construction, so more HIGHs should survive.

**P3 — Arm 3b's control-side false alarms fall, but not to the pipeline's 0.04.** A model can
reasonably tell that a line it was shown as context is not a line the diff added, so asking for
introduced-only should help. But it has no base tree and no second scan, so I expect it to keep
firing on vulnerable-looking context. Guess: **0.06–0.12 per control PR, from 0.12/0.19/0.15.**

**P4 — Arm 3b's recall drops, and by more than its false alarms do.** The instruction removes
findings, and the corpus's ground truth is a *reverted fix* — so the vulnerability genuinely is
introduced by the diff and should survive an introduced-only filter. If recall falls a long way,
the model is not distinguishing introduced from pre-existing; it is just reporting less.

**P5 — Pair discrimination rises.** This is the metric the change should most help: the control half
is the fixed file, where an introduced-only instruction has the most to bite on. If P3 holds and P5
does not, the model is suppressing findings without using the distinction.

## What would falsify the exercise itself

If arm 3b returns near-zero findings on almost every case, the new prompt is too restrictive or the
parse broke, and the arm measures the prompt rather than the model. The smoke run on 2 cases is the
check; a full pass with fewer than ~10 findings corpus-wide should be treated as a broken arm, not
as a result.

## Cost, predicted

Arm 2c: no model, ~20 min wall clock. Arm 3b: 52 calls at `--effort low`, **$0.75–2.60** depending
on whether the prompt cache is cold, ~5 min.
