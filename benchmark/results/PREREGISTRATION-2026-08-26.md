# Pre-registration — the context-fed arm (3c), 2026-08-26

Written **before** the arm ran against a model. Established practice here (§14.29); on 2026-08-21 it
caught three wrong predictions in one day, including one that was exactly backwards.

Everything below is checkable against `benchmark/results/2026-08-21-arm3-llm-p{1,2,3}/run.json`,
which is the baseline this arm is defined against.

## The arm

| | |
|---|---|
| what changes | the model receives the diff **and** the pipeline's context bundles, replayed from the pinned capture `benchmark/context/labelled.json` |
| what does not | same model (`sonnet`), same effort (`low`), same corpus, same `score_case`, same `to_findings` parser, no tools, no repository |
| arm 3's input | a **strict subset** of this one's — asserted by `test_the_message_opens_with_the_bytes_arm_3_would_have_sent`, not merely intended |

## The baseline, from the stored runs — not from memory

| | p1 | p2 | p3 | pipeline (arm 2) |
|---|---|---|---|---|
| recall, all rows | 13/36 | 13/36 | 12/36 | 1/36 |
| recall, taxonomy-reachable | 5/9 | 6/9 | 5/9 | 1/9 |
| precision | 18/51 | 16/46 | 14/45 | 1/2 |
| F1 | 0.357 | 0.354 | 0.322 | 0.053 |
| raw findings | 54 | 46 | 49 | 72 |
| reached the right file | 21/44 | 16/39 | 18/42 | 2/36 |
| control-half false alarms | 3/26 | 5/26 | 4/26 | 1/26 |

**Arm 3's run-to-run spread is the yardstick.** Recall moves 12–13, precision 0.31–0.35, findings
46–54. A result inside those bands is not a result.

## What is already known and must not be predicted

- **`slice-only = 0`.** Every one of the 112 ground-truth spans is inside a hunk, so arm 3 already
  sees all of them (§4p). *"Higher recall because it sees more"* is **known false before it is
  written.** This arm can only win on judgment about lines the model could already read.
- **The arm is dearer by construction** — 3.41× arm 3's payload (below). "Cheaper" is not an
  available outcome for this configuration and was never claimed to be (§4p.1, §4p.2).
- **Only 26 of 36 ground-truth rows have source in the context** (§4r.1). The upside is bounded at
  26/36 before a single call.

## Predictions

**P1 — Recall stays inside arm 3's spread: 11–15 of 36.** The context adds no visibility, and the
rows it could help on are capped at 26/36. I expect a small gain at most, and I am explicitly
predicting **no headline recall win**. If recall exceeds 17, something other than context is moving
— check the parser and the prompt before believing it.

**P2 — Precision rises, and this is where the arm should pay.** Arm 3 fires 45–51 findings to land
14–18; its failure mode is asserting a vulnerability it cannot see the guard for. The bundles carry
`sanitizer_nodes`, the enclosing symbol and the callers. Guess: **precision 0.40–0.55**, from
0.31–0.35. This is the prediction I most expect to be right, and the one the arm is worth building
for.

**P3 — Control-half false alarms fall to 0–2 of 26**, from 3/5/4. The control is the *fixed* file, so
the sanitizer the fix added is in the profile slice. If they do not fall, the model is not reading
the context — which would make P2 unlikely too, and the two should move together.

**P4 — "Reached the right file" rises above 30/44.** Arm 3 names the wrong file roughly half the
time. Bundles state the path explicitly for 141 of 175 groups. This is the cheapest possible win and
the one I would be most surprised to lose.

**P5 — THE SHARPEST TEST, and it is inside the arm rather than between arms.** §4r.1 splits the 36
ground-truth rows into **26 with source in the context** and **10 without**. On the 10, this arm
receives nothing arm 3 did not, beyond framing. So:

> **If the arm improves on the 26 and not on the 10, the improvement is attributable to context.
> If it improves equally on both, the improvement is prompt framing, not context — and the headline
> would be about a prompt, not a pipeline.**

I predict the improvement concentrates on the 26. This is the result to report either way; it does
not depend on P1–P4 landing.

**P6 — The failure mode, stated so it cannot be explained away afterwards.** 3.41× the payload is
3.41× the material to be distracted by. If recall falls **below 10** or findings fall below 30, the
context is diluting rather than informing, and that is a real and publishable negative result about
Phase 3b — not a bug to be tuned away. It would also make `OPEN_ITEMS.md` §25 (which six neighbours)
the obvious next experiment rather than a deferred one.

## Cost, recomputed here rather than carried forward

The plan's `$10–20` for Step 6 was written before §4p.1's ratio existed. Recomputed from the measured
payload and arm 3's own stored accounting:

| | arm 3 | arm 3c |
|---|---|---|
| system+user characters, 52 cases | 549,114 | **1,871,705** (3.41×) |
| CLI floor, 52 × 7,300 tokens | 379,600 | 379,600 (identical) |
| content tokens above the floor | 249,665 | ~851,000 |
| projected total tokens | 629,265 | **~1,230,600** (1.96×) |

**Cache warmth dominates, not payload.** Arm 3's three passes cost $2.56 / $0.77 / $0.72 on
*identical* token counts — a 3.5× spread from nothing but a cold cache. So:

| | per pass | three passes |
|---|---|---|
| all warm | ~$1.40–1.50 | **~$4.30** |
| one cold, two warm | — | **~$7.90** |
| all cold (worst case) | ~$5.00 | ~$15.00 |

**Predicted Step 6 total: $4–8, not $10–20.** If the smoke's per-case cost implies more than $20 for
three passes, stop and re-derive before spending it.

## What would falsify the exercise itself

If the arm returns near-zero findings on most cases, the prompt is too restrictive or the parse
broke, and the arm measures the prompt rather than the model. **The smoke on 2 cases is that check.**
A full pass with fewer than ~15 findings corpus-wide should be treated as a broken arm, not a result.

---

## ADDENDUM, 2026-08-26 — the scorer changed after these predictions were written

**Nothing above is edited.** The predictions stand exactly as committed at `439373b`, which is what
makes them predictions. This records what moved underneath them and what each prediction now means.

**What changed.** `_CWE_GROUPS` gained `{CWE-59, CWE-61}` and a second metric, `recall_ignoring_cwe`,
was added — both after the smoke run, and both because of it (`BENCHMARK_STATUS.md` §4u,
`OPEN_ITEMS.md` §27). The scorer had been counting a child CWE as a false positive on the corpus's
most common class. Every stored scorecard was re-scored; **no pipeline number moved**, because the
pipeline emits fixed internal ids that were never affected.

**The baseline table in "The baseline, from the stored runs" is therefore superseded.** It is left in
place. The corrected version, re-derived from the same stored runs:

| | p1 | p2 | p3 | pipeline |
|---|---|---|---|---|
| recall, all rows — **was** | 13/36 | 13/36 | 12/36 | 1/36 |
| recall, all rows — **now** | **18/36** | **18/36** | **17/36** | 1/36 *(unchanged)* |
| **recall ignoring the CWE label** | 29/36 | 27/36 | 28/36 | 1/36 |
| precision | 26/49 | 23/44 | 21/43 | 1/2 |
| F1 | 0.515 | 0.511 | 0.480 | 0.053 |

**Arm 3's yardstick is now recall 17–18, precision 0.48–0.53, and a located-but-unlabelled gap of
9–11 rows.** A result inside those bands is still not a result.

### What each prediction now means

- **P1 (recall 11–15)** was written against a 12–13 baseline and is **void as a numeric band**. Its
  *content* survives and is what matters: **no headline recall win**, because `slice-only = 0`. Judge
  it as "inside arm 3's spread", now 17–18.
- **P2 (precision 0.40–0.55)** was written against 0.31–0.35. The baseline is now **0.48–0.53**, so
  the predicted band and the baseline now *overlap* — the prediction has become nearly unfalsifiable
  and should be read as failed-to-be-a-prediction rather than as met. **Restated for the record:
  precision must exceed 0.55 to count as a win.**
- **P3, P4, P5, P6** are unaffected. P5 in particular — the 26-with-source versus 10-without split —
  never depended on the CWE table.
- **The new metric gives P5 a second, sharper reading**: if context helps the model *locate* defects,
  `recall_ignoring_cwe` moves; if it helps it *classify* them, the gap between the two recalls
  narrows. Those are different claims about what context buys, and until now there was no way to tell
  them apart.

### The negative corpus, pre-registered here rather than separately

Step 6 now covers both corpora (owner's decision, 2026-08-26). The labelled corpus can only answer
whether context improves findings; on 50 ordinary PRs the bundles measure **0.52×** the raw diff
(§4p.2), so the **cost** half of the project's original question is answerable only there.

**P7 — On ordinary PRs the context arm is CHEAPER than arm 3, not dearer.** This is the one place the
"reduce cost" hypothesis is live. §4p.2 measured the bundles at 0.52× the diff on this corpus; the
arm sends diff **and** bundles, so it should land near **1.5×** — dearer than arm 3 but far below the
labelled corpus's 3.4×. **If the rendered payload exceeds 2.0× here, the renderer is the cost, not
the context**, and that is a bug to find rather than a result to report.

**P8 — False alarms fall, and by more than on the labelled corpus.** The negative corpus is 50 merged
PRs from healthy repositories; every finding is counted against the tool. This is where the profile
slice's sanitizers and access-control rows should most help a model decide *not* to fire. Arm 3 has
never been run on it, so there is no arm-3 baseline — **that is a gap this step should close, and it
means the negative half needs arm 3 run too, or it compares against nothing.**

**P9 — The gate-relevant rate stays at or above the pipeline's 0.02.** That figure is a correct HIGH
on a real under-upgrade and must not be tuned to zero (`OPEN_ITEMS.md` §4). If the context arm
reports it, the arms agree on the one thing the negative corpus has to say.

---

## OUTCOME, 2026-08-26 — scored after the fact, predictions above unedited

Full analysis in `BENCHMARK_STATUS.md` §4x. Nine passes, three per arm per corpus.

| | prediction | outcome |
|---|---|---|
| P1 | no headline recall win | **HELD** — mean 16.7 against arm 3's 17.7 |
| P2 | precision > 0.55 *(restated in the addendum)* | **FAILED** — 0.50 against 0.51 |
| P3 | control-half false alarms fall to 0–2 of 26 | **HELD** — mean 4.0 → 2.3 |
| P4 | right-file rises above 30/44 | **FAILED** — flat |
| P5 | improvement concentrates on the 26 covered rows | **NULL** — +0.3 covered, −1.4 uncovered, both inside noise |
| P6 | dilution failure mode | **did not trigger** |
| P7 | negative payload near 1.5× | **HELD** — 1.39× |
| P8 | false alarms fall on ordinary PRs | **FAILED, opposite direction** — 3.3 → 5.0 |
| P9 | gate-relevant at or above 0.02 | **HELD for arm 3c**, failed for arm 3 |

**The headline is a null: the pipeline's context did not make the model a better reviewer.** It made
it a measurably different one — arm 3c emits `BAC-MISSING-AUTHZ` findings that arm 3 never produces,
which is the profile slice reaching the output — but on the labelled corpus that did not convert into
true positives, and on the negative corpus it converted into false alarms.

**Writing P2 down twice is what makes it a failure rather than a success.** Its original band
(0.40–0.55) was set against a 0.31–0.35 baseline; the scorer fix moved the baseline to 0.48–0.53 and
the band would then have been met by standing still. The addendum restated it as **>0.55 to count**,
*before* any result existed. Measured 0.50. Had the band not been restated, this table would be
claiming a win.
