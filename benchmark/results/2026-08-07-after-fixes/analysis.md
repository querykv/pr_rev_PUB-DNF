# Hand analysis — negative set after fixing defects 1, 3 and 5

Second run of the **same pinned corpus** (`benchmark/corpus/negative.json`), same day, against
patched code. The baseline it is compared against is `../2026-08-07/`, which is left untouched.

**Code under measurement:** the three safe fixes from `../2026-08-07/analysis.md` §§1, 3, 5.
The scorecard in this directory carries no `Code under measurement:` line because it was generated
by the run that *motivated* adding that line — see §"What this run changed about the harness".

**Corpus:** 50 merged PRs, 5 each from 10 Python repositories. 50/50 completed, 1128 s, no case
errors. Nothing about the corpus was changed: same repos, same PR numbers, same pinned shas.

## The result

| Metric | Before | After | Change |
|---|---|---|---|
| False positives per PR | 1.96 (98/50) | **0.24 (12/50)** | **−88%** |
| Gate-relevant (high/critical) per PR | 0.00 (0/50) | **0.00 (0/50)** | — |
| PRs where the tool said nothing | 86% (43/50) | **94% (47/50)** | +4 PRs |
| Pre-existing findings excluded | 158 | 158 | — |
| `sca` adapter status | `error: 2 · not_applicable: 48` | **`not_applicable: 50`** | no more false errors |

The taxonomy table is the clearer statement of what happened:

| Taxonomy id | Before | After |
|---|---|---|
| `INTEG-HIDDEN-TEXT` | 85 (87%) | **0** |
| `BAC-MISSING-AUTHZ` | 12 (12%) | 12 (100%) |
| `INJ-CODE-EXEC` | 1 (1%) | **0** |

Both fixed classes went to **exactly zero**, and the class that was deliberately left alone is
**exactly unchanged at 12**. That is the outcome to want from a targeted fix: the fixed things
moved, nothing else did. Had `BAC-MISSING-AUTHZ` also moved, the sentinel or catalog change would
have had a side effect nobody asked for.

Two numbers are unchanged and should be: pre-existing findings excluded (158 — delta scoping was
never in question) and gate-relevant FP (0.00 — it was already zero, and per `M2_STATUS.md` §3.3
partly by construction until the verifier lands at M4).

## What each fix did

**Defect 1 — the sentinel's `@<ZWSP>` false positives: 85 → 0.** Confirmed twice, once end-to-end
here and once directly: `sentinel.scan_text` over all 50 PR titles and bodies now returns no hits
at all, where it previously returned 106 invisible-character matches. The exemption is narrow
enough that a real payload on the same line still reports — `tests/test_safety.py` asserts that a
line carrying both a legitimate `@<ZWSP>mention` and a bidi override is still flagged, and that the
rendering points only at the override.

**Defect 3 — `re.compile`: 1 → 0.** The single `INJ-CODE-EXEC` finding is gone. Nothing else in
`code_exec` changed, and the test asserts `eval` and `exec` still match so the fix cannot be
mistaken for deleting the sink class.

**Defect 5 — SCA: 2 errors → 0.** `sca` now reports `not_applicable: 50` rather than
`error: 2 · not_applicable: 48`. **This did not add coverage and must not be read as if it did.**
It converts a misleading `error` into an accurate "this PR changed nothing osv-scanner can read".
SCA still contributes nothing anywhere in this corpus; it is now honest about why.

## The 12 that remain, and why they were left

All 12 are `BAC-MISSING-AUTHZ`, all MEDIUM, all `cpg-structural`:

| Case | Count | Cause |
|---|---|---|
| `wagtail#14453` | 9 | defect 4 — imperative authorization the guard model cannot see |
| `wagtail#14452` | 2 | defect 4, same file |
| `saleor#19567` | 1 | defect 2 — `@patch(...)` read as a PATCH route |

**A correction to the baseline analysis.** `../2026-08-07/analysis.md` §4 says all 11 Wagtail hits
came from `wagtail#14453`. They are all on **one file** — `wagtail/api/v3/routers/pages.py` — but
that file is touched by **two** PRs in the corpus, 9 findings in one and 2 in the other. The file
claim was right, the single-PR attribution was not. It does not change any conclusion: the same
handlers in the same file are being reported twice because two PRs touched them.

Defect 4 stays deferred to M3 (a design question about imperative authorization, not a patch) and
defect 2 is addressed separately — see below, because measuring it turned up something much larger
than this scorecard can show.

## What this run cannot say — unchanged from the baseline

Every limit in `../2026-08-07/analysis.md` still holds, and two get **worse** with a better number:

- **Still an upper bound.** A merged PR can carry an undiscovered vulnerability, counted here as a
  false alarm.
- **Still says nothing about recall.** A detector that reports nothing scores perfectly on this
  set — and the tool now says nothing on 94% of PRs rather than 86%. **A falling
  false-positive rate on a negative set is not evidence of quality on its own**; it is exactly what
  breaking a detector would also produce. The guard here is that both fixes were argued from
  mechanism (a documented platform convention; a compiler is not an executor) and both are pinned
  by tests that assert the *surviving* behaviour, not just the removed behaviour. Pass 2 is still
  the real check and is still not built.
- **Same 50 PRs, so this is in-sample.** The fixes were derived from this corpus and measured on
  it. The 88% figure is not an out-of-sample claim, and the out-of-sample check is a fresh corpus
  or pass 2.
- **SCA and IaC remain unmeasured, not clean** — now `not_applicable: 50` for both.
- **Cost is UNMEASURED**, not low. No model was called.
- **n = 50**, and the concentration argument now cuts the other way: 11 of the 12 remaining FPs are
  one file in one repository, so a corpus without Wagtail would report ~0.02 FP/PR and mean nothing.

## What this run changed about the harness

Re-running exposed a defect in the harness rather than the detectors, and it is the kind that
destroys evidence rather than producing bad evidence:

**`write_scorecard` keyed results only on the date.** Measure → fix → measure happens *within one
day*, so the second run silently overwrote the baseline it existed to be compared against. It was
recoverable here only because the baseline was already committed. Fixed: it now refuses to
overwrite, takes `--label` for a sibling directory, and stamps the commit under measurement into
the document — because on a pinned corpus the code is the only thing that varies between two runs.

## The finding that outgrew this scorecard

Investigating defect 2 for the next agenda item, the cached Phase-1 profiles say the endpoint
denominator is not slightly inflated but **majority noise**: 8,297 of 17,907 access-control matrix
rows (**46%**) across the corpus are `@patch(...)` mock targets rather than routes, 8,292 of them
in test files, and **99.8% of Saleor's 8,038 rows**. Written up in `BENCHMARK_STATUS.md` §4
defect 2 — it changes that defect from "1 false positive plus some denominator inflation" into a
correctness problem in the artifact M3's BAC agent is meant to read.

## How to reproduce

```bash
.venv/bin/python -m pr_review.benchmark run \
    --corpus benchmark/corpus/negative.json --label after-fixes
```
