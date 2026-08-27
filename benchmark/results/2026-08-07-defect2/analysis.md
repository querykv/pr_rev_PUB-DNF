# Hand analysis — negative set after fixing defect 2

Third run of the **same pinned corpus**, after `promote._is_route_decorator()` stopped reading
`@patch("a.b.c")` as a PATCH route. Compared against `../2026-08-07-after-fixes/` (defects 1, 3, 5)
and `../2026-08-07/` (baseline). Both are left untouched.

**Code under measurement:** `a6e0226` — stamped in the scorecard, the first run to carry it.
50/50 completed, 1105 s, no case errors. Every Phase-1 profile was rebuilt from scratch
(`ANALYZER_VERSION` 3), which is why it cost the same as the earlier runs despite doing more.

## The result

| Metric | Baseline | Fixes 1/3/5 | **+ defect 2** |
|---|---|---|---|
| False positives per PR | 1.96 (98/50) | 0.24 (12/50) | **0.22 (11/50)** |
| Gate-relevant per PR | 0.00 | 0.00 | **0.00** |
| PRs with no findings | 86% | 94% | **96% (48/50)** |
| Pre-existing findings excluded | 158 | 158 | **91** |
| PRs where a detector saw an endpoint | 10 | 10 | **5** |
| Endpoints seen | 142 | 142 | **74** |
| `missing-authz` per endpoint | 0.085 | 0.085 | **0.149** |

**The prediction held exactly.** `BENCHMARK_STATUS.md` §3 was written before this run and said:
12 → 11 false positives, Saleor's `@patch` case disappears, and the 11 Wagtail hits are defect 4
and must not move. All three are true. The Wagtail findings are byte-for-byte where they were —
9 on `wagtail#14453` and 2 on `wagtail#14452`, all on `wagtail/api/v3/routers/pages.py`.

The stated falsification criterion was `BAC-MISSING-AUTHZ` coming back **below** 11, which would
have meant the rule took genuine endpoints with it. It did not.

## The false-positive count is the least interesting number here

One false positive removed. That was always the direct cost of defect 2, and it is why the defect
was first rated "safe to defer". The numbers that moved are the other three.

### The endpoint denominator halved: 142 → 74

Five of the ten PRs that appeared to touch endpoints **touched none at all** — they qualified
purely on phantom `@patch` decorators in their test files. This is the real defect, and it was
invisible in the false-positive column.

### `missing-authz` per endpoint rose: 0.085 → 0.149

It got **worse by 75%**, and that is the correct direction. Errata §14.20's corollary predicted
exactly this: phantom endpoints inflate `endpoints_seen`, so the rule's own false-positive rate
was *understated* by the defect. `BENCHMARK_STATUS.md` blind spot 4 guessed "roughly a factor of
two"; the measured factor is 1.75.

This is the one number in the whole exercise that a fix made **worse**, and it is the one most
worth trusting — the denominator is now real.

### 67 fewer pre-existing findings: 158 → 91

Unexpected, and it checks out. Pre-existing findings come from the baseline pass over the *base*
checkout, and phantom endpoints existed on both sides of every diff — so the detector was
generating ~67 spurious `BAC-MISSING-AUTHZ` findings per corpus on the base side too, and
`findings/delta.py` was dutifully excluding them.

They never reached a report, so nothing in any earlier scorecard showed them. They were pure
waste: generated, fingerprinted, matched and discarded on every baseline scan.

Worth stating plainly because the direction is counter-intuitive: **a smaller "pre-existing
excluded" count is an improvement here**, not a regression in delta scoping. If the baseline had
genuinely weakened, the *introduced* count would have risen. It fell.

## What this run does not say

Everything in `../2026-08-07/analysis.md` still holds — upper bound, no recall measured,
in-sample, SCA and IaC unexercised, cost UNMEASURED, n = 50. Plus, specific to this fix:

- **The recall cost of `_is_route_decorator` is still argued, not measured.** It is verified by 13
  parametrized tests and by replaying the rule over all 17,907 cached matrix rows (rejects 2,123 of
  2,123 mock targets, 0 of 8,685 URL paths, 0 of 925 unresolved markers). None of that is a
  labelled corpus. **Pass 2 is what would catch a route shape that neither the tests nor this
  corpus contains.**
- **The corpus is Python and heavily Django/GraphQL.** Flask and FastAPI route shapes are
  represented by the framework repositories themselves rather than by applications using them.
- **11 of 11 remaining false positives are one file in one repository.** The headline is now
  entirely hostage to Wagtail, and the honest reading of 0.22 FP/PR is "one unresolved design
  question (defect 4) plus nothing else this corpus can see".

## How to reproduce

```bash
.venv/bin/python -m pr_review.benchmark run \
    --corpus benchmark/corpus/negative.json --label defect2
```
