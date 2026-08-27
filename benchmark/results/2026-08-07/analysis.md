# Hand analysis — negative set, 2026-08-07

Companion to `negative.md`, which is machine-generated and is overwritten by the
next run. This file is the human read: what the numbers mean, which findings were
inspected by hand, and what is actually broken.

**Corpus:** 50 merged PRs, 5 each from 10 Python repositories, pinned in
`benchmark/corpus/negative.json`. 50/50 completed, 1244s, no case errors.

## The headline

| Number | Value |
|---|---|
| False positives per PR | **1.96** (98/50) |
| **Gate-relevant** (high/critical) FP per PR | **0.00** (0/50) |
| PRs where the tool said nothing at all | **86%** (43/50) |
| Pre-existing findings correctly excluded by the baseline | 158 |

The second row is the one that matters most for adoption: **nothing this corpus
produced could have failed anyone's build.** Every false positive was MEDIUM, and
`policy.gate()` fires on `validated` findings at HIGH or above. That is partly by
construction — M2 emits `candidate`, as `M2_STATUS.md` §3.3 says — so it should be
re-measured once the verifier lands at M4 and findings start reaching `validated`.

The third row is the more honest summary of the experience of using it: on 43 of
50 real PRs the tool was silent. The noise is not spread thin across the corpus,
it is concentrated: **3 PRs produce 85 of the 98 false positives.**

The 158 excluded pre-existing findings are the delta-scoping machinery from M2
doing exactly its job. Without `findings/delta.py` the false-positive rate would
have been 5.1/PR instead of 1.96.

## Five defects, hand-verified

### 1. The sentinel fires on GitHub's own escaping convention — 85 FPs (87%)

Every `INTEG-HIDDEN-TEXT` finding in the corpus is on `pr:body`, and every one has
the same cause. GitHub's auto-generated release notes write contributor handles as
`<code>@<ZWSP>username</code>`, inserting a **zero-width space** after the `@` so
the rendered changelog does not notify hundreds of people. `sentinel.py`'s
`hidden-text` rule sees a zero-width character in changed content and reports it.

All 85 came from 3 PRs (`fastapi#16121` 52, `psf/requests#7596` 18,
`fastapi#16141` 15) — dependabot and release PRs whose bodies are machine-written
changelogs.

This is a pure false-positive class: it is not an attack, it is a convention of
the platform we read PRs from. It is also invisible to a fixture, because
`tests/fixtures/injection_pr.diff`'s PR body was written by hand. Errata §14.18's
lesson — a fixture validates a parser, only the real thing validates an adapter —
reappearing at the sentinel.

Mitigating: `hidden-text` is one of the two non-gating heuristics (`M1_STATUS.md`
§5.2), so it can never fail a build. It is still 87% of everything the tool said.

### 2. Any decorator whose last segment is an HTTP verb becomes an endpoint — 1 FP

`promote.py:87` `_suffix()` keeps only the last dotted segment of a decorator
name, and `promote.py:204` tests that against `_ROUTE_VERBS`. The catalog spells
these `app.patch` / `router.patch`, but the receiver is discarded — so
`@patch(...)` from `unittest.mock` is read as a **PATCH route**.

Verified on `saleor/plugins/openid_connect/tests/test_utils.py:1354`, where a
mocked-out cache call became "PATCH saleor...cache.get is handled by
test_get_or_create_user_from_payload... and no authorization guard was found".

The direct cost is one finding, capped at MEDIUM by the test-file rule. The
indirect cost is larger and quieter: **phantom endpoints inflate the
`endpoints_seen` denominator**, so `missing-authz per endpoint` (0.085) is
understated by an unknown amount. `@patch` is ubiquitous in Python test suites.

### 3. `re.compile` matches the `compile` code-execution sink — 1 FP

`cpg.py:262` `_matches()` is a documented dotted-suffix match, and
`python.yaml:136` lists `compile` (the builtin) in the `code_exec` sink class.
`re.compile` ends with `.compile`, so it matches. Compiling a regex is not
evaluating code.

Verified on `tests/utils/test_download.py:183`: "request.headers is untrusted
input and reaches re.compile with no code_exec sanitizer on the path."

Same root shape as #2 — a single-segment pattern matched against any receiver.
`eval` and `exec` are rarely attribute names, so `compile` is the exposed case.

### 4. The guard model sees decorators and DI, not imperative authorization — 11 FPs

All 11 remaining `BAC-MISSING-AUTHZ` hits are on one file,
`wagtail/api/v3/routers/pages.py`, from `wagtail#14453`. This is the
`M2_STATUS.md` §3.2 worry firing exactly as predicted: every unguarded endpoint in
a changed router file is reported.

Inspecting the source shows two different things behind those 11:

- Wagtail *does* use decorator guards — `@require_any_permission(Page, ("add",))`
  at lines 463 and 487 — and the detector correctly did not flag those.
- The flagged handlers enforce authorization **imperatively and indirectly**:
  `delete` and `unpublish` build `action_class(page, user=request.user)` and let
  the action object do the permission check. The detector cannot see this, and
  structurally cannot: `cpg._resolve_callee` is local-file-first by design, so no
  call edge crosses a file (`M2_STATUS.md` §2). The check lives in another module.
- A few (`list_pages`, `find_page`) plausibly *are* meant to be public, which is
  §3.2's "including deliberately public ones" case verbatim.

So this is not a broken rule; it is a rule whose guard model covers a real but
partial share of how authorization is written. That is worth stating precisely,
because "add more decorator names" would not fix it.

### 5. SCA feeds `pyproject.toml` to osv-scanner, which cannot read it — 2 errors

`osv-scanner 2.4.0` exits **127** with "could not determine extractor suitable to
this file" when given `--lockfile pyproject.toml`. It extracts from real lockfiles
(`poetry.lock`, `uv.lock`, `requirements.txt`), not from dependency manifests.

Recorded honestly by the pipeline — `status=error`, with the message in
`detect_notes` — which is `AdapterRun.status` working as designed. The effect is
that **SCA covers nothing on a repository that pins only in `pyproject.toml`**,
and the scorecard's detector table is what makes that visible (`sca: error: 2 ·
not_applicable: 48` — SCA contributed no coverage anywhere in this corpus).

## What this measurement cannot say

- **It is an upper bound.** A merged PR from a healthy repo can still carry an
  undiscovered vulnerability; any such finding is counted here as a false alarm.
- **It says nothing about recall.** A detector that reports nothing scores
  perfectly on this set. Pass 2 (labelled corpus) is where recall gets measured.
- **SCA and IaC are unmeasured**, not clean: `iac` was `not_applicable` on all 50
  cases and `sca` never ran successfully. This corpus does not price them at all.
- **`missing-authz per endpoint` is understated** by defect #2 inflating its
  denominator.
- **Cost is UNMEASURED**, not low. No model was called.
- **n = 50.** Small. The three-PR concentration of defect #1 means a different
  sample of 50 could move the headline substantially.

## Recommended follow-ups, in order of measured impact

1. **Exempt GitHub's `@<ZWSP>` convention from `hidden-text`** (or exempt
   machine-generated PR bodies). Removes 87% of the corpus's noise.
2. **Require a receiver for route decorators and single-segment sinks** — fixes
   #2 and #3, which share a root cause, and un-inflates the endpoint denominator.
3. **Decide what `missing-authz` should do about imperative authorization.**
   Options: demote to INFO when the handler references `request.user`, or leave it
   to the M3 BAC agent, which is what phase-3 §3b is for. This is a design
   decision, not a bug fix.
4. **Give SCA a real lockfile** or mark `pyproject.toml` as unsupported input so
   the failure is `not_applicable` rather than `error`.

Every one of these should be re-measured against this same pinned corpus, which
is what it is committed for.
