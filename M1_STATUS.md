# M1 — Build Status & Handoff

**Last updated:** 2026-08-05 · **Milestone:** M1 (Phase-1 Profiling + Phase-2 Change Analysis)
**State:** **M1 complete** — Phase 1 and Phase 2 both built and accepted on the fixture, and
wired into `pipeline.py`.

> 🧊 **FROZEN — this is the record as it stood at the end of M1, not current state.** Numbers here
> (416 tests, the module inventory) were true on 2026-08-05 and have moved since. For where the
> project is now, read `CONTINUATION.md`. Corrections are **appended** rather than rewritten, so
> the reasoning that produced a wrong call stays legible — that convention is why §5.3's Bedrock
> argument is still worth reading even though its "M2 can proceed without it" prediction has since
> been confirmed.
>
> Two things here have been superseded by decision: `extract/tickets.py` and `extract/blame.py`
> are **descoped**, not backlog (`OPEN_ITEMS.md` §15), and the "M0 was never run against a real
> GitHub PR" note carries its own supersession — the benchmark did it 102 times.

> Detail record for the M1 build. `CONTINUATION.md` is the short "where are we"; this is the
> "what was built, why it looks like that, and what bit us". Design intent lives in
> `PR_Rev_0620.md` + `plan/`; the working plan is
> `~/.claude/plans/melodic-bubbling-raccoon.md`.

---

## 1. Where M1 stands

**416 tests pass** (`.venv/bin/python -m pytest tests/ -q`), plus CAP's own 4
(`cd cap_engine && ../.venv/bin/python -m pytest tests/ -q`). `pr_review/` is ~6,700 lines of
source and ~4,000 of tests. **`cap_engine/`'s working tree is clean — zero edits to the
restricted tree.**

M1 closed with the repository's **first commit** (2026-08-05, 111 files). `cap_engine/` is
gitignored — see `PR_Rev_0620.md` §14.1: confining imports bounds the CAP-lite retrofit, but only
excluding the tree from version control stops the licence contradiction becoming a distribution.

| tooling.md # | Deliverable | Status |
|---|---|---|
| #8 | `profile/promote.py` (+Python extraction) | ✅ |
| #9 | `profile/cpg.py` + `patterns/python.yaml` | ✅ |
| #10 | `security-profile.yaml` workflow + task prompts | ✅ authored |
| #11 | `profile/drift.py` + `profile/cache.py` + `profile/incremental.py` | ✅ |
| #12 | `change/` (filter, classify, context) | ✅ + `astdiff.py` |
| #13 | (unplanned) repo checkout | ✅ `vcs/checkout.py` |
| #26 | `models/provider.py` + a concrete provider | ✅ fake; `bedrock.py` deferred |
| #28 | `safety/` (wrap, sentinel, permissions) | ✅ all three (§5.2) |
| — | `extract/deps.py` (Phase-2 prerequisite) | ✅ |
| — | `profile/schema.py`, `profile/security_profile.py` | ✅ |
| — | `config.py` extension, `cap_compat.py` | ✅ |
| — | pipeline stages, `pr-review profile --rebuild` | ✅ |

### M1 acceptance — met on the fixture

**Phase 1 (phase-1 §11)**

| Criterion | Evidence |
|---|---|
| Cold-profile → valid `ProjectProfile` + correct matrix | 11/11 rows match the hand-labelled key |
| CPG contains endpoints/sources/sinks | + 2 taint paths, 3 sensitive fields |
| Re-run is warm (no re-parse) | end to end through `pipeline.py`: 0.099s → 0.0013s |
| Dep-manifest change → rebuild | anchor rule |
| Docstring change → incremental | under both churn thresholds; **patched, not rebuilt** (§5.1) |
| Cost recorded in telemetry | `ProfileBuild.telemetry` — **unmeasured, not low** (§4) |

**Phase 2 (phase-2 §8)** — against `tests/fixtures/phase2_pr.diff`, a 10-file PR built to
exercise every tier

| Criterion | Evidence |
|---|---|
| Coherent change groups with correct `touches` | 6 groups; `app.py` → endpoint/authz/source |
| Sensible family routing | guard removal → BAC; SQLi region → Injection; `models.py` → Privacy/PII |
| Minimal bundles, no full files unless the rule fires | 3 × `none`, 2 × `full_file`, 1 × `multi_hop` |
| Dropped files all have audit reasons | 4 drops, each with reason + detail + `guardrail_considered` |
| Formatting-only detection (AST equality) | `test_astdiff.py`, 23 tests |
| Guardrail override | comment-only edit to `models.py` kept — it holds `password_hash` |
| Family-routing table | parametrized in `test_change_classify.py` |
| Escalation rules | `test_change_context.py` |
| Recall after filter = 100% on the labelled set | `recall_report()` over the 4 vuln-bearing files |

---

## 2. What was built, and the reasoning that isn't obvious from the code

### `vcs/checkout.py` — the missing producer

Phase 1's declared input is "repo checkout @ base_sha" and CAP's `build_cache(stats_dir)` walks a
real directory, but nothing in any plan component table produced one. `LocalCheckout` (offline,
mirrors `--diff-file`) and `GitCheckout` (bare mirror + `git archive` into
`<cache>/<repo>/src/<sha>`, warm on repeat).

- `git archive`, not `git worktree` — we only ever read the tree, and an extracted archive has no
  worktree bookkeeping to leak or prune.
- Extraction stages into a temp dir and renames. A half-extracted tree would look *warm* next run
  and silently profile an incomplete repo — a wrong answer rather than an error.
- `LocalCheckout` verifies the sha when the directory is a git repo; a silent mismatch would
  poison the cache under a `profile_version` claiming to *be* that sha.

### `profile/promote.py` — framework extraction

Wraps `build_cache`, then extracts endpoints and guards for Flask / FastAPI / Django.

- **Framework detection is per file, not per repo.** `@app.get` is valid Flask *and* valid
  FastAPI; only the import disambiguates. Per-repo detection mislabels every endpoint in a repo
  mid-migration.
- **`AllowAny` is tracked separately from "no guard found."** It is not an absence, it is a
  decision to remove one — which is what lets Phase 2 treat *adding* it to an existing view as the
  high-signal change it is.
- **Django route paths are left empty, not guessed.** Resolving them needs `urls.py` `path()`
  tables and call-argument extraction the ParseCache does not provide. An empty route is honest;
  a wrong one poisons the matrix. Guards are still fully extracted.

### `profile/cpg.py` — security overlay + taint-lite

Merges AST/symbol + call layers with security node kinds and edge kinds, seeded from
`patterns/python.yaml`.

- **Taint requires a call path, not co-location.** `_dump_all` holds the same `cursor.execute`
  sink but no source reaches it. A CPG that connected every source to every sink would report it
  and the verifier would burn tokens refuting it.
- **Sensitive fields match by identifier segment.** Exact matching misses `password_hash` (which
  is how these are actually spelled); plain substring matches `token` against `tokenizer`. Split
  on `_`, require the term's segments contiguous.
- **The CPG lives outside the CGP session** — deliberate deviation from phase-1 §1. It is
  repo-scoped and cached (§8) while a CGP session is run-scoped; `ContextNode` is sized for agent
  artifacts, not tens of thousands of AST nodes; and tooling.md §1 already assumes a separate
  object (`make_find_sources_sinks(cpg, parse_cache)`). Persistence is `cache.py`'s job.
- **Serializes as nodes/edges/taint-paths**, not a pickled rustworkx graph — everything Phase 2
  asks of it is answerable from that, and text survives a library upgrade.

### `models/` — the provider bridge

`PRFramework(CAPFramework)` overrides `_build_provider()`. That is the entire integration; the
provider must be assigned **before** `super().__init__`, which builds the dispatcher.

- **Two provider ABCs, on purpose.** Overview §7.2 says the CAP dispatcher binds to our
  `ModelProvider`; it binds to CAP's `InferenceProvider`. Both are kept because CAP's `invoke()`
  takes `system_prompt_parts` so a provider can place prompt-cache breakpoints between stable and
  volatile segments — flattening it into `complete(messages, ...)` destroys that seam. Our
  `ModelProvider` serves the one-shot path (Phase-2 triage, Phase-3c verifier).
- **Role→model routing lives in the provider.** CAP has a single `model.model_id` for all
  personas; only `invoke()` sees `agent_id` (hence the persona).
- **The fake records every call** so prompt-shape invariants are assertable: the planner never
  receives source, `system_prompt_parts` stays segmented, tiering actually routes.

### `prompts/` — the authored CAP assets

3 personas · `security-profile.yaml` (7 steps + synthesis) · 7 task prompts · 8 report templates.
They live in `pr_review/prompts/`, **not** `cap_engine/config/` as phase-1 §9 specifies — we
authored them, so they are our code, and CAP resolves all four directories from configurable
strings, so it costs nothing to keep them out of the restricted tree.

- **Seven steps, not eleven.** Each step is a full orchestration loop; several of phase-1 §5's
  questions are one cheap read of the same files. A `covers:` comment on each step records which
  of the 11 it answers.
- **The prompts assume the deterministic pre-fill** (phase-1 §7 mechanism 5). They explicitly
  forbid re-enumerating endpoints and ask only "is it safe".

### `profile/security_profile.py` — deterministic floor, agent lift

The floor (`promote` + `cpg`) costs zero tokens, cannot hallucinate, and is complete by
construction. The lift (the CAP workflow) judges what structure can only observe.

- **The floor is emitted whether or not the workflow succeeds.** A broken agent layer yields a
  profile that is *incomplete* rather than *wrong*. Tested with an exploding provider.
- **The floor never emits `declared_not_enforced`.** That value asserts intent; no structural pass
  can know it, and a wrong one is a finding a reviewer will chase. It is the agent layer's single
  highest-value contribution.
- **On merge the agent may overwrite judgement, never structure.** `enforcement`,
  `required_roles`, `auth_pattern` yes; route/file/line no. A hallucinated endpoint is dropped.
- **Gaps are written into `notes`.** A silent blank reads as evidence of safety.

### `profile/drift.py` + `profile/cache.py`

- **The drift check costs nothing.** `decide()` reads only the `DeltaManifest` and a cached
  `RepoFingerprint`. `cache.load_fingerprint()` is separate from `cache.load()` so deciding
  whether to reuse a profile does not require deserializing it.
- **Anchors beat churn thresholds.** A dep-manifest / settings / auth-middleware change
  invalidates conclusions drawn elsewhere, so it rebuilds regardless of how few files moved.
- **Corrupt cache reads as absent, never raises.** A cold start is always recoverable; raising
  turns a cache problem into a failed review. Saves are atomic.
- **`edge_churn` is an approximation** — *edges belonging to changed files* over total edges,
  from cached per-file counts. The plan defines it as added+removed edges, which cannot be known
  without re-parsing, and re-parsing is the cost this check exists to avoid. It over-counts, which
  biases toward rebuild; that is the right direction.

---

## 2b. Phase 2 — what was built, and the reasoning

### The two prerequisites, first

**`extract/deps.py`** closes the recall leak. The tier-1 filter is allowed to drop "lockfile churn
already captured as a `DepDelta`" — that is a **precondition**, not a description, and
`manifest.dep_deltas` was always `[]`. The drop is now conditional on a delta actually existing
for that path (`test_a_lockfile_with_no_depdelta_is_kept` pins it).

- **Lockfiles are droppable; manifests are not.** A lockfile is machine-generated and fully
  described by name+version. A `pyproject.toml` is where a human writes a dependency *and* is a
  profile anchor, so it is never dropped regardless of what the parser makes of it. This is what
  bounds the parsers' inaccuracy to *which bucket* a package lands in, never to whether the file
  was looked at.
- **Everything is line-oriented, read from the diff.** No checkout, no ecosystem toolchain, works
  on a fork PR.
- **`ParsedHunk` now carries context lines** (`body`, `side("old"|"new")`). Without them the
  commonest lockfile change in the ecosystem — a `poetry.lock` version bump, where only
  `version = "…"` moves and the `name = "…"` that says which package it is arrives as context —
  parses to nothing. Unchanged entries appear on both sides and cancel out in the diff algebra.
- **`ParsedHunk` also carries removed-line text now.** M0 kept only removed line *numbers*;
  "changed" is only expressible as (old → new), and a hunk cannot be reconstructed without it.

**`change/astdiff.py`** is the AST-equality check. It ended up its own module (a fifth file in
`change/`, not in phase-2 §7's four) because both the filter and the escalation decision need it
and neither owns it.

- **Two checks, because one side is usually all we have.** `ast_equal(before, after)` is the exact
  check the plan names and needs two checkouts. `inert_hunks()` works from the diff alone — every
  changed line blank or a comment — and exists because the common path (offline `--diff-file`, or
  an unfetched fork PR) has no base checkout, and "could not check" would mean the cheapest and
  commonest noise is never filtered.
- **The comment heuristic has one unsound case, and it is closed.** A `#` line inside a
  triple-quoted string is not a comment. `string_lines()` disqualifies it whenever the *after*
  version is available — one side is enough, and that is the side a head checkout gives free.
- **Comments and bare string expressions are ignored; everything else is compared verbatim.** So a
  docstring edit is formatting, and `q = "SELECT 1"` → `q = "DROP TABLE users"` is not.
- **Python re-indentation is not whitespace.** It is block structure, so it survives normalization
  and is correctly *not* formatting-only — the case a strip-and-compare gets catastrophically
  wrong.
- **A parse error never reports equal.** Two files that both fail to parse are not the same file.

### `change/filter.py` — three tiers, all failing toward keeping

- **The guardrail set is narrower than the touch set.** `GUARDRAIL_KINDS` excludes `config` and
  `dependency`. They are not a security surface, and including them makes the guardrail veto the
  tier-1 rules that exist to act on them — a lockfile is `dependency` *by definition*, so the
  `lockfile_captured` drop could never fire. Found by running it: the first build rescued every
  lockfile.
- **`sanitizer` counts for the guardrail but is not a touch kind.** A file whose only security
  presence is `shlex.quote` is a file where deleting one line turns a safe call into command
  injection. It routes via the sink it protects, not on its own.
- **Ambiguous means *no signal at all*, not "no security surface".** A lockfile already has a
  touch kind and a family; paying a cheap model to relabel it is spend with no decision attached.
- **Tier 3 drops only an explicit `no`.** `maybe`, unlabelled, unparseable reply, exploding
  provider, and an over-ceiling remainder all resolve to *keep*, each with a note.
- **The triage prompt wraps the diff via `safety/wrap.py`.** It is the first place untrusted
  repository text reaches a model in this pipeline.
- **`recall_report()` lives with the filter**, so `benchmark.md`'s recall-after-filter metric runs
  against the filter's own output rather than a reimplementation of it.

### `change/classify.py` — and why `SecurityIndex` lives there

The guardrail ("does this file touch security-relevant structure?") and the routing ("what does
this change touch?") are the same query with different consequences. Answering it twice lets the
two drift, so `filter.py` imports the index from here — which is where phase-2 §7 puts
"CPG-driven `touches`" anyway. A file the filter refused to drop is a file this module can explain.

- **The profile is at `base_sha`; the diff is not.** A guard the PR **removes** is still in the
  graph, and one it **adds** is absent from it. That is why `guard_edits()` reads hunk text against
  the framework catalog — without it, "someone deleted `@login_required`", the highest-signal
  one-line change in a Python PR, produces no signal whatsoever. Same for adding `AllowAny`.
- **Three signal sources, each covering what the others cannot.** CPG nodes (precise, lined);
  profile rows (carry the agent lift, e.g. `declared_not_enforced`); path shape and Phase-0 flags
  (a file this PR *adds* has no node in a base-sha graph — a new `permissions.py` must never be
  filtered out).
- **Grouping is per file, deliberately.** Cross-file merging needs a similarity notion the
  benchmark has not tuned, and over-merging produces one enormous context bundle — exactly the
  failure the tiered design exists to prevent. Cross-file relationships are carried instead as
  1-hop `neighbors` in the bundle.
- **Signals are scoped by hunk span, so a change at the top of a file does not inherit the SQLi at
  the bottom.** Line-0 signals (path flags, profile rows with no line) always apply — they
  describe the file, not a region.
- **Family names are validated against the registry.** A typo produces a group no Phase-3b runner
  claims — a coverage hole that reads as "analyzed". `taxonomy/registry.py` gained the 13-family
  vocabulary (cross-cutting §2) plus `validate_families()` for exactly this.
- **`Software Supply Chain` is routed even though no agent runs it.** 3a's SCA owns it; routing it
  keeps the Phase-4 coverage denominator honest — a dependency bump is *handled*, not *skipped*.

### `change/context.py` — tiers decided by the graph, not by appetite

- **Escalation is computed structurally, here.** §5 assigns the decision to the planner precisely
  so a worker cannot choose its own files. The planner wiring is Phase 3 and will consume this
  decision rather than re-make it; computing it now preserves the property that matters — the tier
  is a function of the graph.
- **`return` is not a control-flow signal on its own.** The first build escalated a new
  three-line helper to `full_file` because its body said `return`. Every function has one, so
  counting it makes the tier meaningless. Now: branch/exception keywords always escalate; `return`
  only when *removed* (an exit path disappeared) or beside a branch keyword.
- **A new file never escalates.** The hunks already *are* the file, so `full_file` is the same
  bytes under a more expensive label.
- **An empty `CodeSlice.content` with correct bounds is a resolvable pointer**, which a Phase-3
  file-read tool can fetch under permissions. Fabricating the text, or dropping the bounds, would
  not be.
- **Bundles are not pre-wrapped.** `safety/wrap.py` is applied where text enters a prompt;
  wrapping in the data structure would corrupt it for the report, the run artifacts and the
  benchmark.

### `pipeline.py` — and the footgun it now refuses

- **A skipped phase is loud.** A run with no checkout and no cached profile has no matrix and no
  CPG, so its silence about broken access control is an absence of evidence. `PHASE 1 SKIPPED` and
  `GUARDRAIL DEGRADED` go into `telemetry.json`.
- **One directory cannot serve as both sides.** `base_dir == head_dir` would make `ast_equal`
  compare every file with itself and declare the entire PR formatting-only — a silent mass drop
  bounded only by the guardrail. Caught while probing; the same path passed twice is now treated
  as the head alone.
- **Phase 2 still runs with no profile at all**, on path shape and the guard-edit text pass. The
  highest-signal change survives a fully degraded run.

---

## 3. CAP engine — verified working, two defects found

The drop-in is a **transcription from photographs** of the original source. This session ran it
for the first time.

**It works.** `build_cache` parses with zero errors and populates `structural_index`,
`type_hierarchy` and `call_graph`; `CAPFramework` constructs; the 7-step workflow completes end to
end. The tree-sitter queries — `ARCHITECTURE.md` §8.5's one genuinely unverified UNCERTAIN class —
are correct against the installed grammar. Guard: `tests/test_cap_smoke.py`.

### Defect 1 — colliding session ids (blocking, shimmed)

`CAPOrchestrationLoop.__init__` builds `session-{_timestamp()}` at **second** resolution and
`CGPServer.session_create` raises on a duplicate. Two workflow steps starting in the same second
abort the run: `CGPError [-32012] Session already exists`. Blocks **every** multi-step workflow.

Reproducing needs steps to be fast, which is why static analysis and the single-call smoke test
both missed it. Shimmed in `pr_review/cap_compat.py` by patching the module-level `_timestamp` to
microseconds + counter — exactly what `SubAgentDispatcher._make_agent_id` already does for agent
ids. `test_the_defect_is_still_present_upstream` tells you when the shim can be deleted.

### Defect 2 — namespace shadow on the top-level import (workaround: import style)

From the repo root, setuptools registers its editable finder **after** `PathFinder` on
`sys.meta_path`, so `PathFinder` claims the `cap_engine/` project directory as a namespace package
and `__init__.py` never executes:

| From the repo root | |
|---|---|
| `from cap_engine.config.framework import CAPFramework` | ✅ |
| `from cap_engine import CAPFramework` | ❌ `ImportError` |
| `cap_engine.__version__` | ❌ `AttributeError` |

**Always import CAP by fully-qualified submodule path.** The bare form is what `ARCHITECTURE.md`
§2.1 documents and it passes in tests run from another CWD — so it fails only in the CLI. Pinned
by `test_import_style_guard`.

### Three ParseCache gaps → the `_trees` workaround

Framework extraction cannot come from `Symbol`/call-graph alone. `promote.py` and `cpg.py` walk
`ParseCache._trees[path]`, which retains `(tree, source)` — zero file I/O, zero tokens. **Do not
solve this by re-reading files.**

1. `Symbol.params` is empty for Python (no params capture in the query catalog) — and FastAPI puts
   authorization in the signature (`user=Depends(get_current_user)`).
2. `Depends(...)` reaches the call graph as callee `Depends`; the dependency name is an argument.
3. Attribute chains collapse: `request.args.get(q)` records callee `get`, so `python.yaml`'s
   `sources.attributes` cannot match against call-graph callees.

All three pinned as known-gap tests in `tests/test_cap_smoke.py`.

**A fourth gap, found building the incremental updater: `ParseCache.refresh()` is not the
incremental hook it looks like.** It re-parses by mtime over files already in `file_mtimes`, so it
never sees a file a PR *adds*; and it updates neither `call_graph` nor `type_hierarchy`, so taint
would silently disappear from any file it did refresh. `profile/incremental.partial_cache()` is
the supported path — it walks a given file list using CAP's `CodeParser`, `StructuralIndexer` and
`CallGraphBuilder` directly.

### Other CAP facts worth keeping

- **Qualified-symbol format is load-bearing.** CAP keys methods `{stem}.{Class}.{method}`
  (`models.User.fetch`). Dropping the class collides sibling handlers (four Django views each with
  a `get`) *and* silently fails to join the call graph.
- **A fake provider must return a parseable `InferencePlan`** for the planner
  (`plan_response()` in `models/fake.py`). A bare envelope leaves the plan empty and **zero
  workers dispatch** — a healthy-looking run producing nothing.
- **kiro is a non-issue** — a provider behind a one-method ABC; the default is already
  `strands`→Bedrock. Excising it is ~15 lines + 2 directories.

---

## 4. Known blind spots — state these, do not let them read as clean

Four items **cannot be validated without Bedrock access** and are the explicit blind spot of M1:

1. **`token_tracker.py:116` guesses the Strands usage key `cacheWriteInputTokens`.** If wrong it
   reports **0** silently — and the token-economy claim, the budget gate, and Principle #4 all
   ride on that number. `models/fake.py` emits the same guessed keys, so the fake looks healthy
   either way; the module docstring and a test say so where the numbers are produced.
2. **`_CacheableBedrockModel` overrides the private Strands attribute `_supports_caching`** —
   breaks silently on a Strands upgrade. Pin `strands-agents` when access lands.
3. **CAP's default `model_id` is `anthropic.claude-sonnet-4-20250514`** — deprecated, past its
   published retirement date. Our `config.models.roles` carries current ids
   (`anthropic.claude-opus-5` / `claude-sonnet-5` / `claude-haiku-4-5`).
4. **`temperature` is removed on current Claude models** (400 on Opus 5 / Sonnet 5 / Opus 4.8+).
   CAP's `ModelConfig.temperature` must not be forwarded; `RoleModel.effort` replaces it.

Also unmeasured: **the agent lift itself**. With a fake provider `agent_rows_merged == 0`, so the
merge path is unit-tested but never exercised against real model output.

**When reporting M1 results, say token/cost telemetry is _unmeasured_, not _low_.** Zeros in a
token-economy report read as "cheap" when they mean "we did not measure".

---

## 5. Next step — M2 (deterministic detectors), and the debts M1 leaves behind

M1 is done. §5.1 (incremental profiling) and §5.2 (`safety/`) are both closed. **§5.3 — the
measurement blind spot — is the only M1 debt left.**

> **Update 2026-08-05, after M2.** M2 was built without it, exactly as §5.3 said it could be —
> the detector suite and delta scoping are model-free. Nothing in M2 called a model, so **all
> four blind spots in §4 survive verbatim** and cost telemetry is still *unmeasured*. §5.3 is now
> the only thing between here and M3. The M2 record is **`M2_STATUS.md`**.

### 5.1 ✅ The incremental profile updater — built 2026-08-05

`profile/incremental.py`. `drift.decide()`'s third outcome now does work: re-parse only the files
that moved, splice them into the cached profile and CPG, write back into the same cache entry.

**Measured on synthetic repos** (`update_profile` vs `build_profile`, one file changed):

| Repo size | Full build | Incremental | Ratio | Matrix |
|---|---|---|---|---|
| 54 files | 0.504s | 0.010s | **50×** | 211 rows, identical |
| 304 files | 2.356s | 0.016s | **144×** | 1211 rows, identical |

Cost is priced by the *change*, not the repo, so the ratio grows with repo size — which is the
shape Principle #4 needs. `test_cost_does_not_grow_with_the_repository` pins the invariant behind
it (one file changed → one file parsed) without asserting timings.

The reasoning that isn't obvious from the code:

- **It patches artifacts, not a parse cache.** The obvious design keeps the `ParseCache` warm and
  re-parses into it, but `cache.py` deliberately does not persist it — it holds every file's full
  source and tree-sitter tree. A warm process has the derived artifacts and no parse state, so the
  updater parses touched files into a **partial** `ParseCache` and splices the derived results.
- **CAP's own `ParseCache.refresh()` is unusable here**, and not for a small reason: it re-parses
  by mtime over files *already known*, so it never sees a file a PR adds; and it updates neither
  the call graph nor the type hierarchy, so taint would silently disappear. `partial_cache()`
  walks the given list using CAP's `CodeParser`, `StructuralIndexer` and `CallGraphBuilder`
  unchanged. **Still zero `cap_engine` edits.**
- **The splice precondition is checked, not assumed.** Patching per file is sound only because no
  derived fact crosses a file boundary — verified empirically: zero cross-file edges, zero
  cross-file taint paths, and the only shared nodes are file-less `permission` nodes.
  That is a property of `_resolve_callee` being local-file-first, *not a law*.
  `CPG.splice_violations()` asserts it every run and the updater raises `NotSpliceable` rather than
  guessing; the pipeline then rebuilds and says so. Without it, cross-file import resolution would
  one day leave stale edges hanging off every patched file's neighbours, silently.
- **`base_sha` moves, `profile_version` does not.** They answer different questions and phase-1 §6
  keeps them apart: `profile_version` is the last *full* build's commit, so `01_profile.ref` stays
  a stable replay pointer; `fingerprint.base_sha` is "which commit does this describe". Leaving the
  latter behind would re-patch the same base forever and never go warm.
- **Which tree, and which files — both were underspecified.** It re-parses the checkout at
  **base_sha**, never head: the profile is a base-commit artifact and Phase 2 is built on that
  (`classify.py` reads guard *edits* from hunk text precisely because the graph predates the PR).
  Patching from head would leave a profile at base for most files and head for a few — neither
  commit, and undetectable downstream. For *which* files, §6 offers the PR's own diff, but the
  drift being repaired is between the cached base and this PR's base; those differ. So the set is
  the PR's paths ∪ a `stat()` size comparison against the cached fingerprint, which costs no
  parsing. A same-size edit between bases is still missed, and the profile notes say so.
- **A re-derived row loses its agent judgement, and that is correct.** The agent judged the
  *previous* version of a function the PR just rewrote; a stale `declared_not_enforced` is a
  finding a reviewer chases. Rows affected are named in `notes`. Repo-level agent output
  (`description`, `roles`, `authentication`, `authorization`) is preserved — it describes the
  project, not the files. This needed a new field, `ProjectProfile.agent_rows_merged`: a *cached*
  profile previously could not tell you whether it had ever been lifted.
- **A bug the 4-file fixture could not show.** `IOChannel` is keyed by route, and a route is not
  unique across files — two blueprints can serve `/admin/export`. Evicting channels by name
  deleted the untouched files' channels too. Now reference-counted against surviving `code_flows`,
  the same way the CPG prunes shared `permission` nodes. Caught by the 30-module scaling test.

### 5.2 ✅ `pr_review/safety/` — completed 2026-08-05 (tooling #28)

All three of cross-cutting §9's code mechanisms now exist. §9.4 (determinism for audit) is not a
module — it is the verifier's `effort` pinning at M4 plus tool-call logging CAP already does.

**`sentinel.py` (mechanism 3, `LLM-PROMPT-INJ`).** Runs against the manifest in its own
`tel.phase("sentinel")`, **before** the change stage. Five rules in two tiers: three whose
patterns have no innocent reading (`override-instruction`, `fence-forgery`, `addressed-to-agent`)
emit `status=validated` + `high` and therefore *can fail the gate*; two heuristics
(`suppress-finding`, `hidden-text`) report and never gate. On
`tests/fixtures/injection_pr.diff`: 4 findings, 2 gate triggers, exit 1, sentinel phase 0.8ms.
The existing `phase2_pr.diff` thread is unchanged — 6 groups, 4 dropped, approved, zero sentinel
findings — so the new stage costs the M1 acceptance case nothing.

The reasoning that isn't obvious from the code:

- **The ordering is the design, not a preference.** A README carrying an injection is dropped by
  tier 1 as `docs_only`, and the guardrail does not save it because a README touches no source,
  sink or endpoint. A sentinel running after the filter would be structurally blind to the single
  likeliest carrier. `test_the_sentinel_sees_what_the_noise_filter_drops` asserts both halves —
  the filter *does* drop it, and the sentinel finds it anyway — so the constraint is now a
  failing test rather than a comment in two docstrings.
- **It scans added lines, not comments.** The obvious design extracts comments and string
  literals with tree-sitter. That is wrong twice over: a README and a YAML have no comment
  concept and are exactly the files tier 1 drops, and a legitimate LLM system prompt lives in a
  *string literal*, so position is not the precision signal anyone assumes. Precision comes from
  the phrases. Position would have cost recall on the surfaces that matter most.
- **The gating tier is drawn where it can be defended, not where it is widest.** A bare
  `Human:` / `Assistant:` line start is the obvious next `fence-forgery` pattern and is
  deliberately absent: it is too common in legitimate prompt-handling code to carry a verdict
  that fails CI, and an LLM application would flag its own every PR. The tier exists to be
  defensible.
- **This repository is its own worst false positive.** `tests/test_taxonomy_and_safety.py:78`
  carries `"# TODO: ignore previous instructions"` as a fixture. Test files cap at MEDIUM (the
  same move `secrets.py` makes) and `detectors.sentinel.allowlist_paths` handles the rest. A tool
  that flags its own test suite is one nobody runs.
- **`hidden-text` renders rather than quotes.** Evidence is verbatim everywhere else
  (cross-cutting §1); here a verbatim snippet displays as ordinary text and shows the reviewer
  nothing, because unreadability *is* the defect. The snippet substitutes `<ZWSP>` and the
  evidence `why` says so.
- **A flagged file is force-kept through the filter.** Not because the finding needs it — that is
  already emitted — but because someone who plants an injection is plausibly pointing attention
  away from something else in the same PR. This is *not* errata §14.9 in a new place: that rule
  is about a signal a stage acts on vetoing that same stage, and the sentinel is a prior stage
  whose verdict the filter consumes and never produces.
- **`apply_trust()` is wired while it is still a no-op.** There are no `DetectorKind.AGENT`
  findings until M3. Building the penalty now, with a test against a synthetic agent finding, is
  the alternative to discovering at M3 that the trust flag was only ever a field in a JSON file.
  Deterministic findings are deliberately exempt: a regex cannot be talked out of a match, and
  penalizing it would hand an attacker a way to discount the floor.

**`permissions.py` (mechanism 2).** `PRFramework._build_tool_sets()` overrides CAP's, runs
`enforce()`, and binds what survives — the same shape as the existing `_build_provider()`
override, so `cap_engine/` stays unmodified. All 25 of CAP's tools are classified;
`classify_tool()` returns `source` for anything unknown, so a tool this table has never heard of
fails closed. Violations reach `telemetry.json` as `profile_telemetry.tool_permission_violations`.

**It currently finds nothing, and that is the point.** CAP's planner set is already source-free —
`planner_search_codebase_summary` returns per-directory match *counts*, not lines. The override
earns its place the day that stops being true: `cap_engine/` is a transcription of a separate
restricted repo that may be re-synced or swapped for CAP-lite, and a re-sync handing the planner
a source reader would otherwise widen the trust boundary permanently and silently.
`test_a_source_tool_planted_on_the_planner_is_stripped_and_recorded` is that regression.

It **strips rather than raises**: a planner short one tool degrades and its persona prompt already
tells it to report an honest gap, whereas a framework that refuses to construct takes down the
whole review — including the deterministic floor that needs no agent at all — and turns a
tightened boundary into an outage.

**Two gaps this work creates, stated rather than absorbed:**

1. **The sentinel sees added diff lines only.** A pre-existing injection in a file that a
   `full_file` context bundle later ships to an agent is invisible to it. `scan_text()` is
   exported as the primitive precisely so Phase 3's bundle assembly can close this — **an M3 line
   item, not a maybe.** Also unhandled by construction: payloads split across two lines,
   homoglyphs, and non-English phrasing.
2. **Mechanism 2 has three clauses and only one is enforceable today.** "Workers write only to
   the run dir" is satisfied *by construction* — no filesystem-write tool is bound to any
   persona, worker output goes through `create_inference_node` into the CGP store — so there is
   nothing to enforce. "The verifier receives claim + evidence pointers" has no binding to
   enforce against: CAP has three personas and the verifier is not one of them. `POLICY` carries
   the row so the policy lives in one place; it binds at M4.

**One thing found while building it** (errata §14.13): the **PR body was never captured**.
`PRRef` and `DeltaManifest` carried only `title`, though phase-0 §4 says title *and body* are
stored as untrusted input. A sentinel built strictly to the brief would have been blind to the PR
description — the surface a fork PR actually uses. Now fetched (`d.get("body")`, already on the
REST response we make), stored, and scanned; a body hit taints the run rather than a path,
because nothing downstream can attribute it to a file.

**And a small output-side hole**, found by asking where evidence is rendered: `report/markdown.py`
interpolated `evidence.snippet` straight into a ``` fence, so crafted evidence could close the
block and continue as markdown in a report that gets posted as a PR comment. Escaped for all
findings now — the same hole `wrap.py` closes for prompts, on the way out instead of in.

### 5.3 The measurement blind spot — M1's last open debt

Four Bedrock-dependent unknowns (§4) were acceptable while M1 was structural. `models/bedrock.py`
plus one real run settles all four at once. **Nothing in §5.2 measured anything, so all four
survive verbatim.**

It binds unevenly across what comes next, and the distinction is worth keeping straight rather
than treating "binding constraint" as a blanket:

- **M2 (deterministic detectors) does not need it.** semgrep/SCA/IaC adapters and the
  baseline/delta scoping the gate needs are model-free. M2 can proceed honestly without
  credentials — though `semgrep`, `osv-scanner` and `checkov` are all absent from this
  environment too, so those adapters would land unvalidated in the same way, which is a debt in a
  different place rather than no debt.
- **M3 (agentic families) cannot start without it.** Against a fake provider the agent lift is
  scripted JSON: `agent_rows_merged == 0`, tier-3 triage exercises its prompt's *labels* but
  never its *judgement*, and every cost number is a zero that means "unmeasured".

Writing `bedrock.py` ahead of credentials was considered and declined: blind spot #2 is that
`_CacheableBedrockModel` overrides the private Strands attribute `_supports_caching`, and its
mitigation is *pin `strands-agents` when access lands*. Code written against an unpinned Strands
would be wrong at exactly the seam no mock can test.

### Still open, beyond that

- **CAP-lite / licensing** (deferred by decision). `cap_engine` is restricted and cannot ship in
  an open-sourced `pr_review`, contradicting `PR_Rev_0620.md` §13.3. Mitigations in place:
  `cap_engine` imports are confined to six files — `profile/promote.py`, `profile/cpg.py`,
  `profile/security_profile.py`, `profile/incremental.py`, `models/framework.py`,
  `cap_compat.py`; all authored assets live in `pr_review/prompts/`; `cap_engine/` is unmodified
  **and gitignored** (§1); and nothing in `change/` imports CAP at all.
- The full taxonomy YAML mapping tables (the 13-family vocabulary is in `registry.py`; the
  OWASP/CWE/ASVS tables are still code-free placeholders), `extract/tickets.py`,
  `extract/blame.py`.
- **Django route resolution.** 4 of 11 matrix rows still read `(unresolved:ViewName)`; guards are
  extracted, routes are not. Needs `urls.py` `path()` table parsing.
- **M0 was never run against a real GitHub PR** — every run dir is an offline `--diff-file` run.
  Phase-0 acceptance (tickets, real base/head SHAs, blame) is still unverified, and `--base-dir`
  now makes a real two-checkout run worth doing.
