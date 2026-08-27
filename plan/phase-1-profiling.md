# Plan — Phase 1: Project Profiling (Amortized Knowledge Base)

> The expensive-once, reuse-many brain. Wraps the **CAP Engine** to build a **Code Property
> Graph (CPG)** + a structured **security profile**, cached per repo and updated incrementally.
> Package: `pr_review/profile/`. This is the phase the whole token economy hinges on, so it gets
> the most design detail.

## 1. Contract

- **Input:** repo checkout @ `base_sha`, `DeltaManifest` (for incremental updates), `Config`.
- **Output:** `ProjectProfile` (pydantic) + a `CPG` persisted as a CAP **CGP session snapshot**;
  both cached under `.pr_review/cache/<repo>/profile/<profile_version>/`.
- **Amortization rule:** Phase 1 runs **fully** only on first sight of a repo (cold start) or on
  a rebuild trigger (§5). Otherwise it does a cheap **incremental update** keyed off the manifest.

## 2. Relationship to CAP (what we reuse vs add)

| CAP provides (reuse as-is) | Phase 1 adds (`pr_review/profile/`) |
|---|---|
| `code_promoter.build_cache()` → `ParseCache` (tree-sitter structural index + call graph) | Python framework pattern catalogs; CPG security overlay |
| CGP server (rustworkx + SQLite), sessions, nodes, edges, assembly | security node/edge kinds; profile→graph writer |
| WorkflowRunner + Planner/Worker/Synthesizer + role-authorization workflow | the security-profile workflow (Python-adapted); drift engine; profile cache/versioning |
| Token tracker, prompt caching, structural tools | none (used directly) |

`profile/` calls CAP; CAP never imports `pr_review/` (overview §4 boundary rule).

## 3. Step 1 — Code promotion (structural index)

`profile/promote.py` wraps `cap_engine.environment.code_promoter.build_cache(base_dir)`:

- Parses all Python sources with `tree_sitter_python` → `structural_index: dict[path, list[Symbol]]`
  (classes, functions, methods, decorators, params, line ranges, imports) + forward/reverse
  `call_graph`. Java/JS grammars remain available but off by `languages: [python]`.
- **Python-specific extraction** (the v1 work item flagged in overview §9): recognize framework
  surface so endpoints/authz are first-class —
  - **Flask/Quart:** `@app.route`, `@blueprint.route`, method args; `flask_login` `@login_required`.
  - **FastAPI/Starlette:** `@app.get/post/...`, `APIRouter`, `Depends(...)` (esp. auth deps),
    `Security(...)`.
  - **Django/DRF:** `urls.py` route tables, `ViewSet`/`APIView`, `permission_classes`,
    `@permission_required`, `LoginRequiredMixin`, middleware.
  - Generic: decorators, call targets, string-literal route tables.
- Skip-promotion heuristic (from CAP): if a snapshot exists and the repo fingerprint
  (file-count + total-size + base_sha) is unchanged, skip parsing entirely.

## 4. Step 2 — CPG construction (security overlay)

`profile/cpg.py` builds the **Code Property Graph** on top of the CGP session by merging four
layers into one rustworkx multigraph (the "what graph" decision, outline §1.4):

- **AST/symbol layer** — file & symbol nodes from `ParseCache`.
- **Call layer** — `calls` edges from `call_graph` (forward/reverse).
- **Security node kinds** (added): `endpoint`, `role`, `permission`, `source` (untrusted input:
  request params/body/headers, env, file reads, message queues), `sink` (dangerous op: SQL exec,
  `subprocess`, `eval/exec`, template render, `open(path)`, deserialize, outbound HTTP),
  `sanitizer`, `trust_boundary`, `sensitive_field` (PII/secret-typed data).
- **Security edge kinds** (added): `guards` (auth check → endpoint), `authorizes` (role →
  endpoint/action), `taints` (source → … → sink along call/data flow), `sanitizes`, `exposes`
  (endpoint → sensitive_field).

Sources/sinks/sanitizers are seeded from a **pattern catalog** (`profile/patterns/python.yaml`,
data not code) per framework, then connected using the call graph to produce **"taint-lite"**
reachability scaffolding — cheap, structural, not a full dataflow engine, but enough to (a) feed
3a structural detectors, (b) give 3b/3c reachability without re-reading files, and (c) downgrade
unreachable findings (cross-cutting §3). Deeper taint is delegated to CodeQL/Semgrep-pro when
enabled (3a).

## 5. Step 3 — Security profile (CAP workflow)

The profile is produced by a **CAP workflow** (`cap_engine/config/workflows/security-profile.yaml`),
one task per template question (outline Phase 1.2). Each task = a task prompt
(`config/prompts/tasks/profile-*.md`) + an output schema; workers read only what the planner
assigns (token economy). Tasks:

`description` · `components` (role/location/access-control/data-sensitivity) · `tech-stack` ·
`cloud-services` · `architecture` (patterns/data-flow/integration) · `io-channels` ·
`code-flow` (channel↔file maps) · `roles-and-checks` · `authentication` · `authorization`
(reuses the **role-authorization workflow** from the writeup as a sub-workflow) · `notes`.

Output = `ProjectProfile` (`profile/schema.py`):

```python
class AccessControlRow(BaseModel):
    endpoint: str; http_method: str; controller: str
    required_roles: list[str]; auth_pattern: str        # "decorator:login_required" | "none" | ...
    enforcement: Literal["enforced","declared_not_enforced","none"]

class ProjectProfile(BaseModel):
    profile_version: str                 # = base_sha at full build (see §6)
    description: str; tech_stack: list[str]; cloud_services: list[str]
    components: list[Component]; architecture: Architecture
    io_channels: list[IOChannel]; code_flows: list[CodeFlow]
    roles: list[Role]; permission_checks: list[PermissionCheck]
    authentication: AuthModel; authorization: AuthzModel
    access_control_matrix: list[AccessControlRow]    # the flagship artifact
    sensitive_fields: list[SensitiveField]
    notes: list[str]
    built_at: datetime; build_kind: Literal["full","incremental"]
```

The access-control matrix + sources/sinks are the highest-value outputs: they power Broken
Access Control (A01, the flagship family) and Injection reachability in Phase 3.

## 6. Step 4 — Drift metric: incremental update vs. full rebuild

`profile/drift.py`. Default to **incremental**; rebuild only when the project has drifted enough
that the cached profile is no longer representative (resolves outline §1.4 "deviation benchmark").

**Drift score inputs** (computed from the manifest + cached graph, no AI):
- `file_churn = changed_files / total_files` since last **full** build.
- `edge_churn = (added+removed call-graph edges) / total_edges`.
- `anchor_touched` = any change to an **anchor file**: dep manifests, security config, auth
  middleware/filters, framework/runtime version, settings (`profile.anchor_globs`).
- `stack_changed` = language/framework set differs.

**Decision:**
```
rebuild if  anchor_touched or stack_changed
            or file_churn > drift_file_pct (default 0.25)
            or edge_churn > drift_edge_pct (default 0.15)
else        incremental
```

**Incremental update procedure:** re-parse only the manifest's touched files → patch
`structural_index` + `call_graph` for those nodes → re-derive the **affected subgraph** (1–2 hops
in the CPG) → re-run only the profile tasks whose inputs intersect the change (e.g., an endpoint
change re-runs `authorization` for that controller, not the whole workflow). `build_kind="incremental"`,
`profile_version` unchanged.

**Full rebuild:** re-promote + rebuild CPG + run the full security-profile workflow;
`profile_version = base_sha`; old snapshot retained for one generation for diffing.

Thresholds are **starter values, tuned by the benchmark** (`benchmark.md`) to balance
cost vs. profile staleness (measured as: agreement between an incrementally-updated profile and a
from-scratch rebuild on the same commit).

## 7. Step 5 — Token-efficiency mechanisms (applied here)

The seven CAP mechanisms (structural-first planning · outline→search→section reading ·
cross-task injection · cross-session reuse · prompt caching · tool-call limiting · budget gating)
**plus** the five PR-specific ones:

1. **Diff-scoped analysis** — incremental updates touch only the changed subgraph.
2. **Baseline reuse** — never re-profile unchanged code; the cache is the default path.
3. **Semantic cache** — per-file LLM summaries keyed by content hash; reused across runs/files.
4. **Tiered models** — cheap model for structural/triage tasks, strong model only for deep
   profile reasoning (config `models.roles`).
5. **Deterministic pre-fills** — the structural index/CPG answers "what exists" with zero tokens
   so agents spend tokens only on "is it safe."

Target: cold-start profile cost comparable to the writeup's optimized authz audit (~216K tokens
for a 50-endpoint service); **incremental updates an order of magnitude cheaper.** Tracked in
telemetry; must trend down (Principle #4).

## 8. Caching, versioning & invalidation

- Profile + CPG snapshot stored under `.pr_review/cache/<repo>/profile/<profile_version>/`;
  `profile_version = base_sha` of the last full build.
- A `profile.ref` in each run dir points to the profile used (replayability).
- Invalidation: rebuild trigger (§6) or explicit `pr-review profile --rebuild`. Corrupt/missing
  cache → automatic cold start.
- Cross-repo isolation: caches keyed by repo; no bleed between projects.

## 9. Components & files

| File | Responsibility |
|---|---|
| `profile/promote.py` | wrap CAP `build_cache`; Python framework extraction hooks |
| `profile/cpg.py` | build security CPG overlay; source/sink/sanitizer wiring |
| `profile/patterns/python.yaml` | framework source/sink/sanitizer/auth catalogs (data) |
| `profile/security_profile.py` | run the CAP security-profile workflow → `ProjectProfile` |
| `profile/schema.py` | `ProjectProfile` + sub-models |
| `profile/drift.py` | drift score + incremental/rebuild decision + incremental updater |
| `profile/cache.py` | snapshot save/load, versioning, invalidation |
| `cap_engine/config/workflows/security-profile.yaml` | the workflow definition |
| `cap_engine/config/prompts/tasks/profile-*.md` | per-task prompts |

## 10. Risks & tests

- **Risk: Python flagship gap.** The CAP authz workflow was proven on Java/Spring/JAX-RS;
  Python decorator/middleware patterns differ. Mitigation: `patterns/python.yaml` + M3 builds
  Broken Access Control for Python first; benchmark guards against regressions.
- **Risk: taint-lite false edges.** Structural taint over-connects. Mitigation: it only *seeds*
  candidates; 3c verifies reachability; precision measured by ablation.
- **Tests:** unit on pattern catalog matching + drift math; integration profiling a known
  vulnerable Python app (e.g., a deliberately-insecure Flask/Django target) → assert the
  access-control matrix matches a hand-labeled key; **warm-start test** (second run skips
  promotion); **drift test** (anchor-file change forces rebuild, small change stays incremental);
  **incremental-vs-rebuild agreement** metric ≥ threshold.

## 11. Acceptance (M1)

Cold-profile a Python repo → valid `ProjectProfile` with a correct access-control matrix and a
CPG containing endpoints/sources/sinks; re-run is warm (no re-parse); a dep-manifest change
triggers rebuild while a docstring change stays incremental; cost recorded in telemetry.
