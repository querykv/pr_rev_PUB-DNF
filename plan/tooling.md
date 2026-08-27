# Plan — Tooling: Per-Tool Development Specs

> One consolidated, buildable inventory of every tool/component the phase docs reference, with
> type, I/O, dependencies, build order, and test approach. Resolves outline §3 "how to develop
> each tool." Five tool *classes*, each with a shared development pattern.

## 1. Tool classes & shared patterns

| Class | Pattern | Lives in |
|---|---|---|
| **A. Internal structural tools** | closures over CAP `ParseCache`/CGP; **zero file I/O, zero tokens** | `cap_engine` (reused) + `pr_review/profile/` |
| **B. External detector adapters** | subprocess → parse native output (prefer SARIF) → normalize to `Finding` | `pr_review/detect/` |
| **C. Agentic skills/workflows** | CAP YAML workflow + task prompts + output schema, wrapped by a `DetectorFamily` | `pr_review/analyze/` + `cap_engine/config/` |
| **D. Emitters** | pure function `NormalizedFindingSet → artifact` (no LLM) | `pr_review/report/` |
| **E. Interfaces / infra** | abstract base + one v1 impl (VCS, model provider, config, telemetry) | `pr_review/{vcs,models,...}` |

### Class A — internal structural tool (template)

CAP already ships the key ones (`find_symbols`, `find_by_decorator`, `find_endpoints`,
`get_call_chain`, `find_callers`, `get_file_outline`, `search_resource`,
`read_resource_section`). We add security-aware ones over the CPG:

```python
def make_find_sources_sinks(cpg, parse_cache):
    def find_sources_sinks(scope: str) -> list[Node]:
        "Return source/sink/sanitizer nodes in scope. Zero tokens; pure graph query."
        ...
    return find_sources_sinks
```
New Class-A tools: `find_sources_sinks`, `get_taint_paths(entry, sink)`, `get_access_control_row(endpoint)`,
`find_unguarded_endpoints()`, `get_sensitive_fields(symbol)`. Dev = pure-Python over rustworkx +
`ParseCache`; **fast unit tests on a fixture graph**, no model calls.

### Class B — external detector adapter (template)

```python
class SemgrepDetector(Detector):
    tool, version = "semgrep", ">=1.x (pinned)"
    def applicable(self, manifest, profile) -> bool: return manifest.has_python_changes
    def run(self, targets) -> list[Finding]:
        sarif = subprocess(["semgrep", "--sarif", "--baseline-commit", base, *targets])
        return [normalize(r, kind=SAST) for r in parse_sarif(sarif)]
```
Rules: pinned version; **missing binary → disable + telemetry warning (never crash)**; SARIF is
the stable contract; `detect/normalize.py` maps `rule_id → taxonomy` + confidence prior. Tests use
**recorded tool output fixtures** (don't shell out in unit tests); one integration test per tool
actually invokes the binary.

### Class C — agentic family (template)

A `DetectorFamily` = `workflow.yaml` (family steps) + `tasks/*.md` (planner/worker prompts) +
output schema + `to_findings()` mapper. Dev pattern: start from the writeup's role-authorization
workflow, adapt prompts to the family + Python idioms, define the structured output keys
(`endpoint_csv_rows`-style) for deterministic extraction. Tests: run the workflow on a fixture
Python app, assert structured findings + taxonomy (model calls mocked in unit tests, real in a
nightly integration test).

### Class D — emitter (template)

Pure function, golden-file tested. SARIF validated against the 2.1.0 JSON schema; HTML rendered
from Jinja2 and checked for self-containment (no external refs); PR comments tested for
idempotency (no double-post).

### Class E — interface (template)

Abstract base + one v1 impl; the rest of the code depends only on the base. Tests target the base
contract with a fake impl + one integration test on the real impl.

## 2. The buildable inventory

| # | Tool / component | Class | In | Out | Key deps | Milestone |
|---|---|---|---|---|---|---|
| 1 | `GitHubAdapter` | E | PR URL | PR/diff/issues/blame | gh/PyGithub | M0 |
| 2 | `config.py` loader | E | yaml/env/CLI | `Config` | pydantic | M0 |
| 3 | `schema.py` (Finding + enums) | E | — | models | pydantic | M0 |
| 4 | `extract/` (manifest, diff, classify, tickets, deps, blame, guard) | — | PR | `DeltaManifest` | git | M0 |
| 5 | `secrets.py` adapter | B | diff | Finding[secrets] | gitleaks | M0 |
| 6 | `markdown.py` + `sarif.py` emitters | D | findings | report | jinja2 | M0 |
| 7 | gate + exit code | E | findings | verdict | — | M0 |
| 8 | `profile/promote.py` (+Python extraction) | A | repo | ParseCache | tree-sitter, CAP | M1 |
| 9 | `profile/cpg.py` + `patterns/python.yaml` | A | ParseCache | CPG | rustworkx | M1 |
| 10 | `security-profile.yaml` workflow + task prompts | C | CPG | `ProjectProfile` | CAP, Bedrock | M1 |
| 11 | `profile/drift.py` + `cache.py` | A | manifest+graph | rebuild/incremental | — | M1 |
| 12 | `change/` (filter, classify, context) | A | manifest+profile | `AnnotatedChangeSet`+bundles | triage model | M1 |
| 13 | `sast_semgrep.py` | B | files | Finding | semgrep | M2 |
| 14 | `sca.py` | B | DepDeltas | Finding | osv-scanner | M2 |
| 15 | `iac.py` | B | iac files | Finding | checkov | M2 |
| 16 | `structural.py` | A | CPG | Finding | rustworkx | M2 |
| 17 | `findings/` pipeline (validate→…→normalize) | A | Finding[] | NormalizedFindingSet | — | M2→M4 |
| 18 | `families/broken_access_control` | C | bundle | Finding[BAC] | CAP, CPG | M3 |
| 19 | `families/{injection,crypto,insecure_data}` | C | bundle | Finding | CAP | M3 |
| 20 | `families/{authentication,insecure_design,exceptional,llm_safety}` | C | bundle | Finding | CAP | M3 |
| 21 | `analyze/runner.py` + `coverage.py` | A | change groups | family dispatch + CoverageMap | — | M3 |
| 22 | `verify/` (verifier, reachability, checklist) | C | Finding | Finding[verdict] | CAP, CPG | M4 |
| 23 | `codeql.py` adapter (optional) | B | repo DB | Finding | codeql | M4 (opt) |
| 24 | `orchestrate/` (orchestrator, scout, registries, policy, router, synthesize, feedback) | C/A | findings+registries | ReviewReport+updates | CAP | M5 |
| 25 | `html.py` + `pr_comments.py` emitters | D | findings | dashboard, comments | jinja2, VCS | M5 |
| 26 | `models/provider.py` + `bedrock.py` | E | messages | completion | Strands/Bedrock | M0→M1 |
| 27 | `tracking/` telemetry (extends CAP) | E | run events | telemetry.json | — | M0→ |
| 28 | `safety/` (wrap, sentinel, permissions) | A | text/diff | wrapped/flags | — | M1→ |
| 29 | `benchmark/` (loaders, runner, scoring, metrics, report, gate) | A | BenchCases | scorecard | datasets | M6 |
| 30 | `cli.py` + `pipeline.py` | E | args | run | typer | M0→ |
| 31 | `action.yml` + container | E | CI event | run in CI | Docker | M6 |

## 3. External binary dependency matrix

| Binary | Purpose | Required? | Fallback if missing |
|---|---|---|---|
| `git`, `gh` | extraction, blame, comments | yes (git) | PyGithub for gh |
| `semgrep` | SAST | yes (v1) | disable SAST family-deterministic track (degrade) |
| `osv-scanner` | SCA | yes (v1) | Trivy/Grype; else disable SCA |
| `checkov` | IaC | yes (v1) | tfsec; else disable IaC |
| `gitleaks` | secrets | yes (v1) | detect-secrets |
| `codeql` | deep taint | no (opt) | skip; Semgrep taint covers baseline |
| tree-sitter grammars | parsing | yes | — (core) |

Versions pinned in `pyproject.toml`/`action.yml`; the GitHub Action container bakes them in so CI
is reproducible. Adapters detect+report tool versions in telemetry.

## 4. Development order (cross-referenced to milestones)

M0 → #1–7,26(min),30 (walking skeleton, no AI). M1 → #8–12,28 (the brain). M2 → #13–17 (recall
floor). M3 → #18–21 (semantic findings). M4 → #17(finish),22,23 (precision). M5 → #24,25 (amortize
+ rich output). M6 → #29,31 (trust + ship). Within a milestone, Class-A/B/D tools parallelize;
Class-C families are serialized behind the CPG (#9) and the family base (#18).

## 5. Testing strategy summary

- **Unit (fast, no network/model):** Class A on fixture graphs; Class B on recorded tool output;
  Class D golden files; Class E against base contracts with fakes.
- **Integration (nightly):** real binaries (B), real model calls (C), real GitHub fixture PRs (E).
- **Eval (benchmark, M6):** the harness in `benchmark.md` is the system-level test + regression
  gate.
- **Trust tests:** prompt-injection corpus (comments/strings trying to suppress findings) must not
  change the gate; sentinel must flag them.

## 6. Open engineering choices (safe defaults, revisit if needed)

- Secrets tool: **gitleaks** default (fast, good Python coverage) — detect-secrets alternative.
- SCA tool: **osv-scanner** default (matches Gemini's OSV approach; broad ecosystem) — Trivy/Grype optional.
- IaC tool: **Checkov** default (multi-framework) — tfsec optional.
- Diff library: parse `git` unified diff directly (no heavy dep) vs `unidiff` — start with `unidiff`.
- These are config-swappable (cross-cutting §10) so none is load-bearing.
