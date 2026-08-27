# Plan 00 — Overview, Architecture & Build Sequencing

> Companion to `../PR_Rev_0620.md` (the locked outline). This file is the architectural
> spine: scope, stack, layout, the contracts between phases, and the order we build in.
> Everything in the other plan docs conforms to the contracts defined here and in
> `cross-cutting.md`.

## 0. Plan document index

| Doc | Covers |
|---|---|
| `00-overview.md` (this) | Architecture, v1 scope, stack, repo layout, phase data-flow, milestones |
| `cross-cutting.md` | Finding schema, taxonomy, severity/confidence, trust, config, gating, outputs |
| `phase-0-extraction.md` | PR/diff/ticket extraction → delta manifest (pure I/O) |
| `phase-1-profiling.md` | CAP-engine profiling → CPG + security profile (amortized) |
| `phase-2-change-analysis.md` | Delta scoping, noise filter, classification, context selection |
| `phase-3-security-analysis.md` | 3a deterministic detectors · 3b agents · 3c verifier · 3d pipeline |
| `phase-4-orchestration.md` | RLM orchestrator, registries, synthesis, gating, reporting, feedback |
| `benchmark.md` | Evaluation harness, datasets, metrics, methodology |
| `tooling.md` | Per-tool dev specs (internal closures + external adapters) |

## 1. What we are building (one paragraph)

A **GitHub-first, Python-first, security-focused PR review tool** that ingests a pull
request, reasons over an amortized project model (the CAP Engine's tree-sitter index +
Context Graph), runs a **deterministic detector sweep** and **agentic deep analysis** over
the diff, passes every candidate through an **independent adversarial verifier**, and emits
a calibrated, taxonomy-tagged, auditable security report plus a SARIF feed, inline PR
comments, and an HTML dashboard. It ships as a `pr-review` CLI that also runs as a GitHub
Action, defaults to Amazon Bedrock (provider-pluggable), and is benchmarked against
real-CVE fixing commits.

## 2. v1 scope — locked decisions (from outline §13)

| Area | v1 decision | Implication |
|---|---|---|
| VCS | **GitHub-first, modular** | `vcs/` adapter interface; only `GitHubAdapter` implemented |
| Language | **Python only** | tree-sitter Python; Django/Flask/FastAPI security patterns; other langs deferred behind same interfaces |
| Model/deploy | **Bedrock default, provider-pluggable, OSS-able** | `models/` provider interface; no data-residency handling needed |
| Detectors | **All in v1**: SAST + secrets + SCA + IaC + agentic | larger v1; sequenced by milestone (see §6) |
| Verifier | **Single** adversarial verifier | ensemble/PoC-sketch documented in docstrings, not built |
| Budget | **Configurable, sane default** | per-PR token ceiling + wall-clock target in `pr_review.yaml` |
| Benchmark | **≈ Gemini ~P90/R93** on real-CVE post-cutoff holdout | approximate, not-directly-comparable bar |

**v1 non-goals** (explicit): non-GitHub VCS; non-Python languages; multi-verifier ensembles;
exploit/PoC generation; IDE plugins; a hosted service/UI beyond the static HTML report;
auto-fix/auto-commit of remediations (we *suggest* diffs, we don't apply them).

## 3. Tech stack

- **Language/runtime:** Python 3.11+.
- **Agent runtime:** Strands SDK on Amazon Bedrock (inherited from CAP). Model access behind
  `models/provider.py` so the agent layer never imports Bedrock directly.
- **Parsing/index:** tree-sitter (`tree_sitter_python` primary; java/js present in CAP), the
  CAP `ParseCache` + call graph.
- **Graph:** rustworkx + SQLite (CAP's CGP server), extended with security node/edge kinds.
- **Data models/validation:** pydantic v2 (Finding schema, config, manifests).
- **CLI:** typer. **Templating:** Jinja2 (HTML/Markdown report). **SARIF:** hand-built model
  conforming to SARIF 2.1.0 (validated against schema in tests).
- **VCS:** GitHub REST/GraphQL via `gh` CLI shell-out and/or PyGithub, behind the adapter.
- **External detectors (subprocess adapters):** Semgrep, CodeQL (optional), gitleaks (or
  detect-secrets), osv-scanner (+ Trivy/Grype optional), Checkov (+ tfsec optional). All
  invoked as subprocesses emitting SARIF/JSON, normalized to the Finding schema.
- **Packaging:** `pyproject.toml`; console entry point `pr-review`; `action.yml` GitHub Action
  wrapping the CLI in a container.

## 4. Repository / package layout

```
PR Review 2026/
├── cap_engine/                  # SUBSTRATE (reused as-is; see context_assembly_writeup.md)
│   ├── framework.py             #   CAPFramework, tool construction, env promotion
│   ├── graph/server.py          #   CGP server (rustworkx + SQLite)
│   ├── environment/             #   code_promoter.py (tree-sitter → ParseCache)
│   ├── orchestration/           #   workflow.py, loop.py
│   ├── inference/orchestrator.py
│   ├── agents/dispatcher.py     #   Strands SDK integration, persona/tool binding
│   ├── tracking/token_tracker.py
│   └── config/                  #   prompts/tasks/*, prompts/templates/*, workflows/*.yaml
│
├── pr_review/                   # THIS TOOL (consumer of cap_engine)
│   ├── cli.py                   # typer entry point: `pr-review review <pr-url>`
│   ├── pipeline.py              # orchestrates Phase 0→4, owns run lifecycle + telemetry
│   ├── config.py                # pydantic config models + pr_review.yaml loader
│   ├── schema.py                # Finding schema, enums (Severity/Status/Family/...)
│   ├── taxonomy/                # canonical families + owasp2025/cwe/asvs mapping tables
│   ├── models/                  # provider.py (interface) + bedrock.py (default)
│   ├── vcs/                     # base.py (adapter interface) + github.py
│   ├── extract/                 # Phase 0  → DeltaManifest
│   ├── profile/                 # Phase 1  → ProjectProfile + CPG (wraps cap_engine workflows)
│   ├── change/                  # Phase 2  → AnnotatedChangeSet + ContextBundles
│   ├── detect/                  # Phase 3a deterministic detectors
│   │   ├── base.py              #   Detector adapter interface
│   │   ├── sast_semgrep.py  codeql.py  secrets.py  sca.py  iac.py  structural.py
│   ├── analyze/                 # Phase 3b agentic detector families (CAP skills/workflows)
│   │   ├── families/            #   broken_access_control.py, injection.py, crypto.py, ...
│   │   └── runner.py            #   maps Phase-2 change groups → family workflows
│   ├── verify/                  # Phase 3c independent verifier
│   ├── findings/               # Phase 3d schema-validate, dedup, delta-scope, calibrate, normalize
│   ├── orchestrate/            # Phase 4 RLM orchestrator + pattern/pipeline registries
│   ├── report/                 # emitters: sarif.py, html.py, markdown.py, pr_comments.py
│   └── benchmark/              # harness, dataset loaders, metrics, ablations
│
├── plan/                        # this planning set
├── PR_Rev_0620.md               # locked outline
├── context_assembly_writeup.md  # CAP engine reference
├── pr_review.yaml               # default config
├── action.yml                   # GitHub Action
└── pyproject.toml
```

**Boundary rule:** `pr_review/` may import `cap_engine/`, never the reverse. CAP stays a
generic code-analysis engine; all security/PR semantics live in `pr_review/`.

## 5. The pipeline as data contracts

Each phase is a pure function of typed inputs → typed outputs (all pydantic; all
serializable to the run directory for replay/audit). This is what lets us test, benchmark,
and resume each phase independently.

```
PR URL
  │  Phase 0  extract/
  ▼
DeltaManifest ───────────────────────────────────────────────┐  (files, hunks, tickets, manifests)
  │  Phase 1  profile/  (amortized; keyed by base_sha)        │
  ▼                                                           │
ProjectProfile + CPG (CGP session snapshot) ─────────────┐    │
  │  Phase 2  change/  (consumes manifest + profile)      │    │
  ▼                                                       │    │
AnnotatedChangeSet  +  ContextBundle[] ──────────────┐   │    │
  │           │                                      │   │    │
  │  Phase 3a detect/         Phase 3b analyze/       │   │    │
  ▼           ▼                                       │   │    │
Finding[candidate]   Finding[semantic] ──────────────┤   │    │   (all = Finding schema)
        │                    │                        │   │    │
        └────────┬───────────┘                        │   │    │
                 ▼  Phase 3c verify/                   │   │    │
        Finding[verdict] ────────────────────────────-┘   │    │
                 ▼  Phase 3d findings/                     │    │
        NormalizedFindingSet + CoverageMap                 │    │
                 ▼  Phase 4 orchestrate/ + report/  ◄──────┴────┘
        ReviewReport (verdict, MD, SARIF, HTML, JSON, PR comments) + RegistryUpdates
```

**Contract table:**

| Producer | Artifact | Key consumers |
|---|---|---|
| Phase 0 | `DeltaManifest` (file/hunk ids, tickets, manifest deltas) | 2 (scope), 3a (targets), benchmark |
| Phase 1 | `ProjectProfile` + `CPG` (security nodes/edges) | 2 (context slices), 3a (sources/sinks), 3b (checklists), 3c (reachability) |
| Phase 2 | `AnnotatedChangeSet` + `ContextBundle[]` | 3a (which files), 3b (which families + context) |
| Phase 3a/3b | `Finding[]` (candidate/semantic) | 3c |
| Phase 3c | `Finding[]` (verdict) | 3d |
| Phase 3d | `NormalizedFindingSet` + `CoverageMap` | 4 |
| Phase 4 | `ReviewReport` + `RegistryUpdates` | user, CI gate, next run |

Detailed field-level schemas live in `cross-cutting.md` (`Finding`) and each phase doc
(`DeltaManifest`, `ProjectProfile`, `AnnotatedChangeSet`, `ContextBundle`, `ReviewReport`).

## 6. Build sequencing — milestones (within v1)

"Ship it all" is large, so v1 is built as **independently demonstrable milestones**, each
end-to-end on a real PR. Earlier milestones de-risk the contracts before the expensive
agentic work.

| M | Goal | Builds | Demo / acceptance |
|---|---|---|---|
| **M0** Walking skeleton | end-to-end thread, no AI | `cli.py`, `pipeline.py`, `vcs/github.py`, `extract/` → manifest, `detect/secrets.py`, `report/markdown.py`+`sarif.py`, gate, `config.py` | run on a real GitHub PR; secrets finding appears in MD + SARIF; gate exit code works |
| **M1** Profiling + change analysis | the amortized brain | wire `cap_engine`; `profile/` (Python CPG + security profile workflow); `findings/` skeleton (schema, dedup); Phase 2 delta/noise/classify | profile a Python repo once; second run is warm; Phase 2 emits change groups + context bundles |
| **M2** Deterministic detector suite | high-recall floor | `detect/` semgrep, sca (osv), iac (checkov), structural (CPG taint-lite); normalization to schema; baseline/delta scoping | all candidate findings normalized, deduped, delta-scoped on a sample PR |
| **M3** Agentic deep analysis | semantic findings | `analyze/families/` starting with **Broken Access Control** (Python authz, the flagship) then Injection, Crypto, Insecure-Data; `analyze/runner.py` | authz workflow reproduces an access-control matrix on a Python app; finds a planted IDOR |
| **M4** Verifier + finding pipeline | precision | `verify/` adversarial verifier; `findings/` full pipeline (calibrate stub, normalize, suppression/allowlist) | verifier refutes a known false positive; precision↑ measured |
| **M5** Orchestration + registries | amortized cost | `orchestrate/` RLM, pattern/pipeline registries, delta-report mode; `report/html.py` + `pr_comments.py` | second PR on same repo skips scout, costs less, posts inline comments + dashboard |
| **M6** Benchmark + tuning | trust | `benchmark/` harness, datasets, metrics, ablations; tune thresholds; `action.yml` | P/R/calibration report vs CVE holdout; regression gate green; runs in GitHub Actions |

Dependency order is strict M0→M6; within a milestone, components may proceed in parallel.
Each milestone closes with: contracts frozen, unit + one integration test, telemetry wired.

## 7. Cross-phase interfaces (the seams that keep it modular)

These five interfaces are the extension points; v1 implements one concrete class each.

1. **`vcs/base.py: VCSAdapter`** — `get_pr(url) -> PRRef`, `get_diff(base, head) -> RawDiff`,
   `get_linked_issues(pr) -> list[Ticket]`, `post_comments(findings)`, `upload_sarif(path)`.
   v1: `GitHubAdapter`.
2. **`models/provider.py: ModelProvider`** — `complete(messages, tools, cfg) -> Response`,
   `cache_point()`, token accounting hook. v1: `BedrockProvider`. (Agents/CAP dispatcher bind
   to this, not to Bedrock directly.)
3. **`detect/base.py: Detector`** — `applicable(manifest, profile) -> bool`,
   `run(targets) -> list[Finding]` (status=`candidate`). One subclass per external tool.
4. **`analyze/families/base.py: DetectorFamily`** — `name`, `taxonomy`, `workflow_yaml`,
   `select(change_set) -> list[ChangeGroup]`, `to_findings(workflow_output) -> list[Finding]`.
   Wraps a CAP workflow.
5. **`report/base.py: Emitter`** — `emit(NormalizedFindingSet, run_ctx) -> Artifact`.
   v1: markdown, sarif, html, pr_comments.

## 8. Run lifecycle & layout on disk

`pipeline.py` creates a run directory per invocation:
```
.pr_review/runs/<repo>/<pr#>-<head_sha>/
  00_manifest.json        # DeltaManifest
  01_profile.ref          # pointer to CGP session + profile snapshot (profile is repo-level, cached)
  02_changeset.json       # AnnotatedChangeSet + context bundle refs
  03_findings.raw.jsonl   # candidate + semantic findings (pre-verify)
  03c_findings.verified.jsonl
  03d_findings.normalized.json
  report.md  report.sarif  report.html  findings.json
  telemetry.json          # tokens/$/wall-clock per phase, coverage, tool traces
  trace/                  # per-agent logs (CAP-style cycle subdirs)
```
Repo-level caches (profile/CPG, registries, baseline, calibration) live under
`.pr_review/cache/<repo>/` so they amortize across PRs. Everything is replayable from these
artifacts.

## 9. Top risks & mitigations (carried into the phase docs)

| Risk | Mitigation | Owner doc |
|---|---|---|
| Python flagship gap (CAP authz proven on Java) | M3 builds Python framework patterns first; benchmark catches regressions | phase-1, phase-3 |
| Noise-filter false negatives (recall leak) | allow-by-default for profile-touching files; measure recall after filter | phase-2, benchmark |
| Verifier over-refutes (recall cost) | ablation measures recall cost; tune refutation strictness | phase-3, benchmark |
| Benchmark contamination (model memorized CVEs) | temporal post-cutoff holdout; report pre/post split | benchmark |
| Cost blowups on big PRs | budget gate + tiered models + diff-scoping + large-diff chunking | phase-1, cross-cutting |
| Prompt injection from source/tickets | data-not-instructions wrapping + structural tool perms + injection sentinel | cross-cutting |
| External tool drift (semgrep/codeql versions) | pin versions; adapters tolerate schema changes; SARIF as the stable contract | tooling |

## 10. Definition of done for v1

End-to-end on a real GitHub Python PR: extracts → profiles (amortized) → detects (all
families) → verifies → reports (MD+SARIF+HTML+PR comments) with a gate decision; benchmark
shows detection ≈ Gemini's P90/R93 ballpark on a real-CVE post-cutoff holdout with FP rate
reported on a clean-PR negative set; second PR on the same repo is measurably cheaper; runs
locally and as a GitHub Action; every finding is traceable to file·line·evidence·confidence.
