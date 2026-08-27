# Plan — Phase 4: Orchestration & Synthesis

> The meta layer: decides *what analysis to run* (cold start vs. warm), coordinates families
> across a run, **synthesizes** the final report, makes the **gate decision**, manages the
> **pattern/pipeline registries** for cross-run learning, and captures **feedback**. Package:
> `pr_review/orchestrate/` + `report/`.

## 1. Boundary vs. CAP and vs. Phase 3 (avoid duplication)

CAP already runs the **per-task** Planner→Worker→Synthesizer loop *inside* each Phase-3b family.
Phase 4 is the **Recursive Language Model (RLM) meta-orchestrator** one level up:

- **CAP loop** = "analyze this one family/task well." (reused)
- **Phase 4** = "for this PR, which families/patterns to run, in what order, reusing what prior
  knowledge; then synthesize and decide." It recursively decomposes the *review* task and
  delegates to children: **scout** (discovery), **workers** (= Phase-3b family runs), and a
  **synthesizer** (final report). It owns the registries, gate, report, and feedback.

## 2. Contract

- **Input:** `AnnotatedChangeSet`, `ProjectProfile`/`CPG`, the live `NormalizedFindingSet` +
  `CoverageMap` (Phase 3d), prior-run registries + baseline.
- **Output:** `ReviewReport` (verdict + artifacts), `RegistryUpdates`, updated calibration +
  allowlist; the CI gate exit code.

## 3. Orchestration flow (per run)

```
START
 ├─ load registries (pattern, pipeline) + profile + baseline for this repo
 ├─ is this a COLD start (no patterns for this app/domain)?
 │     ├─ YES → spawn SCOUT: deep structural discovery (auth patterns, framework idioms,
 │     │        source/sink conventions) → register PATTERNS + a reusable PIPELINE
 │     └─ NO  → skip scout; reuse registered patterns/pipeline (warm path = cheaper)
 ├─ plan family execution from Phase-2 routing ∩ registered pipeline
 ├─ run WORKERS sequentially (= Phase-3b families), each injected with prior workers' results
 │        (CAP cross-task injection) and relevant registered patterns
 ├─ verify (3c) + finalize (3d)              # findings pipeline
 ├─ COVERAGE check: any uncovered `significant` group? → optional extra cycle (budget-gated)
 ├─ SYNTHESIZE: synthesizer builds the ReviewReport from findings + coverage + profile
 ├─ GATE decision (cross-cutting §8) → verdict
 ├─ EMIT artifacts (report/: markdown, sarif, html, pr_comments, json)
 ├─ REGISTRY update (new patterns learned this run) + telemetry
 └─ DONE (snapshot session for replay/cross-run reuse)
```

Workers run sequentially (informed by prior results) in v1; parallel dispatch is a documented
future optimization (CAP limitation #4). Budget gating (CAP, `budget.gate_fraction`) bounds the
whole run.

## 4. Registries (cross-run learning)

`orchestrate/registries.py`, persisted under `.pr_review/cache/<repo>/registries/`.

```python
class Pattern(BaseModel):           # a learned multi-step search strategy
    id: str; domain: str            # "flask-auth", "django-drf-permissions"
    family: str; steps: list[str]   # structural query plan that found auth/sinks last time
    evidence_uris: list[str]; hits: int; precision_prior: float
    learned_at: datetime; last_used: datetime

class Pipeline(BaseModel):          # a reusable analysis workflow for a familiar app
    id: str; app_fingerprint: str   # ties to the CPG environment fingerprint
    family_order: list[str]; pattern_ids: list[str]
    runs: int; avg_tokens: int
```

- **Scout** registers `Pattern`s on cold starts (e.g., "this app gates routes via a
  `@require_role` decorator defined in `auth/decorators.py`"). Subsequent PRs reuse them →
  orchestrator can start workers directly, skipping discovery → **decreasing cost over time**
  (Principle #4).
- **Pipeline** records the family order/cost that worked for this app → warm runs replay it and
  emit a **delta report** (only what changed since last review).
- Patterns carry a `precision_prior` updated from verifier outcomes + feedback (a pattern that
  keeps producing false positives is demoted).

## 5. Added capabilities (resolves outline §4 "suggest useful capabilities")

| Capability (`orchestrate/`) | Purpose |
|---|---|
| `CalibrationRegistry` | raw confidence → empirical P(correct); from benchmark + feedback; used by `findings/calibrate.py` |
| `FalsePositiveMemory` | per-project learned suppressions (fingerprints repeatedly dismissed) → auto-lowered confidence |
| `policy.py` (gate engine) | severity×confidence gate + per-family floors (cross-cutting §8) |
| delta-report mode | warm runs report only new/changed findings vs last review |
| `model_router.py` / cost governor | tiered model routing + budget enforcement (config `models.roles`, `budget`) |
| replay/audit | re-run any phase from run-dir artifacts; full provenance |
| regression-eval hook | every pipeline change runs `benchmark/` as a gate (CI) |
| feedback intake | reviewer accept/dismiss → `allowlist.yaml` + calibration data + FP memory |

## 6. Synthesis & report generation

`orchestrate/synthesize.py` spawns the **Synthesizer** (CAP, single `assemble` tool) over the
`NormalizedFindingSet` + `CoverageMap` + profile summary → the `ReviewReport`:

```python
class ReviewReport(BaseModel):
    verdict: Literal["approved","flagged"]
    summary: str                              # human exec summary
    per_change: list[ChangeAnalysis]          # change group → findings + rationale
    findings: list[Finding]                   # validated + pre_existing (sorted)
    remediation: list[RemediationItem]        # prioritized, severity×calibrated-confidence
    coverage: CoverageMap                     # analyzed vs not (honesty)
    cost: CostSummary                         # tokens/$/wall-clock (telemetry)
    artifacts: dict[str,str]                  # paths: md, sarif, html, json
```

The synthesizer writes prose (summary/rationale); **everything machine-readable (verdict,
findings, SARIF, gate) is computed deterministically**, not by the LLM — so the gate can't be
talked out of a finding by injected text (trust boundary). Emission delegates to `report/`
(cross-cutting §7).

## 7. Components & files

| File | Responsibility |
|---|---|
| `orchestrate/orchestrator.py` | the RLM flow (§3), cold/warm decision, cycle control |
| `orchestrate/scout.py` | cold-start discovery persona; registers patterns/pipeline |
| `orchestrate/registries.py` | Pattern/Pipeline registries + calibration + FP memory |
| `orchestrate/policy.py` | gate engine + delta-report logic |
| `orchestrate/model_router.py` | tiered routing + cost governor |
| `orchestrate/synthesize.py` | synthesizer → `ReviewReport` |
| `orchestrate/feedback.py` | ingest reviewer accept/dismiss → allowlist/calibration/FP memory |
| `report/{markdown,sarif,html,pr_comments}.py` | emitters |

## 8. Tests & acceptance (M5)

- Unit: gate decision truth table; registry promote/demote on verifier outcomes; delta-report
  diffing; model-router selection per role.
- **Cross-run test:** first PR on a repo runs the scout and registers patterns; **second PR skips
  the scout**, costs measurably fewer tokens (telemetry assertion), and produces a delta report.
- **Acceptance:** end-to-end on a real PR → correct verdict, a coherent `ReviewReport`, inline PR
  comments only for introduced+validated findings, an HTML dashboard, and a SARIF upload; feedback
  on a dismissed finding suppresses it on the next run.
