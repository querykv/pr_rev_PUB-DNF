# Plan — Phase 3: Security Analysis

> The heart of the tool. Four stages: **3a** deterministic detectors (high recall, cheap) →
> **3b** agentic deep analysis (semantic findings SAST can't see) → **3c** independent
> adversarial verifier (precision) → **3d** finding pipeline (normalize, calibrate, emit-ready).
> All stages speak the **Finding schema** (cross-cutting §1). Packages: `pr_review/detect/`,
> `analyze/`, `verify/`, `findings/`.

---

## 3a. Deterministic candidate generation (the SAST track)

`detect/`. Runs on the diff + touched files **before** any LLM work. Every adapter implements
`Detector` (overview §7.3), runs as a subprocess, parses native output (prefer SARIF), and
**normalizes to `Finding` with `status=candidate`, `detector ∈ {sast,secrets,sca,iac,structural}`**.
High recall is the goal; precision comes later (3c).

| Adapter (`detect/`) | Tool (default) | Targets | Emits (families) | Notes |
|---|---|---|---|---|
| `sast_semgrep.py` | Semgrep (`p/python` + custom) | changed files | Injection, Crypto, Misconfig, Logging | **diff-aware** (`--baseline-commit base_sha`); taint mode for source→sink; SARIF out |
| `codeql.py` *(optional)* | CodeQL | whole repo (DB) | Injection, BAC(SSRF), Integrity | deep taint; async (DB build); off by default (`codeql.enabled=false`); gated on budget |
| `secrets.py` | gitleaks (or detect-secrets) | diff | Hardcoded Secrets | scans **added** lines; entropy + rule based |
| `sca.py` | osv-scanner (+ Trivy/Grype opt.) | `DepDelta`s | Supply Chain (A03) | uses Phase-0 dep deltas → query OSV; only **newly added/changed** deps |
| `iac.py` | Checkov (+ tfsec opt.) | `is_iac` files | Misconfiguration (A02) | Terraform/Docker/k8s |
| `structural.py` | **our CPG** (no subprocess) | CPG taint-lite | BAC, Injection, Exceptional | app-specific structural rules (ast-grep-style) over Phase-1 graph; feeds 3b cheap context |

**"Semgrep vs AST crawling" resolution (outline):** both, layered — Semgrep/CodeQL for breadth
and community rules; `structural.py` for app-specific rules the external tools can't express and
to reuse the CPG we already built. `detect/normalize.py` maps each tool's rule id → our taxonomy
(`taxonomy/` tool-rule maps) and assigns a per-rule confidence prior.

**Adapter contract & resilience:** pinned tool versions; missing tool → adapter disabled with a
telemetry warning (degrade, don't crash); SARIF is the stable interface so tool upgrades rarely
break us. Each adapter is independently unit-tested with recorded fixtures.

**Why first:** sets a recall floor, avoids spending tokens on clean PRs (if 3a + structural find
nothing in a group and the group isn't `significant`, 3b may skip it), and gives the benchmark a
baseline to prove agentic lift.

---

## 3b. Taxonomy-driven agentic deep analysis

`analyze/`. For `significant` change groups and for what SAST structurally misses — **Broken
Access Control, Insecure Design, business logic, auth bypass, intent mismatch**. Each detector
**family** is a CAP skill/workflow with an ASVS-derived checklist.

### Family interface (`analyze/families/base.py`)

```python
class DetectorFamily(Protocol):
    name: str                       # "broken_access_control"
    taxonomy_internal_prefix: str   # "BAC-"
    workflow_yaml: str              # cap_engine workflow path
    asvs_checklist: list[str]
    def select(self, cs: AnnotatedChangeSet) -> list[ChangeGroup]: ...   # which groups apply
    def to_findings(self, workflow_output, ctx: ContextBundle) -> list[Finding]: ...
```

`analyze/runner.py` reads each group's `candidate_families` (Phase 2) and dispatches the matching
family workflow with that group's `ContextBundle`. Families run as CAP workflows reusing the
**Planner→Worker→Synthesizer** loop and the **structural separation** (planner reads structure
only; workers read source; cross-task knowledge injection between families).

### v1 families (build order = M3)

1. **`broken_access_control`** (flagship, built first — A01). Reuses the writeup's
   role-authorization workflow, Python-adapted: role discovery → endpoint mapping → access-control
   matrix → **diff overlay** (does this PR add an endpoint with no `guards` edge? weaken an authz
   check? introduce IDOR by trusting a client-supplied id?). Consumes the Phase-1 matrix so it
   reasons about *deltas*, not from scratch.
2. **`injection`** (A05) — confirms/extends 3a taint candidates with semantic reachability
   (is the source truly attacker-controlled? is there a real sink?). Covers SQLi/XSS/cmd/SSTI/
   deserialize.
3. **`crypto`** (A04) — weak algos, hardcoded keys in context, missing TLS, bad randomness.
4. **`insecure_data_handling`** (A04/A09) — sensitive logging, PII to third parties, unsafe
   deserialization (overlaps injection; dedup in 3d).
5. **`authentication`** (A07), **`insecure_design`** (A06), **`exceptional_conditions`** (A10),
   **`llm_safety`** (prompt-injection/unsafe-output in the *reviewed* code) — built after 1–4.

Each family emits `Finding`s with `detector=agent`, `tool="cap-agent:<family>"`, evidence with
verbatim snippets, `confidence` per the band rubric, and `data_flow`/`reachability` from the CPG.

### Coverage evaluation

`analyze/coverage.py` tracks, quantitatively, planned groups×families (Phase 2 `coverage_plan`)
vs. actually-analyzed → a `CoverageMap`. Uncovered `significant` groups are surfaced in the
report (honesty about blind spots) and can trigger another orchestration cycle (Phase 4).

---

## 3c. Independent verification / triage

`verify/`. A **mandatory gate** every candidate/finding passes before Phase 3d. Separate agent
class with **its own context**, given only **claim + evidence pointers** (not the finder's
reasoning) to avoid anchoring. **Objective: adversarially refute.** This is the main precision
lever and the unifying triage for both noisy 3a candidates and 3b findings.

### Verifier procedure (`verify/verifier.py`)

For each finding (batched by file for cache efficiency):

1. **Refutation checklist** (adapted from Gemini's "Final Review Filter"). Auto-refute unless ALL
   hold: in **executable, non-test** code · **specific line(s)** identifiable · **direct
   evidence**, not a framework assumption · **developer-fixable** via a code change · **plausible
   production impact**. Auto-refute classes: hypothetical dep vulns (except documented
   CVEs/SCA-confirmed), commented-out code, test/placeholder values, pure architecture opinions.
2. **Reachability & compensating controls** (uses CPG + targeted reads): is there a real
   source→sink path? is the entry attacker-reachable? is input sanitized upstream / auto-escaped
   by the framework / guarded by auth? → **confirm / downgrade severity / refute**.
3. **Verdict** written to `verification`: `confirmed | refuted | uncertain` + adjusted
   severity/confidence + the refutation attempts (audit trail). `confirmed` → `status=validated`;
   `refuted` → dropped to audit log; `uncertain` → kept at reduced confidence, flagged for human.

### Independence & configuration

- `verifier` model pinned **temperature 0** (determinism) and may differ from the finder model
  (`models.roles.verifier`).
- **v1 = single verifier.** Docstrings document the deferred alternatives (cross-cutting/outline
  §13.5): a **second independent verifier (ensemble)** for Critical findings, and a
  **PoC/exploit-sketch** step for the highest severity (cf. CVE-GENIE). `refute_strictness`
  config (`lenient|standard|strict`) tunes the precision/recall trade-off — set by the benchmark.
- The benchmark runs a **verifier ablation**: precision before vs. after 3c, and the recall cost
  (did it refute any true positives?). This is how we keep it from over-refuting.

---

## 3d. Finding pipeline (deterministic where possible)

`findings/`. Turns the raw, multi-source finding stream into a clean, calibrated, emit-ready set.
Order matters:

```
validate → cross-source dedup → merge → delta-scope → severity finalize → calibrate → suppress → normalize
```

| Step (`findings/`) | What it does |
|---|---|
| `validate.py` | enforce schema invariants (cross-cutting §1); reject malformed agent output (re-ask once) |
| `dedup.py` | collapse SAST ∪ agent ∪ verifier findings on **fingerprint** (cross-cutting §6); keep richest evidence; record all contributing detectors in provenance |
| `merge.py` | merge a 3a candidate + its 3b confirmation into one finding (higher confidence than either alone — agreement signal) |
| `delta.py` | compute `introduced_by_pr` vs the base-branch **baseline**; mark pre-existing (cross-cutting §5) |
| `severity.py` | finalize severity incl. reachability downgrade/upgrade + CVSS v4 vector |
| `calibrate.py` | map raw confidence → calibrated P(correct) via `CalibrationRegistry` (Phase 4) |
| `suppress.py` | apply `allowlist.yaml` by fingerprint → `status=suppressed` |
| `normalize.py` | final ordering (severity×confidence), produce `NormalizedFindingSet` + `CoverageMap` |

**Output → `03d_findings.normalized.json`.** The **visualizer** (HTML dashboard) and SARIF/PR
comments are emitted here via `report/` (cross-cutting §7) — the visualizer is a deterministic
render of this set, not a separate analysis.

---

## 4. Components & files (Phase 3 overall)

| Area | Files |
|---|---|
| 3a | `detect/base.py`, `sast_semgrep.py`, `codeql.py`, `secrets.py`, `sca.py`, `iac.py`, `structural.py`, `normalize.py` |
| 3b | `analyze/families/base.py` + one module per family, `analyze/runner.py`, `analyze/coverage.py`, CAP workflows under `cap_engine/config/workflows/` |
| 3c | `verify/verifier.py`, `verify/reachability.py`, `verify/checklist.py` |
| 3d | `findings/{validate,dedup,merge,delta,severity,calibrate,suppress,normalize}.py`, `findings/schema.py` (`NormalizedFindingSet`, `CoverageMap`) |

## 5. Tests & acceptance

- **3a (M2):** each adapter normalizes its tool's output to valid `Finding`s on fixtures; missing
  tool degrades gracefully; dedup across two detectors works; delta-scoping marks pre-existing.
- **3b (M3):** the BAC family reproduces an access-control matrix on a Python target and flags a
  **planted IDOR / missing-authz** endpoint with correct taxonomy + evidence; injection family
  confirms a real taint and rejects a sanitized one.
- **3c (M4):** verifier **refutes a known false positive** (e.g., a Semgrep hit on test/placeholder
  code) and **confirms a true positive**, with reachability reasoning recorded; precision↑ vs.
  pre-verify measured.
- **3d:** golden-file test of the full pipeline on a mixed finding set → stable
  `NormalizedFindingSet` (ordering, dedup, statuses) + correct `CoverageMap`.
- **End-to-end (M2→M4):** on a sample PR, candidates flow 3a→3b→3c→3d into a normalized set with
  no schema violations and a coverage map covering all `significant` groups.
