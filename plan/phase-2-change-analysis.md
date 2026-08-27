# Plan — Phase 2: Change Analysis

> Turns "a diff + a project model" into "a prioritized, contextualized work order for Phase 3."
> Mostly deterministic + a cheap triage model; the expensive agents don't run here. Package:
> `pr_review/change/`. The **noise filter here is the pipeline's #1 false-negative risk**, so it
> is recall-guarded and benchmarked.

## 1. Contract

- **Input:** `DeltaManifest` (Phase 0), `ProjectProfile` + `CPG` (Phase 1), `Config`.
- **Output:** `AnnotatedChangeSet` (`02_changeset.json`) + `ContextBundle[]` (one per change
  group) — the precise context Phase 3b agents receive.

## 2. Step 1 — Incremental profile sync

Delegates to `profile/drift.py` (Phase 1 §6): ensure the profile reflects this PR's changes
(incremental update or rebuild). Phase 2 then **consumes** the up-to-date profile/CPG. No
regeneration logic lives here.

## 3. Step 2 — Noise filter (recall-guarded)

Goal: drop security-irrelevant changes so agents aren't wasted — **without dropping anything a
vuln could hide in.** Three tiers, cheapest first:

1. **Deterministic drop** (from manifest flags, zero cost): `is_generated`, pure
   formatting/whitespace hunks (AST-equal before/after via tree-sitter), docs-only
   (`*.md`/`*.rst` with no code), lockfile churn already captured as `DepDelta`.
2. **Allow-by-default guardrail** (overrides drops): **never** drop a file that the CPG/profile
   marks as touching `source`/`sink`/`endpoint`/`auth`/`sensitive_field`, even if it looks
   test-like or trivial. Security-relevant beats "looks boring."
3. **Cheap-model triage** (only for the ambiguous remainder): the `triage` model (cheap, temp 0)
   labels each remaining hunk `security_relevant ∈ {yes,no,maybe}`; `maybe` is kept.

**Test changes are not silently dropped** — a *deleted or weakened* security test (e.g., removed
authz assertion) is itself a signal and becomes a `quality`/`security` change group. Filter
decisions are logged per file with reasons (auditability + the recall ablation in `benchmark.md`,
which measures recall **after** this stage as a first-class metric).

## 4. Step 3 — Classification & the change→file→group graph

`change/classify.py` groups surviving hunks into **change groups** and annotates them using the
CPG (structural, cheap) + the triage model (labels only):

```python
class ChangeGroup(BaseModel):
    id: str
    kind: Literal["security","architecture","quality","convention"]
    files: list[str]; hunk_ids: list[str]
    touches: list[Literal["endpoint","auth","authz","source","sink",
                           "sensitive_field","config","dependency"]]   # from CPG
    candidate_families: list[str]            # which Phase-3b families to run (taxonomy §2)
    projected_severity: Severity             # cheap prior, refined later
    confidence: int                          # triage confidence in the routing
    significant: bool                        # significant-changes checklist hit
    rationale: str

class AnnotatedChangeSet(BaseModel):
    pr_number: int; base_sha: str; head_sha: str
    groups: list[ChangeGroup]
    dropped: list[DropRecord]                # what the filter removed + why (audit)
    coverage_plan: dict                      # groups → planned families (for coverage eval)
```

**Significant-changes checklist** (sets `significant=True`, routes to deep dive): auth/authz
logic · new/modified API endpoints · sensitive-data handling · new I/O channels ·
architecture/config changes · business logic around sensitive actions. Detection is
CPG-driven (e.g., a hunk that adds a node with an `endpoint`/`guards` edge → endpoint/authz
change) so it's deterministic, not vibes.

**Family routing** (`candidate_families`): map `touches` → families, e.g. `endpoint`+`authz` →
Broken Access Control; `sink`+tainted `source` → Injection; `sensitive_field`+log sink →
Privacy/Logging; `dependency` → handled by SCA in 3a (no agent). A change can map to several
families. This list is the contract Phase 3b's `runner.py` consumes.

## 5. Step 4 — Context selection (tiered)

`change/context.py` builds one `ContextBundle` per group — the **exact** context an agent gets,
resolving outline §2.5 ("what context is necessary"). Tiered, never full-file-by-default:

```python
class ContextBundle(BaseModel):
    group_id: str
    hunks: list[Hunk]                                 # the change itself
    enclosing_symbols: list[CodeSlice]                # function/method around each hunk
    neighbors: list[CodeSlice]                         # 1-hop callers/callees from call graph
    profile_slice: ProfileSlice                        # only the relevant profile rows:
        # endpoint's access-control row(s), data-sensitivity tags of touched fields,
        # auth model summary, relevant source/sink/sanitizer nodes
    reachability_hints: list[FlowNode]                 # CPG taint-lite paths through the hunk
    escalation: Literal["none","full_file","multi_hop"] = "none"
```

**Tier rules:** default = hunk + enclosing symbol + 1-hop neighbors + profile slice. **Escalate
to `full_file`** when the hunk touches control flow/guards/early-returns (the surrounding logic
matters). **Escalate to `multi_hop`** when a taint/reachability question spans several functions.
Escalation is decided structurally by the **planner using zero-cost CPG tools** — workers never
choose their own files (preserves the CAP separation + token economy).

## 6. Output to Phase 3

- 3a (deterministic) consumes the **manifest targets** (changed files) directly + `DepDelta`s; it
  does not need change groups (it scans broadly for recall).
- 3b (agentic) consumes `ChangeGroup` + `ContextBundle` (which families, what context).
- The `coverage_plan` is the denominator for Phase 3/4 **coverage evaluation** (planned vs
  actually-analyzed groups).

## 7. Components & files

| File | Responsibility |
|---|---|
| `change/filter.py` | three-tier noise filter + recall guardrail + drop log |
| `change/classify.py` | change groups, CPG-driven `touches`/`significant`, family routing |
| `change/context.py` | tiered context bundle assembly + escalation decision |
| `change/schema.py` | `ChangeGroup`, `AnnotatedChangeSet`, `ContextBundle`, `ProfileSlice` |

## 8. Tests & acceptance (M1)

- Unit: formatting-only detection (AST equality), guardrail override (a "trivial" change to an
  endpoint file is kept), family-routing table, escalation rules.
- Recall test: a labeled PR set where the filter must keep 100% of vuln-bearing files (feeds the
  benchmark recall-after-filter metric).
- **Acceptance:** on a sample PR, Phase 2 emits coherent change groups with correct `touches`
  from the CPG, sensible family routing, and minimal context bundles (no full files unless the
  escalation rule fires); dropped files all have audit reasons.
