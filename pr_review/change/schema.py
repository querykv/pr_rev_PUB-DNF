"""Phase-2 change-analysis contracts (phase-2-change-analysis.md §4, §5).

Turns "a diff + a project model" into a prioritized, contextualized work order
for Phase 3: `AnnotatedChangeSet` (what changed and why it matters) plus one
`ContextBundle` per group (the exact context an agent receives).

Two invariants this schema is built to enforce:

1. **Drops are auditable.** Every file the noise filter removes gets a
   `DropRecord` with a reason. The filter is the pipeline's #1 false-negative
   risk (phase-2 §3), so "what did we not look at" has to be answerable from
   the run artifacts alone.
2. **Context is bounded by construction.** `ContextBundle` has no "the whole
   file" field — full-file access requires setting `escalation`, which the
   planner sets structurally from the CPG. Workers never choose their own files.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from pr_review.extract.schema import Hunk
from pr_review.schema import FlowNode, Severity

# What a change group touches, derived from the CPG rather than from a model
# (phase-2 §4) — this is the routing key into Phase-3b families.
TouchKind = Literal[
    "endpoint", "auth", "authz", "source", "sink",
    "sensitive_field", "config", "dependency",
]

DropReason = Literal[
    "generated",
    "docs_only",
    "formatting_only",      # AST-equal before/after
    "lockfile_captured",    # churn already recorded as a DepDelta
    "binary",
    "triage_not_relevant",  # cheap-model verdict, only for the ambiguous remainder
]


class DropRecord(BaseModel):
    """Why a file/hunk was excluded from analysis (phase-2 §3).

    `guardrail_considered` records that the allow-by-default check ran and did
    not fire — the difference between "the CPG said this file is inert" and
    "we never asked", which is what makes the recall ablation meaningful.
    """
    path: str
    hunk_ids: list[str] = []
    reason: DropReason
    detail: str = ""
    guardrail_considered: bool = True


class ChangeGroup(BaseModel):
    """A cluster of related hunks plus its Phase-3 routing (phase-2 §4)."""
    id: str
    kind: Literal["security", "architecture", "quality", "convention"]
    files: list[str] = []
    hunk_ids: list[str] = []
    touches: list[TouchKind] = []
    candidate_families: list[str] = []     # taxonomy family names, cross-cutting §2
    projected_severity: Severity = Severity.INFO
    confidence: int = Field(default=5, ge=0, le=10)
    significant: bool = False              # significant-changes checklist hit
    rationale: str = ""


class AnnotatedChangeSet(BaseModel):
    """Phase-2 output, written to `02_changeset.json` (phase-2 §1)."""
    repo: str = ""
    pr_number: int
    base_sha: str = ""
    head_sha: str = ""
    profile_version: str = ""              # the profile these annotations were derived against
    groups: list[ChangeGroup] = []
    dropped: list[DropRecord] = []
    coverage_plan: dict = {}               # group_id -> planned families (Phase-4 denominator)

    def planned_families(self) -> set[str]:
        return {f for g in self.groups for f in g.candidate_families}


class CodeSlice(BaseModel):
    """A bounded region of source handed to an agent."""
    file: str
    start_line: int
    end_line: int
    symbol: str | None = None
    content: str = ""                      # UNTRUSTED — wrapped before any prompt use


class ProfileSlice(BaseModel):
    """Only the profile rows relevant to one change group (phase-2 §5).

    Deliberately not the whole `ProjectProfile`: sending the full profile per
    group is the single easiest way to lose the token economy Phase 1 exists to
    buy. Types are loose dicts so `change/context.py` can project rows without
    importing the profile models into every agent payload.
    """
    access_control_rows: list[dict] = []
    auth_summary: str = ""
    sensitive_fields: list[dict] = []
    source_nodes: list[dict] = []
    sink_nodes: list[dict] = []
    sanitizer_nodes: list[dict] = []


class ContextBundle(BaseModel):
    """The exact context a Phase-3b agent receives for one group (phase-2 §5).

    Tier rules: default is hunk + enclosing symbol + 1-hop neighbors + profile
    slice. `full_file` when the hunk touches control flow/guards/early-returns;
    `multi_hop` when a taint question spans several functions. The planner picks
    the tier using zero-cost CPG queries.
    """
    group_id: str
    hunks: list[Hunk] = []
    enclosing_symbols: list[CodeSlice] = []
    neighbors: list[CodeSlice] = []
    profile_slice: ProfileSlice = ProfileSlice()
    reachability_hints: list[FlowNode] = []
    escalation: Literal["none", "full_file", "multi_hop"] = "none"
    escalation_reason: str = ""
