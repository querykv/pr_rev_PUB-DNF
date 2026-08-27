"""ProjectProfile schema (phase-1-profiling.md §5) + CPG security kinds (§4).

The amortized, repo-level security model that Phase 2 slices, Phase 3a seeds
sources/sinks from, Phase 3b builds checklists against, and Phase 3c uses for
reachability. Produced by the CAP security-profile workflow and cached under
`.pr_review/cache/<repo>/profile/<profile_version>/`.

The `access_control_matrix` is the flagship artifact: it powers Broken Access
Control (A01) in Phase 3 and is extracted deterministically from worker
`structured` output, not re-summarized by a model.

This module deliberately imports nothing from `cap_engine` — the profile is our
contract, and CAP is only the engine that fills it in.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

# --------------------------------------------------------------------------
# CPG security overlay kinds (phase-1 §4)
#
# Declared here rather than in cpg.py so change/ and detect/structural.py can
# reference them without importing the graph builder. The CGP `ContextNode.kind`
# and `Edge.relation` fields are free-form strings, so these ride on top of the
# CAP schema without modifying it.
# --------------------------------------------------------------------------

SecurityNodeKind = Literal[
    "endpoint",          # externally reachable entry point
    "role",              # a named principal role
    "permission",        # a discrete capability a role may hold
    "source",            # untrusted input: request params/body/headers, env, file, queue
    "sink",              # dangerous op: SQL exec, subprocess, eval, render, open, deserialize
    "sanitizer",         # neutralizes taint for a given sink class
    "trust_boundary",    # process/network/privilege transition
    "sensitive_field",   # PII- or secret-typed data
]

SecurityEdgeKind = Literal[
    "guards",       # auth check -> endpoint
    "authorizes",   # role -> endpoint/action
    "taints",       # source -> ... -> sink along call/data flow
    "sanitizes",    # sanitizer -> tainted path
    "exposes",      # endpoint -> sensitive_field
]

# Sink classes are what make "sanitizes" meaningful: a shell-quoting sanitizer
# does not neutralize an SQL sink. Detectors and the taint-lite walk match on
# this, not on the sanitizer's name.
SinkClass = Literal[
    "sql", "command", "code_exec", "template", "path", "deserialize",
    "http_outbound", "log", "response",
]


# --------------------------------------------------------------------------
# Profile sub-models — one per template question (phase-1 §5)
# --------------------------------------------------------------------------

class Component(BaseModel):
    """A logical unit of the system (service, module, package)."""
    name: str
    role: str = ""                      # what it does, in one line
    location: list[str] = []            # repo-relative paths/globs
    access_control: str = ""            # how access to it is gated, if at all
    data_sensitivity: Literal["none", "internal", "confidential", "regulated"] = "none"


class Architecture(BaseModel):
    patterns: list[str] = []            # "layered", "event-driven", "MVC", ...
    data_flow: list[str] = []           # prose edges: "web -> service -> repo -> postgres"
    integrations: list[str] = []        # third-party systems this talks to


class IOChannel(BaseModel):
    """An externally-facing input or output surface (outline Phase 1.2)."""
    name: str
    kind: Literal["http_api", "ui", "queue", "cron", "cli", "export",
                  "notification", "log", "file", "webhook"]
    direction: Literal["inbound", "outbound", "bidirectional"] = "inbound"
    authenticated: bool | None = None
    description: str = ""


class CodeFlow(BaseModel):
    """Channel -> file-path map: where a given I/O channel is implemented."""
    channel: str                        # IOChannel.name
    files: list[str] = []
    entry_symbols: list[str] = []       # "module.Class.method"


class Role(BaseModel):
    name: str
    description: str = ""
    source: str = ""                    # where the role is defined (constant, enum, IdP claim)
    inherits: list[str] = []


class PermissionCheck(BaseModel):
    """A concrete authorization enforcement point found in the code."""
    name: str                           # "login_required", "IsAdminUser", ...
    kind: Literal["decorator", "middleware", "dependency", "mixin",
                  "inline_conditional", "policy_class", "other"]
    file: str
    line: int | None = None
    grants: list[str] = []              # roles/permissions this check admits


class AuthModel(BaseModel):
    """Authentication: who the caller is (phase-1 §5)."""
    methods: list[str] = []             # "session_cookie", "jwt", "oauth2", "api_key", "mtls"
    session_management: str = ""
    mfa: bool | None = None
    password_policy: str = ""
    notes: list[str] = []


class AuthzModel(BaseModel):
    """Authorization: what the caller may do (phase-1 §5)."""
    model: Literal["rbac", "abac", "acl", "ownership", "mixed", "none", "unknown"] = "unknown"
    resource_level_controls: bool | None = None
    default_posture: Literal["deny", "allow", "unknown"] = "unknown"
    enforcement_points: list[str] = []  # PermissionCheck names, in enforcement order
    notes: list[str] = []


class SensitiveField(BaseModel):
    """PII- or secret-typed data, for privacy/logging analysis (A09/A04)."""
    name: str
    classification: Literal["pii", "credential", "financial", "health", "secret", "other"]
    locations: list[str] = []           # "module.Model.field" or file paths
    exposed_by: list[str] = []          # endpoint names that return it


class AccessControlRow(BaseModel):
    """One row of the flagship access-control matrix (phase-1 §5).

    `enforcement` is the finding-bearing field: `declared_not_enforced` means a
    role requirement is documented or annotated but no runtime check backs it —
    which is a Broken Access Control candidate on its own.
    """
    endpoint: str
    http_method: str
    controller: str
    required_roles: list[str] = []
    auth_pattern: str = "none"          # "decorator:login_required" | "dependency:get_current_user" | "none"
    enforcement: Literal["enforced", "declared_not_enforced", "none"] = "none"
    file: str = ""
    line: int | None = None


# --------------------------------------------------------------------------
# The profile
# --------------------------------------------------------------------------

class ProjectProfile(BaseModel):
    """The amortized project model (phase-1 §5).

    `profile_version` is the base_sha of the last **full** build; incremental
    updates patch the profile in place and leave it unchanged (§6), so a run's
    `01_profile.ref` stays a stable pointer for replay.
    """
    repo: str
    profile_version: str

    description: str = ""
    tech_stack: list[str] = []
    cloud_services: list[str] = []

    components: list[Component] = []
    architecture: Architecture = Architecture()
    io_channels: list[IOChannel] = []
    code_flows: list[CodeFlow] = []

    roles: list[Role] = []
    permission_checks: list[PermissionCheck] = []
    authentication: AuthModel = AuthModel()
    authorization: AuthzModel = AuthzModel()

    access_control_matrix: list[AccessControlRow] = []
    sensitive_fields: list[SensitiveField] = []

    notes: list[str] = []

    built_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    build_kind: Literal["full", "incremental"] = "full"

    # How many matrix rows carry agent judgement rather than the structural
    # floor. Recorded on the profile, not just on the transient `ProfileBuild`,
    # because a *cached* profile otherwise cannot tell you whether it was ever
    # lifted — and `profile/incremental.py` has to know that to report what a
    # re-derived row lost.
    agent_rows_merged: int = 0

    def endpoints(self) -> list[str]:
        """Distinct endpoints in the matrix, for coverage accounting."""
        return sorted({row.endpoint for row in self.access_control_matrix})

    def unguarded_endpoints(self) -> list[AccessControlRow]:
        """Rows with no effective enforcement — the A01 candidate set.

        Includes `declared_not_enforced` deliberately: a documented-but-absent
        check is the more interesting finding of the two, because the intent is
        on record.
        """
        return [r for r in self.access_control_matrix if r.enforcement != "enforced"]
