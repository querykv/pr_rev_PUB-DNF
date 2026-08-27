"""Assemble the `ProjectProfile` (phase-1-profiling.md §5).

**Deterministic floor, agent lift.**

The profile is built in two layers. The floor comes from `promote.py` and
`cpg.py`: every endpoint, its guards, its file and line, the sensitive fields,
the source→sink paths. That layer costs zero tokens, cannot hallucinate, and is
complete by construction. The lift comes from the CAP `security-profile`
workflow, which judges what the floor can only observe — whether a guard is the
*right* guard, whether an authenticated endpoint still leaks through an
unchecked object identifier, what the data actually is.

The floor is emitted whether or not the workflow succeeds. That is not defensive
padding: it is what makes the profile trustworthy. A workflow that half-runs, or
runs against a provider with no model behind it, then yields a profile that is
*incomplete* rather than *wrong* — every endpoint still present, with structural
enforcement and lowered confidence, instead of a matrix silently missing rows.

One thing the floor deliberately cannot produce is `declared_not_enforced`. That
value means "a requirement is stated and nothing backs it", which is a judgement
about intent — no structural pass can make it. The floor emits `enforced` or
`none`; upgrading a row to `declared_not_enforced` is the single highest-value
thing the agent layer adds, and phase-1 §5 marks it as such.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pr_review.config import Config
from pr_review.profile.cpg import CPG, build_cpg
from pr_review.profile.promote import Endpoint, PromotionResult, promote
from pr_review.profile.schema import (
    AccessControlRow,
    CodeFlow,
    IOChannel,
    PermissionCheck,
    ProjectProfile,
    SensitiveField,
)

WORKFLOW_NAME = "security-profile"

# `Endpoint.guard_kind` -> `PermissionCheck.kind`. Both FastAPI kinds that record
# where a dependency was *declared* collapse to `dependency` here: the schema's
# Literal describes the enforcement mechanism, and all three are the same
# mechanism. Widening the Literal to keep the distinction would put a
# declaration-site detail into a field about mechanism, and the distinction is
# already carried losslessly by `auth_pattern` in the matrix.
#
# Every kind must appear here. The `.get(..., "other")` fallback below is a
# fallback, not a default: an unmapped kind is silently downgraded, which is how
# a new guard can land and report as `other` with every test still green.
_GUARD_KIND_TO_CHECK = {
    "decorator": "decorator",
    "dependency": "dependency",
    "route_dependency": "dependency",
    "router_dependency": "dependency",
    "mixin": "mixin",
    "permission_classes": "policy_class",
    "none": "other",
}


@dataclass
class ProfileBuild:
    """The profile plus the artifacts it was derived from."""
    profile: ProjectProfile
    promotion: PromotionResult
    cpg: CPG
    workflow_report: str = ""
    workflow_error: str = ""
    agent_rows_merged: int = 0
    telemetry: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# The deterministic floor
# ---------------------------------------------------------------------------

def _auth_pattern(ep: Endpoint) -> str:
    if not ep.guards:
        return "none"
    return f"{ep.guard_kind}:{ep.guards[0]}"


def _enforcement(ep: Endpoint) -> str:
    """Structural enforcement only.

    `declared_not_enforced` is intentionally unreachable here — see the module
    docstring. Emitting it structurally would mean guessing at intent, and a
    wrong `declared_not_enforced` is worse than an honest `none`: it is a
    finding a reviewer will chase.
    """
    return "enforced" if ep.guarded else "none"


def _matrix(promotion: PromotionResult) -> list[AccessControlRow]:
    return [
        AccessControlRow(
            endpoint=ep.route or f"(unresolved:{ep.symbol})",
            http_method=",".join(ep.http_methods) or "GET",
            controller=ep.symbol,
            required_roles=list(ep.guards),
            auth_pattern=_auth_pattern(ep),
            enforcement=_enforcement(ep),
            file=ep.file,
            line=ep.line,
        )
        for ep in sorted(promotion.endpoints, key=lambda e: (e.file, e.line))
    ]


def _permission_checks(promotion: PromotionResult) -> list[PermissionCheck]:
    seen: dict[str, PermissionCheck] = {}
    for ep in promotion.endpoints:
        for guard in ep.guards:
            check = seen.setdefault(guard, PermissionCheck(
                name=guard,
                kind=_GUARD_KIND_TO_CHECK.get(ep.guard_kind, "other"),
                file=ep.file,
                line=ep.line,
            ))
            if guard not in check.grants:
                check.grants.append(guard)
    return list(seen.values())


def _io_channels(promotion: PromotionResult) -> tuple[list[IOChannel], list[CodeFlow]]:
    """HTTP surface only.

    Queues, cron jobs and exports are not structurally discoverable — the task
    prompt asks the agent for exactly those, and their absence here is recorded
    as a coverage gap rather than left to read as "there are none".
    """
    channels, flows = [], []
    for ep in sorted(promotion.endpoints, key=lambda e: (e.file, e.line)):
        name = ep.route or f"(unresolved:{ep.symbol})"
        channels.append(IOChannel(
            name=name, kind="http_api", direction="inbound",
            authenticated=ep.guarded,
            description=f"{'/'.join(ep.http_methods)} handled by {ep.symbol} ({ep.framework})",
        ))
        flows.append(CodeFlow(channel=name, files=[ep.file], entry_symbols=[ep.symbol]))
    return channels, flows


def _sensitive_fields(cpg: CPG) -> list[SensitiveField]:
    return [
        SensitiveField(
            name=n.name,
            classification=n.attrs.get("classification", "other"),
            locations=[f"{n.file}:{n.attrs.get('owner') or '<module>'}.{n.name}"],
        )
        for n in sorted(cpg.nodes_of_kind("sensitive_field"), key=lambda n: n.name)
    ]


def _floor(repo: str, base_sha: str, promotion: PromotionResult, cpg: CPG) -> ProjectProfile:
    channels, flows = _io_channels(promotion)
    frameworks = sorted(set(promotion.frameworks.values()))
    return ProjectProfile(
        repo=repo,
        profile_version=base_sha or "LOCAL",
        tech_stack=frameworks,
        io_channels=channels,
        code_flows=flows,
        permission_checks=_permission_checks(promotion),
        access_control_matrix=_matrix(promotion),
        sensitive_fields=_sensitive_fields(cpg),
        build_kind="full",
        built_at=datetime.now(timezone.utc),
    )


def _coverage_notes(profile: ProjectProfile, promotion: PromotionResult,
                    cpg: CPG, agent_rows: int, workflow_error: str) -> list[str]:
    """Say what was not established. A blank that looks like "nothing found
    here" is read as evidence of safety."""
    notes: list[str] = []
    if not agent_rows:
        notes.append(
            "COVERAGE GAP: structural profile only — no agent judgement merged. "
            "`enforcement` reflects the presence of a guard, not whether it is the "
            "correct guard; no row can be `declared_not_enforced`, and "
            "authenticated-but-unowned access (IDOR) is not detected."
        )
    if workflow_error:
        notes.append(f"COVERAGE GAP: security-profile workflow did not complete: {workflow_error}")
    if not profile.roles:
        notes.append("COVERAGE GAP: role vocabulary not established (needs the agent layer).")
    notes.append(
        "COVERAGE GAP: non-HTTP I/O channels (queues, cron, exports) are not "
        "structurally discoverable and were not enumerated."
    )
    unresolved = [r for r in profile.access_control_matrix if r.endpoint.startswith("(unresolved")]
    if unresolved:
        notes.append(
            f"COVERAGE GAP: {len(unresolved)} endpoint(s) have no resolved route "
            f"(Django urls.py tables are not parsed); guards are still recorded."
        )
    if cpg.taint_paths:
        for p in cpg.taint_paths:
            notes.append(
                f"TAINT: {p.source.name} ({p.source.file}:{p.source.line}) reaches "
                f"{p.sink.name} [{p.sink_class}] via {' -> '.join(p.symbols)}"
            )
    return notes


# ---------------------------------------------------------------------------
# The agent lift
# ---------------------------------------------------------------------------

def _merge_agent_profile(profile: ProjectProfile, payload: dict) -> int:
    """Overlay the workflow's structured output onto the floor.

    Scalar/descriptive fields are taken from the agent — the floor has nothing
    to say about them. Matrix rows are joined on `(controller, file)` and only
    the *judgement* columns are overwritten; route, file and line stay
    structural, because those are facts the agent has no better access to and
    every opportunity to garble.
    """
    for key in ("description", "tech_stack", "cloud_services", "notes"):
        value = payload.get(key)
        if value:
            setattr(profile, key, value if key != "description" else str(value))

    by_controller = {(r.controller, r.file): r for r in profile.access_control_matrix}
    merged = 0
    for raw in payload.get("access_control_matrix", []) or []:
        key = (raw.get("controller", ""), raw.get("file", ""))
        row = by_controller.get(key)
        if row is None:
            continue
        if raw.get("enforcement") in ("enforced", "declared_not_enforced", "none"):
            row.enforcement = raw["enforcement"]
        if raw.get("required_roles"):
            row.required_roles = list(raw["required_roles"])
        if raw.get("auth_pattern"):
            row.auth_pattern = raw["auth_pattern"]
        merged += 1
    return merged


def _read_workflow_payload(output_dir: Path) -> dict:
    """Read the synthesis output, tolerating everything a model can do to JSON."""
    path = output_dir / "project-profile.json"
    if not path.exists():
        return {}
    text = path.read_text().strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return {}
        return {}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_profile(
    base_dir: str | Path,
    repo: str,
    base_sha: str = "",
    config: Config | None = None,
    provider: Any | None = None,
    output_dir: str | Path | None = None,
    log_dir: str | Path | None = None,
) -> ProfileBuild:
    """Profile a checkout. Runs the agent workflow only when given a provider."""
    config = config or Config()
    base_dir = Path(base_dir)

    promotion = promote(base_dir, language=config.languages[0] if config.languages else "python")
    cpg = build_cpg(promotion)
    profile = _floor(repo, base_sha, promotion, cpg)

    report, error, merged, tool_violations = "", "", 0, []
    if provider is not None:
        report, error, merged, tool_violations = _run_workflow(
            config, base_dir, provider, profile,
            Path(output_dir or ".pr_review/runs/profile"),
            Path(log_dir or ".pr_review/logs"),
        )

    profile.agent_rows_merged = merged
    profile.notes = _coverage_notes(profile, promotion, cpg, merged, error)

    return ProfileBuild(
        profile=profile, promotion=promotion, cpg=cpg,
        workflow_report=report, workflow_error=error, agent_rows_merged=merged,
        telemetry={
            **promotion.stats,
            "taint_paths": len(cpg.taint_paths),
            "sensitive_fields": len(profile.sensitive_fields),
            "matrix_rows": len(profile.access_control_matrix),
            "agent_rows_merged": merged,
            "agent_calls": len(getattr(provider, "calls", []) or []),
            "tokens": getattr(provider, "total_tokens", 0),
            "tool_permission_violations": tool_violations,
        },
    )


def _run_workflow(config, base_dir, provider, profile, output_dir, log_dir
                  ) -> tuple[str, str, int, list[str]]:
    """Run the CAP workflow and merge what it produced.

    A workflow failure degrades to the floor rather than propagating: the
    structural profile is still correct and useful, and the failure is recorded
    as a coverage gap where a reviewer will see it.
    """
    from cap_engine.orchestration.workflow import WorkflowRunner

    from pr_review import cap_compat
    from pr_review.models.framework import build_framework

    cap_compat.apply()
    output_dir.mkdir(parents=True, exist_ok=True)

    violations: list[str] = []
    try:
        framework = build_framework(config, base_dir, provider,
                                    output_dir=output_dir, log_dir=log_dir)
        # Tool bindings CAP offered and `safety/permissions.py` refused. Empty
        # is the healthy state and the state today; non-empty means the trust
        # boundary moved under us and needs a human, so it goes in telemetry
        # rather than staying an attribute nobody reads.
        violations = [str(v) for v in framework.permission_violations]
        report = WorkflowRunner(framework).run(
            WORKFLOW_NAME, output=str(output_dir / "profile-report.md")
        )
    except Exception as exc:                      # noqa: BLE001 — degrade, don't crash
        return "", f"{type(exc).__name__}: {exc}", 0, violations

    merged = _merge_agent_profile(profile, _read_workflow_payload(output_dir))
    return str(report), "", merged, violations
