"""Schema-invariant enforcement (phase-3 §3d, cross-cutting §1).

Pydantic already guarantees the *shape* of a `Finding`. What it cannot check is
whether the finding is coherent: that its evidence exists, that its line numbers
fall inside the file it names, that its taxonomy id is one the registry knows.

Deterministic detectors rarely violate these — they build findings through
`detect/normalize.make_finding`, which gets them right by construction. The
stage exists for what arrives at M3: an agent's JSON, where a hallucinated line
number or an invented `internal` id is an ordinary failure mode. Building it now
means the agent path lands into a pipeline that already rejects malformed
findings, instead of one that discovers it needs to.

A rejected finding goes to an audit list, never to the report. Silence would be
the wrong response in both directions: dropping it quietly loses a possibly-real
finding, and repairing it quietly would mean reporting a location we made up.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pr_review.schema import Finding
from pr_review.taxonomy.registry import known_ids


@dataclass
class ValidationResult:
    kept: list[Finding] = field(default_factory=list)
    rejected: list[tuple[Finding, str]] = field(default_factory=list)

    @property
    def notes(self) -> list[str]:
        return [f"REJECTED {f.taxonomy.internal} at {f.location.file}:"
                f"{f.location.start_line} ({f.provenance.tool}): {why}"
                for f, why in self.rejected]

    def stats(self) -> dict:
        return {"kept": len(self.kept), "rejected": len(self.rejected)}


def _problem(f: Finding, line_counts: dict[str, int] | None) -> str | None:
    if not f.evidence:
        return "no evidence"
    if not (f.evidence[0].snippet or "").strip() and not (f.evidence[0].why or "").strip():
        return "evidence is empty"
    if f.location.start_line < 0 or f.location.end_line < f.location.start_line:
        return (f"impossible line range "
                f"{f.location.start_line}-{f.location.end_line}")
    if f.taxonomy.internal not in known_ids():
        return f"taxonomy id {f.taxonomy.internal!r} is not in the registry"
    if line_counts is not None:
        total = line_counts.get(f.location.file)
        # A file we have no line count for is not a violation: findings from
        # non-file surfaces (`pr:body`) and from files outside the checkout are
        # both legitimate, and only a *known* count can contradict a location.
        if total is not None and f.location.start_line > total:
            return f"line {f.location.start_line} is past the end of the file ({total} lines)"
    return None


def validate(findings: list[Finding],
             line_counts: dict[str, int] | None = None) -> ValidationResult:
    """Split `findings` into the coherent ones and the rejects, with reasons."""
    result = ValidationResult()
    for f in findings:
        why = _problem(f, line_counts)
        if why is None:
            result.kept.append(f)
        else:
            result.rejected.append((f, why))
    return result
