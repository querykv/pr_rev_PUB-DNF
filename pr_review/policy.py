"""Gating policy (cross-cutting §8). The verdict is computed deterministically —
never by an LLM — so injected text in source/diff cannot talk the gate out of a
finding.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pr_review.config import GateConfig
from pr_review.schema import Finding, Status


@dataclass
class GateResult:
    verdict: str  # "flagged" | "approved"
    triggers: list[Finding] = field(default_factory=list)


def gate(findings: list[Finding], cfg: GateConfig) -> GateResult:
    triggers = [
        f for f in findings
        if f.introduced_by_pr
        and f.status == Status.VALIDATED
        and f.severity.rank >= cfg.severity_floor.rank
        and f.confidence >= cfg.confidence_floor
    ]
    return GateResult(verdict="flagged" if triggers else "approved", triggers=triggers)
