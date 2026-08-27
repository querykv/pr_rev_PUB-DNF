"""Normalized finding-set output of the Phase 3d pipeline (phase-3 §3d).

M0 implements validate→dedup→sort; delta-scoping, calibration, suppression and
merge land at M2–M4.
"""
from __future__ import annotations

from pydantic import BaseModel

from pr_review.schema import Finding


class NormalizedFindingSet(BaseModel):
    findings: list[Finding] = []
    counts: dict = {}
    coverage: dict = {}
