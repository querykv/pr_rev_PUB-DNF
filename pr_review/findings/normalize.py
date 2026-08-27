"""Final ordering and counts (phase-3 §3d, last stage).

The stage order is `validate -> dedup -> merge -> delta -> severity ->
calibrate -> suppress -> normalize`. M0 had none of it and did its own dedup
inline here; M2 builds validate, dedup and delta as real stages, so this module
is back to what §3d actually asks of it — a deterministic ordering and an honest
count.

`dedup()` is still called from here rather than left entirely to the caller: a
`NormalizedFindingSet` is what every emitter renders, and it must not be
possible to produce one containing the same defect twice by forgetting a stage.
Running it a second time on already-deduped input is a no-op.
"""
from __future__ import annotations

from collections import Counter

from pr_review.findings.dedup import dedup
from pr_review.findings.schema import NormalizedFindingSet
from pr_review.schema import Finding


def normalize(findings: list[Finding]) -> NormalizedFindingSet:
    uniq = dedup(findings).findings
    # severity desc, then confidence desc, then stable by location
    uniq.sort(key=lambda f: (-f.severity.rank, -f.confidence, f.location.file,
                             f.location.start_line))

    counts = {
        "total": len(uniq),
        "by_severity": dict(Counter(f.severity.value for f in uniq)),
        "by_status": dict(Counter(f.status.value for f in uniq)),
        "by_family": dict(Counter(f.taxonomy.family for f in uniq)),
        "by_detector": dict(Counter(f.provenance.detector.value for f in uniq)),
        # The two numbers a reviewer reads first: what this PR is answerable
        # for, and what it merely inherited (cross-cutting §5).
        "introduced": sum(1 for f in uniq if f.introduced_by_pr),
        "pre_existing": sum(1 for f in uniq if not f.introduced_by_pr),
    }
    return NormalizedFindingSet(findings=uniq, counts=counts)
