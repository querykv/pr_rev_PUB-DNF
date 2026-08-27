"""Cross-source dedup (phase-3 §3d, cross-cutting §6).

Several detectors legitimately find the same thing. Semgrep's taint mode and our
CPG both see `request.args` reaching `cursor.execute`; at M3 an agent will see
it a third time. One defect must be one finding, or the report's counts measure
how many tools we ran rather than how much is wrong.

The join key is the **fingerprint** (cross-cutting §6): path, taxonomy id,
symbol and a structural-context proxy, with line numbers deliberately excluded.
Two detectors that disagree about the exact line still collapse; two genuinely
different defects in one function do not, because their taxonomy ids differ.

WHAT SURVIVES A COLLAPSE. The richest finding wins — highest severity, then
confidence, then the most evidence — and it absorbs what the losers knew:
evidence for locations it did not have, a data flow if it had none, and the
names of the detectors that agreed (`provenance.also_detected_by`).

WHAT DOES NOT HAPPEN HERE: no confidence bump for agreement. Two tools agreeing
is real evidence, but converting it into a number is `findings/merge.py`'s job
at M3, where 3a candidates meet their 3b confirmations and the weighting can be
decided once. Doing it here as well would apply it twice.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pr_review.schema import Finding


@dataclass
class DedupResult:
    findings: list[Finding] = field(default_factory=list)
    collapsed: int = 0
    groups: dict[str, list[str]] = field(default_factory=dict)   # fingerprint -> sources

    def stats(self) -> dict:
        return {
            "unique": len(self.findings),
            "collapsed": self.collapsed,
            "agreed": sum(1 for s in self.groups.values() if len(set(s)) > 1),
        }


def _source(f: Finding) -> str:
    return f"{f.provenance.detector.value}:{f.provenance.tool}"


def _richness(f: Finding) -> tuple:
    """Ordering for "which of these is the better finding". Higher wins."""
    return (
        f.severity.rank,
        f.confidence,
        len(f.evidence),
        len(f.data_flow),
        sum(len(e.snippet or "") for e in f.evidence),
    )


def dedup(findings: list[Finding]) -> DedupResult:
    result = DedupResult()
    by_fp: dict[str, list[Finding]] = {}
    for f in findings:
        by_fp.setdefault(f.fingerprint, []).append(f)

    for fp, group in by_fp.items():
        result.groups[fp] = [_source(f) for f in group]
        if len(group) == 1:
            result.findings.append(group[0])
            continue
        winner, *losers = sorted(group, key=_richness, reverse=True)
        result.collapsed += len(losers)

        seen = {(e.file, e.lines) for e in winner.evidence}
        for other in losers:
            source = _source(other)
            if source != _source(winner) and source not in winner.provenance.also_detected_by:
                winner.provenance.also_detected_by.append(source)
            for ev in other.evidence:
                if (ev.file, ev.lines) not in seen:
                    seen.add((ev.file, ev.lines))
                    winner.evidence.append(ev)
            if not winner.data_flow and other.data_flow:
                winner.data_flow = other.data_flow
            if not winner.reachability.entry and other.reachability.entry:
                winner.reachability = other.reachability
        winner.provenance.also_detected_by.sort()
        result.findings.append(winner)
    return result
