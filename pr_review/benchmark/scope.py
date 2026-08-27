"""What the 3a detectors can express (`plan/benchmark.md` §1, per-taxonomy P/R).

A recall number over a corpus half of which no detector in this milestone can
express is arithmetically true and answers a question nobody asked — the same
error errata §14.20 recorded for `BAC-MISSING-AUTHZ` averaged over PRs with no
endpoint in them, arriving from the other direction. Roughly half the labelled
corpus is CWE-400, CWE-1333, CWE-834, CWE-455, CWE-200, CWE-59 and CWE-61, none
of which any 3a detector emits. A miss there is a milestone boundary.

**The right response is a stratum, not a filter.** Dropping those advisories
would make the corpus unrepresentative of what the advisory feed actually
contains, and choosing a corpus to suit the tool is the classic benchmark
failure `Corpus.selection_criteria` exists to expose. So they stay in, the
headline covers all of them, and this module supplies the split.

WHY THIS IS DERIVED AND NOT A LIST

A hand-maintained list of "CWEs we cover" is a number-flattering edit waiting to
happen: adding a line raises recall without changing the tool, exactly as
widening `scoring._CWE_GROUPS` would. So the set is read out of the detectors'
own tables — the sink map the structural detector dispatches on, the rules the
secrets scanner matches, the mapping tables the SARIF adapters route through —
and then through `taxonomy.registry.lookup()`, which is where an internal id's
CWEs are already defined.

That means it reaches into module-level tables other modules own. Deliberate,
and pinned by tests: if a refactor renames one, `in_scope_cwes()` shrinks and
the tests fail rather than the scorecard quietly reporting a better number.

IT IS A STATEMENT OF REACH, NOT OF SKILL. A CWE is in scope when some detector
could name it, which says nothing about whether it would find any particular
instance. In-scope recall is still recall, with all of its misses.
"""
from __future__ import annotations

from pr_review.benchmark.scoring import _norm_cwe, cwe_match
from pr_review.detect import normalize, secrets, structural
from pr_review.taxonomy.registry import lookup

# The structural detector's access-control rules are the one class not reachable
# from a table — `structural.py` writes the id inline at the two call sites, so
# there is nothing to iterate. Named here rather than pattern-matched out of the
# source, and asserted by a test that fails if the module stops emitting it.
_STRUCTURAL_EXTRA = ("BAC-MISSING-AUTHZ",)


def detector_internal_ids() -> set[str]:
    """Every internal taxonomy id a 3a detector can emit."""
    ids: set[str] = set(_STRUCTURAL_EXTRA)
    ids |= {entry[0] for entry in structural._SINKS.values()}
    ids |= {rule.internal for rule in secrets._SPECIFIC}
    ids.add(secrets._GENERIC.internal)
    # The SARIF-shaped adapters (semgrep, checkov, osv) all route through the
    # same mapping tables, so one sweep covers the three of them.
    ids |= {m.internal for table in normalize._EXACT.values() for m in table.values()}
    ids |= {m.internal for _pattern, m in normalize._COMPILED}
    ids |= {m.internal for m in normalize._FALLBACK.values()}
    return {i for i in ids if i}


def in_scope_cwes() -> set[str]:
    """The CWE ids those internal taxonomy entries claim."""
    out: set[str] = set()
    for internal in detector_internal_ids():
        try:
            taxonomy = lookup(internal)
        except Exception:                        # noqa: BLE001 — unmapped id
            continue
        out |= {_norm_cwe(c) for c in taxonomy.cwe if c}
    return {c for c in out if c}


def is_in_scope(cwe: str, scope: set[str] | None = None) -> bool:
    """Could any 3a detector have named this ground-truth CWE?

    Matched through `scoring.cwe_match`, not by string equality, so the same
    parent/child relations that decide a true positive decide scope. Deciding
    them differently would let a case be scored against a rule that the stratum
    says is out of reach, or the reverse.
    """
    scope = in_scope_cwes() if scope is None else scope
    return cwe_match(sorted(scope), cwe) is not None
