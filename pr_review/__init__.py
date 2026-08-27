"""pr_review — security-focused PR review tool.

Built through M2: Phase 0 (extract) -> Phase 1 (cached repository profile + CPG)
-> Phase 2 (change analysis) -> Phase 3a (five deterministic detectors) ->
Phase 4 (findings, baseline/delta scoping, report, gate).

**Phase 3b agentic families and the Phase 3c verifier are designed and not
built**, and are out of scope on this branch: they need a model provider and the
Bedrock credentials never arrived. `README.md` states the boundary,
`CONTINUATION.md` §4.0 is the authoritative designed-vs-built table, and
`PIVOT_PLAN.md` records why. Do not read an absent detector as a clean result.

See ../plan/ for the full design; milestones are plan/00-overview.md §6.
"""

__version__ = "0.2.0"
