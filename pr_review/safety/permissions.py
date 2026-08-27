"""Structural tool permissions (cross-cutting §9.2).

§9.2's controls are worth restating precisely, because the wording carries the
design: *"planners/scouts read only structural metadata, never source; workers
write only to the run dir; the verifier receives claim + evidence pointers, not
the reporter's chain-of-thought. Permissions enforced by tool-binding, not
prompt."*

**Enforced by tool-binding, not prompt** is the whole mechanism. A persona
prompt asking an agent not to read source is a request; an agent that was never
handed a source-reading callable cannot read source no matter what the diff it
is reading tells it to do. That distinction is the reason this module exists
rather than another paragraph in `personas/planner.md` — which does also say it,
and is tested to say it, because an agent that spends its turns calling a tool
it does not have is a wasted invocation.

WHERE THE SEAM IS
`CAPFramework._build_tool_sets()` returns `dict[PersonaClass, list[Callable]]`,
and `SubAgentDispatcher.spawn()` passes exactly that persona's list to the
provider. `PRFramework` overrides the builder, runs `enforce()` over CAP's
result, and binds what survives. `cap_engine/` is not edited — same discipline
as the `_build_provider()` override next to it.

WHAT THIS CURRENTLY FINDS: NOTHING, AND THAT IS THE POINT
CAP's planner tool set is already source-free — `planner_search_codebase_summary`
returns per-directory match *counts*, not lines. So this enforces an invariant
that holds today. Its value is the day it stops holding: `cap_engine/` is a
transcription of a separate, restricted repository that may be re-synced or
swapped for CAP-lite, and a re-sync that hands the planner a source reader would
otherwise widen the trust boundary silently and permanently. `unknown -> source`
makes that fail closed: a tool this table has never heard of is assumed to be
the dangerous kind.

TWO CLAUSES SHIP DECLARED AND UNENFORCED, RATHER THAN LOOKING DONE
- *"workers write only to the run dir"* is satisfied **by construction**: no
  filesystem-write tool is bound to any persona at all. Worker output goes
  through `worker_create_inference_node` into the CGP session store. There is
  nothing here to enforce, so nothing here pretends to.
- *"the verifier receives claim + evidence pointers"* has no binding to enforce
  against: CAP has three personas and the verifier is not one of them. It
  arrives at M4. `POLICY` carries the row with an empty capability set so the
  policy is written down in one place, and `audit()` skips personas CAP does not
  dispatch.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

# Capabilities, coarsest useful granularity:
#   structural  symbol outlines, call graphs, decorators, endpoint lists,
#               aggregate match counts — metadata about code, never its text
#   source      the text of the repository under review
#   inference   the analysis graph: prior findings, coverage, assembled output
#   output      the agent's own deliverable
STRUCTURAL = "structural"
SOURCE = "source"
INFERENCE = "inference"
OUTPUT = "output"

# CAP's bound tools, by name. Anything absent is treated as SOURCE.
CAPABILITIES: dict[str, str] = {
    # -- planner ---------------------------------------------------------
    "planner_get_resource_outline": STRUCTURAL,
    "planner_search_codebase_summary": STRUCTURAL,   # aggregate counts, not lines
    "planner_explore_directories": STRUCTURAL,
    "planner_get_call_chain": STRUCTURAL,
    "planner_find_by_decorator": STRUCTURAL,
    "planner_find_by_parameter": STRUCTURAL,
    "planner_find_symbols": STRUCTURAL,
    "planner_find_callers": STRUCTURAL,
    "planner_get_file_symbols": STRUCTURAL,
    "planner_find_endpoints": STRUCTURAL,
    "planner_get_inference_outline": INFERENCE,
    "planner_get_coverage_map": INFERENCE,
    "planner_save_inference_plan": OUTPUT,
    # -- worker ----------------------------------------------------------
    "worker_read_file": SOURCE,
    "worker_read_resource_section": SOURCE,
    "worker_search_resource": SOURCE,
    "worker_search_files": SOURCE,
    "worker_get_file_outline": STRUCTURAL,
    "worker_find_implementations": STRUCTURAL,
    "worker_find_by_decorator": STRUCTURAL,
    "worker_find_by_parameter": STRUCTURAL,
    "worker_get_call_chain": STRUCTURAL,
    "worker_read_prior_inference": INFERENCE,
    "worker_create_inference_node": OUTPUT,
    # -- synthesizer -----------------------------------------------------
    "synthesizer_assemble_inference": INFERENCE,
}

POLICY: dict[str, frozenset[str]] = {
    # Never SOURCE. The planner decides what deserves a worker's tokens, and
    # that judgement should not be coloured by having already skimmed the answer.
    "planner": frozenset({STRUCTURAL, INFERENCE, OUTPUT}),
    # The only persona that reads the repository.
    "worker": frozenset({STRUCTURAL, SOURCE, INFERENCE, OUTPUT}),
    # Works from assembled worker output, not from source (personas/synthesizer.md).
    "synthesizer": frozenset({INFERENCE, OUTPUT}),
    # Declared for M4; CAP dispatches no such persona today (module docstring).
    "verifier": frozenset({INFERENCE}),
}


@dataclass(frozen=True)
class Violation:
    persona: str
    tool: str
    capability: str
    reason: str

    def __str__(self) -> str:                        # for notes/telemetry
        return f"{self.persona} may not be bound {self.tool!r} ({self.reason})"


def _persona_name(key) -> str:
    """`PersonaClass.PLANNER` or `"planner"` -> `"planner"`."""
    return str(getattr(key, "value", key)).lower()


def _tool_name(tool: Callable) -> str:
    return getattr(tool, "__name__", repr(tool))


def classify_tool(name: str) -> str:
    """The capability a tool confers. **Unknown means SOURCE.**

    Failing closed is the entire value of this module. An unrecognised tool is
    either new or renamed, and in both cases the honest default is the one that
    costs a capability rather than grants one.
    """
    return CAPABILITIES.get(name, SOURCE)


def audit(tool_sets: dict) -> list[Violation]:
    """Every binding that its persona's policy forbids. Empty is the healthy state."""
    violations: list[Violation] = []
    for key, tools in (tool_sets or {}).items():
        persona = _persona_name(key)
        allowed = POLICY.get(persona)
        if allowed is None:
            # A persona with no policy row: report rather than silently permit.
            violations.append(Violation(
                persona, "*", "*",
                "no permission policy is defined for this persona"))
            continue
        for tool in tools or []:
            name = _tool_name(tool)
            capability = classify_tool(name)
            if capability in allowed:
                continue
            known = name in CAPABILITIES
            violations.append(Violation(
                persona, name, capability,
                f"{capability} is not permitted for {persona}" if known
                else f"unknown tool, treated as {SOURCE} (fails closed)",
            ))
    return violations


def enforce(tool_sets: dict) -> tuple[dict, list[Violation]]:
    """Drop the forbidden bindings. Returns the filtered sets and what was cut.

    **Strips rather than raises**, deliberately. A planner short one tool
    degrades — it plans with less, and the persona prompt already tells it to
    report an honest gap. A framework that refuses to construct takes down the
    whole review, including the deterministic floor that needs no agent at all,
    and turns a tightened boundary into an outage. The violations are returned
    so the caller can record them where a human will see them; they are not
    swallowed.
    """
    violations = audit(tool_sets)
    if not violations:
        return tool_sets, []
    cut = {(v.persona, v.tool) for v in violations}
    filtered = {
        key: [t for t in (tools or [])
              if (_persona_name(key), _tool_name(t)) not in cut]
        for key, tools in (tool_sets or {}).items()
    }
    return filtered, violations


def describe(tool_sets: dict) -> dict[str, dict[str, list[str]]]:
    """`{persona: {capability: [tool, ...]}}` — for telemetry and for tests that
    want to assert on the shape of a binding rather than on a count."""
    out: dict[str, dict[str, list[str]]] = {}
    for key, tools in (tool_sets or {}).items():
        persona = _persona_name(key)
        by_capability: dict[str, list[str]] = {}
        for tool in tools or []:
            name = _tool_name(tool)
            by_capability.setdefault(classify_tool(name), []).append(name)
        out[persona] = {k: sorted(v) for k, v in sorted(by_capability.items())}
    return out


def permitted_tools(persona: str, names: Iterable[str]) -> list[str]:
    """Filter tool *names* by policy. Used by tests and by any future non-CAP
    binding site that has names but no callables."""
    allowed = POLICY.get(_persona_name(persona), frozenset())
    return [n for n in names if classify_tool(n) in allowed]
