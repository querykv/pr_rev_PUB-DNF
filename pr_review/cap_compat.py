"""Runtime workarounds for defects in the vendored CAP engine.

`cap_engine/` is a separate repository under a restricted licence, and its tree
is kept byte-identical to what was dropped in — every edit avoided is one fewer
conflict when it is re-synced or swapped for CAP-lite. So defects we hit are
patched from *this* side, at import time, and collected here rather than
scattered through the call sites that trip over them.

Each shim states what it fixes, how it was found, and how to tell whether it is
still needed. `apply()` is idempotent and returns the names it applied, so a
test can assert the set rather than trusting it silently.

If CAP is ever fixed upstream, delete the shim and its guard test together —
`still_needed()` on each shim is what tells you when that moment has arrived.
"""
from __future__ import annotations

import itertools
from datetime import datetime, timezone

_applied: set[str] = set()
_counter = itertools.count()


# ---------------------------------------------------------------------------
# Shim 1 — unique orchestration-session ids
# ---------------------------------------------------------------------------

def _unique_timestamp() -> str:
    """Second resolution + microseconds + a process-wide counter.

    Mirrors what `SubAgentDispatcher._make_agent_id` already does for agent ids
    (`"%H%M%S%f"[:10]` plus an atomic counter) — the loop simply did not get the
    same treatment.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S%f")
    return f"{stamp}-{next(_counter)}"


def _fix_session_id_collisions() -> bool:
    """`CAPOrchestrationLoop.__init__` builds `session-{_timestamp()}` at second
    resolution, then calls `CGPServer.session_create`, which raises on an
    existing id. Two workflow steps that start within the same second therefore
    abort the whole workflow with:

        CGPError [-32012] Session already exists: session-20260804-074320

    Found by running `security-profile` end to end: step 1 completed, step 2
    died. It needs steps to be *fast* to reproduce, which is why neither the
    static analysis nor the single-call smoke test saw it — but a fake provider,
    a small repo, or a quick model all hit it, so it blocks every multi-step
    workflow.

    Patching the module-level `_timestamp` is the narrowest fix: it is looked up
    as a global at call time, and its only other use in that module is a log
    directory name, which is equally happy to be more unique.
    """
    from cap_engine.orchestration.loop import loop as loop_mod

    loop_mod._timestamp = _unique_timestamp
    return True


def _session_ids_still_collide() -> bool:
    """True while CAP's own `_timestamp` is still second-resolution."""
    import importlib

    src = importlib.import_module("cap_engine.orchestration.loop.loop")
    fn = getattr(src, "_timestamp", None)
    return fn is not _unique_timestamp and "%S\"" not in repr(fn)


SHIMS = {
    "unique_session_ids": _fix_session_id_collisions,
}


def apply() -> set[str]:
    """Apply every shim once. Safe to call repeatedly."""
    for name, fn in SHIMS.items():
        if name not in _applied and fn():
            _applied.add(name)
    return set(_applied)


def applied() -> set[str]:
    return set(_applied)
