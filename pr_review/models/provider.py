"""Model-provider seam for our own one-shot completions (cross-cutting §10).

THERE ARE TWO PROVIDER INTERFACES, ON PURPOSE.

Overview §7.2 says the CAP dispatcher binds to this `ModelProvider`. It does
not — `SubAgentDispatcher` binds to `cap_engine.inference.provider
.InferenceProvider`, a different one-method ABC. That is not a defect to
paper over, because the two interfaces serve two genuinely different call paths:

  CAP-orchestrated agents   planner / worker / synthesizer, running inside a
  -> CAP's InferenceProvider  workflow. Its `invoke()` takes `system_prompt_parts`
                              so a provider can place prompt-cache breakpoints
                              between stable and volatile segments — the token
                              economy Phase 1 exists to buy.

  Direct completions        Phase-2 triage (`change/filter.py`) and the Phase-3c
  -> this ModelProvider     verifier. One prompt, one answer, no orchestration.

Collapsing CAP's interface into this one would flatten `system_prompt_parts`
into a single string and silently destroy the caching seam. So both exist, and
`models/framework.py` binds the CAP side.

What both guarantee is the thing §7.2 actually cares about: nothing above this
line imports Bedrock, so the tool stays provider-pluggable and open-sourceable.
Concrete impls of THIS interface: `models/fake.py`, and `models/claude_cli.py`
since 2026-08-21 -- a real one, over `claude -p --output-format json`, which has
billed real money against arm 3 and tier-3 triage. `models/bedrock.py` is still
unwritten and still blocked (`M1_STATUS.md` §5.3); it is no longer the only way
this seam gets filled, and this line said it was until 2026-08-24.

The CAP side is the half that is still fake. `claude_cli.py` deliberately does
not implement `InferenceProvider`: flattening `system_prompt_parts` into one CLI
prompt would destroy the cache-breakpoint seam described above, which is the
token economy Phase 1 exists to buy (`PIVOT_PLAN.md` §1.0). That is why M3 is
blocked by more than a credential.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ModelProvider(ABC):
    @abstractmethod
    def complete(self, messages: list[dict], tools: list | None = None, **cfg: Any) -> Any:
        """Run a (tool-using) completion. Implemented at M1."""
        raise NotImplementedError

    def cache_point(self) -> Any:  # pragma: no cover - placeholder
        """Provider-specific prompt cache marker; no-op until M1."""
        return None
