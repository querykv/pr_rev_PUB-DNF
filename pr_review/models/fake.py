"""Recording fake providers — how M1 runs the agent layer with no Bedrock.

Two fakes because there are genuinely two call paths (see `provider.py`):
`FakeInferenceProvider` stands in for CAP's agent backend, `FakeModelProvider`
for our own one-shot completions.

Beyond unblocking M1, the recording is a test instrument. Several properties the
design depends on are only observable in what the model was *sent*:

- the planner receives structural metadata and never source (cross-cutting §9.2),
- the system prompt is segmented so a real provider can place cache breakpoints
  between stable and volatile parts (phase-1 §7),
- tiered routing actually routes (`config.models.roles`).

A fake that swallowed its inputs would let all three regress silently.

⚠ The synthetic usage dict below emits `cacheReadInputTokens` /
`cacheWriteInputTokens` — the key names CAP *guesses* for Strands' accumulated
usage, one of which carries an `# UNCERTAIN` marker. Exercising the plumbing
with these keys does **not** validate them. If they are wrong, real runs report
zero and the fake will still look healthy. Only a Bedrock run settles it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cap_engine.agents.envelope import ResponseEnvelope
from cap_engine.inference.provider import InferenceProvider

from pr_review.models.provider import ModelProvider


@dataclass
class RecordedCall:
    agent_id: str
    persona: str
    system_prompt_parts: list[str]
    user_prompt: str
    tool_names: list[str]
    max_tool_calls: int | None = None

    @property
    def system_prompt(self) -> str:
        return "\n".join(self.system_prompt_parts)

    @property
    def everything_sent(self) -> str:
        return f"{self.system_prompt}\n{self.user_prompt}"


def _persona_of(agent_id: str) -> str:
    """`worker-1345574659-3` -> `worker` (dispatch.py `_make_agent_id`)."""
    return agent_id.split("-", 1)[0] if agent_id else ""


def default_envelope(persona: str, summary: str = "") -> str:
    """A minimal valid agent response, built with CAP's own envelope type."""
    return ResponseEnvelope(
        persona=persona,
        status="complete",
        confidence="high",
        summary=summary or f"fake {persona} response",
    ).to_json()


def plan_response(analysis: str = "fake plan", tasks: list[dict] | None = None,
                  ready: bool = True) -> str:
    """A parseable `InferencePlan` for the planner persona.

    A real provider runs an agent loop and the planner *calls* the
    `save_inference_plan` tool. A fake returns text and executes nothing, so the
    only route in is the planner's JSON fallback parser, which extracts the
    largest balanced object and validates it. Returning a bare envelope leaves
    the plan empty and **no workers are dispatched at all** — which looks like a
    working run producing nothing.
    """
    import json

    return json.dumps({
        "analysis": analysis,
        "inference_tasks": tasks or [],
        "relevant_resource_uris": [],
        "ready_for_synthesis": ready,
    })


class FakeInferenceProvider(InferenceProvider):
    """Scripted stand-in for CAP's inference backend.

    `responses` may be:
      - a str                       — returned for every call
      - a dict[persona, str|list]   — per-persona; a list is consumed in order
      - a callable(RecordedCall)    — full control
      - None                        — a valid default envelope per persona
    """

    def __init__(
        self,
        responses: str | dict[str, Any] | Callable[[RecordedCall], str] | None = None,
        tokens_per_call: tuple[int, int] = (1000, 200),
        model_id: str = "fake",
        role_models: dict[str, str] | None = None,
    ) -> None:
        self._responses = responses
        self._in, self._out = tokens_per_call
        self._model_id = model_id
        # Tiered routing lives in the provider, not in CAPConfig: CAP has a
        # single `model.model_id` for every persona, but `invoke()` receives the
        # agent_id, so the provider is the only place role->model can happen.
        self._role_models = role_models or {}
        self.calls: list[RecordedCall] = []

    @property
    def display_name(self) -> str:
        return f"fake/{self._model_id}"

    def model_for(self, persona: str) -> str:
        return self._role_models.get(persona, self._model_id)

    def invoke(self, system_prompt_parts, user_prompt, tools, agent_id,
               max_tool_calls=None, log_dir=None):
        call = RecordedCall(
            agent_id=agent_id,
            persona=_persona_of(agent_id),
            system_prompt_parts=list(system_prompt_parts or []),
            user_prompt=user_prompt,
            tool_names=[getattr(t, "__name__", repr(t)) for t in (tools or [])],
            max_tool_calls=max_tool_calls,
        )
        self.calls.append(call)
        return self._resolve(call), self._usage()

    # -- response resolution ----------------------------------------------

    def _resolve(self, call: RecordedCall) -> str:
        r = self._responses
        if r is None:
            return default_envelope(call.persona)
        if callable(r):
            return r(call)
        if isinstance(r, str):
            return r
        entry = r.get(call.persona, r.get("*"))
        if entry is None:
            return default_envelope(call.persona)
        if isinstance(entry, list):
            # Consume in order; repeat the last once exhausted rather than
            # raising — a workflow adding a step should not break every test.
            used = sum(1 for c in self.calls[:-1] if c.persona == call.persona)
            return entry[min(used, len(entry) - 1)]
        return entry

    def _usage(self) -> dict:
        return {
            "inputTokens": self._in,
            "outputTokens": self._out,
            "totalTokens": self._in + self._out,
            "cacheReadInputTokens": 0,
            "cacheWriteInputTokens": 0,
        }

    # -- assertion helpers -------------------------------------------------

    def calls_for(self, persona: str) -> list[RecordedCall]:
        return [c for c in self.calls if c.persona == persona]

    def tools_offered_to(self, persona: str) -> set[str]:
        return {t for c in self.calls_for(persona) for t in c.tool_names}

    def sent_to(self, persona: str) -> str:
        return "\n".join(c.everything_sent for c in self.calls_for(persona))

    @property
    def total_tokens(self) -> int:
        return (self._in + self._out) * len(self.calls)


class FakeModelProvider(ModelProvider):
    """Stand-in for our own direct completions (triage, verifier)."""

    def __init__(self, responses: list[str] | str | None = None) -> None:
        self._responses = responses
        self.calls: list[dict] = []

    def complete(self, messages: list[dict], tools: list | None = None, **cfg: Any) -> Any:
        self.calls.append({"messages": messages, "tools": tools, "cfg": cfg})
        if isinstance(self._responses, list):
            idx = min(len(self.calls) - 1, len(self._responses) - 1)
            return self._responses[idx] if self._responses else ""
        return self._responses if self._responses is not None else ""

    def cache_point(self) -> Any:
        return None
