"""Provider bridge — injecting our provider into CAP with zero cap_engine edits."""
import pytest

pytest.importorskip(
    "cap_engine.config.framework",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from cap_engine.agents.envelope import parse_envelope  # noqa: E402
from cap_engine.inference.provider import InferenceProvider  # noqa: E402

from pr_review.config import Config  # noqa: E402
from pr_review.models.fake import (  # noqa: E402
    FakeInferenceProvider,
    FakeModelProvider,
    RecordedCall,
    default_envelope,
)
from pr_review.models.framework import (  # noqa: E402
    PRFramework,
    build_cap_config,
    build_framework,
    role_model_map,
)
from pr_review.models.provider import ModelProvider  # noqa: E402

FIXTURE = "tests/fixtures/sample_app"


def _call(provider, persona="worker", prompt="do the thing", parts=None, tools=()):
    return provider.invoke(
        system_prompt_parts=parts if parts is not None else ["stable", "volatile"],
        user_prompt=prompt,
        tools=list(tools),
        agent_id=f"{persona}-1234567890-1",
    )


# --------------------------------------------------------------------------
# FakeInferenceProvider
# --------------------------------------------------------------------------

def test_it_is_a_cap_provider():
    assert isinstance(FakeInferenceProvider(), InferenceProvider)


def test_default_response_is_a_valid_cap_envelope():
    """CAP's dispatcher parses the response; an unparseable fake would exercise
    only the fallback path."""
    text, usage = _call(FakeInferenceProvider(), persona="planner")
    env = parse_envelope(text)
    assert env is not None
    assert env.persona == "planner" and env.status == "complete"
    assert usage["totalTokens"] == usage["inputTokens"] + usage["outputTokens"]


def test_persona_is_derived_from_the_agent_id():
    p = FakeInferenceProvider()
    _call(p, persona="planner")
    _call(p, persona="worker")
    _call(p, persona="worker")
    assert [c.persona for c in p.calls] == ["planner", "worker", "worker"]
    assert len(p.calls_for("worker")) == 2


def test_scripted_responses_per_persona():
    p = FakeInferenceProvider(responses={"planner": "PLAN", "worker": ["W1", "W2"]})
    assert _call(p, persona="planner")[0] == "PLAN"
    assert _call(p, persona="worker")[0] == "W1"
    assert _call(p, persona="worker")[0] == "W2"


def test_exhausted_script_repeats_rather_than_raising():
    """A workflow gaining a step should not break every unrelated test."""
    p = FakeInferenceProvider(responses={"worker": ["only"]})
    assert _call(p, persona="worker")[0] == "only"
    assert _call(p, persona="worker")[0] == "only"


def test_callable_responses_see_the_call():
    p = FakeInferenceProvider(responses=lambda c: f"saw:{c.user_prompt}")
    assert _call(p, prompt="hello")[0] == "saw:hello"


def test_system_prompt_segmentation_is_preserved():
    """A real provider places cache breakpoints *between* these parts. Joining
    them here would hide a regression that silently disables prompt caching."""
    p = FakeInferenceProvider()
    _call(p, parts=["frozen preamble", "per-run context"])
    call = p.calls[0]
    assert call.system_prompt_parts == ["frozen preamble", "per-run context"]
    assert len(call.system_prompt_parts) == 2


def test_recording_supports_the_planner_reads_no_source_invariant():
    """cross-cutting §9.2: planners get structural metadata, never source.

    Only observable in what was *sent*, which is why the fake records.
    """
    p = FakeInferenceProvider()
    _call(p, persona="planner", prompt="outline of app.py: 4 symbols")
    _call(p, persona="worker", prompt="def search():\n    cursor.execute(q)")
    assert "cursor.execute" not in p.sent_to("planner")
    assert "cursor.execute" in p.sent_to("worker")


def test_tool_names_are_recorded_per_persona():
    def planner_get_outline():
        ...

    def worker_read_file():
        ...

    p = FakeInferenceProvider()
    _call(p, persona="planner", tools=[planner_get_outline])
    _call(p, persona="worker", tools=[worker_read_file])
    assert p.tools_offered_to("planner") == {"planner_get_outline"}
    assert p.tools_offered_to("worker") == {"worker_read_file"}


def test_role_routing_lives_in_the_provider():
    """CAP has one `model.model_id` for every persona; only the provider sees
    the agent_id, so it is the only place tiering can happen."""
    p = FakeInferenceProvider(role_models=role_model_map(Config()))
    assert p.model_for("planner") == "anthropic.claude-opus-5"
    assert p.model_for("triage") == "anthropic.claude-haiku-4-5"
    assert p.model_for("unknown") == "fake"


def test_usage_keys_are_plumbed_but_not_validated():
    """⚠ The fake emits the key names CAP *guesses* for Strands usage.

    Exercising the plumbing is not evidence the names are right. If they are
    wrong, a real run reports zero and this test still passes — only Bedrock
    settles it. Asserted here so the limitation is written down where the
    numbers are produced.
    """
    _text, usage = _call(FakeInferenceProvider())
    assert {"cacheReadInputTokens", "cacheWriteInputTokens"} <= set(usage)
    assert usage["cacheReadInputTokens"] == 0


def test_total_tokens_accumulates():
    p = FakeInferenceProvider(tokens_per_call=(10, 5))
    _call(p)
    _call(p)
    assert p.total_tokens == 30


# --------------------------------------------------------------------------
# FakeModelProvider (the non-CAP path)
# --------------------------------------------------------------------------

def test_fake_model_provider_is_our_abc():
    fm = FakeModelProvider(responses=["a", "b"])
    assert isinstance(fm, ModelProvider)
    assert fm.complete([{"role": "user", "content": "x"}]) == "a"
    assert fm.complete([{"role": "user", "content": "y"}]) == "b"
    assert len(fm.calls) == 2


# --------------------------------------------------------------------------
# Framework wiring
# --------------------------------------------------------------------------

def test_cap_config_points_at_our_prompt_tree():
    """Assets live in pr_review/prompts/, not inside the restricted CAP tree."""
    cc = build_cap_config(Config(), FIXTURE)
    assert cc.workflows_dir.endswith("pr_review/prompts/workflows")
    assert cc.tasks_dir.endswith("pr_review/prompts/tasks")
    assert cc.templates_dir.endswith("pr_review/prompts/templates")
    assert cc.environment.base_dir == FIXTURE
    assert cc.environment.promotion == "code"


def test_cap_config_carries_our_budget_gate():
    cfg = Config()
    cfg.budget.gate_fraction = 0.5
    assert build_cap_config(cfg, FIXTURE).inference.budget_gate == 0.5


def test_framework_uses_the_injected_provider():
    provider = FakeInferenceProvider()
    fw = build_framework(Config(), FIXTURE, provider)
    assert isinstance(fw, PRFramework)
    assert fw._build_provider() is provider
    # The dispatcher is built during __init__ — the override has to be live by
    # then, which is why the provider is set before super().__init__.
    assert fw.dispatcher is not None


def test_framework_construction_makes_no_cap_edits():
    """The provider seam is an override, not a patch: CAP's own default is
    still the strands branch."""
    import inspect

    from cap_engine.config.framework import CAPFramework

    assert "kiro-cli" in inspect.getsource(CAPFramework._build_provider)
    assert "strands" in inspect.getsource(CAPFramework._build_provider)


def test_invalid_config_fails_fast():
    cfg = Config()
    cfg.budget.gate_fraction = 5.0          # CAP requires 0 < gate <= 1
    with pytest.raises(ValueError, match="budget_gate"):
        build_framework(cfg, FIXTURE, FakeInferenceProvider())


def test_role_model_map_covers_every_configured_role():
    assert set(role_model_map(Config())) == {"planner", "worker", "verifier", "triage"}


def test_default_envelope_helper():
    env = parse_envelope(default_envelope("synthesizer", "did the thing"))
    assert env.persona == "synthesizer" and env.summary == "did the thing"


def test_recorded_call_exposes_everything_sent():
    c = RecordedCall(agent_id="worker-1-1", persona="worker",
                     system_prompt_parts=["a", "b"], user_prompt="c", tool_names=[])
    assert c.system_prompt == "a\nb"
    assert c.everything_sent == "a\nb\nc"
