"""`ClaudeCliProvider` -- the `claude -p` transport behind the ModelProvider seam.

Every test here uses an injected runner. Nothing in this file spends money or
requires the CLI to exist; the one-time measurement of the real transport is
recorded in the module docstring of `claude_cli.py`, not re-run per test.

The bias of these tests is deliberate. Most of them assert that something
*raises*, because the failure this class exists to prevent is silent: a run that
reports zero cost when it means uncounted cost. A provider that degrades quietly
would pass a happy-path suite and still produce the wrong headline number.
"""
import json

import pytest

from pr_review.change import filter as change_filter
from pr_review.config import Config
from pr_review.models.claude_cli import (
    ClaudeCliError,
    ClaudeCliProvider,
    _REQUIRED_USAGE,
)

_USAGE = {
    "input_tokens": 2,
    "output_tokens": 62,
    "cache_creation_input_tokens": 2766,
    "cache_read_input_tokens": 13136,
}


def _response(result='{"a":"yes"}', **over):
    body = {
        "is_error": False,
        "result": result,
        "usage": dict(_USAGE),
        "total_cost_usd": 0.0224378,
        "duration_ms": 2081,
        "num_turns": 1,
        "permission_denials": [],
    }
    body.update(over)
    return json.dumps(body)


def _provider(raw=None, **kw):
    """Provider whose runner returns a canned CLI response and records argv."""
    seen: list[list[str]] = []

    def runner(argv, timeout):
        seen.append(argv)
        return raw if raw is not None else _response()

    p = ClaudeCliProvider("/tmp", runner=runner, **kw)
    p.seen = seen                                     # type: ignore[attr-defined]
    return p


# -- the happy path, and what it must carry ---------------------------------

def test_the_result_field_is_what_comes_back():
    p = _provider()
    assert p.complete([{"role": "user", "content": "hi"}]) == '{"a":"yes"}'


def test_tools_are_disallowed_on_every_call():
    p = _provider()
    p.complete([{"role": "user", "content": "hi"}])
    argv = p.seen[0]
    assert "--disallowedTools" in argv
    for tool in ("Read", "Bash", "Task", "WebFetch"):
        assert tool in argv


def test_the_system_message_becomes_a_replaced_prompt_not_an_appended_one():
    """`--append-system-prompt` would keep the CLI's ~15.7k-token agent prompt,
    which both inflates cost ~4x and tells a supposedly raw baseline that it is
    a coding agent. Replacement is correct on both axes."""
    p = _provider()
    p.complete([{"role": "system", "content": "SYS"}, {"role": "user", "content": "hi"}])
    argv = p.seen[0]
    assert "--system-prompt" in argv
    assert "--append-system-prompt" not in argv
    assert argv[argv.index("--system-prompt") + 1] == "SYS"
    assert "--exclude-dynamic-system-prompt-sections" in argv


def test_accounting_reports_the_cached_and_uncached_buckets():
    """Quoting `cost_usd` alone overstates what an API caller would pay; quoting
    one token bucket alone understates the bill. Both are reported, named for
    what the CLI actually reports rather than for what we wish it reported."""
    p = _provider()
    p.complete([{"role": "user", "content": "hi"}])
    acct = p.accounting()
    assert acct["calls"] == 1
    assert acct["uncached_tokens"] == 64            # input 2 + output 62
    assert acct["cached_tokens"] == 15902           # creation 2766 + read 13136
    assert acct["cost_usd"] > 0


def test_a_large_prompt_does_not_show_up_in_the_uncached_bucket():
    """§14.44. These fields were named `content_tokens` / `transport_overhead`
    and documented as ours-vs-theirs. Claude Code caches through the last user
    message, so a 23 KB prompt reported `input_tokens: 2` -- the old names
    claimed our whole prompt was 2 tokens of "content" and 11,643 tokens of
    somebody else's "overhead".

    This pins the shape that falsified it: a call whose prompt is entirely in
    `cache_creation` must not be describable as having sent nothing.
    """
    p = _provider(raw=_response(
        result="406",
        total_cost_usd=0.05556,
        # Verbatim from the 2026-08-22 probe: a 23 KB prompt through this
        # transport, `--model sonnet --effort low`.
        usage={"input_tokens": 2, "output_tokens": 3,
               "cache_creation_input_tokens": 11643,
               "cache_read_input_tokens": 7445},
    ))
    p.complete([{"role": "user", "content": "x" * 23_000}])
    acct = p.accounting()
    assert acct["uncached_tokens"] == 5             # NOT our 23 KB prompt
    assert acct["cached_tokens"] == 19088           # our prompt is in here


def test_zero_calls_is_distinguishable_from_zero_cost():
    """M0's telemetry stub wrote {"input": 0, "output": 0} to mean "no AI ran",
    and that ambiguity is the thing this project keeps paying for."""
    assert _provider().accounting()["calls"] == 0


# -- the guards, each of which exists because of a specific past failure -----

@pytest.mark.parametrize("key", _REQUIRED_USAGE)
def test_a_missing_usage_key_raises_rather_than_defaulting_to_zero(key):
    """The Strands lesson: guessed usage keys failed silently to zero, and a run
    reported "free" when it meant "uncounted"."""
    usage = {k: v for k, v in _USAGE.items() if k != key}
    p = _provider(_response(usage=usage))
    with pytest.raises(ClaudeCliError, match="usage keys absent"):
        p.complete([{"role": "user", "content": "hi"}])


def test_passing_tools_raises_rather_than_dropping_them():
    p = _provider()
    with pytest.raises(NotImplementedError):
        p.complete([{"role": "user", "content": "hi"}], tools=[lambda: None])


def test_an_unmapped_model_id_raises_rather_than_falling_back():
    """A silent fallback reports numbers for a model nobody selected."""
    p = _provider()
    with pytest.raises(ClaudeCliError, match="no CLI alias"):
        p.complete([{"role": "user", "content": "hi"}], model_id="anthropic.claude-nonexistent")


def test_the_configs_bedrock_ids_all_resolve():
    """Anti-vacuity for the test above: the guard must not be rejecting the ids
    the shipped config actually uses."""
    p = _provider()
    for role in Config().models.roles.values():
        assert p.resolve_model(role.model_id) in ("opus", "sonnet", "haiku")


def test_an_error_response_raises():
    p = _provider(_response(is_error=True, subtype="rate_limited"))
    with pytest.raises(ClaudeCliError, match="rate_limited"):
        p.complete([{"role": "user", "content": "hi"}])


def test_non_json_output_raises_with_the_output_in_the_message():
    p = _provider("Usage: claude [options]")
    with pytest.raises(ClaudeCliError, match="did not return JSON"):
        p.complete([{"role": "user", "content": "hi"}])


def test_a_denied_tool_is_fatal_because_a_tool_was_attempted():
    """Arm 3's guard. A baseline that read the repo is a different experiment,
    and the difference is invisible in the answer text.

    `--disallowedTools` blocks tool USE, so an attempted tool is refused and
    lands in `permission_denials`. That is the signal, and it is unambiguous.
    """
    p = _provider(_response(num_turns=4, permission_denials=[{"tool_name": "Read"}]))
    p.complete([{"role": "user", "content": "hi"}])
    with pytest.raises(ClaudeCliError, match="ATTEMPTED"):
        p.assert_no_tool_use()


def test_more_than_one_turn_alone_is_recorded_rather_than_fatal():
    """THIS TEST ASSERTED THE OPPOSITE UNTIL 2026-08-26, and the inference it
    encoded was wrong.

    It read: more than one turn "means tools ran". It does not. A denied tool
    forces a second turn, but a second turn has other causes -- a continuation,
    an internal retry -- and with zero denials nothing was attempted, let alone
    read. The denylist and the neutral cwd both held.

    The old reading cost five paid corpus passes on 2026-08-26, because the
    guard also ran before the scorecard was written. Errata §14.60. What the
    multi-turn count deserves is a line in the accounting, which it now has.
    """
    p = _provider(_response(num_turns=4))
    p.complete([{"role": "user", "content": "hi"}])
    p.assert_no_tool_use()                       # must not raise
    assert p.accounting()["multi_turn_calls"] == 1
    assert p.accounting()["tool_denials"] == 0


def test_a_single_turn_passes_the_same_guard():
    p = _provider()
    p.complete([{"role": "user", "content": "hi"}])
    p.assert_no_tool_use()
    assert p.accounting()["multi_turn_calls"] == 0


def test_effort_is_passed_through_because_it_is_the_cost_lever():
    """Measured: default effort spends 9,033 thinking tokens on one arm-3 call
    and --effort low spends 0, a 15x wall-clock difference. An earlier version
    of this file claimed the CLI could not express effort. It can."""
    p = _provider()
    p.complete([{"role": "user", "content": "hi"}], effort="low")
    argv = p.seen[0]
    assert "--effort" in argv and argv[argv.index("--effort") + 1] == "low"
    assert p.accounting()["effort"] == ["low"]


def test_an_invalid_effort_raises_rather_than_being_dropped():
    p = _provider()
    with pytest.raises(ClaudeCliError, match="not one of"):
        p.complete([{"role": "user", "content": "hi"}], effort="turbo")


# -- the seam it plugs into -------------------------------------------------

def test_it_satisfies_what_tier_3_triage_actually_calls():
    """`filter._triage` calls `provider.complete(messages, model_id=, effort=)`
    and parses a JSON label map out of the string it gets back. This asserts the
    two halves fit, without running the pipeline."""
    labels_json = '{"f1:h1": "yes", "f1:h2": "no"}'
    p = _provider(_response(result=labels_json))
    items = [("f1:h1", "a.py", "@@ -1 +1 @@"), ("f1:h2", "b.py", "@@ -2 +2 @@")]
    labels, notes = change_filter._triage(items, p, Config())
    assert labels == {"f1:h1": "yes", "f1:h2": "no"}
    assert notes == []
    assert p.accounting()["calls"] == 1


def test_a_provider_failure_degrades_to_keeping_every_hunk():
    """`_triage` catches everything and keeps. Raising is therefore safe -- the
    filter never drops a hunk because the model was unreachable."""
    p = _provider("not json at all")
    items = [("f1:h1", "a.py", "@@ -1 +1 @@")]
    labels, notes = change_filter._triage(items, p, Config())
    assert labels == {}
    assert notes and "triage unavailable" in notes[0]


# -- the transport floor's provenance (OPEN_ITEMS.md §21) --------------------

def test_the_version_is_not_probed_when_no_call_was_made():
    """The majority of benchmark runs are offline. Probing there would shell out
    on every invocation to answer a question nobody asked, so `cli_version` is
    gated on a call having happened -- and the gate is what makes putting the
    probe in `accounting()` safe."""
    probes: list[str] = []
    p = _provider(version_probe=lambda b: probes.append(b) or "9.9.9")
    assert p.cli_version() is None
    assert p.accounting()["cli_version"] is None
    assert probes == []


def test_the_version_is_probed_once_and_reported_with_the_accounting():
    p = _provider(version_probe=lambda b: "2.1.241")
    p.complete([{"role": "user", "content": "hi"}])
    assert p.accounting()["cli_version"] == "2.1.241"
    assert p.accounting()["cli_version"] == "2.1.241"      # cached, not re-probed


def test_a_probe_that_cannot_answer_reports_unknown_rather_than_failing():
    """A missing or broken CLI must not fail a run that already succeeded. But
    unknown must stay distinguishable from matching -- that is the whole point,
    so it is asserted here rather than left to the reader."""
    p = _provider(version_probe=lambda b: None)
    p.complete([{"role": "user", "content": "hi"}])
    assert p.accounting()["cli_version"] is None
