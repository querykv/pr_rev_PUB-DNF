"""A concrete `ModelProvider` backed by the `claude` CLI in headless mode.

WHY THIS EXISTS, GIVEN `bedrock.py` DOES NOT

`M1_STATUS.md` §5.3 blocks `models/bedrock.py` on AWS credentials that are not
coming. But `ModelProvider.complete()` is a one-shot seam -- messages in, text
out -- and `claude -p --output-format json` is exactly that shape. So the seam
can be filled without Bedrock, without `boto3` and without `strands-agents`.

WHAT THIS IS NOT

It is *not* `bedrock.py` and does not discharge §5.3. It fills the
`ModelProvider` half only. CAP's `InferenceProvider` -- the agent-orchestration
half -- takes `system_prompt_parts` so a provider can place prompt-cache
breakpoints, which is the token economy Phase 1 exists to buy. Flattening that
into one CLI prompt would destroy the mechanism, so this deliberately does not
implement it (`PIVOT_PLAN.md` §1.0).

THE THING THIS MODULE IS PARANOID ABOUT

Token accounting. The standing caveat on this project is that cost is
**unmeasured, not low** -- the Strands usage keys were guessed and failed
silently to zero, so a run reported "free" when it meant "uncounted". Every
guard here exists to make that failure loud instead:

  * a missing usage key raises, it does not default to 0;
  * a non-empty `tools=` raises rather than being silently dropped;
  * an unmapped `model_id` raises rather than falling back to a default, because
    a silent fallback measures a different model than the config names;
  * `effort` IS expressible -- `--effort {low,medium,high,xhigh,max}` -- which
    an earlier version of this file got wrong and recorded as "dropped". It is
    now passed through, and it is the single largest cost lever measured here.

THE FLOOR IS A CALIBRATION AND IT HAS ALREADY EXPIRED ONCE

`TRANSPORT_FLOOR_TOKENS` below was measured once, against `claude` 2.1.235. On
2026-08-24 a version check was added -- and fired immediately: the machine was
running 2.1.241, whose floor measures **7,777**, ~477 above the constant. Nobody
had noticed, because there is no second source for this number and therefore
nothing that can disagree with it. That is the entire argument for recording the
CLI version per run (`accounting()`), and for `_FLOOR_BY_VERSION` holding every
measurement rather than the latest one. `OPEN_ITEMS.md` §21.

MEASURED TRANSPORT OVERHEAD (2026-08-21, `--model sonnet`)

The CLI prepends its own system prompt, and it is not small. Measured on a
one-line prompt:

    default prompt             15,720 cached tokens   $0.0963   cold
    same again (cache warm)    13,136 read            $0.0224
    `--system-prompt` +
      `--exclude-dynamic-...`   7,263 cached          $0.0448   cold

WHERE OUR PROMPT ACTUALLY LANDS (measured 2026-08-22, and it is not where the
first version of this file said)

A 23 KB user prompt (~6k tokens) sent through this transport reported:

    input_tokens                      2
    output_tokens                     3
    cache_creation_input_tokens  11,643      <- our prompt is IN HERE
    cache_read_input_tokens       7,445      <- the CLI system prompt, warm

Claude Code sets a cache breakpoint after the last user message, so the prompt
we send is *cached input*, not `input_tokens`. The consequence is that
`input_tokens + output_tokens` is NOT "our content" -- it is the uncached
remainder, and it is near-zero regardless of how large our prompt is. The
fields are named `uncached_tokens` / `cached_tokens` for that reason, and any
report that splits them as ours-vs-theirs is wrong. Errata §14.44.

AND THE PLACEMENT IS NOT STABLE. Arm 2b's 33 haiku triage calls put 80,794
tokens in `input_tokens` and only 239,553 in the two cache fields -- the
opposite of arm 3's sonnet calls (230 uncached per call vs ~11.9k cached).
The likely mechanism is the minimum cacheable prompt length, which is higher
for Haiku than for Sonnet, so a triage prompt that clears Sonnet's threshold
misses Haiku's and is billed uncached. Marked as inference: the CLI does not
report why.

The consequence for reporting is concrete. Our content is `total - floor`, NOT
`cached - floor`; taking it from the cached bucket alone reports zero tokens of
our own content for arm 2b. See `benchmark/report.py:render_cost`.

Two consequences, both load-bearing. **Cost:** the overhead dominates a small
call, so a cold invocation costs ~4x a warm one; the cache is keyed on the
prompt prefix and lives ~1h, so batched runs amortize it and scattered ones do
not. **Method:** the default prompt tells the model it is a coding agent with
tools, which is not "a raw LLM given a diff". `--system-prompt` replaces it and
is therefore correct on both axes -- but ~7.3k tokens of harness remain, and any
cost reported from this transport must say so rather than be quoted as an API
price.

EFFORT IS THE COST LEVER, AND IT IS LARGER THAN THE PROMPT (measured 2026-08-21)

One arm-3 call on a 9.2 KB diff, `--model sonnet`:

    (no flag, the default)   9,399 output   of which 9,033 thinking   78s   $0.149
    --effort medium            646 output   of which   342 thinking    8s   $0.087
    --effort low               245 output   of which     0 thinking    5s   $0.081

**96% of the default call's output is extended thinking**, at the output token
price. Effort therefore decides both the bill and the wall clock -- 15x on the
latter -- and a benchmark arm that does not state its effort level has not
described what it measured. `plan/benchmark.md` §3 asks for "a raw
single-prompt LLM"; a default-effort call is a reasoning loop, which is a
defensible baseline but a different one, and either way it must be named.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Callable

from pr_review.models.provider import ModelProvider

# Config carries Bedrock-style ids; the CLI takes its own aliases. Unmapped ids
# raise: silently defaulting would report numbers for a model nobody selected.
_MODEL_ALIASES = {
    "anthropic.claude-opus-5": "opus",
    "anthropic.claude-sonnet-5": "sonnet",
    "anthropic.claude-haiku-4-5": "haiku",
}

# `--disallowedTools` blocks *use*. It is half the guard: the other half is the
# working directory, because a tool-free model in a repo still cannot read what
# it is not given. Callers that care (the arm-3 baseline) must also run from a
# neutral cwd -- see `PIVOT_PLAN.md` §1.4.
_TOOL_DENYLIST = (
    "Read", "Write", "Edit", "Bash", "Glob", "Grep",
    "WebFetch", "WebSearch", "Task", "NotebookEdit", "TodoWrite",
)

_EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})

# Cached tokens one call costs before we send anything of our own, measured with
# `--system-prompt` + `--exclude-dynamic-system-prompt-sections` (see the module
# docstring: 7,263 cold, 7,445 read warm). It is a CALIBRATION, not a per-run
# measurement -- the CLI does not report the split, so this is the only way to
# say how much of `cached_tokens` is ours. Re-measure it when the CLI version
# changes; a stale floor silently reattributes harness tokens to our content.
TRANSPORT_FLOOR_TOKENS = 7_300

# The calibration's provenance, kept beside the number it qualifies. `OPEN_ITEMS.md`
# §21: the floor is ONE measurement against ONE CLI build, and nothing in the test
# suite can notice when it goes stale -- there is no second source to disagree with
# it. So the run records the CLI version it actually used (`accounting()` below) and
# the readers compare. A mismatch is REPORTED, never raised: the stale floor is still
# the best number available, it just stops being trusted silently.
TRANSPORT_FLOOR_CLI_VERSION = "2.1.235"

# Every floor measurement taken, keyed by the CLI build it was taken against.
# This exists because the check above FIRED THE FIRST TIME IT RAN (2026-08-24):
# the machine had moved to 2.1.241 and nothing had noticed, which is precisely
# the silent staleness `OPEN_ITEMS.md` §21 describes.
#
#   2.1.235  7,263 cold / 7,445 warm   2026-08-21, `--model sonnet`
#   2.1.241  7,777 both                2026-08-24, same method, `--effort low`
#
# `TRANSPORT_FLOOR_TOKENS` still reads 7,300 deliberately. Changing it re-derives
# the harness/ours split of every STORED run -- including runs produced by the
# older CLI, whose split 7,300 is right for -- and that split is published
# (`REPORT.md` §4: ~380k harness against ~250k content). So the constant is a
# published number with a landing cost, not a knob. See §21 for the decision.
_FLOOR_BY_VERSION = {"2.1.235": 7_300, "2.1.241": 7_777}


def measured_floor(cli_version: str | None) -> int | None:
    """The floor actually measured against `cli_version`, or None if that build
    was never calibrated. None means unknown -- never substitute the default."""
    return _FLOOR_BY_VERSION.get(cli_version or "")


def floor_for(accounting: dict | None) -> int:
    """The floor to price THIS run's harness with.

    A run priced by the floor measured for its own CLI, falling back to
    `TRANSPORT_FLOOR_TOKENS` when the version is unknown or was never
    calibrated. `OPEN_ITEMS.md` §21.

    The fallback is what keeps this change inert on everything already stored:
    no `run.json` written before 2026-08-24 carries `cli_version`, so every one
    of them prices exactly as it did before. That is asserted, not assumed --
    see `test_a_run_with_no_version_prices_exactly_as_the_constant_does`.

    Note what this does NOT do: it does not guess. A build nobody measured
    (2.1.239, 2.1.240) falls back to the constant and the readers say so,
    because inventing an interpolated floor would produce a number with no
    measurement behind it and no way to tell that from one that has.
    """
    return measured_floor((accounting or {}).get("cli_version")) or TRANSPORT_FLOOR_TOKENS

_REQUIRED_USAGE = (
    "input_tokens", "output_tokens",
    "cache_creation_input_tokens", "cache_read_input_tokens",
)


class ClaudeCliError(RuntimeError):
    """The CLI failed, or answered in a shape we refuse to guess at."""


@dataclass
class CliCall:
    """One invocation's accounting. Every field is read from the CLI's own
    report; nothing here is inferred."""

    model: str
    usage: dict
    cost_usd: float
    duration_ms: int
    num_turns: int
    denials: int
    effort: str = ""

    @property
    def uncached_tokens(self) -> int:
        """`input_tokens + output_tokens`, exactly as the CLI reports them.

        THIS IS NOT "OUR CONTENT". It was named `content_tokens` and documented
        as "our prompt and the answer" until a probe on 2026-08-21 showed the
        claim is false: Claude Code marks a cache breakpoint *after* the last
        user message, so **our prompt lands in `cache_creation_input_tokens`**
        and `input_tokens` is the trailing remainder -- measured at **2** for a
        23 KB prompt. Errata §14.44.

        So this bucket is "what the CLI billed uncached", which under its
        caching design is essentially the answer plus rounding. The honest split
        of ours-vs-theirs is not derivable from `usage` alone; it needs the
        measured per-call transport floor in this module's docstring.
        """
        return int(self.usage["input_tokens"]) + int(self.usage["output_tokens"])

    @property
    def cached_tokens(self) -> int:
        """`cache_creation + cache_read`. Contains the CLI's system prompt **and
        our prompt**, which is why it cannot be quoted as pure overhead."""
        return (int(self.usage["cache_creation_input_tokens"])
                + int(self.usage["cache_read_input_tokens"]))


def _default_version_probe(binary: str) -> str | None:
    """`claude --version` -> "2.1.235", or None if the CLI cannot be asked.

    Deliberately total: a provider that cannot report its version must record
    *unknown* rather than fail a run, and unknown must not read as *matching*.
    """
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True,
                              text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    # "2.1.235 (Claude Code)" -> "2.1.235"
    head = proc.stdout.strip().split()
    return head[0] if head else None


def _default_runner(argv: list[str], timeout: int) -> str:
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise ClaudeCliError(
            f"`claude` exited {proc.returncode}: {proc.stderr.strip()[:400]}")
    return proc.stdout


class ClaudeCliProvider(ModelProvider):
    """`ModelProvider` over `claude -p`.

    `cwd` matters and has no safe default, so it is required. The triage caller
    can run anywhere; the arm-3 baseline must run outside any corpus checkout,
    and making the caller say which keeps that decision visible.
    """

    def __init__(
        self,
        cwd: str,
        *,
        system_prompt: str | None = None,
        default_model: str = "sonnet",
        binary: str = "claude",
        timeout: int = 300,
        runner: Callable[[list[str], int], str] | None = None,
        version_probe: Callable[[str], str | None] | None = None,
    ) -> None:
        self.cwd = cwd
        self.system_prompt = system_prompt
        self.default_model = default_model
        self.binary = binary
        self.timeout = timeout
        self._runner = runner or _default_runner
        # Separate from `runner` on purpose: a test fake that returns a canned
        # JSON response would otherwise "answer" --version with it.
        self._version_probe = version_probe or _default_version_probe
        self._cli_version: str | None = None
        self._version_probed = False
        self.calls: list[CliCall] = []

    # -- accounting ---------------------------------------------------------

    @property
    def total_cost_usd(self) -> float:
        return sum(c.cost_usd for c in self.calls)

    @property
    def total_uncached_tokens(self) -> int:
        return sum(c.uncached_tokens for c in self.calls)

    @property
    def total_cached_tokens(self) -> int:
        return sum(c.cached_tokens for c in self.calls)

    def accounting(self, since: int = 0) -> dict:
        """What telemetry should record. Zero calls is distinguishable from
        zero cost -- the M0 telemetry stub reported `{"input": 0, "output": 0}`
        for "no AI ran", and that ambiguity is what this avoids.

        `since` slices from a call index, so one long-lived provider can report
        both a per-case cost and a corpus total without the caller keeping a
        second ledger that could disagree with this one.
        """
        calls = self.calls[since:]
        return {
            "calls": len(calls),
            "cost_usd": round(sum(c.cost_usd for c in calls), 6),
            "uncached_tokens": sum(c.uncached_tokens for c in calls),
            "cached_tokens": sum(c.cached_tokens for c in calls),
            "models": sorted({c.model for c in calls}),
            "tool_denials": sum(c.denials for c in calls),
            # Calls the CLI reported as taking more than one turn. Recorded
            # separately from `tool_denials` because they are different facts and
            # were conflated until 2026-08-26: a denied tool forces a second turn,
            # but a second turn does not imply a tool (errata §14.60).
            "multi_turn_calls": sum(1 for c in calls if c.num_turns > 1),
            "effort": sorted({c.effort for c in calls if c.effort}),
            # Which CLI produced these numbers, so `TRANSPORT_FLOOR_TOKENS` can be
            # checked against the build it was calibrated on rather than assumed.
            # Absent when nothing ran -- see `cli_version`.
            "cli_version": self.cli_version(),
        }

    def cli_version(self) -> str | None:
        """The live `claude --version`, probed once, only if a call was made.

        Gated on `self.calls` so an offline benchmark run -- the majority of them
        -- never shells out. `None` means *not asked* or *could not be asked*, and
        readers must render that as unknown rather than as agreement.
        """
        if not self.calls:
            return None
        if not self._version_probed:
            self._version_probed = True
            self._cli_version = self._version_probe(self.binary)
        return self._cli_version

    def assert_no_tool_use(self) -> None:
        """The arm-3 guard: a baseline that read the repo is a different
        experiment, and the difference is invisible in the answer text.

        WHAT THIS USED TO ASSERT, AND WHY IT WAS WRONG. It raised on any call
        with `num_turns > 1` and said "which means tools ran". That inference
        does not hold. `--disallowedTools` blocks tool *use*, so an attempted
        tool is DENIED and appears in `permission_denials`; the denial then
        forces a second turn. A second turn with **zero denials** is something
        else entirely -- a continuation or an internal retry -- and no tool ran.

        On 2026-08-26 that conflation destroyed five paid corpus passes: the
        check raised after every model call and before the scorecard was
        written, so the guard deleted the evidence it existed to protect
        (errata §14.60). Both halves are fixed. This now separates the two facts:

        * **a denial is fatal.** A tool was attempted. That is the arm-4 boundary
          and the run is not this arm.
        * **a multi-turn call with no denial is recorded, not fatal.** Nothing
          read the repository -- the denylist and the neutral cwd both held -- but
          the call was not a single prompt, so it is reported in the accounting
          under `multi_turn_calls` and belongs in the write-up rather than in an
          exception that costs a pass.
        """
        denied = [c for c in self.calls if c.denials]
        if denied:
            raise ClaudeCliError(
                f"{len(denied)} call(s) had a tool denied "
                f"({sum(c.denials for c in denied)} denial(s) in total): a tool "
                f"was ATTEMPTED, which makes this the repo-access arm rather "
                f"than a tool-free baseline.")

    # -- the seam -----------------------------------------------------------

    def resolve_model(self, model_id: str | None) -> str:
        if not model_id:
            return self.default_model
        if model_id in _MODEL_ALIASES:
            return _MODEL_ALIASES[model_id]
        if model_id in set(_MODEL_ALIASES.values()):
            return model_id
        raise ClaudeCliError(
            f"no CLI alias for model_id {model_id!r}. Add it to _MODEL_ALIASES "
            f"rather than letting the run silently use {self.default_model!r} -- "
            f"a fallback here reports numbers for a model nobody selected.")

    def complete(self, messages: list[dict], tools: list | None = None, **cfg: Any) -> str:
        if tools:
            raise NotImplementedError(
                "ClaudeCliProvider takes no tool list: the CLI has its own tools "
                "and cannot be handed Python callables. Silently dropping them "
                "would run a different computation than the caller asked for.")

        system = "\n\n".join(m["content"] for m in messages if m.get("role") == "system")
        user = "\n\n".join(m["content"] for m in messages if m.get("role") != "system")
        if not user.strip():
            raise ClaudeCliError("no user content in messages")

        model = self.resolve_model(cfg.get("model_id"))
        argv = [self.binary, "-p", user, "--output-format", "json", "--model", model]

        # Replace rather than append: see the module docstring. `--system-prompt`
        # both strips ~8.5k tokens of harness and stops the baseline from being
        # told it is a coding agent.
        prompt = self.system_prompt if self.system_prompt is not None else system
        if prompt:
            argv += ["--system-prompt", prompt, "--exclude-dynamic-system-prompt-sections"]
        effort = str(cfg.get("effort") or "").strip().lower()
        if effort:
            if effort not in _EFFORTS:
                raise ClaudeCliError(
                    f"effort {effort!r} is not one of {sorted(_EFFORTS)}. Refusing "
                    f"to drop it silently: effort is this transport's largest cost "
                    f"lever, and a run that ignored it would report the wrong price "
                    f"for the wrong computation.")
            argv += ["--effort", effort]
        argv += ["--disallowedTools", *_TOOL_DENYLIST]

        raw = self._runner(argv, self.timeout)
        return self._parse(raw, model, effort=effort)

    def _parse(self, raw: str, model: str, effort: str = "") -> str:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ClaudeCliError(
                f"`claude` did not return JSON ({exc}); first 200 chars: {raw[:200]!r}"
            ) from exc

        if data.get("is_error"):
            raise ClaudeCliError(
                f"CLI reported an error: {data.get('api_error_status') or data.get('subtype')}")

        usage = data.get("usage")
        if not isinstance(usage, dict):
            raise ClaudeCliError("CLI response carried no `usage` object")
        missing = [k for k in _REQUIRED_USAGE if k not in usage]
        if missing:
            # The whole point of this class. See the module docstring.
            raise ClaudeCliError(
                f"usage keys absent from the CLI response: {missing}. Refusing to "
                f"default them to 0 -- that is precisely how this project's cost "
                f"telemetry came to read 'free' when it meant 'uncounted'.")

        if "result" not in data:
            raise ClaudeCliError("CLI response carried no `result` field")

        self.calls.append(CliCall(
            model=model,
            usage=usage,
            cost_usd=float(data.get("total_cost_usd") or 0.0),
            duration_ms=int(data.get("duration_ms") or 0),
            num_turns=int(data.get("num_turns") or 0),
            denials=len(data.get("permission_denials") or ()),
            effort=effort,
        ))
        return str(data["result"])


def cli_available(binary: str = "claude") -> bool:
    return shutil.which(binary) is not None
