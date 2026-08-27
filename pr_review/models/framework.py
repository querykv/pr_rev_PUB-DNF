"""CAP framework wiring — injecting our provider without editing `cap_engine/`.

`CAPFramework._build_provider()` is hardcoded to a kiro/strands branch, but it
is a method, and `SubAgentDispatcher` already takes an injected provider. So the
whole integration is one override. That matters beyond convenience: `cap_engine/`
is a separate repository under a restricted licence, and every edit we avoid is
one fewer conflict when it is re-synced or eventually swapped for CAP-lite.

Also maps our `Config` onto `CAPConfig`. One mismatch is worth naming: CAP has a
**single** `model.model_id` for all personas, while `config.models.roles` is
tiered. Rather than flattening the tiering away, role→model routing lives in the
provider, which is the only component that sees `agent_id` (and therefore the
persona) at call time.
"""
from __future__ import annotations

from pathlib import Path

from cap_engine.config.framework import (
    CAPConfig,
    CAPFramework,
    EnvironmentConfig,
    InferenceConfig,
    ModelConfig,
    PersonaConfig,
    PersonasConfig,
)
from cap_engine.inference.provider import InferenceProvider

from pr_review.config import Config

# Where our authored CAP assets live. NOT `cap_engine/config/` as phase-1 §9 and
# tooling #10 specify: we author them, so they are our code, and putting new
# work inside a restricted third-party tree is gratuitous. CAP resolves all four
# of these from configurable strings, so this costs nothing.
PROMPTS_ROOT = Path(__file__).resolve().parent.parent / "prompts"


class PRFramework(CAPFramework):
    """`CAPFramework` with the provider injected and tool permissions enforced.

    The provider must be set before `super().__init__`, which calls
    `_build_dispatcher()` -> `_build_provider()` and `_build_tool_sets()` during
    construction.
    """

    def __init__(self, cap_config: CAPConfig, provider: InferenceProvider) -> None:
        self._pr_provider = provider
        self.permission_violations: list = []
        super().__init__(cap_config)

    def _build_provider(self):  # noqa: D102 — overrides CAP
        return self._pr_provider

    def _build_tool_sets(self):
        """CAP's bindings, filtered by `safety/permissions.py` (cross-cutting §9.2).

        This is the enforcement point for "planners read only structural
        metadata, never source". It is an override rather than a patch for the
        same reason `_build_provider` is: `cap_engine/` stays unmodified.

        Nothing is dropped today — CAP's planner set is already source-free. The
        override earns its place when that changes: a re-synced or CAP-lite tool
        table that hands the planner a source reader gets stripped here instead
        of quietly widening the trust boundary.
        """
        from pr_review.safety import permissions

        tool_sets, violations = permissions.enforce(super()._build_tool_sets())
        self.permission_violations = violations
        return tool_sets


def build_cap_config(
    config: Config,
    base_dir: str | Path,
    prompts_root: str | Path | None = None,
    output_dir: str | Path = ".pr_review/runs",
    log_dir: str | Path = ".pr_review/logs",
) -> CAPConfig:
    """Project our `Config` onto CAP's."""
    root = Path(prompts_root or PROMPTS_ROOT)
    worker = config.models.role("worker")
    personas = root / "personas"
    return CAPConfig(
        environment=EnvironmentConfig(base_dir=str(base_dir), promotion="code"),
        inference=InferenceConfig(budget_gate=config.budget.gate_fraction),
        # CAPConfig.validate() checks these paths exist, so a missing persona
        # prompt fails at construction rather than as a confusing agent error.
        personas=PersonasConfig(
            planner=PersonaConfig(prompt=str(personas / "planner.md")),
            worker=PersonaConfig(prompt=str(personas / "worker.md")),
            synthesizer=PersonaConfig(prompt=str(personas / "synthesizer.md")),
        ),
        # Informational only — the provider routes per persona (see module docstring).
        model=ModelConfig(provider="strands", model_id=worker.model_id),
        log_dir=str(log_dir),
        output_dir=str(output_dir),
        workflows_dir=str(root / "workflows"),
        tasks_dir=str(root / "tasks"),
        templates_dir=str(root / "templates"),
    )


def build_framework(
    config: Config,
    base_dir: str | Path,
    provider: InferenceProvider,
    **cap_config_kwargs,
) -> PRFramework:
    """Construct a ready CAP framework backed by `provider`.

    Raises on an invalid CAP config rather than letting a missing persona prompt
    or a bad budget surface later as a confusing agent failure.
    """
    cap_config = build_cap_config(config, base_dir, **cap_config_kwargs)
    errors = cap_config.validate()
    if errors:
        raise ValueError("invalid CAP configuration: " + "; ".join(errors))
    return PRFramework(cap_config, provider)


def role_model_map(config: Config) -> dict[str, str]:
    """`{persona: model_id}` for the provider's routing table.

    CAP's personas are planner/worker/synthesizer; our config also carries
    `verifier` and `triage`, which are used off the CAP path.
    """
    return {name: role.model_id for name, role in config.models.roles.items()}
