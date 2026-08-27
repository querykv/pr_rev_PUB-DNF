"""Configuration (cross-cutting §10).

Precedence: CLI > env > file > defaults. The file (pr_review.yaml) is optional —
defaults produce a working run.

M0 shipped vcs/detectors/gate/output. M1 adds the four sections the profiling and
change phases need: `models` (role tiering), `budget`, `languages`, `profile`
(drift thresholds + anchor globs).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel

from pr_review.schema import Severity


class VCSConfig(BaseModel):
    provider: str = "github"
    token_env: str = "GH_TOKEN"


# ---------------------------------------------------------------------------
# Models (cross-cutting §10) — tiered routing is the main cost lever
# ---------------------------------------------------------------------------

class RoleModel(BaseModel):
    """Per-role model binding.

    NOTE: no `temperature`. Current Claude models (Opus 5, Sonnet 5, Opus 4.8/4.7)
    reject `temperature`/`top_p`/`top_k` with a 400 — the knob was removed. Depth
    is controlled by `effort` instead. cross-cutting §10 predates that change and
    still specifies per-role temperatures; `effort` is the replacement, and
    `verifier` gets the determinism role that "temperature pinned to 0" used to
    serve (cross-cutting §9.4).

    This also means CAP's `ModelConfig.temperature` must NOT be forwarded to a
    current model — see the M1 plan, fix #5.
    """
    model_id: str
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"


class ModelsConfig(BaseModel):
    provider: str = "bedrock"
    roles: dict[str, RoleModel] = {
        # Structural-only planning; decides what gets read, so it pays for depth.
        "planner": RoleModel(model_id="anthropic.claude-opus-5", effort="high"),
        # The bulk of tokens — reads source and produces findings.
        "worker": RoleModel(model_id="anthropic.claude-sonnet-5", effort="high"),
        # The precision lever; adversarial refutation.
        "verifier": RoleModel(model_id="anthropic.claude-opus-5", effort="high"),
        # Noise filter / SAST triage: cheap, high volume, shallow judgements.
        "triage": RoleModel(model_id="anthropic.claude-haiku-4-5", effort="low"),
    }

    def role(self, name: str) -> RoleModel:
        try:
            return self.roles[name]
        except KeyError:
            raise KeyError(
                f"no model configured for role {name!r} "
                f"(have: {', '.join(sorted(self.roles))})"
            ) from None


class BudgetConfig(BaseModel):
    """Per-PR ceiling (locked decision §13.6: configurable, sane default)."""
    max_tokens_per_pr: int = 400_000     # 0 = unlimited
    gate_fraction: float = 0.8           # CAP halts further planning cycles at this fraction
    wall_clock_target_s: int = 300


class ProfileConfig(BaseModel):
    """Phase-1 drift thresholds (phase-1 §6).

    Starter values, tuned by the benchmark. `anchor_globs` empty means "use the
    language catalog's list" (`profile/patterns/<lang>.yaml: anchor_globs`), so
    the anchors stay next to the framework knowledge that motivates them.
    """
    drift_file_pct: float = 0.25
    drift_edge_pct: float = 0.15
    anchor_globs: list[str] = []
    cache_root: str = ".pr_review/cache"


class SecretsConfig(BaseModel):
    enabled: bool = True
    tool: str = "gitleaks"  # falls back to builtin scanner if the binary is absent


class SentinelConfig(BaseModel):
    """Injection sentinel (cross-cutting §9.3).

    `allowlist_paths` exists because the sentinel's phrase rules are lexical:
    a repo that legitimately carries prompt text — an LLM application, a
    security test corpus — contains its own attack payloads as data. Globs
    listed here are scanned but never gate. Empty by default; a repo that needs
    it should say so explicitly rather than have the tool guess.
    """
    enabled: bool = True
    allowlist_paths: list[str] = []


class SemgrepConfig(BaseModel):
    """SAST breadth (cross-cutting §10, phase-3 §3a).

    `baseline_aware` turns on Semgrep's own `--baseline-commit` diff scoping.
    It is on by default and is *not* a substitute for `findings/delta.py`: it
    scopes only Semgrep's results, while delta scoping has to answer the same
    question for every detector, including the ones with no notion of a commit.
    """
    enabled: bool = True
    ruleset: str = "p/python"
    baseline_aware: bool = True
    configs: list[str] = []          # extra --config values (custom rule packs)
    timeout_s: int = 300


class SCAConfig(BaseModel):
    enabled: bool = True
    tool: str = "osv-scanner"
    timeout_s: int = 300


class IaCConfig(BaseModel):
    enabled: bool = True
    tool: str = "checkov"
    timeout_s: int = 300


class StructuralConfig(BaseModel):
    """Our own CPG rules. No external binary, but it needs `--head-dir`."""
    enabled: bool = True


class BaselineConfig(BaseModel):
    """Base-commit baseline for delta scoping (cross-cutting §5).

    Turning it off is supported and costs precision, not correctness: scoping
    falls back to hunk overlap and says so in the run's notes.
    """
    enabled: bool = True
    cache: bool = True


class DetectorsConfig(BaseModel):
    secrets: SecretsConfig = SecretsConfig()
    sentinel: SentinelConfig = SentinelConfig()
    semgrep: SemgrepConfig = SemgrepConfig()
    sca: SCAConfig = SCAConfig()
    iac: IaCConfig = IaCConfig()
    structural: StructuralConfig = StructuralConfig()


class GateConfig(BaseModel):
    severity_floor: Severity = Severity.HIGH
    confidence_floor: int = 6
    comment_threshold: Severity = Severity.MEDIUM


class OutputConfig(BaseModel):
    formats: list[str] = ["markdown", "sarif", "json"]


class Config(BaseModel):
    vcs: VCSConfig = VCSConfig()
    models: ModelsConfig = ModelsConfig()
    budget: BudgetConfig = BudgetConfig()
    languages: list[str] = ["python"]
    profile: ProfileConfig = ProfileConfig()
    detectors: DetectorsConfig = DetectorsConfig()
    baseline: BaselineConfig = BaselineConfig()
    gate: GateConfig = GateConfig()
    output: OutputConfig = OutputConfig()

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        """Load from yaml if present, else defaults. Looks for pr_review.yaml in CWD."""
        if path is None:
            default = Path("pr_review.yaml")
            path = default if default.exists() else None
        if path is None:
            return cls()
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls.model_validate(data)
