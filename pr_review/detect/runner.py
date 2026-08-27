"""The 3a stage: build the detector set, run it, and build the baseline.

Separated from `pipeline.py` because two callers need the same set built the
same way — the head-side pass that produces candidates, and the base-side pass
that produces the baseline those candidates are scoped against
(`findings/delta.py`). If the two sets could drift apart, delta scoping would
compare findings from one collection of detectors against fingerprints from
another, and the difference would read as "introduced by this PR".

EVERY DETECTOR'S ABSENCE IS RECORDED. `telemetry["detect"]` carries one entry
per detector with a status — `ran`, `missing_tool`, `not_applicable`, `disabled`
or `error` — because a detector that found nothing and a detector that never ran
produce the same empty list, and only one of them is reassuring. In this
environment `semgrep`, `osv-scanner` and `checkov` are all absent, so a run here
should show three `missing_tool` entries. If it ever shows a silent zero
instead, that is the bug this design exists to make impossible.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pr_review.config import Config
from pr_review.detect.base import AdapterRun, Detector, ScanTarget
from pr_review.detect.iac import IaCDetector
from pr_review.detect.sast_semgrep import SemgrepDetector
from pr_review.detect.sca import SCADetector
from pr_review.detect.secrets import SecretsDetector
from pr_review.detect.structural import StructuralDetector, head_subgraph
from pr_review.extract.schema import DeltaManifest
from pr_review.findings.delta import (
    Baseline,
    BaselineCache,
    build_baseline,
    expected_baseline_paths,
)
from pr_review.schema import Finding


@dataclass
class DetectStage:
    findings: list[Finding] = field(default_factory=list)
    baseline: Baseline | None = None
    telemetry: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _reader(root: Path):
    """A `(path, side) -> text` reader pinned to one checkout.

    The pipeline's own reader answers "before" and "after" from two different
    trees. The baseline pass has only one tree and needs it to answer whatever
    side a detector asks for, because to the base-side detectors that tree *is*
    the current state of the world.
    """
    def read(path: str, side: str = "after") -> str | None:
        try:
            return (root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    return read


def _run_one(det: Detector, targets: list[ScanTarget]) -> AdapterRun:
    """Run a detector without letting it take the review down with it."""
    try:
        if not det.applicable(targets):
            scan = getattr(det, "scan", None)
            # An adapter with `scan()` explains its own inapplicability better
            # than a generic string can (missing binary vs. nothing to scan).
            return scan(targets) if scan else AdapterRun("not_applicable")
        scan = getattr(det, "scan", None)
        if scan is not None:
            return scan(targets)
        return AdapterRun("ran", findings=det.run(targets))
    except Exception as exc:                         # noqa: BLE001
        return AdapterRun("error", notes=[
            f"{det.name} detector raised {type(exc).__name__}: {exc}. The review "
            f"continued without it, so this class is unscanned."])


def build_detectors(
    *,
    config: Config,
    manifest: DeltaManifest,
    root: Path | None,
    cpg=None,
    base_cpg=None,
    changed_paths: set[str] | None = None,
    sources=None,
    baseline_commit: str | None = None,
    include_sca: bool = True,
) -> list[Detector]:
    """The configured detector set, pointed at one checkout.

    `root` is whichever side is being scanned — head for candidates, base for
    the baseline — and `cpg` is the graph of that same side. Keeping them as
    parameters rather than reading them from a run context is what lets the
    baseline pass reuse this function unchanged.
    """
    cfg = config.detectors
    dets: list[Detector] = []
    if cfg.secrets.enabled:
        dets.append(SecretsDetector())
    if cfg.structural.enabled:
        dets.append(StructuralDetector(head_cpg=cpg, base_cpg=base_cpg,
                                       changed_paths=changed_paths, sources=sources))
    if cfg.semgrep.enabled:
        dets.append(SemgrepDetector(
            ruleset=cfg.semgrep.ruleset, head_dir=root,
            baseline_commit=baseline_commit, timeout_s=cfg.semgrep.timeout_s,
            configs=tuple(cfg.semgrep.configs)))
    if cfg.iac.enabled:
        dets.append(IaCDetector(
            head_dir=root,
            iac_paths={f.path for f in manifest.files if f.is_iac},
            timeout_s=cfg.iac.timeout_s))
    if include_sca and cfg.sca.enabled:
        dets.append(SCADetector(manifest=manifest, head_dir=root,
                                timeout_s=cfg.sca.timeout_s))
    return dets


def detect_stage(
    *,
    repo: str,
    manifest: DeltaManifest,
    targets: list[ScanTarget],
    config: Config,
    base_dir: Path | None,
    head_dir: Path | None,
    base_cpg=None,
    sources=None,
) -> DetectStage:
    """Run 3a on the head side and produce the base-side baseline."""
    stage = DetectStage()
    changed = {f.path for f in manifest.files}
    language = config.languages[0] if config.languages else "python"

    # -- the head-side graph, if there is a head checkout to build it from ---
    head_cpg = None
    if head_dir is not None and config.detectors.structural.enabled:
        try:
            head_cpg = head_subgraph(head_dir, manifest, language=language)
        except Exception as exc:                     # noqa: BLE001
            stage.notes.append(
                f"head-side CPG could not be built ({type(exc).__name__}: {exc}); "
                f"the structural detector is disabled for this run.")

    detectors = build_detectors(
        config=config, manifest=manifest, root=head_dir, cpg=head_cpg,
        base_cpg=base_cpg, changed_paths=changed, sources=sources,
        baseline_commit=(manifest.base_sha
                         if config.detectors.semgrep.baseline_aware else None),
    )

    for det in detectors:
        run = _run_one(det, targets)
        stage.findings.extend(run.findings)
        stage.notes.extend(run.notes)
        stage.telemetry[det.name] = {"status": run.status,
                                     "findings": len(run.findings), **run.detail}

    stage.baseline = _baseline(repo=repo, manifest=manifest, config=config,
                               base_dir=base_dir, base_cpg=base_cpg,
                               changed=changed, stage=stage)
    return stage


def _baseline(*, repo: str, manifest: DeltaManifest, config: Config,
              base_dir: Path | None, base_cpg, changed: set[str],
              stage: DetectStage) -> Baseline | None:
    """Load or build the base-commit baseline (cross-cutting §5)."""
    if not config.baseline.enabled:
        stage.notes.append("baseline disabled by config: delta scoping falls back "
                           "to hunk overlap, which over-estimates what is new.")
        return None
    if base_dir is None:
        stage.notes.append(
            "NO BASELINE: without a base checkout there is nothing to compare "
            "findings against, so delta scoping is hunk-based (findings/delta.py).")
        return None

    cache = BaselineCache(repo, config.profile.cache_root)
    if config.baseline.cache:
        cached = cache.load(manifest.base_sha)
        # `covers` is asked about the files a baseline *could* have scanned —
        # a file this PR adds does not exist at the base commit, so its absence
        # is not a gap and must not force a rebuild on every run.
        if cached is not None and cached.covers(expected_baseline_paths(manifest)):
            stage.telemetry["baseline"] = {"source": "cache",
                                           "fingerprints": len(cached.fingerprints),
                                           "paths": len(cached.paths)}
            return cached

    # The base side gets the same detectors minus SCA (a dependency this PR adds
    # cannot be present in the base manifest, so the scan would be a no-op) and
    # with the base-side graph in the structural slot.
    #
    # `sources` matters more than it looks. A finding's fingerprint includes its
    # evidence snippet, so the base pass has to read its snippets from the base
    # tree exactly as the head pass reads them from the head tree. Leaving it
    # None makes every structural finding fall back to a synthesized snippet,
    # which cannot equal a real source line — and then no pre-existing
    # structural finding ever matches its baseline entry.
    detectors = build_detectors(
        config=config, manifest=manifest, root=base_dir, cpg=base_cpg,
        base_cpg=None, changed_paths=changed, sources=_reader(base_dir),
        baseline_commit=None, include_sca=False,
    )
    baseline = build_baseline(manifest, detectors, base_dir)
    if config.baseline.cache:
        try:
            cache.save(baseline)
        except OSError as exc:
            stage.notes.append(f"baseline could not be cached: {exc}")
    stage.telemetry["baseline"] = {"source": "built",
                                   "fingerprints": len(baseline.fingerprints),
                                   "paths": len(baseline.paths),
                                   "tools": baseline.tools}
    return baseline
