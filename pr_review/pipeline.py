"""Run lifecycle: orchestrates Phase 0 -> 1 (profile) -> 2 (change) -> detect
(3a) -> findings (3d) -> report -> gate, and writes the run directory
(overview §8). Phases 3b/3c/4 slot in at later milestones behind the same
artifacts.

PHASES 1 AND 2 ARE OPTIONAL, AND SAY SO WHEN SKIPPED
Profiling needs a checkout; without one the run still completes as the M0 thread
did. What it must not do is complete *quietly* — a review that never built a
profile has no access-control matrix and no CPG, so its silence about broken
access control is an absence of evidence, not evidence of absence. Every skip is
recorded in `telemetry.json` and in the run's notes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from pr_review.change.context import build_bundles, bundle_stats
from pr_review.change.filter import filter_changes
from pr_review.change.classify import classify_changes
from pr_review.change.schema import AnnotatedChangeSet, ContextBundle
from pr_review.config import Config
from pr_review.detect.base import ScanTarget
from pr_review.detect.runner import detect_stage
from pr_review.extract.diff import ParsedFile
from pr_review.extract.manifest import build_manifest
from pr_review.extract.schema import DeltaManifest
from pr_review.findings.delta import scope
from pr_review.findings.normalize import normalize
from pr_review.findings.validate import validate
from pr_review.policy import gate
from pr_review.profile import drift
from pr_review.profile.cache import ProfileCache
from pr_review.report.markdown import render_markdown
from pr_review.report.sarif import build_sarif
from pr_review.safety import sentinel
from pr_review.telemetry import Telemetry


@dataclass
class ProfileStage:
    """What Phase 1 produced (or reused) for this run."""
    profile: object | None = None
    cpg: object | None = None
    action: str = "skipped"
    reasons: list[str] = field(default_factory=list)
    entry_path: Path | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def available(self) -> bool:
        return self.profile is not None


@dataclass
class RunResult:
    verdict: str
    out_dir: Path
    findings: int
    triggers: int
    groups: int = 0
    dropped: int = 0
    profile_version: str = ""


def _run_dir(out_root: str, repo: str, pr_number: int, head_sha: str) -> Path:
    slug = head_sha[:12] if head_sha else "LOCAL"
    d = Path(out_root) / repo.replace("/", "__") / f"{pr_number}-{slug}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _scan_targets(manifest: DeltaManifest, parsed: list[ParsedFile]) -> list[ScanTarget]:
    by_path = {fc.path: fc for fc in manifest.files}
    targets: list[ScanTarget] = []
    for pf in parsed:
        fc = by_path.get(pf.path)
        if fc is None:
            continue
        added = [(a.lineno, a.text) for h in pf.hunks for a in h.added]
        targets.append(ScanTarget(
            path=pf.path, is_test=fc.is_test, is_generated=fc.is_generated,
            is_binary=fc.is_binary, added_lines=added,
        ))
    return targets


def _source_reader(base_dir: Path | None, head_dir: Path | None):
    """(path, side) -> file text, from whichever checkouts exist.

    The two sides come from two different trees: `before` is the profile's
    checkout at `base_sha`, `after` is the PR's head. Conflating them would make
    the AST-equality check compare a file with itself and declare **every**
    change formatting-only — a silent mass drop bounded only by the guardrail.
    So one directory cannot serve both sides: if the same path is given twice it
    is treated as the head alone, and the before side reports unavailable.
    """
    if base_dir is None and head_dir is None:
        return None
    if base_dir is not None and head_dir is not None and base_dir == head_dir:
        base_dir = None
    roots = {"before": base_dir, "after": head_dir}

    def read(path: str, side: str) -> str | None:
        root = roots.get(side)
        if root is None:
            return None
        target = root / path
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    return read


def _profile_stage(repo: str, manifest: DeltaManifest, config: Config,
                   base_dir: Path | None, tel: Telemetry) -> ProfileStage:
    """Phase 1: reuse the cached profile, or build one from a checkout (§6, §8)."""
    cache = ProfileCache(repo, config.profile.cache_root)
    decision = drift.decide(manifest, cache.load_fingerprint(), config)
    stage = ProfileStage(action=decision.action, reasons=list(decision.reasons))

    if decision.action == "warm":
        entry = cache.load(manifest.base_sha) or cache.latest()
        if entry is not None:
            stage.profile, stage.cpg, stage.entry_path = entry.profile, entry.cpg, entry.path
            return stage
        stage.notes.append("drift said warm but the cache entry failed to load; rebuilding")

    if base_dir is None:
        entry = cache.latest()
        if entry is None:
            stage.action = "skipped"
            stage.notes.append(
                "PHASE 1 SKIPPED: no checkout and no cached profile. There is no "
                "access-control matrix and no CPG for this run, so the change "
                "filter's guardrail is degraded and no Phase-3b routing is "
                "grounded in repo structure."
            )
            return stage
        stage.action = "stale_reuse"
        stage.profile, stage.cpg, stage.entry_path = entry.profile, entry.cpg, entry.path
        stage.notes.append(
            f"reused the cached profile at {entry.profile.profile_version[:12]} "
            f"without revalidating it: drift said {decision.action!r} but no "
            f"checkout was available to rebuild from."
        )
        return stage

    if decision.action == "incremental":
        patched = _incremental(repo, manifest, config, base_dir, cache, stage, tel)
        if patched is not None:
            return patched
        # `_incremental` already recorded why it declined; fall through and
        # rebuild, which is always correct and never cheaper.

    from pr_review.profile.drift import fingerprint_repo
    from pr_review.profile.security_profile import build_profile

    build = build_profile(base_dir, repo=repo, base_sha=manifest.base_sha, config=config)
    fingerprint = fingerprint_repo(build.promotion, base_sha=manifest.base_sha)
    stage.entry_path = cache.save(build.profile, fingerprint, build.cpg)
    stage.profile, stage.cpg = build.profile, build.cpg
    stage.notes.extend(build.profile.notes)
    tel.set("profile_telemetry", build.telemetry)
    return stage


def _incremental(repo: str, manifest: DeltaManifest, config: Config, base_dir: Path,
                 cache: ProfileCache, stage: ProfileStage,
                 tel: Telemetry) -> ProfileStage | None:
    """Patch the cached profile in place (phase-1 §6). None means "rebuild".

    Declining is always safe and never silent: a stale profile produces
    confidently wrong access-control rows, so every path that cannot patch says
    so and falls back to the full build.
    """
    from pr_review.profile.incremental import NotSpliceable, update_profile

    entry = cache.latest()
    if entry is None:
        stage.notes.append("incremental update skipped: cached entry failed to load")
        return None

    try:
        result = update_profile(
            entry.profile, entry.cpg, base_dir, manifest, config,
            fingerprint=entry.fingerprint,
        )
    except NotSpliceable as exc:
        stage.notes.append(f"incremental update declined, rebuilding: {exc}")
        return None
    except Exception as exc:                     # noqa: BLE001 — degrade to rebuild
        stage.notes.append(
            f"incremental update failed, rebuilding: {type(exc).__name__}: {exc}")
        return None

    # The fingerprint is patched, not recomputed: recomputing it needs a full
    # parse, which is the cost this whole path exists to avoid.
    fingerprint = _patch_fingerprint(entry.fingerprint, result, base_dir,
                                     manifest.base_sha)
    stage.entry_path = cache.save(result.profile, fingerprint, result.cpg)
    stage.profile, stage.cpg = result.profile, result.cpg
    stage.notes.extend(result.profile.notes)
    tel.set("profile_telemetry", result.telemetry)
    return stage


def _patch_fingerprint(fingerprint, result, base_dir: Path, base_sha: str):
    """Update the cached fingerprint for the files that were re-parsed.

    **`base_sha` moves, `profile_version` does not** — the two answer different
    questions and phase-1 §6 keeps them apart. `profile_version` is the commit
    of the last *full* build and stays put so `01_profile.ref` remains a stable
    replay pointer; `fingerprint.base_sha` is "which commit does this profile
    describe", and after a patch that is the new base. Leaving it behind would
    make the next run at the same base drift to `incremental` again instead of
    going warm, so the profile would be re-patched forever and never reused.

    Only sizes and the file set are corrected. `total_edges` and the per-file
    symbol/edge counts are left as they were: they feed the churn thresholds,
    which are a *heuristic* for "has this drifted too far", and a slightly stale
    denominator biases toward rebuilding — the safe direction.
    """
    from pr_review.profile.drift import FileStat

    for path in result.dropped:
        fingerprint.files.pop(path, None)
    for path in result.reparsed:
        try:
            size = (base_dir / path).stat().st_size
        except OSError:
            continue
        stat = fingerprint.files.setdefault(path, FileStat())
        stat.size = size
    fingerprint.base_sha = base_sha or fingerprint.base_sha
    fingerprint.file_count = len(fingerprint.files)
    fingerprint.total_size = sum(s.size for s in fingerprint.files.values())
    fingerprint.frameworks = sorted(set(result.profile.tech_stack))
    return fingerprint


def run_extract(*, repo: str, pr_number: int, diff_text: str, out_root: str = ".pr_review/runs",
                **meta) -> tuple[DeltaManifest, Path]:
    manifest, _ = build_manifest(repo=repo, pr_number=pr_number, diff_text=diff_text, **meta)
    out_dir = _run_dir(out_root, repo, pr_number, manifest.head_sha)
    path = out_dir / "00_manifest.json"
    path.write_text(manifest.model_dump_json(indent=2))
    return manifest, path


def run_review(*, repo: str, pr_number: int, diff_text: str, config: Config,
               out_root: str = ".pr_review/runs",
               base_dir: str | Path | None = None,
               head_dir: str | Path | None = None,
               triage_provider=None, checkout_info: dict | None = None,
               **meta) -> RunResult:
    tel = Telemetry()
    tel.set("repo", repo)
    tel.set("pr_number", pr_number)
    # Where the two trees came from. A run that profiled auto-materialized
    # checkouts and one handed them on the command line produce the same
    # artifacts, and only this says which -- which matters because the online
    # path had never materialized anything until 2026-08-21.
    if checkout_info:
        tel.set("checkout", checkout_info)

    with tel.phase("extract"):
        # `head_dir` lets Phase 0 read a generated-file header (§17). It is
        # optional on purpose: with no checkout the marker is found only when
        # the diff's first hunk reaches line 1, which is the arm-2c
        # configuration and a measured one.
        manifest, parsed = build_manifest(
            repo=repo, pr_number=pr_number, diff_text=diff_text,
            head_dir=head_dir, **meta
        )
    out_dir = _run_dir(out_root, repo, pr_number, manifest.head_sha)
    (out_dir / "00_manifest.json").write_text(manifest.model_dump_json(indent=2))

    # PHASE 0.5 — THE INJECTION SENTINEL, AND ITS POSITION IS THE POINT
    # It runs against the manifest, before the change stage, because the noise
    # filter's tier 1 drops comment-only and docs-only files — which is exactly
    # what an injection attempt looks like on the way in. Running it here means
    # its recall does not depend on another stage's appetite. Its output feeds
    # the filter (flagged files are force-kept) rather than the other way round.
    with tel.phase("sentinel"):
        sentry = sentinel.scan_manifest(manifest, parsed, config=config)
    tel.set("sentinel", sentry.stats())
    if sentry.notes:
        tel.set("sentinel_notes", sentry.notes)

    base_dir = Path(base_dir) if base_dir else None
    head_dir = Path(head_dir) if head_dir else None

    with tel.phase("profile"):
        stage = _profile_stage(repo, manifest, config, base_dir, tel)
    tel.set("profile_action", stage.action)
    tel.set("profile_reasons", stage.reasons)
    if stage.entry_path is not None:
        ProfileCache(repo, config.profile.cache_root).write_ref(out_dir, stage.entry_path)

    with tel.phase("change"):
        changeset, bundles, filtered = _change_stage(
            manifest, parsed, stage, config,
            sources=_source_reader(base_dir, head_dir),
            provider=triage_provider,
            force_keep=set(sentry.flagged),
        )
    (out_dir / "02_changeset.json").write_text(changeset.model_dump_json(indent=2))
    (out_dir / "02_context_bundles.json").write_text(
        json.dumps([b.model_dump(mode="json") for b in bundles], indent=2))
    tel.set("filter", filtered.stats())
    tel.set("filter_notes", filtered.notes + stage.notes)
    tel.set("context", bundle_stats(bundles))
    tel.set("coverage_plan", changeset.coverage_plan)

    findings = list(sentry.findings)
    with tel.phase("detect"):
        targets = _scan_targets(manifest, parsed)
        det = detect_stage(
            repo=repo, manifest=manifest, targets=targets, config=config,
            base_dir=base_dir, head_dir=head_dir, base_cpg=stage.cpg,
            sources=_source_reader(base_dir, head_dir),
        )
        findings += det.findings
    tel.set("detect", det.telemetry)
    if det.notes:
        tel.set("detect_notes", det.notes)
    (out_dir / "03a_candidates.json").write_text(
        json.dumps([f.model_dump(mode="json") for f in det.findings], indent=2))

    with tel.phase("findings"):
        # Order is phase-3 §3d's: validate, then dedup (inside `normalize`),
        # then delta-scope. `merge`, `severity`, `calibrate` and `suppress` are
        # M3/M4 stages and are absent rather than stubbed.
        #
        # `apply_trust` is still a no-op until M3 produces agent findings, and
        # is wired so that it is not discovered at M3 that the trust flag was
        # only ever a JSON field.
        checked = validate(sentinel.apply_trust(findings, sentry))
        delta = scope(checked.kept, manifest, det.baseline)
        fset = normalize(delta.findings)
    tel.set("findings_validate", checked.stats())
    if checked.rejected:
        tel.set("findings_rejected", checked.notes)
    tel.set("delta", delta.stats())
    if delta.notes:
        tel.set("delta_notes", delta.notes)
    (out_dir / "03d_findings.normalized.json").write_text(fset.model_dump_json(indent=2))

    gres = gate(fset.findings, config.gate)

    with tel.phase("report"):
        fmts = config.output.formats
        if "markdown" in fmts:
            (out_dir / "report.md").write_text(
                render_markdown(manifest, fset, gres.verdict, gres.triggers)
            )
        if "sarif" in fmts:
            (out_dir / "report.sarif").write_text(json.dumps(build_sarif(fset), indent=2))
        if "json" in fmts:
            (out_dir / "findings.json").write_text(fset.model_dump_json(indent=2))

    tel.set("verdict", gres.verdict)
    tel.set("counts", fset.counts)
    tel.write(out_dir / "telemetry.json")

    return RunResult(
        verdict=gres.verdict, out_dir=out_dir,
        findings=len(fset.findings), triggers=len(gres.triggers),
        groups=len(changeset.groups), dropped=len(changeset.dropped),
        profile_version=changeset.profile_version,
    )


def _change_stage(manifest: DeltaManifest, parsed: list[ParsedFile],
                  stage: ProfileStage, config: Config, sources=None,
                  provider=None, force_keep: set[str] | None = None
                  ) -> tuple[AnnotatedChangeSet, list[ContextBundle], object]:
    """Phase 2: filter, classify, and assemble context bundles."""
    language = config.languages[0] if config.languages else "python"
    filtered = filter_changes(
        manifest, parsed, cpg=stage.cpg, profile=stage.profile,
        config=config, sources=sources, provider=provider,
        force_keep=force_keep,
    )
    changeset = classify_changes(
        manifest, filtered.kept, parsed, cpg=stage.cpg, profile=stage.profile,
        config=config, dropped=filtered.dropped,
        triage_labels=filtered.triage_labels,
    )
    bundles = build_bundles(
        changeset, manifest, parsed, cpg=stage.cpg, profile=stage.profile,
        sources=sources, language=language,
    )
    return changeset, bundles, filtered
