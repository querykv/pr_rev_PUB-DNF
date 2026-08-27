"""Baseline and delta scoping (cross-cutting §5, phase-3 §3d).

"The single biggest noise lever: we only gate on findings the PR introduces or
modifies." Until this module existed, `detect/secrets.py` hardcoded
`introduced_by_pr=True` on every finding, so the gate could not tell a secret
this PR committed from one that had been in the file for two years — and the
second kind is the one that makes a reviewer stop reading the tool's output.

TWO METHODS, AND THE WEAKER ONE SAYS SO

*Baseline* (`method="baseline"`) is the real answer. The same deterministic
detectors run over the **base-side** content of the files this PR touches, and
every fingerprint they produce is a defect that already existed. A finding whose
fingerprint is in that set is pre-existing, whatever the diff looks like.

*Hunks* (`method="hunks"`) is the fallback when there is no base checkout. It
can only ask whether the finding sits in a region the PR edited, which is a
proxy: it cannot see that an untouched line's finding was already there, and it
cannot see that a moved line's finding is not new. It is used when it is all we
have, and the run records that the weaker method was used.

WHY THE BASELINE IS SCOPED TO CHANGED FILES. §5 describes "the same pipeline run
on the base commit", which for a large repo is the expensive thing this tool is
built to avoid. Every finding we could possibly need to classify is in a file
the PR touches — no detector here reports on untouched files — so a baseline
over exactly those files answers every question a full one would, at the cost of
one scan of a handful of files. The cache entry records which paths it covers so
a later PR touching different files does not silently reuse an answer that never
looked at them.

FINDINGS WITH NO FILE. `pr:body`, `pr:title`, `ticket:42` — the injection
sentinel's non-file surfaces. They are not in any checkout and never will be, so
neither method applies; they are introduced by definition, because the PR's own
description is part of the PR. Getting this wrong would silently un-gate the
planted-instruction case that `safety/sentinel.py` exists for.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pr_review.detect.base import Detector, ScanTarget
from pr_review.detect.normalize import mapping_digest
from pr_review.extract.schema import DeltaManifest
from pr_review.schema import Finding, Status

# `pr:body`, `ticket:17` — a surface that is part of the PR rather than a path
# in the repository. Real paths never contain a colon before their first slash.
_SYNTHETIC_PREFIXES = ("pr:", "ticket:", "commit:")


def _is_synthetic(path: str) -> bool:
    return path.startswith(_SYNTHETIC_PREFIXES)


# ---------------------------------------------------------------------------
# The baseline
# ---------------------------------------------------------------------------

# Bump when the *shape* of a cached baseline changes, or when anything outside
# the mapping tables changes a finding's fingerprint (the fields
# `util.fingerprint` hashes, or how a detector produces a snippet). Mapping
# changes are caught automatically by `normalize.mapping_digest()` and need no
# bump — see `BaselineCache.load`.
BASELINE_VERSION = 1


@dataclass
class Baseline:
    base_sha: str
    fingerprints: set[str] = field(default_factory=set)
    paths: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    built_at: str = ""
    # Which taxonomy mapping produced these fingerprints. Empty means a dump
    # written before 2026-08-22, which cannot be trusted for the same reason.
    mapping: str = ""

    def covers(self, paths: set[str]) -> bool:
        """Is this baseline usable for a PR touching `paths`?

        Subset, not equality: a cached baseline built for a wider set still
        answers questions about a narrower one, and a PR touching a file the
        baseline never scanned would otherwise get a confident "not present in
        base" that means "not looked for".
        """
        return paths.issubset(set(self.paths))

    def to_dict(self) -> dict:
        return {"version": BASELINE_VERSION,
                "base_sha": self.base_sha, "fingerprints": sorted(self.fingerprints),
                "paths": sorted(self.paths), "tools": sorted(self.tools),
                "built_at": self.built_at,
                "mapping": self.mapping or mapping_digest()}

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        return cls(base_sha=data.get("base_sha", ""),
                   fingerprints=set(data.get("fingerprints") or []),
                   paths=list(data.get("paths") or []),
                   tools=list(data.get("tools") or []),
                   built_at=data.get("built_at", ""),
                   mapping=data.get("mapping", ""))


class BaselineCache:
    """`.pr_review/cache/<repo>/baseline/<base_sha>.json` (cross-cutting §5)."""

    def __init__(self, repo: str, cache_root: str | Path = ".pr_review/cache") -> None:
        self.root = Path(cache_root) / (repo.replace("/", "__") or "_local") / "baseline"

    def path_for(self, base_sha: str) -> Path:
        return self.root / f"{base_sha or 'LOCAL'}.json"

    def load(self, base_sha: str) -> Baseline | None:
        """A cached baseline, or `None` when it cannot be trusted.

        THE STALENESS THIS REFUSES. `Finding.fingerprint` hashes the taxonomy
        `internal` id, so remapping a rule changes every affected fingerprint on
        the head side while a cached baseline still holds the old ones. Nothing
        matches, and a pre-existing finding is reported as **introduced** —
        silently, and in the direction that invents false positives.

        Measured on the IaC corpus when `CKV_DOCKER_3` was remapped: **32
        reported findings became 112**, and a fresh baseline came back to 32
        exactly. `ProfileCache` has had `ANALYZER_VERSION` for this class since
        M1; this cache was keyed on `base_sha` alone. Errata §14.49.

        Two checks, because they fail for different reasons. `version` is manual
        and covers shape changes; `mapping` is derived from the tables
        themselves and covers the edit somebody makes without thinking about
        caches, which is the one that actually happened.
        """
        path = self.path_for(base_sha)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        if data.get("version") != BASELINE_VERSION:
            return None
        if data.get("mapping") != mapping_digest():
            return None
        try:
            return Baseline.from_dict(data)
        except (OSError, ValueError):
            return None

    def save(self, baseline: Baseline) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.path_for(baseline.base_sha)
        path.write_text(json.dumps(baseline.to_dict(), indent=2))
        return path


def expected_baseline_paths(manifest: DeltaManifest) -> set[str]:
    """The paths a complete baseline can be expected to cover.

    A file this PR *adds* has no base-side version, and neither does a binary.
    Counting them as gaps would make every baseline look incomplete and would
    put a false "nothing looked for them at the base commit" in every run — the
    truth is that nothing could, and nothing needed to.
    """
    return {fc.path for fc in manifest.files
            if fc.change != "added" and not fc.is_binary}


def base_targets(manifest: DeltaManifest, base_dir: str | Path) -> list[ScanTarget]:
    """Scan targets for the **base-side** content of the PR's changed files.

    Whole files, not added lines: on the base side there is no diff, and the
    question is "what did this file already contain". Added files have no base
    version and are skipped, which is correct — nothing in them can be
    pre-existing.
    """
    base_dir = Path(base_dir)
    targets: list[ScanTarget] = []
    for fc in manifest.files:
        if fc.is_binary or fc.change == "added":
            continue
        # A rename is the same file under a different name; its history lives
        # at the old path.
        rel = fc.previous_path if (fc.change == "renamed" and fc.previous_path) else fc.path
        source = base_dir / rel
        try:
            text = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        targets.append(ScanTarget(
            # Named by the *head* path so fingerprints line up with the head-side
            # findings they have to be compared against.
            path=fc.path,
            is_test=fc.is_test, is_generated=fc.is_generated, is_binary=fc.is_binary,
            added_lines=list(enumerate(text.splitlines(), start=1)),
        ))
    return targets


def build_baseline(manifest: DeltaManifest, detectors: list[Detector],
                   base_dir: str | Path) -> Baseline:
    """Run `detectors` over the base-side files and collect their fingerprints."""
    targets = base_targets(manifest, base_dir)
    baseline = Baseline(
        base_sha=manifest.base_sha,
        paths=[t.path for t in targets],
        built_at=datetime.now(timezone.utc).isoformat(),
    )
    if not targets:
        return baseline
    for det in detectors:
        try:
            if not det.applicable(targets):
                continue
            scan = getattr(det, "scan", None)
            if scan is not None:
                run = scan(targets)
                # A detector whose binary is missing returns an empty list, and
                # recording it here would claim the base side was scanned for a
                # class nothing looked at — which is the exact confusion
                # `AdapterRun.status` exists to prevent.
                if run.status != "ran":
                    continue
                found = run.findings
            else:
                found = det.run(targets)
        except Exception:                            # noqa: BLE001
            # A detector that fails on the base side must not fail the review.
            # The consequence is under-scoping — findings look introduced — which
            # is the safe direction: noisier, never quieter.
            continue
        baseline.tools.append(det.name)
        baseline.fingerprints.update(f.fingerprint for f in found)
    return baseline


# ---------------------------------------------------------------------------
# Scoping
# ---------------------------------------------------------------------------

@dataclass
class DeltaResult:
    findings: list[Finding] = field(default_factory=list)
    method: str = "none"
    introduced: int = 0
    pre_existing: int = 0
    notes: list[str] = field(default_factory=list)

    def stats(self) -> dict:
        return {"method": self.method, "introduced": self.introduced,
                "pre_existing": self.pre_existing}


def _touched_ranges(manifest: DeltaManifest) -> dict[str, list[tuple[int, int]]]:
    """path -> the line ranges this PR edited, on the **new** side.

    Hunk ranges rather than added-line numbers, and that difference is
    load-bearing: removing a line leaves no added line to point at, so a finding
    caused by a *deletion* — an authorization decorator taken off an endpoint —
    has no added line anywhere near it. The hunk's range covers the context
    around the removal, which is where such a finding lands.
    """
    out: dict[str, list[tuple[int, int]]] = {}
    for fc in manifest.files:
        spans: list[tuple[int, int]] = []
        for hunk in fc.hunks:
            if hunk.new_range and "-" in hunk.new_range:
                start, _, end = hunk.new_range.partition("-")
                try:
                    spans.append((int(start), int(end)))
                except ValueError:
                    continue
            elif hunk.added_lines:
                spans.append((min(hunk.added_lines), max(hunk.added_lines)))
        if spans:
            out[fc.path] = spans
    return out


def scope(findings: list[Finding], manifest: DeltaManifest,
          baseline: Baseline | None = None) -> DeltaResult:
    """Set `introduced_by_pr` and demote pre-existing findings to `pre_existing`."""
    result = DeltaResult(method="baseline" if baseline is not None else "hunks")
    ranges = _touched_ranges(manifest)
    known_paths = {fc.path for fc in manifest.files}

    if baseline is None:
        result.notes.append(
            "DELTA SCOPING IS HUNK-BASED: no base checkout was available, so a "
            "finding is called introduced when it sits in a region this PR "
            "edited. That cannot recognise a pre-existing defect on a line the "
            "PR happens to touch, so the introduced set is an over-estimate.")
    else:
        gaps = sorted(expected_baseline_paths(manifest) - set(baseline.paths))
        if gaps:
            shown = ", ".join(gaps[:3]) + ("..." if len(gaps) > 3 else "")
            result.notes.append(
                f"the baseline does not cover {len(gaps)} changed file(s) that "
                f"exist at the base commit ({shown}) — findings there are treated "
                f"as introduced because nothing looked for them at the base.")

    for f in findings:
        path = f.location.file
        if _is_synthetic(path):
            introduced = True
        elif baseline is not None and f.fingerprint in baseline.fingerprints:
            introduced = False
        elif baseline is not None and path in set(baseline.paths):
            introduced = True
        else:
            spans = ranges.get(path)
            if spans is None:
                # Not a file this PR changed at all. Whatever produced it looked
                # outside the diff, and the PR is not answerable for it.
                introduced = path in known_paths
            else:
                introduced = any(
                    start <= f.location.end_line and f.location.start_line <= end
                    for start, end in spans)

        f.introduced_by_pr = introduced
        if introduced:
            result.introduced += 1
        else:
            result.pre_existing += 1
            # §5: reported informationally, never blocking. `policy.gate()` keys
            # on `validated`, so this demotion is what actually stops a
            # pre-existing secret from failing the build.
            f.status = Status.PRE_EXISTING
        result.findings.append(f)
    return result
