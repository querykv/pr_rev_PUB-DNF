"""Profile cache — save, load, invalidate (phase-1-profiling.md §8).

Layout, keyed by repo so nothing bleeds between projects:

    .pr_review/cache/<repo-slug>/profile/<profile_version>/
        profile.json       the ProjectProfile
        fingerprint.json   RepoFingerprint — read by drift.decide() with no parsing
        cpg.json           serialized security overlay
        meta.json          schema + analyzer version, written-at

Three separate things decide whether a cached entry is still good, and they are
independent: `profile_version` (which *repo state* it describes), `SCHEMA_VERSION`
(what *shape* the files are) and `ANALYZER_VERSION` (which *code* produced their
contents). Missing the third is what made a fix to `promote.py` invisible to a
re-run — see the constant below.

`profile_version` is the base_sha of the last **full** build (phase-1 §6), so an
incremental update writes back into the same directory rather than forking a new
one — which is what lets a run's `01_profile.ref` stay a stable pointer.

A corrupt or partial entry reads as *absent*, not as an error. Phase 1 can always
rebuild from source, so the safe failure is a cold start; raising here would turn
a recoverable cache problem into a failed review.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pr_review.profile.cpg import CPG
from pr_review.profile.drift import RepoFingerprint
from pr_review.profile.schema import ProjectProfile

SCHEMA_VERSION = 1

# Bump when the *meaning* of a cached profile changes — new or changed extraction
# rules in `promote.py`, `cpg.py` or `patterns/*.yaml` — as opposed to the shape
# of the files, which is `SCHEMA_VERSION` above.
#
# The two are genuinely different keys and conflating them cost a measurement.
# `profile_version` is the repo's base sha and `SCHEMA_VERSION` is the artifact
# layout, so **neither changes when the analyzer is fixed**: after correcting the
# route-decorator rule, re-running the pinned benchmark corpus would have loaded
# the profiles built by the code that had the bug and reported no improvement,
# with nothing anywhere saying why. A measure -> fix -> measure loop cannot run
# on a cache that cannot see the fix.
#
# Deliberately a hand-maintained constant rather than a hash of the analyzer's
# source: a content hash is correct by construction but invalidates every cached
# profile on a comment edit, and a full rebuild of a large repository is minutes
# of work to discard for a docstring. The cost of that choice is that **it has to
# be bumped by hand**, so it is named in `M2_STATUS.md` and asserted by a test
# that fails if `promote.py` gains a rule without one.
ANALYZER_VERSION = 8


@dataclass
class CacheEntry:
    profile: ProjectProfile
    fingerprint: RepoFingerprint
    cpg: CPG
    path: Path


def _slug(repo: str) -> str:
    return repo.replace("/", "__") or "_local"


class ProfileCache:
    def __init__(self, repo: str, cache_root: str | Path = ".pr_review/cache") -> None:
        self.repo = repo
        self.root = Path(cache_root) / _slug(repo) / "profile"

    def dir_for(self, version: str) -> Path:
        return self.root / (version or "LOCAL")

    def versions(self) -> list[str]:
        if not self.root.is_dir():
            return []
        return sorted(p.name for p in self.root.iterdir() if p.is_dir())

    # -- write -------------------------------------------------------------

    def save(self, profile: ProjectProfile, fingerprint: RepoFingerprint,
             cpg: CPG) -> Path:
        """Write atomically — a half-written entry would load as a valid but
        incomplete profile, which is worse than no cache at all."""
        target = self.dir_for(profile.profile_version)
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(dir=target.parent, prefix=".save-"))
        try:
            (staging / "profile.json").write_text(profile.model_dump_json(indent=2))
            (staging / "fingerprint.json").write_text(
                json.dumps(fingerprint.to_dict(), indent=2))
            (staging / "cpg.json").write_text(json.dumps(cpg.to_dict(), indent=2))
            (staging / "meta.json").write_text(json.dumps({
                "schema_version": SCHEMA_VERSION,
                "analyzer_version": ANALYZER_VERSION,
                "repo": self.repo,
                "profile_version": profile.profile_version,
                "build_kind": profile.build_kind,
                "written_at": datetime.now(timezone.utc).isoformat(),
            }, indent=2))
            if target.exists():
                shutil.rmtree(target)
            staging.rename(target)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        return target

    def write_ref(self, run_dir: str | Path, entry_path: Path) -> Path:
        """`01_profile.ref` — which profile a run used, for replay (phase-1 §8)."""
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        ref = run_dir / "01_profile.ref"
        ref.write_text(json.dumps({
            "repo": self.repo,
            "profile_path": str(entry_path),
            "profile_version": entry_path.name,
        }, indent=2))
        return ref

    # -- read --------------------------------------------------------------

    def load(self, version: str) -> CacheEntry | None:
        path = self.dir_for(version)
        try:
            # Entries written before `analyzer_version` existed read as stale by
            # the same check: the key was added *because* the analyzer changed.
            if not self._current(path):
                return None
            return CacheEntry(
                profile=ProjectProfile.model_validate_json(
                    (path / "profile.json").read_text()),
                fingerprint=RepoFingerprint.from_dict(
                    json.loads((path / "fingerprint.json").read_text())),
                cpg=CPG.from_dict(json.loads((path / "cpg.json").read_text())),
                path=path,
            )
        except Exception:            # noqa: BLE001 — corrupt cache == cold start
            return None

    def latest(self) -> CacheEntry | None:
        """Most recently written entry, skipping any that fail to load."""
        candidates = []
        for version in self.versions():
            meta = self.dir_for(version) / "meta.json"
            try:
                candidates.append(
                    (json.loads(meta.read_text()).get("written_at", ""), version))
            except Exception:        # noqa: BLE001
                continue
        for _written, version in sorted(candidates, reverse=True):
            entry = self.load(version)
            if entry is not None:
                return entry
        return None

    def load_fingerprint(self, version: str | None = None) -> RepoFingerprint | None:
        """Just the fingerprint — what `drift.decide()` needs.

        Kept separate so the drift check stays cheap: deciding whether to reuse
        a profile must not require deserializing the profile and its CPG.
        """
        path = self.dir_for(version) if version else None
        if path is None:
            entry = self.latest()
            return entry.fingerprint if entry else None
        try:
            # Cheap, but not cheap enough to skip the version gate: this is the
            # path `drift.decide()` takes, so an entry rejected by `load()` would
            # otherwise still be reused for the decision about whether to reuse it.
            if not self._current(path):
                return None
            return RepoFingerprint.from_dict(
                json.loads((path / "fingerprint.json").read_text()))
        except Exception:            # noqa: BLE001
            return None

    def _current(self, path: Path) -> bool:
        """Was this entry written by this schema *and* this analyzer?"""
        try:
            meta = json.loads((path / "meta.json").read_text())
        except Exception:            # noqa: BLE001
            return False
        return (meta.get("schema_version") == SCHEMA_VERSION
                and meta.get("analyzer_version") == ANALYZER_VERSION)

    # -- invalidate --------------------------------------------------------

    def invalidate(self, version: str | None = None) -> list[str]:
        """Drop one version, or every version for this repo."""
        dropped = []
        for name in ([version] if version else self.versions()):
            path = self.dir_for(name)
            if path.is_dir():
                shutil.rmtree(path)
                dropped.append(name)
        return dropped
