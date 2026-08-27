"""Drift metric — incremental update vs. full rebuild (phase-1-profiling.md §6).

Phase 1 is the expensive phase, so the question "can we reuse what we already
built" is where most of the token economy is won. This module answers it from
the `DeltaManifest` and a cached fingerprint alone — **no parsing, no model, no
file reads**. Deciding to skip work must not itself cost the work.

Four outcomes:

  cold         nothing cached for this repo — full build
  warm         same base_sha as the cached profile — reuse it untouched
  incremental  drifted a little — re-parse the touched files, patch the graph
  rebuild      drifted enough that the cached profile is no longer representative

Thresholds are starter values tuned by the benchmark (`benchmark.md`), the same
status as the pattern catalogs. They are deliberately biased toward rebuilding:
a stale profile produces confidently wrong access-control rows, which is a worse
failure than paying to rebuild.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Literal

from pr_review.config import Config
from pr_review.extract.schema import DeltaManifest
from pr_review.profile.patterns import load_catalog
from pr_review.profile.promote import PromotionResult

Action = Literal["cold", "warm", "incremental", "rebuild"]


@dataclass
class FileStat:
    size: int = 0
    symbols: int = 0
    edges: int = 0


@dataclass
class RepoFingerprint:
    """What a cached profile knows about the tree it was built from.

    `layers` are CAP's own shape/surface/topology hashes — cheap change
    detection that is already stable against docstring and comment edits.
    They answer *whether* structure moved; the per-file counts answer *how much*,
    which is what the churn thresholds need.
    """
    base_sha: str = ""
    file_count: int = 0
    total_size: int = 0
    total_edges: int = 0
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    layers: dict[str, str] = field(default_factory=dict)
    files: dict[str, FileStat] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "base_sha": self.base_sha, "file_count": self.file_count,
            "total_size": self.total_size, "total_edges": self.total_edges,
            "languages": self.languages, "frameworks": self.frameworks,
            "layers": self.layers,
            "files": {p: vars(s) for p, s in self.files.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RepoFingerprint":
        return cls(
            base_sha=data.get("base_sha", ""),
            file_count=data.get("file_count", 0),
            total_size=data.get("total_size", 0),
            total_edges=data.get("total_edges", 0),
            languages=data.get("languages", []),
            frameworks=data.get("frameworks", []),
            layers=data.get("layers", {}),
            files={p: FileStat(**s) for p, s in (data.get("files") or {}).items()},
        )


@dataclass
class DriftDecision:
    action: Action
    reasons: list[str] = field(default_factory=list)
    file_churn: float = 0.0
    edge_churn: float = 0.0

    @property
    def needs_full_build(self) -> bool:
        return self.action in ("cold", "rebuild")


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

def fingerprint_repo(promotion: PromotionResult, base_sha: str = "") -> RepoFingerprint:
    cache = promotion.cache
    files: dict[str, FileStat] = {}
    for path, size in cache.all_files.items():
        files[path] = FileStat(size=size)
    for path, symbols in cache.structural_index.items():
        files.setdefault(path, FileStat()).symbols = len(symbols)

    total_edges = 0
    for caller, callees in cache.call_graph.forward.items():
        stem = caller.split(".", 1)[0]
        total_edges += len(callees)
        for path in files:
            if path.rsplit("/", 1)[-1].removesuffix(".py") == stem:
                files[path].edges += len(callees)
                break

    try:
        from cap_engine.environment.fingerprint import compute_code_environment_layers
        layers = compute_code_environment_layers(cache, promotion.base_dir.name)
    except Exception:                                   # noqa: BLE001
        layers = {}

    return RepoFingerprint(
        base_sha=base_sha,
        file_count=len(cache.all_files),
        total_size=sum(cache.all_files.values()),
        total_edges=total_edges,
        languages=sorted(set(cache.file_languages.values())),
        frameworks=sorted(set(promotion.frameworks.values())),
        layers=layers,
        files=files,
    )


# ---------------------------------------------------------------------------
# Anchors
# ---------------------------------------------------------------------------

def anchor_globs(config: Config, language: str = "python") -> list[str]:
    """Config wins; otherwise the language catalog's list.

    Keeping the default next to the framework knowledge that motivates it means
    adding a framework brings its anchors along instead of silently omitting
    them.
    """
    if config.profile.anchor_globs:
        return list(config.profile.anchor_globs)
    try:
        return list(load_catalog(language).get("anchor_globs") or [])
    except Exception:                                   # noqa: BLE001
        return []


def _matches_anchor(path: str, globs: list[str]) -> bool:
    p = PurePosixPath(path)
    for pattern in globs:
        try:
            if p.full_match(pattern):
                return True
        except AttributeError:                          # pragma: no cover — py<3.13
            if p.match(pattern):
                return True
    return False


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

def decide(
    manifest: DeltaManifest,
    cached: RepoFingerprint | None,
    config: Config | None = None,
    language: str = "python",
) -> DriftDecision:
    config = config or Config()

    if cached is None:
        return DriftDecision("cold", ["no cached profile for this repo"])

    if cached.base_sha and manifest.base_sha and cached.base_sha == manifest.base_sha:
        return DriftDecision("warm", [f"cached profile is at base_sha {cached.base_sha[:12]}"])

    changed = [f for f in manifest.files if not f.is_binary]
    globs = anchor_globs(config, language)
    reasons: list[str] = []

    anchors = [f.path for f in changed if _matches_anchor(f.path, globs)]
    if anchors:
        reasons.append(f"anchor file(s) changed: {', '.join(sorted(anchors)[:4])}")

    known_langs = set(cached.languages)
    new_langs = {f.lang for f in changed if f.lang} - known_langs
    if new_langs and known_langs:
        reasons.append(f"language set changed: +{', '.join(sorted(new_langs))}")

    file_churn = (len(changed) / cached.file_count) if cached.file_count else 1.0
    edge_churn = 0.0
    if cached.total_edges:
        touched = sum(cached.files[f.path].edges for f in changed if f.path in cached.files)
        edge_churn = touched / cached.total_edges

    if file_churn > config.profile.drift_file_pct:
        reasons.append(
            f"file churn {file_churn:.0%} > {config.profile.drift_file_pct:.0%}")
    if edge_churn > config.profile.drift_edge_pct:
        reasons.append(
            f"call-graph edge churn {edge_churn:.0%} > {config.profile.drift_edge_pct:.0%}")

    if reasons:
        return DriftDecision("rebuild", reasons, file_churn, edge_churn)

    return DriftDecision(
        "incremental",
        [f"{len(changed)} file(s) changed; churn {file_churn:.0%} files / "
         f"{edge_churn:.0%} edges, both under threshold"],
        file_churn, edge_churn,
    )


def touched_paths(manifest: DeltaManifest) -> list[str]:
    """Files an incremental update must re-parse."""
    return [f.path for f in manifest.files
            if not f.is_binary and f.change != "deleted"]
