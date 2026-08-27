"""Incremental profile update (phase-1-profiling.md §6).

The third of `drift.decide()`'s four outcomes. `cold` and `rebuild` do a full
build, `warm` reuses the cache untouched, and this module handles the one in
between: the profile is mostly still right, so re-parse only what the PR touched
and patch the cached profile and CPG in place.

This is the mechanism Principle #4 rests on — "cost must trend down across PRs
on the same repo". A full rebuild costs one tree-sitter parse of every file in
the repository; this costs one parse per *changed* file, and a PR changes a
handful. Everything downstream (the CPG, the matrix) is in-memory graph work
over an already-parsed tree.

WHY IT PATCHES ARTIFACTS, NOT A PARSE CACHE
The obvious design is to keep the `ParseCache` warm and re-parse into it. It is
not available: `cache.py` persists the profile, the fingerprint and the CPG, and
deliberately not the `ParseCache`, which holds every file's full source and its
tree-sitter tree. So a warm process has the *derived* artifacts and no parse
state at all. This module therefore parses the touched files into a **partial**
`ParseCache`, derives their endpoints and CPG subgraph from it, and splices the
result into the cached artifacts.

THE PRECONDITION, AND WHY IT IS CHECKED RATHER THAN ASSUMED
Splicing per file is only sound while no derived fact spans files. Today none
does: `cpg._resolve_callee` is local-file-first and returns None for a name not
defined in the same file, so no `calls` edge and no taint path crosses a file
boundary — the CPG is a disjoint union of per-file subgraphs plus shared,
file-less `permission` nodes. That is a property of the current resolver, not a
law. `CPG.splice_violations()` asserts it on every run and this module refuses
to patch when it reports anything, falling back to a full rebuild. Cross-file
import resolution is a plausible future change, and without the check it would
silently leave stale edges hanging off the neighbours of every patched file.

WHAT A PATCHED FILE LOSES
Its agent judgement. A matrix row carries `enforcement`, `required_roles` and
`auth_pattern` that may have been lifted by the CAP workflow (phase-1 §5) —
including `declared_not_enforced`, which the structural floor cannot produce at
all. Re-deriving the row from structure drops that back to the floor. Keeping it
would be worse: the agent judged the *previous* version of a function the PR has
just rewritten, and a stale `declared_not_enforced` is a finding a reviewer will
chase. The rows affected are named in `ProjectProfile.notes`, so the loss is on
the record rather than silent.

Repo-level agent output (`description`, `tech_stack`, `roles`, `authentication`,
`authorization`) is preserved: it describes the project, not the touched files,
and re-deriving it needs the agent.

WHICH TREE IS RE-PARSED, AND WHICH FILES
Both are underspecified in phase-1 §6, and getting them wrong is silent.

*Which tree:* the checkout at the PR's **base_sha**, never the head. The profile
is a base-commit artifact — `profile_version` says so, and Phase 2 is built on
it (`change/classify.py` reads guard *edits* from hunk text precisely because
the graph predates the PR). Patching touched files from head would leave a
profile that is at base for most files and head for a few, which is neither
commit and is wrong in a way nothing downstream could detect.

*Which files:* §6 offers `drift.touched_paths(manifest)` — the PR's own changed
files. But the drift being repaired is between the **cached profile's base and
this PR's base**, and those are different questions: the PR's diff is only a
proxy for how the base moved, and a file that changed between the two bases
without being touched by this PR would keep a stale row forever. So the set here
is the union of the PR's touched paths and a `stat()` comparison against the
cached fingerprint's recorded per-file sizes, which costs no parsing. That still
misses a same-size edit between bases; the anchor rules and churn thresholds
force a full rebuild for anything substantial, and the residue is recorded in
`ProjectProfile.notes` rather than left to be discovered.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pr_review.config import Config
from pr_review.extract.schema import DeltaManifest
from pr_review.profile.cpg import CPG, build_cpg
from pr_review.profile.promote import PromotionResult, extract_frameworks
from pr_review.profile.schema import ProjectProfile

# The floor builders are reused rather than reimplemented. They already take
# `(promotion, cpg)`, so handing them a partial pair derives exactly the touched
# files' rows — and a second copy of that derivation is the surest way for the
# full and incremental paths to disagree about what an endpoint is.
from pr_review.profile.security_profile import (
    _coverage_notes,
    _io_channels,
    _matrix,
    _permission_checks,
    _sensitive_fields,
)


class NotSpliceable(Exception):
    """The cached graph cannot be patched per file — rebuild instead."""


@dataclass
class IncrementalResult:
    profile: ProjectProfile
    cpg: CPG
    reparsed: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    relifted_rows: list[str] = field(default_factory=list)
    telemetry: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parsing a subset
# ---------------------------------------------------------------------------

def partial_cache(base_dir: str | Path, paths: list[str], config: dict | None = None):
    """A `ParseCache` holding only `paths`, built with CAP's own machinery.

    CAP's `build_cache()` walks a whole directory and `ParseCache.refresh()`
    re-parses by mtime — which skips files a PR *adds*, never touches the call
    graph or the type hierarchy, and cannot be pointed at a specific list. So
    the walk is done here, one file at a time, using CAP's `CodeParser`,
    `StructuralIndexer` and `CallGraphBuilder` unchanged. No `cap_engine` edits;
    the parsing and indexing logic is still entirely CAP's.
    """
    from cap_engine.environment.code_promoter.code_promoter import (
        CodeParser,
        ParseCache,
        StructuralIndexer,
        _get_extension_map,
    )

    base_dir = Path(base_dir)
    cache = ParseCache()
    parser, indexer = CodeParser(), StructuralIndexer()
    ext_map = _get_extension_map(config)

    for rel in sorted(set(paths)):
        fpath = base_dir / rel
        if not fpath.is_file():
            continue
        try:
            cache.all_files[rel] = fpath.stat().st_size
        except OSError:
            cache.all_files[rel] = 0
        if fpath.suffix.lower() not in ext_map:
            continue

        tree, lang = parser.parse_file(fpath)
        if tree is None:
            continue
        try:
            source = fpath.read_bytes()
            syms = indexer.index_file(tree, lang, source, config)
            cache.structural_index[rel] = syms
            cache.file_languages[rel] = lang
            cache._trees[rel] = (tree, source)
            cache.file_mtimes[rel] = fpath.stat().st_mtime
            for parent, children in indexer.extract_type_hierarchy(
                    tree, lang, source, rel, config).items():
                cache.type_hierarchy.setdefault(parent, []).extend(children)
            cache.call_graph.add_file(tree, lang, source, rel, syms, config)
        except Exception as exc:                     # noqa: BLE001
            cache.parse_errors.append(f"{rel}: {exc}")

    cache._config = config or {}
    return cache


# ---------------------------------------------------------------------------
# Splicing the profile
# ---------------------------------------------------------------------------

def _evict_profile(profile: ProjectProfile, paths: set[str]) -> list[str]:
    """Remove every row derived from `paths`. Returns the controllers dropped."""
    dropped = [f"{r.file}:{r.controller}" for r in profile.access_control_matrix
               if r.file in paths]

    profile.access_control_matrix = [
        r for r in profile.access_control_matrix if r.file not in paths]
    profile.permission_checks = [
        c for c in profile.permission_checks if c.file not in paths]
    profile.sensitive_fields = [
        f for f in profile.sensitive_fields
        if not any(loc.split(":", 1)[0] in paths for loc in f.locations)
    ]

    # `IOChannel` is keyed by route, and a route is NOT unique across files —
    # two blueprints can serve `/admin/export`, and a rename in progress
    # routinely does. So a channel is only dropped once no *surviving* code
    # flow still implements it: the same reference-counting the CPG does for
    # shared `permission` nodes. Evicting by name alone deletes the untouched
    # files' channels too, which a 30-module repo makes obvious and a 4-file
    # fixture does not.
    profile.code_flows = [
        f for f in profile.code_flows if not any(x in paths for x in f.files)]
    still_implemented = {flow.channel for flow in profile.code_flows}
    profile.io_channels = [
        c for c in profile.io_channels if c.name in still_implemented]
    return dropped


def _relifted(profile: ProjectProfile, dropped_keys: list[str],
              fresh: PromotionResult) -> list[str]:
    """Which re-derived rows previously carried agent judgement.

    Empty when the cached profile was never lifted — with no agent behind it
    every row was already at the structural floor, so re-deriving it loses
    nothing and warning about it would be noise. Only rows that come back
    count: a row whose endpoint the PR deleted is gone, not downgraded.
    """
    if not profile.agent_rows_merged:
        return []
    returning = {f"{ep.file}:{ep.symbol}" for ep in fresh.endpoints}
    return sorted(k for k in dropped_keys if k in returning)


def drifted_by_size(fingerprint, base_dir: Path) -> list[str]:
    """Files whose on-disk size no longer matches the cached fingerprint.

    The cheap half of "which files actually moved between the two bases" — one
    `stat()` per known file, no reads and no parsing. Deliberately weak: a
    same-size edit is invisible here. It exists to catch the case the PR's own
    diff structurally cannot, namely a file that changed between the cached base
    and this PR's base without this PR touching it.
    """
    if fingerprint is None:
        return []
    base_dir = Path(base_dir)
    moved: list[str] = []
    for path, stat in getattr(fingerprint, "files", {}).items():
        target = base_dir / path
        try:
            size = target.stat().st_size
        except OSError:
            moved.append(path)                   # gone from the new base
            continue
        if stat.size and size != stat.size:
            moved.append(path)
    return sorted(moved)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def update_profile(
    profile: ProjectProfile,
    cpg: CPG,
    base_dir: str | Path,
    manifest: DeltaManifest,
    config: Config | None = None,
    fingerprint=None,
) -> IncrementalResult:
    """Patch a cached profile and CPG for the files that moved.

    `base_dir` must be the checkout at **`manifest.base_sha`** — see the module
    docstring. `fingerprint` is the cached `RepoFingerprint`; supplying it adds
    the `stat()`-based drift check to the PR's own file list.

    Raises `NotSpliceable` when the cached graph holds a cross-file fact, which
    is the caller's signal to do a full rebuild instead.

    `profile_version` is left alone on purpose (phase-1 §6): an incremental
    update writes back into the same cache entry, so a run's `01_profile.ref`
    stays a stable pointer for replay.
    """
    config = config or Config()
    language = config.languages[0] if config.languages else "python"
    base_dir = Path(base_dir)

    violations = cpg.splice_violations()
    if violations:
        raise NotSpliceable(
            f"cached CPG holds {len(violations)} cross-file fact(s), so it cannot "
            f"be patched per file: {violations[0]}"
        )

    # Deletions and renames evict their old path; renames also re-parse the new
    # one, which arrives through `touched` as an ordinary changed file.
    gone = {f.path for f in manifest.files if f.change == "deleted"}
    gone |= {f.previous_path for f in manifest.files
             if f.change == "renamed" and f.previous_path}
    from_pr = [f.path for f in manifest.files
               if not f.is_binary and f.change != "deleted"]
    from_stat = drifted_by_size(fingerprint, base_dir)
    touched = sorted(set(from_pr) | set(from_stat))
    affected = set(touched) | gone

    # 1. Evict. Both artifacts lose everything derived from the affected files.
    for path in sorted(affected):
        cpg.remove_file(path)
    dropped_keys = _evict_profile(profile, affected)
    cpg.prune_orphans()

    # 2. Re-derive, from a cache holding only the touched files.
    cache = partial_cache(base_dir, touched)
    fresh = extract_frameworks(cache, base_dir, language)
    fresh_cpg = build_cpg(fresh, language=language)

    # 3. Splice.
    cpg.merge(fresh_cpg)
    profile.access_control_matrix.extend(_matrix(fresh))
    profile.access_control_matrix.sort(key=lambda r: (r.file, r.line or 0))

    known = {c.name for c in profile.permission_checks}
    profile.permission_checks.extend(
        c for c in _permission_checks(fresh) if c.name not in known)

    channels, flows = _io_channels(fresh)
    known_channels = {c.name for c in profile.io_channels}
    profile.io_channels.extend(c for c in channels if c.name not in known_channels)
    profile.code_flows.extend(flows)
    profile.sensitive_fields.extend(
        f for f in _sensitive_fields(fresh_cpg)
        if any(loc.split(":", 1)[0] in affected for loc in f.locations)
    )

    relifted = _relifted(profile, dropped_keys, fresh)
    profile.build_kind = "incremental"
    profile.tech_stack = sorted(
        set(profile.tech_stack) | set(fresh.frameworks.values()))

    # 4. Notes are derived, so they are regenerated wholesale rather than
    #    patched — a stale TAINT line is a claim about code that no longer
    #    exists.
    parsed = sorted(cache.structural_index)
    profile.notes = _coverage_notes(profile, fresh, cpg, profile.agent_rows_merged, "")
    profile.notes.insert(0, (
        f"INCREMENTAL UPDATE: {len(parsed)} file(s) re-parsed of "
        f"{len(touched)} considered"
        + (f", {len(gone)} deleted/renamed evicted" if gone else "")
        + f"; profile_version unchanged ({profile.profile_version[:12]}). "
        "Files that changed between the cached base and this one without "
        "appearing in this PR are detected only by a size comparison, so a "
        "same-size edit elsewhere in the repo is not reflected."
    ))
    if relifted:
        profile.notes.insert(1, (
            "COVERAGE GAP: agent judgement was dropped from "
            f"{len(relifted)} re-derived row(s) ({', '.join(relifted[:4])}"
            f"{'...' if len(relifted) > 4 else ''}) — the agent judged the "
            "previous version of this code. They are back at the structural "
            "floor until the next full profile."
        ))

    return IncrementalResult(
        profile=profile, cpg=cpg,
        reparsed=parsed, dropped=sorted(gone),
        relifted_rows=relifted,
        telemetry={
            "files_considered": len(touched),
            "files_reparsed": len(parsed),
            "files_evicted": len(gone),
            "drift_from_pr": len(from_pr),
            "drift_from_stat": len(from_stat),
            "parse_errors": len(cache.parse_errors),
            "matrix_rows": len(profile.access_control_matrix),
            "rows_relifted": len(relifted),
            **cpg.stats(),
        },
    )
