"""Tiered context assembly (phase-2-change-analysis.md §5).

Builds one `ContextBundle` per change group — the **exact** context a Phase-3b
agent receives. This is where the token economy is actually spent or wasted:
Phase 1 exists to make a repo-level model available so that Phase 3 does not
have to read the repo, and handing an agent a full file undoes that in one line.

TIERS

  none        the default: the hunk, its enclosing symbol, 1-hop call-graph
              neighbours, and the profile rows for what it touches.
  full_file   the hunk edits control flow, a guard, or an early return — the
              surrounding logic is what decides whether the change is safe, and
              a window around it is not enough to tell.
  multi_hop   a taint question spans several functions, so the answer is not in
              any one of them.

Escalation is decided **structurally, here**, from zero-cost CPG queries — never
by the agent that would benefit from more context. §5 assigns the decision to the
planner for exactly that reason (workers must not choose their own files); the
planner wiring is Phase 3, and it will consume this decision rather than re-make
it. Computing it now keeps the property that matters: the tier is a function of
the graph, not of a model's appetite.

WHY `CodeSlice.content` MAY BE EMPTY
Slices carry file and line bounds always, and text only when a checkout is
available. An empty `content` with correct bounds is a resolvable pointer — the
agent's own file-read tool can fetch it under Phase-3 permissions. Fabricating
or omitting the bounds would not be.

Everything placed in `content` is untrusted repository text and is wrapped by
`safety/wrap.py` at the point it enters a prompt, never here — the bundle is a
data structure, and pre-wrapping would corrupt it for every non-prompt consumer
(the report, the run artifacts, the benchmark).
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable

from pr_review.change.astdiff import hunk_touches_control_flow
from pr_review.change.schema import (
    AnnotatedChangeSet,
    ChangeGroup,
    CodeSlice,
    ContextBundle,
    ProfileSlice,
)
from pr_review.extract.diff import ParsedFile, ParsedHunk
from pr_review.extract.schema import DeltaManifest, Hunk
from pr_review.profile.schema import ProjectProfile

SourceReader = Callable[[str, str], "str | None"]

# A slice wider than this is a full file in all but name; past it, say so and
# let the escalation record it rather than smuggling the file in as a "slice".
MAX_SLICE_LINES = 120
MAX_NEIGHBORS = 6


def _span(hunk: Hunk) -> tuple[int, int] | None:
    if not hunk.new_range:
        return None
    lo, _, hi = hunk.new_range.partition("-")
    try:
        return int(lo), int(hi or lo)
    except ValueError:
        return None


def _slice_text(source: str | None, start: int, end: int) -> str:
    if source is None:
        return ""
    lines = source.splitlines()
    return "\n".join(lines[max(start - 1, 0):min(end, len(lines))])


# ---------------------------------------------------------------------------
# CPG-driven selection
# ---------------------------------------------------------------------------

def _enclosing_symbols(cpg, path: str, spans: list[tuple[int, int]]) -> list:
    """Smallest symbol nodes containing each hunk."""
    if cpg is None:
        return []
    out, seen = [], set()
    symbols = [n for n in cpg.nodes_of_kind("symbol") if n.file == path]
    for lo, hi in spans:
        best = None
        for sym in symbols:
            end = sym.attrs.get("end_line", sym.line)
            if sym.line <= hi and end >= lo:
                if best is None or (end - sym.line) < (
                        best.attrs.get("end_line", best.line) - best.line):
                    best = sym
        if best is not None and best.id not in seen:
            seen.add(best.id)
            out.append(best)
    return out


def _neighbors(cpg, symbol_nodes: list) -> list:
    """1-hop callers and callees of the enclosing symbols, in source order.

    THE ORDER IS PART OF THE OUTPUT, NOT A DETAIL OF IT

    This used to return whatever order `cpg.edges("calls")` yielded, and that
    order is not stable across processes: two captures of the same corpus at the
    same commit produced the same neighbours in different sequence (§14.57).

    Nothing scored reads this field -- `bundle_stats` sums it and the pipeline
    serializes it -- so no published number has ever moved. But the field exists
    to be put in a prompt, and `[:MAX_NEIGHBORS]` **truncates** it, so an
    unstable order stops being cosmetic the moment a symbol has more than
    `MAX_NEIGHBORS` neighbours: a different six survive, and the model gets
    different context for the same commit.

    The reason this was invisible is worth keeping. The test covering this
    function compares neighbours **as a set** -- which is exactly the property
    that was stable, and exactly the property truncation destroys.

    Sorted by `(file, line, name)`: source order, which is also how a reader
    expects a prompt to lay them out. *Which* six are the most useful six is a
    different question, unmeasured, and recorded in `OPEN_ITEMS.md` rather than
    guessed at here.
    """
    if cpg is None or not symbol_nodes:
        return []
    ids = {n.id for n in symbol_nodes}
    out, seen = [], set(ids)
    for src, dst, relation in cpg.edges("calls"):
        for near, far in ((src, dst), (dst, src)):
            if near.id in ids and far.id not in seen:
                seen.add(far.id)
                out.append(far)
    # The *set* above is already order-independent -- every edge is visited, so
    # membership does not depend on which edge came first. Only the sequence was
    # in doubt, and only the sequence is fixed here.
    out.sort(key=lambda n: (n.file, n.line, n.name or ""))
    return out[:MAX_NEIGHBORS]


def _to_slice(node, sources: SourceReader | None) -> CodeSlice:
    start = node.line
    end = min(node.attrs.get("end_line", node.line), start + MAX_SLICE_LINES)
    source = sources(node.file, "after") if sources else None
    return CodeSlice(file=node.file, start_line=start, end_line=end,
                     symbol=node.name, content=_slice_text(source, start, end))


# ---------------------------------------------------------------------------
# Profile projection
# ---------------------------------------------------------------------------

def _profile_slice(profile: ProjectProfile | None, cpg, group: ChangeGroup
                   ) -> ProfileSlice:
    """Only the rows this group needs (phase-2 §5).

    Sending the whole `ProjectProfile` per group is the single easiest way to
    lose the economy Phase 1 buys — on a large repo the matrix alone dwarfs the
    diff. Rows are selected by the group's files, not by keyword similarity, so
    the selection is explainable and stable.
    """
    files = set(group.files)
    slice_ = ProfileSlice()
    if profile is not None:
        slice_.access_control_rows = sorted(
            (r.model_dump() for r in profile.access_control_matrix if r.file in files),
            key=lambda r: (r.get("file", ""), r.get("endpoint", ""),
                           r.get("http_method", "")))
        slice_.sensitive_fields = sorted(
            (f.model_dump() for f in profile.sensitive_fields
             if any(loc.split(":", 1)[0] in files for loc in f.locations)
             or not f.locations),
            key=lambda f: (f.get("name", ""), f.get("classification", "")))
        auth = profile.authentication
        authz = profile.authorization
        slice_.auth_summary = (
            f"authn: {', '.join(auth.methods) or 'not established'}; "
            f"authz model: {authz.model}, default posture: {authz.default_posture}; "
            f"enforcement points: {', '.join(authz.enforcement_points) or 'none recorded'}"
        )
    if cpg is not None:
        def nodes(kind):
            # Source order. `cpg.nodes_of_kind` returns graph insertion order,
            # and a profile that was patched incrementally does not have the
            # insertion order of one built cold -- so the same commit produced
            # differently ordered slices depending on what else had run first
            # (§14.57, and `runner._isolated` for why the branch differs).
            return sorted(
                ({"name": n.name, "file": n.file, "line": n.line, **n.attrs}
                 for n in cpg.nodes_of_kind(kind) if n.file in files),
                key=lambda r: (r["file"], r["line"], r["name"]))
        slice_.source_nodes = nodes("source")
        slice_.sink_nodes = nodes("sink")
        slice_.sanitizer_nodes = nodes("sanitizer")
    return slice_


# ---------------------------------------------------------------------------
# Escalation
# ---------------------------------------------------------------------------

def decide_escalation(group: ChangeGroup, cpg, parsed_hunks: list[ParsedHunk],
                      spans: list[tuple[int, int]], language: str = "python",
                      file_is_new: bool = False) -> tuple[str, str]:
    """(tier, reason). Structural signals first, then the textual control-flow check."""
    paths = _taint_paths_through(cpg, group.files, spans)
    multi = [p for p in paths if len(p.symbols) > 1]
    if multi:
        trail = " -> ".join(multi[0].symbols)
        return "multi_hop", (
            f"a taint-lite path spans {len(multi[0].symbols)} functions ({trail}); "
            f"the reachability question is not answerable inside one of them"
        )

    if cpg is not None:
        for node in cpg.nodes_of_kind("endpoint"):
            if node.file not in set(group.files):
                continue
            if any(lo <= node.line <= hi for lo, hi in spans) and node.attrs.get("guards"):
                return "full_file", (
                    f"the hunk overlaps guarded endpoint {node.name!r}; whether the "
                    f"guard still covers every path out of the handler needs the "
                    f"whole function body"
                )

    for hunk in parsed_hunks:
        if hunk_touches_control_flow(hunk, language, file_is_new):
            return "full_file", (
                "the hunk adds or removes control flow (branch, exception "
                "handling or an exit path), so the surrounding logic decides "
                "whether the change is safe"
            )

    if file_is_new:
        return "none", (
            "the file is new, so the hunks already are the whole file — "
            "escalating would add no context"
        )
    return "none", "hunk, enclosing symbol and 1-hop neighbours are sufficient"


def _taint_paths_through(cpg, files: list[str], spans: list[tuple[int, int]]) -> list:
    """Taint paths touching this group, in a stated order (§14.57).

    Sorted by endpoints rather than by node, because a path's *internal* order is
    meaningful — `TaintPath.to_flow()` emits source, then sanitizers, then sink,
    and shuffling that would turn a data-flow trace into a list of coordinates.
    So the paths are ordered and each path's flow is left alone.
    """
    if cpg is None:
        return []
    fileset = set(files)
    out = []
    for path in getattr(cpg, "taint_paths", ()) or ():
        for node in (path.source, path.sink):
            if node.file in fileset and any(lo <= node.line <= hi for lo, hi in spans):
                out.append(path)
                break
    out.sort(key=lambda p: (p.source.file, p.source.line, p.sink.file, p.sink.line,
                            p.sink_class or ""))
    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_bundles(
    changeset: AnnotatedChangeSet,
    manifest: DeltaManifest,
    parsed: list[ParsedFile] | None = None,
    cpg=None,
    profile: ProjectProfile | None = None,
    sources: SourceReader | None = None,
    language: str = "python",
) -> list[ContextBundle]:
    """One bundle per change group, in group order."""
    hunks_by_id: dict[str, Hunk] = {
        h.id: h for fc in manifest.files for h in fc.hunks
    }
    parsed_by_path = {pf.path: pf for pf in (parsed or [])}
    file_ids = {fc.path: fc.file_id for fc in manifest.files}
    new_files = {fc.path for fc in manifest.files if fc.change == "added"}

    bundles: list[ContextBundle] = []
    for group in changeset.groups:
        hunks = [hunks_by_id[h] for h in group.hunk_ids if h in hunks_by_id]
        spans = [s for s in (_span(h) for h in hunks) if s is not None]
        parsed_hunks = _parsed_hunks_for(group, parsed_by_path, file_ids)

        symbols = [n for path in group.files
                   for n in _enclosing_symbols(cpg, path, spans)]
        escalation, reason = decide_escalation(
            group, cpg, parsed_hunks, spans, language,
            file_is_new=all(f in new_files for f in group.files))

        bundles.append(ContextBundle(
            group_id=group.id,
            hunks=hunks,
            enclosing_symbols=[_to_slice(n, sources) for n in symbols],
            neighbors=[_to_slice(n, sources) for n in _neighbors(cpg, symbols)],
            profile_slice=_profile_slice(profile, cpg, group),
            reachability_hints=[
                node
                for path in _taint_paths_through(cpg, group.files, spans)
                for node in path.to_flow()
            ],
            escalation=escalation,
            escalation_reason=reason,
        ))
    return bundles


def _parsed_hunks_for(group: ChangeGroup, parsed_by_path: dict[str, ParsedFile],
                      file_ids: dict[str, str]) -> list[ParsedHunk]:
    """The in-memory hunks (with line text) behind a group's hunk ids."""
    wanted = set(group.hunk_ids)
    out: list[ParsedHunk] = []
    for path in group.files:
        pf = parsed_by_path.get(path)
        fid = file_ids.get(path, "")
        if pf is None or not fid:
            continue
        for n, hunk in enumerate(pf.hunks, start=1):
            if f"{fid}:h{n}" in wanted:
                out.append(hunk)
    return out


def bundle_stats(bundles: list[ContextBundle]) -> dict:
    """What the bundles will cost, for telemetry and the §5 acceptance check
    ("minimal context bundles, no full files unless the escalation rule fires")."""
    tiers: dict[str, int] = defaultdict(int)
    chars = 0
    for b in bundles:
        tiers[b.escalation] += 1
        chars += sum(len(s.content) for s in b.enclosing_symbols + b.neighbors)
    return {
        "bundles": len(bundles),
        "escalation": dict(sorted(tiers.items())),
        "slice_chars": chars,
        "slices": sum(len(b.enclosing_symbols) + len(b.neighbors) for b in bundles),
    }
