"""Code Property Graph — the security overlay (phase-1 §4).

Merges four layers into one directed multigraph:

  AST/symbol   file and symbol nodes from CAP's `ParseCache`
  call         `calls` edges from the call graph
  security     `endpoint` · `source` · `sink` · `sanitizer` · `sensitive_field`
  flow         `guards` · `taints` · `sanitizes` · `exposes`

Sources, sinks and sanitizers are seeded from `patterns/<language>.yaml` (data,
not code) and connected through the call graph to produce **taint-lite**
reachability: cheap, structural, and deliberately not a dataflow engine. It only
*seeds* candidates — Phase 3c verifies reachability before anything is reported,
and phase-1 §10 names "taint-lite false edges" as the expected failure mode. So
this errs toward over-connecting, and records enough path detail for the
verifier to refute cheaply.

WHERE THIS LIVES
phase-1 §1 describes the CPG as "persisted as a CAP CGP session snapshot". It is
built here as a standalone rustworkx graph instead, for three reasons: the CPG is
**repo-scoped and cached** (phase-1 §8) while a CGP session is run-scoped;
`ContextNode` carries content/metadata sized for agent artifacts, not for tens of
thousands of AST nodes; and tooling.md §1 already assumes a separate object —
its Class-A tool template is `make_find_sources_sinks(cpg, parse_cache)`, taking
the CPG as its own argument. Persistence is `cache.py`'s job.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterator

from pr_review.profile.patterns import load_catalog
from pr_review.profile.promote import PromotionResult, _walk
from pr_review.schema import FlowNode

MAX_TAINT_HOPS = 4          # starter value, tuned by the benchmark like the drift thresholds


# ---------------------------------------------------------------------------
# Graph primitives
# ---------------------------------------------------------------------------

@dataclass
class CPGNode:
    id: str
    kind: str                       # file | symbol | endpoint | source | sink | sanitizer | sensitive_field
    file: str
    name: str
    line: int = 0
    attrs: dict = field(default_factory=dict)


@dataclass
class TaintPath:
    """A structural source -> sink reachability claim."""
    source: CPGNode
    sink: CPGNode
    symbols: list[str]                              # qualified symbols traversed
    sanitized_by: list[str] = field(default_factory=list)

    @property
    def sink_class(self) -> str:
        return self.sink.attrs.get("sink_class", "")

    def to_flow(self) -> list[FlowNode]:
        """Project onto the Finding schema's `data_flow` (cross-cutting §1)."""
        flow = [FlowNode(role="source", file=self.source.file, line=self.source.line,
                         note=self.source.name)]
        for name in self.sanitized_by:
            flow.append(FlowNode(role="sanitizer", file=self.sink.file,
                                 line=self.sink.line, note=name))
        flow.append(FlowNode(role="sink", file=self.sink.file, line=self.sink.line,
                             note=f"{self.sink.name} ({self.sink_class})"))
        return flow


class CPG:
    """Thin, dependency-light graph. rustworkx is used for traversal only."""

    def __init__(self) -> None:
        import rustworkx

        self._rx = rustworkx
        self.graph = rustworkx.PyDiGraph(multigraph=True)
        self._index: dict[str, int] = {}
        self.taint_paths: list[TaintPath] = []

    # -- construction ------------------------------------------------------

    def add(self, node: CPGNode) -> int:
        if node.id in self._index:
            return self._index[node.id]
        idx = self.graph.add_node(node)
        self._index[node.id] = idx
        return idx

    def link(self, src_id: str, dst_id: str, relation: str) -> None:
        if src_id in self._index and dst_id in self._index:
            self.graph.add_edge(self._index[src_id], self._index[dst_id], relation)

    # -- queries (the Class-A tool surface, tooling.md §1) -----------------

    def node(self, node_id: str) -> CPGNode | None:
        idx = self._index.get(node_id)
        return self.graph[idx] if idx is not None else None

    def nodes_of_kind(self, kind: str) -> list[CPGNode]:
        return [n for n in self.graph.nodes() if n.kind == kind]

    def edges(self, relation: str | None = None) -> Iterator[tuple[CPGNode, CPGNode, str]]:
        for a, b, rel in self.graph.weighted_edge_list():
            if relation is None or rel == relation:
                yield self.graph[a], self.graph[b], rel

    def unguarded_endpoints(self) -> list[CPGNode]:
        return [n for n in self.nodes_of_kind("endpoint") if not n.attrs.get("guarded")]

    def paths_to(self, sink_class: str) -> list[TaintPath]:
        return [p for p in self.taint_paths if p.sink_class == sink_class]

    def stats(self) -> dict:
        kinds: dict[str, int] = defaultdict(int)
        for n in self.graph.nodes():
            kinds[n.kind] += 1
        rels: dict[str, int] = defaultdict(int)
        for _a, _b, rel in self.graph.weighted_edge_list():
            rels[rel] += 1
        return {
            "nodes": dict(sorted(kinds.items())),
            "edges": dict(sorted(rels.items())),
            "taint_paths": len(self.taint_paths),
        }

    # -- incremental splicing (phase-1 §6) ---------------------------------
    #
    # These exist because `profile/incremental.py` patches a cached graph
    # rather than rebuilding it. They are only sound while every derived fact
    # is confined to one file — `splice_violations()` is the assertion of that,
    # and the incremental path refuses to run when it reports anything.

    def files(self) -> list[str]:
        return sorted({n.file for n in self.graph.nodes() if n.file})

    def splice_violations(self) -> list[str]:
        """Facts that span files, and therefore cannot be patched per file.

        Today there are none by construction: `_resolve_callee` is local-file
        first and returns None when a name is not defined in the same file, so
        no `calls` edge and no taint path crosses a file boundary. That is a
        *property of the current resolver*, not a law — the day cross-file
        import resolution lands, patching one file's subgraph will silently
        leave stale edges hanging off its neighbours. This check is what turns
        that into a loud fallback to a full rebuild instead.
        """
        bad: list[str] = []
        for src, dst, rel in self.edges():
            if src.file and dst.file and src.file != dst.file:
                bad.append(f"{rel} edge spans files: {src.id} -> {dst.id}")
        for path in self.taint_paths:
            if path.source.file != path.sink.file:
                bad.append(
                    f"taint path spans files: {path.source.id} -> {path.sink.id}")
        return bad

    def remove_file(self, path: str) -> int:
        """Drop everything belonging to `path`. Returns the node count removed.

        File-less nodes (shared `permission` nodes) are deliberately left
        behind — another file's endpoint may still be guarded by one. They are
        collected afterwards by `prune_orphans()`.
        """
        removed = 0
        for node in [n for n in self.graph.nodes() if n.file == path]:
            idx = self._index.pop(node.id, None)
            if idx is not None:
                self.graph.remove_node(idx)
                removed += 1
        self.taint_paths = [
            p for p in self.taint_paths
            if p.source.file != path and p.sink.file != path
        ]
        return removed

    def prune_orphans(self) -> int:
        """Drop file-less nodes that nothing references any more."""
        dropped = 0
        for node in [n for n in self.graph.nodes() if not n.file]:
            idx = self._index.get(node.id)
            if idx is None:
                continue
            if self.graph.in_degree(idx) + self.graph.out_degree(idx) == 0:
                self.graph.remove_node(idx)
                self._index.pop(node.id, None)
                dropped += 1
        return dropped

    def merge(self, other: "CPG") -> None:
        """Splice another graph in. Callers must `remove_file()` first — this
        does not deduplicate edges, because a multigraph cannot tell a repeat
        from a genuine parallel edge."""
        for node in other.graph.nodes():
            self.add(node)
        for a, b, rel in other.graph.weighted_edge_list():
            self.link(other.graph[a].id, other.graph[b].id, rel)
        self.taint_paths.extend(other.taint_paths)

    # -- persistence -------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize to plain JSON-able data.

        Nodes, edges and taint paths rather than a pickled rustworkx graph:
        everything Phase 2 asks of the CPG — which security kinds a changed file
        touches, and the reachability hints for a hunk — is answerable from this,
        and a text format survives a library upgrade that a pickle would not.
        """
        return {
            "nodes": [
                {"id": n.id, "kind": n.kind, "file": n.file, "name": n.name,
                 "line": n.line, "attrs": n.attrs}
                for n in self.graph.nodes()
            ],
            "edges": [
                {"src": self.graph[a].id, "dst": self.graph[b].id, "relation": rel}
                for a, b, rel in self.graph.weighted_edge_list()
            ],
            "taint_paths": [
                {"source": p.source.id, "sink": p.sink.id, "symbols": p.symbols,
                 "sanitized_by": p.sanitized_by}
                for p in self.taint_paths
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CPG":
        cpg = cls()
        for raw in data.get("nodes", []):
            cpg.add(CPGNode(**raw))
        for raw in data.get("edges", []):
            cpg.link(raw["src"], raw["dst"], raw["relation"])
        for raw in data.get("taint_paths", []):
            source, sink = cpg.node(raw["source"]), cpg.node(raw["sink"])
            if source is not None and sink is not None:
                cpg.taint_paths.append(TaintPath(
                    source=source, sink=sink, symbols=raw.get("symbols", []),
                    sanitized_by=raw.get("sanitized_by", []),
                ))
        return cpg


# ---------------------------------------------------------------------------
# Catalog matching
# ---------------------------------------------------------------------------

def _matches(found: str, pattern: str, exact: bool = False) -> bool:
    """Dotted-suffix match, the contract stated at the top of python.yaml.

    `cursor.execute` matches `conn.cursor.execute`; it does not match
    `mycursor_execute`, because the boundary must be a dot.

    `exact` turns the suffix rule off, which a *single-segment* pattern
    sometimes needs. The suffix rule reads `exec` as "any `.exec`", and the
    receiver is unbounded: measured over the 41 cached CPGs, `escape` matched
    `re.escape` 1,036 times against 31 legitimate `html.escape`, and every
    `eval` node in the corpus was `c.eval`/`cs.eval` rather than the
    `pandas.eval` the catalog comment assumed. Which patterns get this is a
    measurement recorded next to each one in python.yaml, not a rule about
    segment counts — `urlparse` and `bindparam` are single-segment too and
    their dotted forms are correct.
    """
    if exact:
        return found == pattern
    return found == pattern or found.endswith("." + pattern)


def _field_matches(name: str, term: str) -> bool:
    """Match a field name against a sensitive-data term, by identifier segment.

    Exact matching is too strict — it misses `password_hash`, `user_ssn`,
    `credit_card_number`, which is most of how these are actually spelled.
    Plain substring is too loose — `token` would hit `tokenizer`. So split on
    `_` and ask whether the term's segments appear contiguously:

        password_hash      vs password    -> hit
        credit_card_number vs credit_card -> hit
        tokenizer          vs token       -> miss
    """
    parts = name.lower().split("_")
    want = term.lower().split("_")
    return any(parts[i:i + len(want)] == want for i in range(len(parts) - len(want) + 1))


def _call_patterns(catalog: dict) -> tuple[dict[str, list[tuple[str, str]]], set[str]]:
    """(pattern -> [(kind, detail)], patterns matched exactly) for call patterns.

    Both `calls` and `exact_calls` are read from every sinks/sanitizers/sources
    block; the only difference is which matching rule `_matches` applies. The
    exact set is keyed on the pattern string and therefore global to the
    catalog — the same string cannot be suffix-matched in one block and
    exact-matched in another, which is the right constraint, because the
    pattern string is also the key of the map it would have to disagree with.
    """
    out: dict[str, list[tuple[str, str]]] = defaultdict(list)
    exact: set[str] = set()
    suffix: set[str] = set()
    blocks = (("sinks", "sink"), ("sanitizers", "sanitizer"), ("sources", "source"))
    for block, kind in blocks:
        for detail, cfg in (catalog.get(block) or {}).items():
            for pat in cfg.get("calls", []) or []:
                out[pat].append((kind, detail))
                suffix.add(pat)
            for pat in cfg.get("exact_calls", []) or []:
                out[pat].append((kind, detail))
                exact.add(pat)
    # Loudly, because the quiet version is the defect this key exists to fix.
    # A pattern in both lists has to resolve one way or the other, and whichever
    # way it resolves is invisible at the catalog — which is how `text` matched
    # `request.text` for as long as it did. Duplicate YAML *keys* are the same
    # hazard one level up and PyYAML keeps the last one without a word, so a
    # stray second `calls:` deletes the list above it (OPEN_ITEMS.md §12).
    both = exact & suffix
    if both:
        raise ValueError(
            f"catalog patterns declared in both `calls` and `exact_calls`: "
            f"{sorted(both)}. Pick one — the matching rule cannot be both.")
    return out, exact


def _attribute_patterns(catalog: dict) -> dict[str, str]:
    """attribute chain -> source group (framework request objects + generic)."""
    out: dict[str, str] = {}
    for name, fw in (catalog.get("frameworks") or {}).items():
        for pat in ((fw.get("sources") or {}).get("attributes") or []):
            out[pat] = f"request:{name}"
    for group, cfg in (catalog.get("sources") or {}).items():
        for pat in cfg.get("attributes", []) or []:
            out[pat] = group
    return out


# ---------------------------------------------------------------------------
# Tree scanning — gap 3: attribute chains collapse in the call graph
# ---------------------------------------------------------------------------

@dataclass
class _Scan:
    calls: list[tuple[str, int]] = field(default_factory=list)
    attributes: list[tuple[str, int]] = field(default_factory=list)
    assignments: list[tuple[str, int]] = field(default_factory=list)


def _scan(cache, path: str) -> _Scan:
    """Calls, attribute chains and assigned names, from the tree CAP parsed.

    Three things the ParseCache cannot give us:
      - `request.args.get(q)` reaches the call graph as the callee `get` — the
        chain is gone (smoke-test gap 3).
      - assigned names are not indexed at all, so class attributes like
        `password_hash` are invisible to `structural_index` (gap 1 again).
    Reading them back out of `_trees` keeps all of this at zero file I/O.
    """
    entry = getattr(cache, "_trees", {}).get(path)
    if entry is None:
        return _Scan()
    tree, _src = entry
    out = _Scan()
    for node in _walk(tree.root_node):
        line = node.start_point[0] + 1
        if node.type == "call":
            fn = node.child_by_field_name("function")
            if fn is not None:
                out.calls.append((fn.text.decode("utf-8", "replace"), line))
        elif node.type == "attribute":
            out.attributes.append((node.text.decode("utf-8", "replace"), line))
        elif node.type == "assignment":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                out.assignments.append((left.text.decode("utf-8", "replace"), line))
    return out


def _enclosing_class(symbols: list, line: int):
    for s in symbols:
        if s.type == "class" and s.line <= line <= s.end_line:
            return s
    return None


# ---------------------------------------------------------------------------
# Symbol resolution
# ---------------------------------------------------------------------------

def _enclosing(symbols: list, line: int) -> Any | None:
    """Smallest symbol whose span contains `line`."""
    best = None
    for s in symbols:
        if s.line <= line <= s.end_line and s.type in ("function", "method"):
            if best is None or (s.end_line - s.line) < (best.end_line - best.line):
                best = s
    return best


def _stem(path: str) -> str:
    return path.rsplit("/", 1)[-1].removesuffix(".py")


def _qualified(path: str, symbol) -> str:
    """Match CAP's call-graph key format exactly.

    `{stem}.{Class}.{method}` for methods, `{stem}.{name}` for functions —
    the form CAP's `CallGraphBuilder` emits (`models.User.fetch`). Omitting the
    class both collides sibling handlers (four Django views each with a `get`
    collapse to one node) and fails to join against the call graph, silently
    dropping every method-level edge.
    """
    parent = getattr(symbol, "parent", "")
    if parent:
        return f"{_stem(path)}.{parent}.{symbol.name}"
    return f"{_stem(path)}.{symbol.name}"


def _resolve_callee(callee: str, path: str, cache) -> str | None:
    """Bare callee -> qualified symbol, local-file first.

    Local-first is right for taint-lite: cross-file propagation needs real
    import resolution, and a name-collision guess would manufacture edges the
    verifier then has to spend tokens refuting.
    """
    bare = callee.rsplit(".", 1)[-1]
    for sym in cache.structural_index.get(path, []):
        if sym.name == bare and sym.type in ("function", "method"):
            return _qualified(path, sym)
    return None


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_cpg(promotion: PromotionResult, language: str = "python",
              max_hops: int = MAX_TAINT_HOPS) -> CPG:
    catalog = load_catalog(language)
    cache = promotion.cache
    cpg = CPG()

    call_pats, exact_pats = _call_patterns(catalog)
    attr_pats = _attribute_patterns(catalog)
    sensitive = {
        name: cls
        for cls, names in (catalog.get("sensitive_fields") or {}).items()
        for name in names
    }

    # Layer 1+2 — files, symbols, calls -----------------------------------
    symbol_node: dict[str, str] = {}                 # qualified symbol -> node id
    for path, symbols in cache.structural_index.items():
        cpg.add(CPGNode(id=f"file:{path}", kind="file", file=path, name=path))
        for sym in symbols:
            if sym.type not in ("function", "method"):
                continue
            qual = _qualified(path, sym)
            nid = f"sym:{qual}"
            cpg.add(CPGNode(id=nid, kind="symbol", file=path, name=qual, line=sym.line,
                            attrs={"end_line": sym.end_line, "parent": sym.parent}))
            cpg.link(f"file:{path}", nid, "contains")
            symbol_node[qual] = nid

    resolved_calls: dict[str, set[str]] = defaultdict(set)
    for path, symbols in cache.structural_index.items():
        for sym in symbols:
            if sym.type not in ("function", "method"):
                continue
            qual = _qualified(path, sym)
            for callee in cache.call_graph.forward.get(qual, ()):
                target = _resolve_callee(callee, path, cache)
                if target and target in symbol_node:
                    resolved_calls[qual].add(target)
                    cpg.link(symbol_node[qual], symbol_node[target], "calls")

    # Layer 3 — endpoints and their guards ---------------------------------
    for ep in promotion.endpoints:
        nid = f"endpoint:{ep.file}:{ep.symbol}"
        cpg.add(CPGNode(
            id=nid, kind="endpoint", file=ep.file, name=ep.symbol, line=ep.line,
            attrs={"route": ep.route, "http_methods": ep.http_methods,
                   "framework": ep.framework, "guarded": ep.guarded,
                   "guards": ep.guards, "opens_access": ep.opens_access},
        ))
        # Function endpoints are one symbol; a Django class-based view is a
        # class (not a symbol node) whose handlers are its methods, so link to
        # each handler — that is where the reachable code actually is.
        stem = _stem(ep.file)
        if cpg.node(f"sym:{stem}.{ep.symbol}") is not None:
            cpg.link(nid, f"sym:{stem}.{ep.symbol}", "implements")
        else:
            for verb in ep.http_methods:
                cpg.link(nid, f"sym:{stem}.{ep.symbol}.{verb.lower()}", "implements")
        for guard in ep.guards:
            gid = f"permission:{guard}"
            cpg.add(CPGNode(id=gid, kind="permission", file="", name=guard))
            cpg.link(gid, nid, "guards")

    # Layer 3 — sources, sinks, sanitizers, sensitive fields ---------------
    in_symbol: dict[str, list[CPGNode]] = defaultdict(list)
    for path in cache.structural_index:
        symbols = cache.structural_index.get(path, [])
        scan = _scan(cache, path)

        for text, line in scan.calls:
            for pattern, roles in call_pats.items():
                if not _matches(text, pattern, exact=pattern in exact_pats):
                    continue
                for kind, detail in roles:
                    nid = f"{kind}:{path}:{line}:{text}"
                    key = "sink_class" if kind in ("sink", "sanitizer") else "group"
                    # The catalog entry that matched, kept alongside the call
                    # text. `_self_pairing` needs to know that the source `open`
                    # and the sink `f.open` are one dual-role pattern rather
                    # than two, which the text alone cannot say.
                    cpg.add(CPGNode(id=nid, kind=kind, file=path, name=text, line=line,
                                    attrs={key: detail, "pattern": pattern}))
                    enc = _enclosing(symbols, line)
                    if enc is not None:
                        qual = _qualified(path, enc)
                        cpg.link(symbol_node.get(qual, ""), nid, "contains")
                        in_symbol[qual].append(cpg.node(nid))

        for text, line in scan.attributes:
            group = next((g for p, g in attr_pats.items() if _matches(text, p)), None)
            if group is None:
                continue
            nid = f"source:{path}:{line}:{text}"
            cpg.add(CPGNode(id=nid, kind="source", file=path, name=text, line=line,
                            attrs={"group": group}))
            enc = _enclosing(symbols, line)
            if enc is not None:
                qual = _qualified(path, enc)
                cpg.link(symbol_node.get(qual, ""), nid, "contains")
                in_symbol[qual].append(cpg.node(nid))

        # Sensitive fields are assigned names, not symbols — `structural_index`
        # holds only classes/functions/methods, so these come from the scan.
        for name, line in scan.assignments:
            cls = next((c for term, c in sensitive.items()
                        if _field_matches(name, term)), None)
            if not cls:
                continue
            owner = _enclosing_class(symbols, line)
            nid = f"sensitive_field:{path}:{name}"
            cpg.add(CPGNode(id=nid, kind="sensitive_field", file=path, name=name,
                            line=line,
                            attrs={"classification": cls,
                                   "owner": owner.name if owner else ""}))
            if owner is not None:
                cpg.link(f"file:{path}", nid, "contains")

    # Layer 4 — taint-lite --------------------------------------------------
    cpg.taint_paths = _taint(cpg, in_symbol, resolved_calls, max_hops)
    return cpg


def _self_pairing(source: CPGNode, sink: CPGNode) -> bool:
    """Is this one dual-role pattern paired with itself, rather than a flow?

    Three patterns in `python.yaml` are legitimately both a source and a sink —
    `open` (filesystem/path), `requests.get` and `httpx.get`
    (network/http_outbound) — and each classification is right on its own terms:
    `open(p)`'s **argument** is a path sink, while `open(f).read()`'s **return
    value** is untrusted data. The node builder does not distinguish argument
    position from return position, so every `open(x)` emits a source node *and*
    a sink node, and `_taint`'s cross product pairs them with each other.

    THE DEGENERATE CASE came first: one `open(x)` emitting `source:f:29:open`
    and `sink:f:29:open` produced a path from a call to itself. Measured on the
    labelled corpus, that shape was 6 introduced and 42 pre-existing paths, and
    removing it took the corpus from 11 false positives to 8.

    THE GENERAL CASE is the same defect at a distance. `open` at line 29 paired
    with `open` at line 38 is not a self-loop, but the claim it makes — that
    file *contents* read at 29 reach the path *argument* at 38 — is not
    something this engine establishes. `_taint` pairs by co-location in a call
    tree, not by dataflow, so the "path" is evidence only that one function
    opens two files. All 8 surviving false positives were this.

    WHAT THIS DELIBERATELY KEEPS. Only a pattern paired with *itself* is
    refused, so `open` still seeds taint into other sinks
    (`os.system(open(cfg).read())`) and still receives taint from other sources
    (`open(request.args["f"])`, the traversal case that matters). The pass-2
    true positive — source `tarfile.open`, sink `tar.extractall` — is two
    patterns and survives.

    Compared on the matched **pattern** rather than the call text, because
    `open` and `f.open` are one dual-role catalog entry and two different
    strings.
    """
    src_pat = source.attrs.get("pattern")
    return bool(src_pat) and src_pat == sink.attrs.get("pattern")


def _taint(cpg: CPG, in_symbol: dict[str, list[CPGNode]],
           calls: dict[str, set[str]], max_hops: int) -> list[TaintPath]:
    """Connect each source to every sink reachable from its enclosing symbol."""
    paths: list[TaintPath] = []
    for start, nodes in in_symbol.items():
        sources = [n for n in nodes if n.kind == "source"]
        if not sources:
            continue

        # BFS over the resolved call graph, remembering how we got there.
        route: dict[str, list[str]] = {start: [start]}
        queue = deque([(start, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_hops:
                continue
            for nxt in calls.get(current, ()):
                if nxt not in route:
                    route[nxt] = route[current] + [nxt]
                    queue.append((nxt, depth + 1))

        for symbol, trail in route.items():
            sinks = [n for n in in_symbol.get(symbol, []) if n.kind == "sink"]
            if not sinks:
                continue
            on_path = [
                n.name for step in trail for n in in_symbol.get(step, [])
                if n.kind == "sanitizer"
            ]
            for source in sources:
                for sink in sinks:
                    # A dual-role pattern is not a flow to itself — see
                    # `_self_pairing`.
                    if _self_pairing(source, sink):
                        continue
                    sanitized = [
                        name for name in on_path
                        if any(n.attrs.get("sink_class") == sink.attrs.get("sink_class")
                               for n in in_symbol.get(symbol, []) + in_symbol.get(start, [])
                               if n.kind == "sanitizer" and n.name == name)
                    ]
                    path = TaintPath(source=source, sink=sink, symbols=trail,
                                     sanitized_by=sanitized)
                    paths.append(path)
                    cpg.link(source.id, sink.id, "sanitizes" if sanitized else "taints")
    return paths
