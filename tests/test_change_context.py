"""Tiered context bundles and the escalation decision (phase-2 §5).

phase-2 §8's acceptance: "minimal context bundles (no full files unless the
escalation rule fires)". The bundle is where the token economy Phase 1 buys is
either spent or thrown away, so these tests are mostly about what is *not* in
one.
"""
import pytest

pytest.importorskip(
    "cap_engine.environment.code_promoter",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from pr_review.change.classify import classify_changes  # noqa: E402
from pr_review.change.context import (  # noqa: E402
    MAX_SLICE_LINES,
    build_bundles,
    bundle_stats,
)
from pr_review.change.filter import filter_changes  # noqa: E402
from pr_review.change.schema import ContextBundle  # noqa: E402
from pr_review.extract.manifest import build_manifest  # noqa: E402
from pr_review.profile.cpg import CPGNode  # noqa: E402
from pr_review.profile.security_profile import build_profile  # noqa: E402

FIXTURE = "tests/fixtures/sample_app"
PR_DIFF = "tests/fixtures/phase2_pr.diff"


def _sources(path, side):
    """The head checkout. The fixture app stands in for both sides here; only
    `after` is served, which is what a run with just `--head-dir` gets."""
    if side != "after":
        return None
    try:
        return open(f"{FIXTURE}/{path}").read()
    except OSError:
        return None


@pytest.fixture(scope="module")
def built():
    return build_profile(FIXTURE, repo="o/r", base_sha="a" * 40)


@pytest.fixture(scope="module")
def bundles(built):
    manifest, parsed = build_manifest(
        repo="o/r", pr_number=7, diff_text=open(PR_DIFF).read(),
        base_sha="b" * 40, head_sha="c" * 40)
    kept = filter_changes(manifest, parsed, cpg=built.cpg, profile=built.profile)
    changeset = classify_changes(manifest, kept.kept, parsed, cpg=built.cpg,
                                 profile=built.profile)
    made = build_bundles(changeset, manifest, parsed, cpg=built.cpg,
                         profile=built.profile, sources=_sources)
    return {b.group_id: b for b in made}, changeset


def _for(bundles, path):
    made, changeset = bundles
    group = next(g for g in changeset.groups if path in g.files)
    return made[group.id]


# --------------------------------------------------------------------------
# What a bundle contains
# --------------------------------------------------------------------------

def test_one_bundle_per_group(bundles):
    made, changeset = bundles
    assert set(made) == {g.id for g in changeset.groups}


def test_the_bundle_carries_the_hunk_and_its_enclosing_symbol(bundles):
    bundle = _for(bundles, "app.py")
    assert [h.id for h in bundle.hunks]
    assert [s.symbol for s in bundle.enclosing_symbols] == ["app.search"]
    assert "def search" in bundle.enclosing_symbols[0].content


def test_one_hop_neighbours_come_from_the_call_graph(bundles):
    """The cross-file relationship that per-file grouping deliberately does not
    merge is carried here instead."""
    bundle = _for(bundles, "app.py")
    assert "app._run_search" in {s.symbol for s in bundle.neighbors}


def test_the_profile_slice_is_a_slice_not_the_profile(bundles, built):
    bundle = _for(bundles, "app.py")
    rows = bundle.profile_slice.access_control_rows
    assert {r["file"] for r in rows} == {"app.py"}
    assert len(rows) < len(built.profile.access_control_matrix)


def test_the_profile_slice_carries_the_auth_summary(bundles):
    assert "authz model" in _for(bundles, "app.py").profile_slice.auth_summary


def test_reachability_hints_are_the_taint_path(bundles):
    flow = _for(bundles, "app.py").reachability_hints
    assert [n.role for n in flow] == ["source", "sink"]
    assert "cursor.execute" in flow[-1].note


def test_an_unrelated_group_gets_no_reachability_hints(bundles):
    assert _for(bundles, "models.py").reachability_hints == []


def test_the_schema_has_no_full_file_field():
    """Context is bounded by construction: full-file access requires setting
    `escalation`, which only the structural decision below can do."""
    assert "escalation" in ContextBundle.model_fields
    assert not {"file_content", "full_file", "source"} & set(ContextBundle.model_fields)


# --------------------------------------------------------------------------
# Escalation
# --------------------------------------------------------------------------

def test_multi_hop_when_the_taint_question_spans_functions(bundles):
    bundle = _for(bundles, "app.py")
    assert bundle.escalation == "multi_hop"
    assert "app.search -> app._run_search" in bundle.escalation_reason


def test_full_file_when_the_hunk_touches_a_guarded_endpoint(bundles):
    bundle = _for(bundles, "views.py")
    assert bundle.escalation == "full_file"
    assert "guarded endpoint" in bundle.escalation_reason


def test_no_escalation_for_a_data_only_change(bundles):
    assert _for(bundles, "models.py").escalation == "none"


def test_a_new_file_is_never_escalated(bundles):
    """The hunks already are the whole file."""
    bundle = _for(bundles, "utils/strings.py")
    assert bundle.escalation == "none"
    assert "the file is new" in bundle.escalation_reason


def test_every_escalation_states_its_reason(bundles):
    made, _ = bundles
    assert all(b.escalation_reason for b in made.values())


def test_most_bundles_do_not_escalate(bundles):
    """The acceptance check: escalation is the exception, not the default."""
    made, _ = bundles
    stats = bundle_stats(list(made.values()))
    assert stats["escalation"].get("none", 0) >= stats["escalation"].get("full_file", 0)


# --------------------------------------------------------------------------
# Degradation
# --------------------------------------------------------------------------

def test_slices_keep_their_bounds_when_no_checkout_is_available(built):
    """An empty `content` with correct bounds is a resolvable pointer; a missing
    bound is not."""
    manifest, parsed = build_manifest(
        repo="o/r", pr_number=7, diff_text=open(PR_DIFF).read())
    kept = filter_changes(manifest, parsed, cpg=built.cpg, profile=built.profile)
    changeset = classify_changes(manifest, kept.kept, parsed, cpg=built.cpg,
                                 profile=built.profile)
    made = build_bundles(changeset, manifest, parsed, cpg=built.cpg,
                         profile=built.profile, sources=None)
    slices = [s for b in made for s in b.enclosing_symbols]
    assert slices
    assert all(s.content == "" for s in slices)
    assert all(s.start_line > 0 and s.end_line >= s.start_line for s in slices)


def test_bundles_build_with_no_cpg_at_all():
    manifest, parsed = build_manifest(
        repo="o/r", pr_number=7, diff_text=open(PR_DIFF).read())
    kept = filter_changes(manifest, parsed)
    changeset = classify_changes(manifest, kept.kept, parsed)
    made = build_bundles(changeset, manifest, parsed)
    assert len(made) == len(changeset.groups)
    assert all(b.enclosing_symbols == [] for b in made)


def test_slices_are_capped(bundles):
    made, _ = bundles
    for bundle in made.values():
        for sl in bundle.enclosing_symbols + bundle.neighbors:
            assert sl.end_line - sl.start_line <= MAX_SLICE_LINES


def test_stats_report_what_the_bundles_will_cost(bundles):
    made, _ = bundles
    stats = bundle_stats(list(made.values()))
    assert stats["bundles"] == len(made)
    assert stats["slice_chars"] > 0
    assert sum(stats["escalation"].values()) == len(made)


# ---------------------------------------------------------------------------
# Neighbour ordering — §14.57
# ---------------------------------------------------------------------------

def _fake_cpg(edges):
    """Just enough graph for `_neighbors`: nodes with an id/file/line/name, and
    an `edges("calls")` that yields them in whatever order is asked for.

    A stub rather than the sample app, because the fixture has three call edges
    and one neighbour — it cannot tell a sorted list from an unsorted one, and it
    can never reach `MAX_NEIGHBORS`, which is where the ordering stops being
    cosmetic. That gap is why §14.57 survived a test suite that covered this
    function.
    """
    class Fake:
        def edges(self, relation=None):
            return list(edges) if relation in (None, "calls") else []
    return Fake()


def _node(name, file, line):
    return CPGNode(id=f"{file}:{name}", kind="symbol", file=file, name=name, line=line)


def test_neighbours_come_back_in_source_order(bundles):
    """The set was always stable; the sequence was not, and the sequence is what
    `MAX_NEIGHBORS` truncates.

    `test_one_hop_neighbours_come_from_the_call_graph` above compares neighbours
    as a **set** — precisely the property that never broke, and precisely the
    property truncation destroys once a symbol has more than `MAX_NEIGHBORS` of
    them. Two captures of the same corpus at the same commit produced the same
    neighbours in different order until 2026-08-25 (§14.57).
    """
    from pr_review.change.context import _neighbors

    anchor = _node("caller", "a.py", 1)
    far = [_node("z", "b.py", 90), _node("m", "a.py", 50),
           _node("a", "b.py", 10), _node("q", "a.py", 5)]
    cpg = _fake_cpg([(anchor, n, "calls") for n in far])
    got = [(n.file, n.line) for n in _neighbors(cpg, [anchor])]
    assert got == [("a.py", 5), ("a.py", 50), ("b.py", 10), ("b.py", 90)], got


def test_which_neighbours_survive_truncation_does_not_depend_on_edge_order(bundles):
    """The half that is not cosmetic.

    With more than `MAX_NEIGHBORS` neighbours the order decides *membership*, so
    an unstable sequence means the model gets different context for the same
    commit. Reversing what the graph yields is the same perturbation as running
    in another process, applied deterministically.
    """
    from pr_review.change.context import MAX_NEIGHBORS, _neighbors

    anchor = _node("caller", "a.py", 1)
    far = [_node(f"s{i:02d}", "a.py", 100 - i) for i in range(MAX_NEIGHBORS + 5)]
    edges = [(anchor, n, "calls") for n in far]

    forward = _neighbors(_fake_cpg(edges), [anchor])
    backward = _neighbors(_fake_cpg(list(reversed(edges))), [anchor])

    assert len(forward) == MAX_NEIGHBORS
    assert [n.id for n in forward] == [n.id for n in backward], (
        "reversing the graph's edge order changed which neighbours survived "
        "MAX_NEIGHBORS truncation -- the model would receive different context "
        "for the same commit (§14.57)")
    assert [n.line for n in forward] == sorted(n.line for n in forward)


def test_the_real_fixture_still_agrees_with_the_stub(bundles):
    """One assertion against the shipping path, so the stub cannot drift from it."""
    from pr_review.change.context import MAX_NEIGHBORS

    bundle = _for(bundles, "app.py")
    keys = [(s.file, s.start_line, s.symbol or "") for s in bundle.neighbors]
    assert keys == sorted(keys) and len(keys) <= MAX_NEIGHBORS


# ---------------------------------------------------------------------------
# Everything else in a bundle that had an order — §14.57
# ---------------------------------------------------------------------------

def test_the_profile_slices_lists_come_back_in_a_stated_order(bundles):
    """`cpg.nodes_of_kind` returns graph insertion order, and a profile patched
    incrementally does not have the insertion order of one built cold — so the
    same commit produced differently ordered slices depending on what else had
    run first in that repository (`runner._isolated`).
    """
    made, _ = bundles
    checked = 0
    for bundle in made.values():
        ps = bundle.profile_slice
        for name in ("source_nodes", "sink_nodes", "sanitizer_nodes"):
            rows = getattr(ps, name)
            keys = [(r["file"], r["line"], r["name"]) for r in rows]
            assert keys == sorted(keys), f"{name} unsorted: {keys}"
            checked += len(rows) > 1
        acl = [(r["file"], r["endpoint"], r["http_method"])
               for r in ps.access_control_rows]
        assert acl == sorted(acl), f"access_control_rows unsorted: {acl}"
        checked += len(acl) > 1
        sens = [(f["name"], f["classification"]) for f in ps.sensitive_fields]
        assert sens == sorted(sens), f"sensitive_fields unsorted: {sens}"
        checked += len(sens) > 1
    assert checked, (
        "no profile-slice list in the fixture had two or more rows, so this "
        "test cannot distinguish sorted from unsorted -- the failure mode "
        "§14.57 records. Give the fixture a group with a real slice.")


def test_taint_paths_are_ordered_but_each_flow_is_left_alone():
    """Paths get a stated order; the nodes *inside* a path keep theirs.

    `TaintPath.to_flow()` emits source, then sanitizers, then sink. Sorting that
    would turn a data-flow trace into a list of coordinates. The fixture carries
    one path per group and so cannot tell the two apart, which is why this is a
    stub.
    """
    from pr_review.change.context import _taint_paths_through
    from pr_review.profile.cpg import TaintPath

    def node(file, line, name, sink_class=""):
        return CPGNode(id=f"{file}:{line}", kind="sink", file=file, name=name,
                       line=line, attrs={"sink_class": sink_class} if sink_class else {})

    late = TaintPath(source=node("a.py", 90, "req"), sink=node("a.py", 95, "exec", "cmd"),
                     symbols=["f"], sanitized_by=["shlex_quote"])
    early = TaintPath(source=node("a.py", 10, "req"), sink=node("a.py", 15, "exec", "cmd"),
                      symbols=["g"])

    class Fake:
        taint_paths = [late, early]

    got = _taint_paths_through(Fake(), ["a.py"], [(1, 100)])
    assert [p.source.line for p in got] == [10, 90], (
        f"paths came back in graph order, not a stated one: "
        f"{[p.source.line for p in got]}")
    assert [n.role for n in got[1].to_flow()] == ["source", "sanitizer", "sink"], (
        "the flow inside a path was reordered -- source/sanitizer/sink is the "
        "trace, not an arbitrary sequence")
