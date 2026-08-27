"""CAP engine runtime smoke test — plan fix #2, the experiment that was never run.

`cap_engine/` is a transcription from photographs of the original source. It was
verified statically (imports resolve, modules parse) but `ARCHITECTURE.md` §8.4
records that a full runtime import was never executed, and §8.5 flags the
tree-sitter query node-types as unverified against the installed grammar. Those
queries are the layer `profile/promote.py` sits directly on top of.

This module is that verification, kept as a regression guard. It also pins two
**known gaps** discovered by running it (see the final section) so that a future
CAP change is noticed rather than silently altering profiling behaviour.

Skips cleanly when CAP is not installed, so the suite stays green for anyone who
has not run `pip install -e cap_engine/'[tree-sitter]'`.
"""
from pathlib import Path

import pytest

# NOTE the import style. `from cap_engine import CAPFramework` — the style
# ARCHITECTURE.md §2.1 documents — raises ImportError when run from the repo
# root, because the repo contains a `cap_engine/` project directory with no
# __init__.py which PathFinder claims as a namespace package before the editable
# finder is consulted. Fully-qualified submodule imports are unaffected. Always
# import CAP this way; see test_import_style_guard below.
cap = pytest.importorskip(
    "cap_engine.environment.code_promoter",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

FIXTURE = Path(__file__).parent / "fixtures" / "sample_app"


@pytest.fixture(scope="module")
def cache():
    return cap.build_cache(str(FIXTURE))


def _symbols(cache, path):
    return {s.name: s for s in cache.structural_index[path]}


# --------------------------------------------------------------------------
# The core claim: tree-sitter parsing works against the installed grammar
# --------------------------------------------------------------------------

FIXTURE_FILES = {"app.py", "api.py", "models.py", "views.py"}


def test_parses_without_errors(cache):
    assert cache.parse_errors == []
    assert set(cache.all_files) == FIXTURE_FILES
    assert set(cache.file_languages.values()) == {"python"}


def test_structural_index_is_populated(cache):
    assert set(cache.structural_index) == FIXTURE_FILES
    assert _symbols(cache, "app.py").keys() >= {
        "public_index", "get_profile", "admin_export", "search", "_run_search",
    }


# --------------------------------------------------------------------------
# What promote.py needs: decorators, class structure, inheritance
# --------------------------------------------------------------------------

def test_decorators_are_captured_with_full_text(cache):
    """Flask endpoint extraction reads the route path and methods out of these."""
    syms = _symbols(cache, "app.py")
    assert syms["public_index"].decorators == ['@app.route("/public", methods=["GET"])']


def test_stacked_decorators_are_all_captured(cache):
    """A guarded endpoint carries both the route and the guard.

    If the proximity walk stopped at the first decorator, every Flask endpoint
    would look unguarded — the access-control matrix would be uniformly wrong in
    the direction that produces false positives.
    """
    syms = _symbols(cache, "app.py")
    assert set(syms["get_profile"].decorators) == {
        "@login_required", '@app.route("/profile/<uid>", methods=["GET"])',
    }
    assert "@login_required" not in syms["admin_export"].decorators


def test_methods_are_promoted_and_carry_their_class(cache):
    syms = cache.structural_index["models.py"]
    fetches = [s for s in syms if s.name == "fetch"]
    assert {s.parent for s in fetches} == {"BaseModel", "User", "Item"}
    assert {s.type for s in fetches} == {"method"}


def test_type_hierarchy_is_populated(cache):
    """Directly exercises the reconciliation fix in ARCHITECTURE.md §8.2.

    That fix claims the Python `base_class` query gained the `@parent` capture
    the extractor reads, "so the type hierarchy is populated rather than empty."
    Asserted rather than trusted.
    """
    assert cache.type_hierarchy["BaseModel"] == [
        ("models.py", "User"), ("models.py", "Item"),
    ]


# --------------------------------------------------------------------------
# What cpg.py needs: reachability scaffolding from the call graph
# --------------------------------------------------------------------------

def test_call_graph_exposes_the_source_to_sink_path(cache):
    """The planted SQLi is reachable in two hops from its endpoint."""
    fwd = cache.call_graph.forward
    assert "_run_search" in fwd["app.search"]
    assert "cursor.execute" in fwd["app._run_search"]


def test_call_graph_exposes_the_command_sink(cache):
    fwd = cache.call_graph.forward
    assert "_spawn" in fwd["api.run_task"]
    assert "subprocess.run" in fwd["api._spawn"]


# --------------------------------------------------------------------------
# KNOWN GAPS — pinned so a CAP change is noticed, not so they stay broken
# --------------------------------------------------------------------------

def test_known_gap_python_params_are_not_extracted(cache):
    """`Symbol.params` is empty for Python — the query set has no params capture.

    Consistent with CAP having been proven on Java (overview §9's "Python
    flagship gap"). It matters because FastAPI expresses authorization as
    `user=Depends(get_current_user)` in the **signature**, not as a decorator.

    Workaround for promote.py: `ParseCache._trees[path]` retains (tree, source),
    so a targeted tree-sitter query against the cached tree recovers signatures
    with no file I/O and no tokens. Do not "fix" this by re-reading files.
    """
    syms = _symbols(cache, "api.py")
    assert syms["list_items"].params == ""


def test_known_gap_depends_is_visible_but_unnamed(cache):
    """The call graph shows *that* an endpoint has a dependency, not *which*.

    `Depends(get_current_user)` yields the callee `Depends`; the dependency name
    is an argument, not a call, so it is not captured. Enough to distinguish
    guarded from unguarded (list_items vs get_item — the planted IDOR), not
    enough to name the guard. Same cached-tree workaround as above.
    """
    fwd = cache.call_graph.forward
    assert "Depends" in fwd["api.list_items"]
    assert "get_current_user" not in fwd["api.list_items"]
    assert "Depends" not in fwd.get("api.get_item", [])


def test_known_gap_attribute_chains_collapse_to_the_last_segment(cache):
    """`request.args.get(q)` is recorded as callee `get`, not `request.args.get`.

    Source detection therefore cannot match the `request.args` attribute
    patterns in profile/patterns/python.yaml against call-graph callees — cpg.py
    must match attribute chains against the cached tree instead.
    """
    assert "get" in cache.call_graph.forward["app.search"]
    assert "request.args.get" not in cache.call_graph.forward["app.search"]


def test_import_style_guard():
    """Fully-qualified imports work from any CWD; the bare form does not.

    `from cap_engine import CAPFramework` fails from the repo root only, which
    means it would pass in a unit test run from elsewhere and fail in the CLI.
    Pin the style that always works.
    """
    from cap_engine.config.framework import CAPConfig, CAPFramework
    from cap_engine.graph.server import CGPServer

    assert CAPFramework.__module__ == "cap_engine.config.framework"
    assert CAPConfig is not None and CGPServer is not None
