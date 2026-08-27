"""Security CPG overlay + taint-lite (`profile/cpg.py`).

Asserts against the planted vulnerabilities in `tests/fixtures/sample_app/`:
a SQLi reachable from `/search`, a command injection reachable from `/run`, an
IDOR on `/items/{iid}`, and sensitive fields on `User`.
"""
import pytest

pytest.importorskip(
    "cap_engine.environment.code_promoter",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from pr_review.profile.cpg import _field_matches, _matches, build_cpg  # noqa: E402
from pr_review.profile.promote import promote  # noqa: E402


@pytest.fixture(scope="module")
def cpg():
    return build_cpg(promote("tests/fixtures/sample_app"))


# --------------------------------------------------------------------------
# Matchers
# --------------------------------------------------------------------------

@pytest.mark.parametrize("found,pattern,hit", [
    ("cursor.execute", "cursor.execute", True),
    ("conn.cursor.execute", "cursor.execute", True),
    ("subprocess.run", "subprocess.run", True),
    ("mycursor_execute", "cursor.execute", False),
    ("execute", "cursor.execute", False),
])
def test_dotted_suffix_matching(found, pattern, hit):
    assert _matches(found, pattern) is hit


def test_compiling_a_regex_is_not_executing_code():
    """`re.compile` matched the `compile` builtin by dotted suffix and was
    reported as a code-execution sink on real PRs
    (`benchmark/results/2026-08-07/analysis.md` §3).

    Asserted against the catalog rather than the removed line, so re-adding
    `compile` anywhere in `code_exec` fails here rather than in production.
    `eval` and `exec` must survive: they are what actually executes, and a
    catalog edit that dropped them would otherwise pass this test silently.

    Reads **both** lists, because 2026-08-09 moved `eval`/`exec` from `calls`
    to `exact_calls` and this test failed — correctly. It is asking "can the
    catalog still see these", not "which list are they in", and pinning the
    list would make it fail again on the next honest move.
    """
    from pr_review.profile.patterns import load_catalog

    cfg = load_catalog("python")["sinks"]["code_exec"]
    exact = set(cfg.get("exact_calls") or [])
    exec_calls = list(cfg["calls"]) + sorted(exact)

    def hit(found):
        return any(_matches(found, p, exact=p in exact) for p in exec_calls)

    assert not hit("re.compile")
    assert hit("eval")
    assert hit("exec")
    # The dot boundary already keeps the safe parser out; keep proving it.
    assert not hit("ast.literal_eval")


@pytest.mark.parametrize("name,term,hit", [
    ("password_hash", "password", True),        # exact matching would miss this
    ("credit_card_number", "credit_card", True),
    ("user_email", "email", True),
    ("ssn", "ssn", True),
    ("tokenizer", "token", False),              # substring matching would hit this
])
def test_sensitive_field_segment_matching(name, term, hit):
    assert _field_matches(name, term) is hit


# --------------------------------------------------------------------------
# Layers 1+2 — symbols and calls
# --------------------------------------------------------------------------

def test_method_symbols_are_qualified_by_class(cpg):
    """Four Django views each define `get`. Unqualified they collapse to one
    node, and they stop joining against CAP's call graph, which keys methods as
    `{stem}.{Class}.{method}`."""
    names = {n.name for n in cpg.nodes_of_kind("symbol")}
    assert {"views.ReportView.get", "views.PublicView.get", "views.LegacyView.get",
            "views.BillingView.post"} <= names
    assert "views.get" not in names


def test_call_edges_are_resolved_to_local_symbols(cpg):
    calls = {(a.name, b.name) for a, b, _ in cpg.edges("calls")}
    assert ("app.search", "app._run_search") in calls
    assert ("api.run_task", "api._spawn") in calls


# --------------------------------------------------------------------------
# Layer 3 — security nodes
# --------------------------------------------------------------------------

def test_sources_come_from_attribute_chains(cpg):
    """Gap 3: the call graph records `get`, not `request.args`. Without the
    cached-tree scan there would be no sources at all."""
    sources = {(n.file, n.name) for n in cpg.nodes_of_kind("source")}
    assert ("app.py", "request.args") in sources
    assert ("api.py", "request.json") in sources


def test_sinks_are_classified(cpg):
    sinks = {(n.name, n.attrs["sink_class"]) for n in cpg.nodes_of_kind("sink")}
    assert ("cursor.execute", "sql") in sinks
    assert ("subprocess.run", "command") in sinks
    assert ("logger.info", "log") in sinks


def test_sensitive_fields_are_found_and_owned(cpg):
    """Assigned names are not in `structural_index` at all — these come from the
    tree scan, same workaround as sources."""
    found = {n.name: (n.attrs["classification"], n.attrs["owner"])
             for n in cpg.nodes_of_kind("sensitive_field")}
    assert found == {
        "email": ("pii", "User"),
        "password_hash": ("credential", "User"),
        "ssn": ("pii", "User"),
    }


def test_guards_edges_point_at_endpoints(cpg):
    guarded = {b.name for _a, b, _r in cpg.edges("guards")}
    assert {"get_profile", "search", "list_items", "ReportView", "BillingView"} == guarded


def test_every_endpoint_is_linked_to_implementing_code(cpg):
    """A Django view is a class, not a symbol node — its handlers are. An
    endpoint with no `implements` edge is unreachable for taint analysis."""
    linked = {a.name for a, _b, _r in cpg.edges("implements")}
    assert linked == {n.name for n in cpg.nodes_of_kind("endpoint")}


def test_unguarded_endpoints_match_the_key(cpg):
    assert {n.name for n in cpg.unguarded_endpoints()} == {
        "public_index", "admin_export", "get_item", "run_task",
        "PublicView", "LegacyView",
    }


# --------------------------------------------------------------------------
# Layer 4 — taint-lite
# --------------------------------------------------------------------------

def test_planted_sqli_is_reachable(cpg):
    sql = cpg.paths_to("sql")
    assert len(sql) == 1
    path = sql[0]
    assert path.source.name == "request.args"
    assert path.sink.name == "cursor.execute"
    assert path.symbols == ["app.search", "app._run_search"]
    assert path.sanitized_by == []


def test_planted_command_injection_is_reachable(cpg):
    cmd = cpg.paths_to("command")
    assert len(cmd) == 1
    assert cmd[0].source.name == "request.json"
    assert cmd[0].symbols == ["api.run_task", "api._spawn"]


def test_taint_requires_a_call_path_not_just_co_location(cpg):
    """`_dump_all` holds the same sink but no source reaches it — the sink is in
    `admin_export`'s call tree, not in any tainted one. A CPG that connected
    every source to every sink would report it, and the verifier would burn
    tokens refuting it."""
    reached = {s for p in cpg.taint_paths for s in p.symbols}
    assert "app._dump_all" not in reached


def test_taint_paths_project_onto_the_finding_schema(cpg):
    """`Finding.data_flow` is the consumer (cross-cutting §1)."""
    flow = cpg.paths_to("sql")[0].to_flow()
    assert [f.role for f in flow] == ["source", "sink"]
    assert flow[0].file == "app.py" and flow[0].note == "request.args"
    assert "sql" in flow[-1].note


def test_stats_shape(cpg):
    stats = cpg.stats()
    assert stats["taint_paths"] == 2
    assert stats["nodes"]["endpoint"] == 11
    assert stats["edges"]["taints"] == 2


# --------------------------------------------------------------------------
# `exact_calls` — patterns whose receiver turned out to be unbounded
# --------------------------------------------------------------------------

# Every call below was a live catalog match under the dotted-suffix rule, and
# every one of them is something else. Counts are the measured populations over
# the 41 cached CPGs (`BENCHMARK_STATUS.md` §4g), which is what decided the
# shortlist — `urlparse` and `bindparam` are single-segment too and stayed on
# the suffix rule because their dotted forms are correct.
#
# Written into a `tmp_path` copy rather than `tests/fixtures/sample_app/`,
# following `test_promote.py:_MOCK_HEAVY`: sample_app is a hand-labelled key
# asserted whole, and `test_stats_shape` above pins its node counts exactly.
_RECEIVER_COLLISIONS = '''\
"""Receivers that used to collide with single-segment catalog patterns."""
import html
import re
import sqlalchemy as sa
import urllib.parse
from markupsafe import escape
from sqlalchemy import text


def collisions(session, c, request, part, proc, broker, value):
    session.exec(value)          # SQLModel: a SQL call. 20/20 `exec` nodes.
    c.eval(value)                # 199 of 340 `eval` nodes. Not the builtin.
    request.text()               # an HTTP response body, reported as SQL.
    part.text()                  # a Qt widget accessor, reported as SQL.
    proc.poll()                  # Popen liveness, read as untrusted input.
    broker.consume(value)        # 15/27 `consume` nodes were `self.consume`.
    return re.escape(value)      # 1,036 of 1,344 `escape` SANITIZER nodes.


def still_live(conn, jinja_env, tar, folder, value):
    conn.execute(sa.text(value))   # the aliased spelling: 1,557 real nodes
    conn.execute(text(value))      # bare, `from sqlalchemy import text`
    exec(value)                    # the builtin, still a sink
    eval(value)                    # the builtin, still a sink
    escape(value)                  # bare markupsafe escape, still a sanitizer
    html.escape(value)             # dotted and correct, still a sanitizer
    urllib.parse.urlparse(value)   # dotted sanitizer that must NOT regress
    sa.bindparam(value)            # dotted sanitizer that must NOT regress
    jinja_env.from_string(value)   # dotted template sink that must NOT regress
    tar.extractall(folder)         # the corpus's one true positive
'''


@pytest.fixture(scope="module")
def receivers(tmp_path_factory):
    """`build_cpg` over sample_app plus the collision module."""
    import shutil

    app = tmp_path_factory.mktemp("receivers") / "app"
    shutil.copytree("tests/fixtures/sample_app", app)
    shutil.rmtree(app / "__pycache__", ignore_errors=True)
    (app / "receivers.py").write_text(_RECEIVER_COLLISIONS)

    graph = build_cpg(promote(str(app)))
    return {(n.kind, n.name)
            for kind in ("sink", "source", "sanitizer")
            for n in graph.nodes_of_kind(kind)
            if n.file.endswith("receivers.py")}


@pytest.mark.parametrize("kind,name", [
    ("sink", "session.exec"),        # SQLModel, not code execution
    ("sink", "c.eval"),              # not the eval builtin
    ("sink", "request.text"),        # an HTTP body, not SQLAlchemy's text()
    ("sink", "part.text"),           # a Qt accessor
    ("source", "proc.poll"),         # Popen.poll(), at trust:high
    ("source", "broker.consume"),
    ("sanitizer", "re.escape"),      # the one that DELETED findings
])
def test_receiver_collisions_are_not_matched(receivers, kind, name):
    assert (kind, name) not in receivers, (
        f"{name} is still read as a {kind}; the suffix rule is back")


@pytest.mark.parametrize("kind,name", [
    ("sink", "sa.text"),                    # 1,557 real nodes ride on this
    ("sink", "text"),
    ("sink", "exec"),
    ("sink", "eval"),
    ("sanitizer", "escape"),
    ("sanitizer", "html.escape"),
    ("sanitizer", "urllib.parse.urlparse"),  # must NOT regress
    ("sanitizer", "sa.bindparam"),           # must NOT regress
    ("sink", "jinja_env.from_string"),       # must NOT regress
    ("sink", "tar.extractall"),              # must NOT regress
])
def test_real_call_sites_survive_the_narrowing(receivers, kind, name):
    assert (kind, name) in receivers, (
        f"{name} stopped being a {kind}; the narrowing cut real coverage")


def test_a_pattern_cannot_be_declared_both_ways():
    """Silent precedence is the defect `exact_calls` exists to fix.

    Found while falsifying: moving `text` back into `calls` without taking it
    out of `exact_calls` left it exact, so the mutation looked inert and the
    guard looked untested. A catalog whose matching rule depends on which list
    was read last is the same class of problem as `text` matching
    `request.text` — invisible at the place someone would look.
    """
    from pr_review.profile.cpg import _call_patterns

    catalog = {"sinks": {"sql": {"calls": ["text"], "exact_calls": ["text"]}}}
    with pytest.raises(ValueError, match="both `calls` and `exact_calls`"):
        _call_patterns(catalog)


def test_exact_mode_is_what_separates_them():
    """The unit contract, so a failure upstairs is readable.

    `sa.text` has to be listed literally in the catalog because dotted-suffix
    cannot resolve `import sqlalchemy as sa`: the found string ends with
    `.text`, not with `.sqlalchemy.text`.
    """
    assert _matches("session.exec", "exec") is True          # the old rule
    assert _matches("session.exec", "exec", exact=True) is False
    assert _matches("exec", "exec", exact=True) is True
    assert _matches("sa.text", "sqlalchemy.text") is False   # why the alias is listed
    assert _matches("sa.text", "sa.text", exact=True) is True
