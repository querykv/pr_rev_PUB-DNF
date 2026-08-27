"""Framework extraction (`profile/promote.py`) against a hand-labelled fixture.

This is the M1 acceptance criterion in miniature: phase-1 §10 asks for an
integration test that profiles a deliberately-insecure Python app and asserts
the access-control matrix matches a hand-labelled key. The key lives in the
docstrings of `tests/fixtures/sample_app/*.py`; these tests are that key,
executable.
"""
import pytest

pytest.importorskip(
    "cap_engine.environment.code_promoter",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from pr_review.profile.patterns import CatalogNotFound, available, load_catalog  # noqa: E402
from pr_review.profile.promote import (  # noqa: E402
    _dep_names, _is_route_decorator, _kwarg_region, _methods_re, _receiver,
    _route_verbs, promote,
)

FIXTURE = "tests/fixtures/sample_app"

# The verb set the catalog is expected to yield. Passed to `_is_route_decorator`
# below so those cases pin the *catalog's* behaviour rather than a constant's.
VERBS = _route_verbs(load_catalog("python"))


@pytest.fixture(scope="module")
def result():
    return promote(FIXTURE)


def _by_symbol(result):
    return {e.symbol: e for e in result.endpoints}


# --------------------------------------------------------------------------
# Catalog loader
# --------------------------------------------------------------------------

def test_catalog_loads_and_lists():
    assert "python" in available()
    assert load_catalog("python")["language"] == "python"


def test_unknown_language_names_what_is_available():
    with pytest.raises(CatalogNotFound, match="python"):
        load_catalog("cobol")


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def test_framework_is_detected_per_file(result):
    """`@app.get` is valid Flask *and* valid FastAPI — the import disambiguates.

    Per-repo detection would mislabel every endpoint in a repo mid-migration.
    """
    assert result.frameworks == {
        "app.py": "flask", "api.py": "fastapi", "views.py": "django",
    }


def test_promotion_stats(result):
    assert result.stats["parse_errors"] == 0
    assert result.stats["endpoints"] == 11
    assert set(result.stats["frameworks"]) == {"flask", "fastapi", "django"}


# --------------------------------------------------------------------------
# Flask — guard is a stacked decorator
# --------------------------------------------------------------------------

def test_flask_routes_and_methods(result):
    eps = _by_symbol(result)
    assert eps["get_profile"].route == "/profile/<uid>"
    assert eps["get_profile"].http_methods == ["GET"]
    assert eps["admin_export"].http_methods == ["POST"]


def test_flask_guard_is_found_alongside_the_route_decorator(result):
    eps = _by_symbol(result)
    assert eps["get_profile"].guards == ["login_required"]
    assert eps["get_profile"].guard_kind == "decorator"
    assert eps["get_profile"].guarded is True


def test_flask_unguarded_endpoints_match_the_key(result):
    eps = _by_symbol(result)
    assert eps["public_index"].guarded is False
    assert eps["admin_export"].guarded is False   # the planted one


# --------------------------------------------------------------------------
# FastAPI — guard is an injected dependency, invisible to ParseCache
# --------------------------------------------------------------------------

def test_fastapi_dependency_guard_is_recovered_by_name(result):
    """Gaps 1 and 2 from the CAP smoke test, recovered from the cached tree.

    `Symbol.params` is empty and the call graph only records the callee
    `Depends`. Without reading the signature out of `ParseCache._trees`, every
    FastAPI endpoint would look unguarded.
    """
    ep = _by_symbol(result)["list_items"]
    assert ep.guards == ["get_current_user"]
    assert ep.guard_kind == "dependency"
    assert ep.guarded is True


def test_fastapi_verb_comes_from_the_decorator_name(result):
    eps = _by_symbol(result)
    assert eps["list_items"].http_methods == ["GET"]
    assert eps["run_task"].http_methods == ["POST"]


def test_fastapi_planted_idor_is_unguarded(result):
    ep = _by_symbol(result)["get_item"]
    assert ep.route == "/items/{iid}"
    assert ep.guarded is False


# --------------------------------------------------------------------------
# Django/DRF — three different ways to express a guard
# --------------------------------------------------------------------------

def test_django_permission_classes(result):
    ep = _by_symbol(result)["ReportView"]
    assert ep.guards == ["IsAuthenticated"]
    assert ep.guard_kind == "permission_classes"
    assert ep.guarded is True


def test_django_mixin_guard(result):
    ep = _by_symbol(result)["BillingView"]
    assert ep.guards == ["LoginRequiredMixin"]
    assert ep.guard_kind == "mixin"


def test_django_allow_any_is_an_explicit_opt_out(result):
    """`AllowAny` is not "no guard found" — it is a decision to remove one.

    Tracking it separately is what lets Phase 2 treat *adding* AllowAny to an
    existing view as the high-signal change it is.
    """
    ep = _by_symbol(result)["PublicView"]
    assert ep.opens_access is True
    assert ep.guarded is False


def test_django_view_with_no_declaration_is_unguarded(result):
    ep = _by_symbol(result)["LegacyView"]
    assert ep.guards == [] and ep.opens_access is False
    assert ep.guarded is False


def test_django_routes_are_left_unresolved_not_guessed(result):
    """urls.py resolution is deferred. An empty route is honest; a wrong one
    poisons the matrix."""
    for symbol in ("ReportView", "PublicView", "BillingView", "LegacyView"):
        assert _by_symbol(result)[symbol].route == ""


def test_django_http_methods_come_from_handler_names(result):
    eps = _by_symbol(result)
    assert eps["ReportView"].http_methods == ["GET"]
    assert eps["BillingView"].http_methods == ["POST"]


# --------------------------------------------------------------------------
# The whole key, in one assertion
# --------------------------------------------------------------------------

def test_unguarded_set_matches_the_hand_labelled_key(result):
    assert {e.symbol for e in result.unguarded()} == {
        "public_index",   # flask, no guard
        "admin_export",   # flask, planted: admin path, no guard
        "get_item",       # fastapi, planted IDOR
        "run_task",       # fastapi, command sink, no guard
        "PublicView",     # django, explicit AllowAny
        "LegacyView",     # django, nothing declared
    }


def test_non_framework_files_contribute_no_endpoints(result):
    assert "models.py" not in result.frameworks
    assert all(e.file != "models.py" for e in result.endpoints)


# --------------------------------------------------------------------------
# Route recognition is read from the catalog, not hardcoded
# --------------------------------------------------------------------------

def test_the_catalog_yields_the_verb_set_that_used_to_be_hardcoded():
    """The proof that making `endpoints.decorators` live changed no behaviour.

    Until 2026-08-08 `promote.py` matched routes against a literal
    `_ROUTE_VERBS` while the catalog declared `endpoints.decorators` and nothing
    read it (errata §14.24). The catalog's own MATCHING CONTRACT says decorators
    match by dotted suffix, so the receivers in `app.route` / `bp.route` were
    always decorative and the suffix set the catalog implies *is* that literal.
    This asserts the two are the same set, which is what let the switch be made
    without re-opening the 8,297-row measurement behind `_is_route_decorator`.

    If a framework is added whose route decorator introduces a new suffix, this
    fails — and it should. A new verb changes what counts as an endpoint, which
    is a measurement, not a catalog edit.
    """
    assert _route_verbs(load_catalog("python")) == frozenset(
        {"route", "get", "post", "put", "patch", "delete", "head", "options"})


def test_the_method_kwarg_regex_is_built_from_the_catalog():
    """`method_kwarg: methods` is Flask's, and it is read rather than hardcoded."""
    pattern = _methods_re(load_catalog("python"))
    assert pattern.search('@app.route("/x", methods=["GET", "POST"])').group(1)
    assert pattern.search('@app.route("/x")') is None


def test_a_framework_declaring_no_route_decorators_contributes_no_verbs():
    """Django declares `view_bases` and no `decorators`, and must not crash or
    widen the set. Its endpoints come from class bases, not from decorators."""
    catalog = load_catalog("python")
    assert "decorators" not in catalog["frameworks"]["django"]["endpoints"]
    assert _route_verbs({"frameworks": {"x": {"endpoints": {}}}}) == frozenset()
    assert _route_verbs({}) == frozenset()


# --------------------------------------------------------------------------
# A decorator can be verb-shaped without being a route
# --------------------------------------------------------------------------

@pytest.mark.parametrize("dec,is_route", [
    # Rejected: `unittest.mock.patch` targets, bare and qualified. Its last
    # segment is an HTTP verb and its argument is a dotted attribute path.
    ('@patch("saleor.plugins.manager.PluginsManager.notify")', False),
    ('@mock.patch("os.environ.get")', False),
    ('@patch("a.b.c", autospec=True)', False),
    # Long targets are written as implicitly-concatenated literals, so the first
    # string ends at a dot. Requiring a name after it left 68 of Saleor's 72
    # surviving rows still phantom — a prefix of an attribute path is no more a
    # URL than a whole one.
    ('@patch(\n    "saleor.graphql.product.bulk_mutations."\n'
     '    "product_bulk_delete.get_webhooks_for_event"\n)', False),

    # Kept: real routes, under any receiver name the catalog never enumerated.
    ('@app.get("/users")', True),
    ('@bp.post("/items/{iid}")', True),
    ('@blueprint.route("/x", methods=["GET"])', True),
    ('@router.patch("/orders/{id}")', True),

    # Kept: routes whose path this cannot read. Giving ground here is the
    # design — recall on these lands on Broken Access Control, the M3 flagship.
    ('@app.route()', True),                    # no argument at all
    ('@router.get(path=ROUTE_CONST)', True),   # path held in a variable
    ('@app.get(PREFIX + "/x")', True),         # first literal has a slash
    ('@app.route(rule=PATH, methods=["GET"])', True),  # first string is a verb
    ('@app.get("new-subscription")', True),    # no dot: not an attribute path
])
def test_a_verb_shaped_decorator_is_not_automatically_a_route(dec, is_route):
    """`@patch(...)` was read as a PATCH route, which made 46% of the corpus's
    access-control matrix rows mock targets rather than endpoints — 99.8% of
    Saleor's. The rejection is on positive evidence only, so every shape whose
    route is unreadable stays an endpoint."""
    assert _is_route_decorator(dec, VERBS) is is_route


def test_the_real_route_decorators_in_the_fixture_all_survive(result):
    """The guard against fixing the false positive by breaking extraction: the
    hand-labelled key must be unchanged, and it is asserted whole above — this
    pins the count so a silent partial loss cannot pass."""
    assert len(result.endpoints) >= 8
    assert {e.symbol for e in result.endpoints} >= {
        "public_index", "admin_export", "get_item", "run_task"}


# A test module in the shape that made 46% of the benchmark corpus's
# access-control matrix phantom, including the implicitly-concatenated form that
# survived the *first* attempt at the fix (errata §14.24). Written out here
# rather than added to `tests/fixtures/sample_app/`, because that fixture is a
# hand-labelled key asserted whole and this needs to be added and removed.
#
# THE FRAMEWORK IMPORT ON LINE 3 IS LOAD-BEARING. `extract_frameworks` skips any
# file `_detect_framework` finds no framework in, so a mock-heavy module that
# imports only `unittest.mock` contributes nothing and the assertion below
# passes no matter what `_is_route_decorator` does. The first draft of this test
# was exactly that, and was inert — verified by neutralizing the fix and
# watching the count stay at 11. Real test modules import the framework they
# exercise (`TestClient`, fixtures, the app itself), which is why Saleor's were
# 99.8% phantom, and the fixture has to do the same to reproduce it.
_MOCK_HEAVY = '''\
"""Mock-heavy tests: every decorator below is `unittest.mock.patch`."""
from fastapi.testclient import TestClient
from unittest import mock
from unittest.mock import patch


@patch("app.services.billing.charge")
def test_charge(m):
    pass


@mock.patch("app.services.mailer.send")
def test_send(m):
    pass


@patch(
    "app.graphql.product.bulk_mutations."
    "product_bulk_delete.get_webhooks_for_event"
)
def test_webhooks(m):
    pass


@patch.object(SomeClass, "method")
def test_object(m):
    pass


@patch("app.api.get")
@patch("app.api.post")
def test_stacked(a, b):
    pass
'''


def test_a_mock_heavy_test_module_adds_no_endpoints(tmp_path, result):
    """THE COUNT ASSERTION, END TO END — blind spot #4.

    `_is_route_decorator` is unit-tested above on decorator *strings*. That is
    not the property that broke: the access-control matrix was 46% mock targets
    for the entire life of the profile while all 31 of these tests passed,
    because the only fixture they run against contains no `@patch` at all and so
    *could not* contain the defect. What was missing was an assertion that the
    endpoint **count** does not move when such a file is present.

    Five `@patch` shapes, 6 decorators, 0 endpoints. If a future change to
    `_suffix()` or `_ROUTE_VERBS` re-admits them, this fails with a number
    rather than passing quietly.
    """
    import shutil

    app = tmp_path / "app"
    shutil.copytree(FIXTURE, app)
    shutil.rmtree(app / "__pycache__", ignore_errors=True)
    (app / "tests").mkdir()
    (app / "tests" / "test_services.py").write_text(_MOCK_HEAVY)

    with_mocks = promote(str(app))

    assert with_mocks.stats["endpoints"] == result.stats["endpoints"] == 11
    assert not [e for e in with_mocks.endpoints if "test_services" in e.file], (
        "a unittest.mock patch target was promoted to an endpoint")


# --------------------------------------------------------------------------
# FastAPI `dependencies=[...]` — the three places it can be declared
# --------------------------------------------------------------------------

# Written out here rather than added to `tests/fixtures/sample_app/` for the
# same reason `_MOCK_HEAVY` is: that fixture is a hand-labelled key asserted
# whole, by this module and by `test_cpg.py`, and this needs to be added without
# moving those counts.
#
# THE FRAMEWORK IMPORT IS LOAD-BEARING, as it was there — `_detect_framework`
# skips any file it finds no framework in, so a fixture that forgets it is
# silently inert and every assertion below passes no matter what the guards do.
# Falsified per errata §14.29 rather than assumed: with guard 3 neutralized this
# module fails, and again with guard 4 neutralized.
_DEPENDENCY_FORMS = '''\
"""FastAPI `dependencies=[...]`, in each place it can be declared.

Hand-labelled key:
    admin_stats     guarded    router_dependency  [verify_admin]
    public_ping     UNGUARDED  none
    submit_form     guarded    route_dependency   [verify_token]
    admin_purge     guarded    dependency         [verify_token, verify_admin]
    inherited_only  UNGUARDED  none               (include_router — deferred)
    ambiguous_router UNGUARDED none               (rebound at module level)
    declared_twice  guarded    dependency         [verify_admin]  (once, not twice)
    conditionally_bound UNGUARDED none           (bound inside an `if`)
"""
from fastapi import APIRouter, Depends, FastAPI


def verify_admin(): ...
def verify_token(): ...
def verify_queue(): ...
def verify_local(): ...


# Guarded where the router is built; every route bound to it inherits that.
guarded_router = APIRouter(prefix="/admin", dependencies=[Depends(verify_admin)])

# A second router in the same file with no guard of its own.
open_router = APIRouter(prefix="/public")

# NOT a router: built with the same keyword and decorating nothing. Nothing may
# be attributed to it, which is the property that makes the constructor scan
# safe without naming `APIRouter`. Never imported or run — only the parse matters.
task_queue = Celery("tasks", dependencies=[Depends(verify_queue)])


@guarded_router.get("/stats")
def admin_stats():
    return {}


@open_router.get("/ping")
def public_ping():
    return {}


@open_router.post("/submit", dependencies=[Depends(verify_token)])
def submit_form():
    return {}


@guarded_router.delete("/purge")
def admin_purge(user=Depends(verify_token)):
    return {}


# Rebound at module level: which construction `@twice.get` resolves to needs the
# assignment live at that line. Not guessed — dropped.
twice = APIRouter(dependencies=[Depends(verify_admin)])
twice = APIRouter()


@twice.get("/ambiguous")
def ambiguous_router():
    return {}


# The same dependency declared in two places is one role required twice.
@guarded_router.get("/both")
def declared_twice(user=Depends(verify_admin)):
    return {}


def _local_scope():
    # A function-local router REBINDING A MODULE-LEVEL NAME — the exact shape of
    # fastapi/tests/test_dependency_yield_scope.py, where a guardless
    # `app = FastAPI()` at module level coexists with two guarded
    # `app = FastAPI(dependencies=[...])` inside test bodies. Pooling by name
    # hands `open_router`'s endpoints a guard from another scope entirely.
    open_router = APIRouter(dependencies=[Depends(verify_local)])
    return open_router


# Bound inside a conditional. At runtime this really does bind a module-level
# name — and that is exactly why it is not read: if the branch is not taken the
# endpoint is unguarded, and reading it would mark it enforced on the strength of
# a binding that may never happen. Refusing costs a possible false missing-authz;
# accepting costs a suppressed one.
if _FEATURE_FLAG:
    conditional_router = APIRouter(dependencies=[Depends(verify_local)])


@conditional_router.get("/conditional")
def conditionally_bound():
    return {}


# The deferred form: the guard is on the *inclusion*, not on the router.
app = FastAPI()
included = APIRouter()


@included.get("/inherited")
def inherited_only():
    return {}


app.include_router(included, dependencies=[Depends(verify_admin)])
'''


@pytest.fixture(scope="module")
def dependency_forms(tmp_path_factory):
    import shutil

    app = tmp_path_factory.mktemp("depforms") / "app"
    shutil.copytree(FIXTURE, app)
    shutil.rmtree(app / "__pycache__", ignore_errors=True)
    (app / "routers.py").write_text(_DEPENDENCY_FORMS)
    return promote(str(app))


def test_a_router_level_dependency_guards_the_routes_bound_to_it(dependency_forms):
    """`router = APIRouter(dependencies=[...])` — `auth.router_kwarg`.

    Attribution is by the decorator's *receiver*, which is the only thing tying
    `@guarded_router.get` back to the assignment that built it.
    """
    ep = _by_symbol(dependency_forms)["admin_stats"]
    assert ep.guarded
    assert ep.guards == ["verify_admin"]
    assert ep.guard_kind == "router_dependency"


def test_a_second_router_in_the_same_file_does_not_inherit_the_first_ones_guard(
        dependency_forms):
    """The map is keyed by name, so a file with two routers must not pool them."""
    ep = _by_symbol(dependency_forms)["public_ping"]
    assert not ep.guarded
    assert ep.guards == []
    assert ep.guard_kind == "none"


def test_a_route_decorator_dependency_guards_that_route(dependency_forms):
    """`@open_router.post("/x", dependencies=[...])` — `auth.route_decorator_kwarg`.

    Bound to a router carrying no guard, so this can only have come from the
    decorator's own argument list.
    """
    ep = _by_symbol(dependency_forms)["submit_form"]
    assert ep.guarded
    assert ep.guards == ["verify_token"]
    assert ep.guard_kind == "route_dependency"


def test_a_non_router_built_with_the_same_kwarg_is_attributed_to_nothing(
        dependency_forms):
    """The discriminator is the attribution, not the constructor's name.

    `_router_guards` does map `task_queue` — it is deliberately name-agnostic —
    and that is harmless precisely because no route decorator names it as a
    receiver. If this fails, the scan is attributing by something other than the
    receiver and the name-agnostic design is unsafe.
    """
    assert not [e for e in dependency_forms.endpoints if "verify_queue" in e.guards]


def test_a_router_guard_does_not_relabel_an_endpoints_own(dependency_forms):
    """Broader never relabels narrower.

    `admin_purge` carries both: its own `Depends` in the signature and the
    router's. Both are real and both are recorded — but `guard_kind` feeds
    `_auth_pattern`, which reports `guard_kind:guards[0]` as what the matrix says
    the mechanism *is*, so the endpoint's own has to win.
    """
    ep = _by_symbol(dependency_forms)["admin_purge"]
    assert ep.guards == ["verify_token", "verify_admin"]
    assert ep.guard_kind == "dependency"


def test_include_router_dependencies_are_deliberately_not_read(dependency_forms):
    """Pins the deferral, so "unguarded" here stays a decision and not a bug.

    `app.include_router(included, dependencies=[...])` is a call, not an
    assignment, and in real code it is in whichever module assembles the app.
    Reaching for it would make every incremental run a splice violation while
    finding nothing on the partial cache. If this test starts failing, the
    cross-file design question in OPEN_ITEMS.md §8 has been answered by accident.
    """
    ep = _by_symbol(dependency_forms)["inherited_only"]
    assert not ep.guarded
    assert ep.guard_kind == "none"


def test_the_hand_labelled_key_does_not_move_when_the_new_forms_are_present(
        dependency_forms, result):
    """The guard against buying these guards with the existing ones."""
    assert dependency_forms.stats["endpoints"] == result.stats["endpoints"] + 8
    old = {e.symbol for e in result.unguarded()}
    still = {e.symbol for e in dependency_forms.unguarded() if "routers.py" not in e.file}
    assert still == old


# --------------------------------------------------------------------------
# The two shared parsers underneath those guards
# --------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("dependencies=[Depends(a)]", "Depends(a)"),
    # Balanced, not `[^\]]*`: the list holds calls, and a neighbouring kwarg
    # must not bleed in.
    ("dependencies=[Depends(a), Security(b)], responses={404: X}",
     "Depends(a), Security(b)"),
    ("prefix='/x', dependencies=[Depends(a)], tags=['t']", "Depends(a)"),
    ("dependencies = [ Depends(a) ]", " Depends(a) "),
    # A nested list inside the region.
    ("dependencies=[Depends(a), [Depends(b)]]", "Depends(a), [Depends(b)]"),
    ("tags=['dependencies']", ""),          # the word, not the keyword
    ("dependencies=[Depends(a)", ""),       # never closes — a truncated parse
    ("", ""),
])
def test_the_kwarg_region_is_bracket_balanced(text, expected):
    assert _kwarg_region(text, "dependencies") == expected


def test_no_kwarg_name_matches_nothing():
    """A framework declaring neither key must not fall through to a match."""
    assert _kwarg_region("dependencies=[Depends(a)]", "") == ""


@pytest.mark.parametrize("text,expected", [
    ("Depends(get_current_user)", ["get_current_user"]),
    ("user=Depends(auth.get_current_user)", ["get_current_user"]),   # by suffix
    ("Depends(a), Security(b)", ["a", "b"]),
    ("Depends()", []),
    ("MyDepends(a)", []),                                           # word boundary
    ("", []),
])
def test_dependency_names_are_read_in_source_order(text, expected):
    """Source order, not set-iteration order.

    The loop this replaced iterated a `set` of call names, and Python randomizes
    string hashes per process — so a signature carrying both `Depends` and
    `Security` could put either first, and `guards[0]` is what reaches the
    access-control matrix.
    """
    assert _dep_names(text, {"Depends", "Security"}) == expected


def test_dependency_names_with_no_call_names_configured():
    assert _dep_names("Depends(a)", set()) == []


@pytest.mark.parametrize("dec,expected", [
    ('@router.get("/x")', "router"),
    ('@app.post("/x")', "app"),
    ("@get", ""),                     # bare, module-level route decorator
    ('@api.v1.get("/x")', "api.v1"),  # no assignment binds this — misses, honestly
])
def test_the_receiver_is_what_attributes_a_router_guard(dec, expected):
    assert _receiver(dec) == expected


def test_a_name_rebound_at_module_level_is_dropped_rather_than_guessed(
        dependency_forms):
    """Over-attribution suppresses a `missing-authz` finding — the bad direction.

    `twice` is built once with a guard and once without. Resolving `@twice.get`
    to one of them needs the assignment live at the decorator's line; without
    that, giving it the guard marks an endpoint enforced on the strength of a
    binding that may already have been replaced.
    """
    ep = _by_symbol(dependency_forms)["ambiguous_router"]
    assert not ep.guarded
    assert ep.guards == []


def test_a_function_local_router_does_not_guard_module_level_endpoints(
        dependency_forms):
    """Found by the profile rebuild, not by review.

    The first draft pooled every `assignment` in the file by name. FastAPI's
    `test_dependency_yield_scope.py` has a module-level `app = FastAPI()` with no
    guard and two function-local `app = FastAPI(dependencies=[...])` inside test
    bodies — so real unguarded endpoints came back enforced.
    """
    assert not [e for e in dependency_forms.endpoints if "verify_local" in e.guards]
    assert not _by_symbol(dependency_forms)["public_ping"].guarded


def test_the_same_dependency_declared_twice_is_recorded_once(dependency_forms):
    """`required_roles` is a list of roles, not of enforcement points.

    `declared_twice` carries `verify_admin` from its router and again from its own
    signature. FastAPI's suite does exactly this with `oauth2_scheme`.
    """
    ep = _by_symbol(dependency_forms)["declared_twice"]
    assert ep.guards == ["verify_admin"]
    assert ep.guard_kind == "dependency"


def test_a_conditionally_bound_router_is_not_read(dependency_forms):
    """Syntactically module-level, and deliberately still not read.

    `if _FEATURE_FLAG: router = APIRouter(dependencies=[...])` binds a real
    module-level name, but only on the branch being taken. Reading it would mark
    the endpoint enforced on a binding that may never happen — a suppressed
    finding. Not reading it costs at most a false `missing-authz`, which is the
    direction this module gives ground in everywhere else.

    This is also the only shape that falsifies the module-level check on its own:
    for a function-local rebinding, the assigned-exactly-once rule catches it too.
    """
    ep = _by_symbol(dependency_forms)["conditionally_bound"]
    assert not ep.guarded
    assert ep.guards == []


# -- the catalog loader refuses what PyYAML would silently discard -----------

def test_a_duplicate_key_is_rejected_rather_than_silently_dropped():
    """`OPEN_ITEMS.md` §12. PyYAML's `safe_load` keeps the **last** of two
    identical keys and says nothing, so a stray second `calls:` deletes every
    pattern in the first one.

    This is not hypothetical. During a falsification pass the mutation added a
    second `calls:` intending to loosen a pattern, deleted it instead, the
    pinning test passed, and a live guard reported as INERT — a wrong conclusion
    drawn from a file that had quietly lost half its content.
    """
    from pr_review.profile.patterns import CatalogError, parse_catalog

    with pytest.raises(CatalogError) as exc:
        parse_catalog("sinks:\n  sql:\n    calls: [cursor.execute]\n"
                      "    calls: [db.query]\n")
    # The message has to locate it: a catalog is 300+ lines and "duplicate key"
    # without a line number is a search, not a diagnosis.
    assert "duplicate key 'calls'" in str(exc.value)
    assert "line 4" in str(exc.value)


def test_the_duplicate_check_reaches_nested_and_top_level_maps():
    """The failure that motivated this was nested three deep. A check that only
    looked at the document root would have passed it."""
    from pr_review.profile.patterns import CatalogError, parse_catalog

    with pytest.raises(CatalogError):
        parse_catalog("language: python\nlanguage: ruby\n")
    with pytest.raises(CatalogError):
        parse_catalog("a:\n  b:\n    c:\n      d: [1]\n      d: [2]\n")


def test_a_valid_catalog_still_loads_unchanged():
    """The loader rejects bad input; it must not change what a good catalog
    produces. This is why no `ANALYZER_VERSION` bump goes with it."""
    from pr_review.profile.patterns import load_catalog, parse_catalog

    cat = load_catalog("python")
    assert cat["language"] == "python"
    assert cat["sinks"] and cat["sources"]
    # Repeated keys in two *different* maps are not duplicates.
    assert parse_catalog("a:\n  calls: [1]\nb:\n  calls: [2]\n") == {
        "a": {"calls": [1]}, "b": {"calls": [2]}}
