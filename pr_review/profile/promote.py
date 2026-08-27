"""Code promotion — CAP's structural index plus Python framework extraction.

Wraps `cap_engine.environment.code_promoter.build_cache` (phase-1 §3) and adds
the layer CAP does not have: recognising Flask / FastAPI / Django endpoints and
the guards on them, so endpoints and authz are first-class rather than anonymous
functions. That is what makes the access-control matrix — the flagship Phase-1
artifact — derivable.

WHY THIS IS MORE THAN "HOOKS"
The plan (phase-1 §9) describes this file as wrapping `build_cache` with
"Python framework extraction hooks". Running CAP showed three gaps that make
hooks insufficient (all pinned in `tests/test_cap_smoke.py`):

  1. `Symbol.params` is empty for Python — the query catalog has no params
     capture. FastAPI puts authorization in the *signature*
     (`user=Depends(get_current_user)`), so this is load-bearing.
  2. `Depends(...)` reaches the call graph as the callee `Depends`; the
     dependency name is an argument, not a call, so it is lost.
  3. Attribute chains collapse to their last segment — `request.args.get(q)`
     records `get`.

So this module walks `ParseCache._trees[path]`, which retains `(tree, source)`
from the original parse. That keeps extraction at **zero file I/O and zero
tokens** — re-reading files would work and would quietly cost the token economy
Phase 1 exists to buy.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from pr_review.profile.patterns import load_catalog

# The HTTP verb set, which is HTTP and not a framework fact. Two things read it
# and neither is catalog business: `_methods_from` falls back to the decorator's
# own verb, and `_extract_class_endpoints` finds Django view methods by name
# (`def get(self, request)`). Route *recognition* is catalog-driven — see
# `_route_verbs` below — but "GET is a verb" is not a thing a catalog gets a vote
# on, and threading it through one would only invite a framework to disagree.
_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}

_STRING_RE = re.compile(r"""["']([^"']*)["']""")

# A dotted Python attribute path: `saleor.plugins.manager.PluginsManager.notify`.
# `unittest.mock.patch` takes one as its first argument, and its own last segment
# is an HTTP verb — so `@patch("a.b.c")` matched the route-verb set and every
# mocked call in a test suite was promoted to an unguarded PATCH endpoint.
#
# Measured across the corpus's cached profiles rather than estimated: **8,297 of
# 17,907 access-control matrix rows (46%) were mock targets**, 8,292 of them in
# test files, and 99.8% of Saleor's 8,038 rows. That matrix is what M3's BAC
# agent reads, so this was not a cosmetic miscount.
#
# THE DISCRIMINATOR IS THE ARGUMENT, NOT THE RECEIVER, and that choice is the
# whole design. Rejecting bare decorators (requiring `@app.get` over `@get`)
# looks tidier and is worse twice over: it still admits `@mock.patch`, and it
# drops frameworks that export module-level route decorators. Requiring the path
# to start with `/` is stricter and drops `@app.route()` with the path in a
# variable, plus Django's `(unresolved:...)` markers.
#
# So this rejects only on *positive evidence of not being a route*: a literal
# first string that is a dotted attribute path with no slash in it. Verified
# against the same 17,907 rows — it removes the 8,297 mock targets and touches
# neither the 8,685 real URL paths nor the 925 unresolved markers. Recall risk
# here lands on Broken Access Control, the M3 flagship family, which is why the
# rule is shaped to give ground rather than take it.
#
# The trailing `[\w.]*` rather than a required final identifier is not sloppiness
# — it is the case that a stricter first attempt missed. Long patch targets are
# written as implicitly-concatenated literals:
#
#     @patch(
#         "saleor.graphql.product.bulk_mutations."
#         "product_bulk_delete.get_webhooks_for_event"
#     )
#
# and `_first_string` sees only `"saleor.graphql.product.bulk_mutations."`, which
# ends at a dot. Requiring a name after the final dot left 68 of Saleor's 72
# surviving rows still phantom. A *prefix* of an attribute path is no more a URL
# than a whole one, and both still need the no-slash guard to get here.
_ATTR_PATH_RE = re.compile(r"^\w[\w.]*\.[\w.]*$")


@dataclass
class Endpoint:
    """One externally-reachable entry point and the guards found on it."""
    symbol: str
    file: str
    line: int
    end_line: int
    framework: str
    route: str = ""                  # "" when unresolved (Django urls.py — see note)
    http_methods: list[str] = field(default_factory=list)
    guards: list[str] = field(default_factory=list)
    # decorator | dependency | route_dependency | router_dependency | mixin |
    # permission_classes | none. The last two FastAPI kinds record *where* the
    # dependency was declared, which is the part a reviewer needs: a
    # `router_dependency` guards every route on that router, so removing it is a
    # different-sized change than removing one endpoint's own.
    guard_kind: str = "none"
    opens_access: bool = False       # an explicit opt-out (AllowAny, login_exempt)

    @property
    def guarded(self) -> bool:
        return bool(self.guards) and not self.opens_access


@dataclass
class PromotionResult:
    base_dir: Path
    cache: Any                       # cap_engine ParseCache
    endpoints: list[Endpoint] = field(default_factory=list)
    frameworks: dict[str, str] = field(default_factory=dict)   # file -> framework
    stats: dict = field(default_factory=dict)

    def unguarded(self) -> list[Endpoint]:
        return [e for e in self.endpoints if not e.guarded]


# ---------------------------------------------------------------------------
# Small parsers over decorator text
# ---------------------------------------------------------------------------

def _decorator_name(dec: str) -> str:
    """`@router.get("/x")` -> `router.get`."""
    return dec.lstrip("@").split("(", 1)[0].strip()


def _suffix(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]


def _first_string(dec: str) -> str:
    """The first string literal in the decorator — the route path, in practice.

    Not the same thing as "positional argument 0", which is what the catalog used
    to declare as `path_arg: 0` and no code ever read. Reading argument 0 properly
    means call-argument extraction the ParseCache does not provide, the same gap
    that defers Django's route tables in `_extract_class_endpoints`. The key was
    deleted rather than left declaring a precision this does not have.
    """
    m = _STRING_RE.search(dec)
    return m.group(1) if m else ""


def _route_verbs(catalog: dict) -> frozenset[str]:
    """Decorator suffixes that denote a route, read from the catalog.

    The catalog spells these with receivers — `app.route`, `bp.route`,
    `router.get` — and its own matching contract (`python.yaml`, MATCHING
    CONTRACT) says decorators match by **dotted suffix**. So the receiver was
    always decorative, and the suffix is the whole of what a route decorator has
    to have. Taking the suffix here is what the contract already promised, and it
    keeps the receiver-agnostic match that exists for a real reason: the catalog
    cannot enumerate every name someone binds a router to (`bp`, `blueprint`,
    `api`, `v1`).

    This replaces a hardcoded `_ROUTE_VERBS` that the catalog block sat next to
    and did not feed (errata §14.24). `tests/test_promote.py` pins the derived set
    against that literal, so the catalog is now load-bearing and provably says the
    same thing the constant did.
    """
    verbs: set[str] = set()
    for fw in (catalog.get("frameworks") or {}).values():
        for dec in ((fw.get("endpoints") or {}).get("decorators") or []):
            verbs.add(_suffix(dec))
    return frozenset(verbs)


def _methods_re(catalog: dict) -> re.Pattern:
    """The kwarg a framework carries its verb list in — Flask's `methods=[...]`."""
    kwargs = sorted({
        kw for fw in (catalog.get("frameworks") or {}).values()
        if (kw := ((fw.get("endpoints") or {}).get("method_kwarg")))
    })
    alternation = "|".join(re.escape(k) for k in kwargs) or r"(?!)"
    return re.compile(rf"(?:{alternation})\s*=\s*\[([^\]]*)\]")


def _receiver(dec: str) -> str:
    """`@router.get("/x")` -> `router`. A bare `@get(...)` has none.

    The receiver is decorative for *recognising* a route (`_route_verbs`), and
    load-bearing for *attributing* a router-level guard to one: the name here is
    what `_router_guards` keyed its map on. An attribute-path receiver
    (`@api.v1.get`) returns `api.v1`, which no module-level assignment binds, so
    it simply misses — the honest outcome rather than a guessed one.
    """
    name = _decorator_name(dec)
    return name.rsplit(".", 1)[0] if "." in name else ""


def _is_route_decorator(dec: str, verbs: frozenset[str]) -> bool:
    """Is this decorator a route, or merely verb-shaped? See `_ATTR_PATH_RE`."""
    if _suffix(_decorator_name(dec)) not in verbs:
        return False
    arg = _first_string(dec)
    return not (arg and "/" not in arg and _ATTR_PATH_RE.match(arg))


def _dep_names(text: str, dep_calls: set[str]) -> list[str]:
    """Names injected by a dependency call — `Depends(get_current_user)` -> `get_current_user`.

    One extractor for all three places FastAPI puts a dependency: the signature
    (`user=Depends(x)`), the route decorator (`dependencies=[Depends(x)]`) and
    the router construction (`APIRouter(dependencies=[Depends(x)])`). It was a
    loop inline in the signature guard; a second and third copy of this regex is
    exactly how the three would drift apart.

    Single alternation rather than a loop per call name so the names come back in
    **source order**. The loop form iterated a `set`, and Python randomizes string
    hashes per process, so an endpoint carrying both `Depends` and `Security`
    could put either one first — and `security_profile._auth_pattern` reports
    `guards[0]` into the access-control matrix. Same output as before wherever
    only one call name matches, which is every case in either corpus.
    """
    if not dep_calls:
        return []
    alternation = "|".join(re.escape(c) for c in sorted(dep_calls))
    return [_suffix(m.group(1)) for m in
            re.finditer(rf"\b(?:{alternation})\s*\(\s*([A-Za-z_][\w.]*)", text)]


def _kwarg_region(text: str, kwarg: str) -> str:
    """The contents of `kwarg=[ ... ]` from a call's argument text.

    Bracket-balanced rather than a `[^\\]]*` character class: the list holds
    calls, and `dependencies=[Depends(a)], responses={404: X}` must not bleed
    into the neighbouring keyword. Returns "" when the brackets do not close,
    which is what a truncated parse looks like.
    """
    if not kwarg:
        return ""
    m = re.search(rf"\b{re.escape(kwarg)}\s*=\s*\[", text)
    if m is None:
        return ""
    depth = 0
    for i in range(m.end() - 1, len(text)):
        if text[i] == "[":
            depth += 1
        elif text[i] == "]":
            depth -= 1
            if depth == 0:
                return text[m.end():i]
    return ""


def _methods_from(dec: str, verb: str, methods_re: re.Pattern) -> list[str]:
    """Flask carries verbs in `methods=[...]`; FastAPI in the decorator name.

    The fallback order is deliberately framework-agnostic, which is why the
    catalog's `method_from_decorator: true` was deleted rather than wired up:
    `_detect_framework` decides per *file* and a file can import both Flask and
    FastAPI, so a per-framework switch here would mislabel whichever one lost.
    Reading the kwarg first and the verb second is correct for both.
    """
    m = methods_re.search(dec)
    if m:
        return [v.strip().strip("\"'").upper() for v in m.group(1).split(",") if v.strip()]
    if verb in _HTTP_VERBS:
        return [verb.upper()]
    return ["GET"]          # bare @app.route defaults to GET, as Flask does


# ---------------------------------------------------------------------------
# Cached-tree access (the workaround for the three ParseCache gaps)
# ---------------------------------------------------------------------------

def _walk(node) -> Iterator[Any]:
    yield node
    for child in node.children:
        yield from _walk(child)


def _signatures(cache, path: str) -> dict[int, str]:
    """line -> parameter text, read from the tree CAP already parsed.

    `Symbol.params` is empty for Python (gap 1), and this is the zero-I/O way to
    get it back.
    """
    entry = getattr(cache, "_trees", {}).get(path)
    if entry is None:
        return {}
    tree, _source = entry
    out: dict[int, str] = {}
    for node in _walk(tree.root_node):
        if node.type == "function_definition":
            params = node.child_by_field_name("parameters")
            if params is not None:
                out[node.start_point[0] + 1] = params.text.decode("utf-8", "replace")
    return out


def _class_bodies(cache, path: str) -> dict[str, str]:
    """class name -> raw body text, for Django `permission_classes` (gap 1 again)."""
    entry = getattr(cache, "_trees", {}).get(path)
    if entry is None:
        return {}
    tree, _source = entry
    out: dict[str, str] = {}
    for node in _walk(tree.root_node):
        if node.type == "class_definition":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                out[name_node.text.decode("utf-8", "replace")] = node.text.decode(
                    "utf-8", "replace"
                )
    return out


def _router_guards(cache, path: str, kwarg: str, dep_calls: set[str]) -> dict[str, list[str]]:
    """name -> guards, for `router = APIRouter(dependencies=[Depends(verify)])`.

    Gap 2 one level up: the guard is an argument to the call that *builds* the
    router, and the call graph keeps callee names and drops their arguments. So
    this is the fourth walker over the tree CAP already parsed, the same zero-I/O
    shape as `_signatures` and `_class_bodies`.

    DELIBERATELY NAME-AGNOSTIC ABOUT THE CONSTRUCTOR. It does not look for
    `APIRouter` or `FastAPI`, and there is no catalog key naming them. The
    discriminator is the *attribution*, not the callee: this map is only ever
    consulted for a name that is the receiver of a route decorator, and an object
    whose name decorates routes is a router whatever it was built by. Matching on
    the constructor instead would enumerate names the catalog cannot know
    (`get_router()`, a factory, a subclass) and would still need this check to be
    safe — the same argument `_ATTR_PATH_RE` makes about receivers one level up.

    Scope is the file. `include_router(r, dependencies=[...])` puts the guard in
    whichever module assembles the app, and reaching across files would make
    every incremental run a splice violation while finding nothing on the partial
    cache — see the catalog comment on `router_kwarg` and OPEN_ITEMS.md §8.

    TWO NARROWINGS, BOTH MEASURED RATHER THAN ANTICIPATED. The first draft of
    this walked every `assignment` in the file and pooled them by name, and the
    profile rebuild caught it attributing a guard to endpoints that do not have
    one — the dangerous direction for an authz reader, because a false "guarded"
    silently removes a `missing-authz` finding.

      1. SYNTACTICALLY MODULE LEVEL. `fastapi/tests/test_dependency_yield_scope.py`
         binds a module-level `app = FastAPI()` with no guard, and two
         *function-local* `app = FastAPI(dependencies=[...])` inside test bodies.
         A local name is not the name a module-level decorator resolves, so the
         endpoints on the real `app` were being marked guarded by a variable in
         another scope. This also excludes a binding inside `if`/`try`, which
         *does* bind the name at runtime but only on the branch taken — reading it
         would mark an endpoint enforced by a construction that may never run.
      2. ASSIGNED EXACTLY ONCE. A name rebound at module level cannot be resolved
         to one construction without tracking which assignment was live at the
         decorator's line. Rather than guess, such a name is dropped entirely.

    Both give ground rather than take it, for the reason `_ATTR_PATH_RE` states
    one level up: over-attribution here *suppresses* a `missing-authz` finding,
    and recall risk on Broken Access Control is the expensive direction.

    THE TWO OVERLAP on the shape that found them — strip rule 1 and a
    function-local rebinding is still caught by rule 2, because it makes the name
    look assigned twice. Rule 1 is falsified on its own only by the conditional
    binding above, which is why `tests/test_promote.py` carries that case
    specifically. Neither needs a second pass over the source.
    """
    entry = getattr(cache, "_trees", {}).get(path)
    if entry is None or not kwarg or not dep_calls:
        return {}
    tree, _source = entry
    bindings: dict[str, int] = {}
    found: dict[str, list[str]] = {}
    for node in _walk(tree.root_node):
        if node.type != "assignment":
            continue
        # Module level: `module > expression_statement > assignment`. Anything
        # deeper is inside a function, a class or a conditional.
        parent = node.parent
        if parent is None or parent.type != "expression_statement":
            continue
        if parent.parent is None or parent.parent.type != "module":
            continue
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or left.type != "identifier":
            continue
        name = left.text.decode("utf-8", "replace")
        bindings[name] = bindings.get(name, 0) + 1
        if right is None or right.type != "call":
            continue
        args = right.child_by_field_name("arguments")
        if args is None:
            continue
        names = _dep_names(_kwarg_region(args.text.decode("utf-8", "replace"), kwarg),
                           dep_calls)
        if names:
            found.setdefault(name, []).extend(names)
    return {name: guards for name, guards in found.items() if bindings[name] == 1}


def _source_of(cache, path: str) -> str:
    entry = getattr(cache, "_trees", {}).get(path)
    return entry[1].decode("utf-8", "replace") if entry else ""


# ---------------------------------------------------------------------------
# Framework detection — per file, not per repo
# ---------------------------------------------------------------------------

def _detect_framework(source: str, catalog: dict) -> str:
    """Which framework a file uses, decided by its imports.

    Per-file rather than per-repo because `@app.get` is valid Flask *and* valid
    FastAPI; the import is what disambiguates. A repo running both (common
    during a migration) would otherwise have every endpoint mislabelled.
    """
    best = ""
    for name, fw in catalog.get("frameworks", {}).items():
        for marker in fw.get("detect", []):
            if re.search(rf"^\s*(?:from|import)\s+{re.escape(marker)}\b", source, re.M):
                # django/rest_framework beats starlette-style generic markers
                if not best or name == "django":
                    best = name
    return best


# ---------------------------------------------------------------------------
# Per-framework extraction
# ---------------------------------------------------------------------------

def _auth_names(fw_cfg: dict) -> tuple[set[str], set[str]]:
    auth = fw_cfg.get("auth", {}) or {}
    guards = set(auth.get("decorators", []) or [])
    guards |= set(auth.get("mixins", []) or [])
    guards |= set(auth.get("dependency_names", []) or [])
    perms = auth.get("permission_classes", {}) or {}
    guards |= set(perms.get("enforcing", []) or [])
    opening = set(auth.get("opt_out_decorators", []) or [])
    opening |= set(perms.get("opening", []) or [])
    return guards, opening


def _extract_function_endpoints(cache, path, framework, fw_cfg, catalog,
                                verbs, methods_re) -> list[Endpoint]:
    """Flask and FastAPI: the route is a decorator on a function.

    `verbs` and `methods_re` come from the catalog and are computed once by
    `extract_frameworks` — recompiling a regex per file would be the only cost of
    reading them here instead.
    """
    guard_names, opening_names = _auth_names(fw_cfg)
    auth_cfg = fw_cfg.get("auth", {}) or {}
    dep_calls = set(auth_cfg.get("dependency_calls", []) or [])
    route_kwarg = auth_cfg.get("route_decorator_kwarg", "") or ""
    routers = _router_guards(cache, path, auth_cfg.get("router_kwarg", "") or "", dep_calls)
    sigs = _signatures(cache, path)
    endpoints: list[Endpoint] = []

    for sym in cache.structural_index.get(path, []):
        if sym.type not in ("function", "method") or not sym.decorators:
            continue
        route_dec = next((d for d in sym.decorators if _is_route_decorator(d, verbs)), None)
        if route_dec is None:
            continue

        verb = _suffix(_decorator_name(route_dec))
        ep = Endpoint(
            symbol=sym.name, file=path, line=sym.line, end_line=sym.end_line,
            framework=framework, route=_first_string(route_dec),
            http_methods=_methods_from(route_dec, verb, methods_re),
        )

        # Guard 1: a decorator on the same function.
        for dec in sym.decorators:
            name = _suffix(_decorator_name(dec))
            if name in guard_names:
                ep.guards.append(name)
                ep.guard_kind = "decorator"
            elif name in opening_names:
                ep.opens_access = True

        # Guard 2: an injected dependency in the signature (FastAPI).
        # This is gap 1 + gap 2 — unreachable from Symbol.params or the call
        # graph, recovered from the cached tree.
        for name in _dep_names(sigs.get(sym.line, ""), dep_calls):
            ep.guards.append(name)
            ep.guard_kind = "dependency"

        # Guards 3 and 4 are the same `Depends(...)` declared somewhere other than
        # the signature, and share three rules:
        #
        #   - A BROADER GUARD NEVER RELABELS A NARROWER ONE. Both append, but only
        #     claim `guard_kind` if nothing more specific did:
        #     `security_profile._auth_pattern` reports `guard_kind:guards[0]`, and
        #     that string is what the matrix says the mechanism *is*.
        #   - A NAME ALREADY RECORDED IS SKIPPED. `required_roles` is
        #     `list(ep.guards)`, so one role required twice is not two roles —
        #     FastAPI's suite has `APIRouter(dependencies=[Security(oauth2_scheme,
        #     ...)])` over an endpoint that also takes `Depends(oauth2_scheme)`.
        #     Confined to these two guards, so no row the older ones produce can
        #     move underneath this change.
        #   - ANY dependency counts, as in guard 2; neither requires the name to
        #     be in `auth.dependency_names`. A stricter standard here than in the
        #     signature would put an arbitrary difference into the matrix.

        # Guard 3: on the route decorator — `@router.post("/x", dependencies=[...])`.
        # No tree walk: `Symbol.decorators` carries the decorator's arguments,
        # which is the same property `_first_string` reads the route path out of.
        for name in _dep_names(_kwarg_region(route_dec, route_kwarg), dep_calls):
            if name in ep.guards:
                continue
            ep.guards.append(name)
            if ep.guard_kind == "none":
                ep.guard_kind = "route_dependency"

        # Guard 4: on the router this route is bound to, by receiver name.
        for name in routers.get(_receiver(route_dec), []):
            if name in ep.guards:
                continue
            ep.guards.append(name)
            if ep.guard_kind == "none":
                ep.guard_kind = "router_dependency"

        endpoints.append(ep)
    return endpoints


def _extract_class_endpoints(cache, path, framework, fw_cfg, catalog) -> list[Endpoint]:
    """Django/DRF: the view is a class; the guard is a mixin or a class attribute.

    The route path is deliberately left empty. Resolving it means reading the
    `path()` / `re_path()` tables in `urls.py` and matching their view argument
    back to this class — real work, and it needs call-argument extraction the
    ParseCache does not provide either. Deferred rather than guessed: an empty
    route is honest, a wrong one poisons the matrix.
    """
    guard_names, opening_names = _auth_names(fw_cfg)
    view_bases = set((fw_cfg.get("endpoints", {}) or {}).get("view_bases", []) or [])
    attr_names = (fw_cfg.get("auth", {}) or {}).get("class_attributes", []) or []
    bodies = _class_bodies(cache, path)
    source = _source_of(cache, path)
    endpoints: list[Endpoint] = []

    for sym in cache.structural_index.get(path, []):
        if sym.type != "class":
            continue
        # Read the base list straight from the source line — type_hierarchy maps
        # base -> children and would need inverting, and mixins matter here.
        m = re.search(rf"^\s*class\s+{re.escape(sym.name)}\s*\(([^)]*)\)", source, re.M)
        bases = [b.strip() for b in m.group(1).split(",")] if m else []
        if not (view_bases & set(bases)):
            continue

        ep = Endpoint(
            symbol=sym.name, file=path, line=sym.line, end_line=sym.end_line,
            framework=framework,
            http_methods=sorted(
                s.name.upper() for s in cache.structural_index.get(path, [])
                if s.parent == sym.name and s.name in _HTTP_VERBS
            ),
        )

        for base in bases:
            if base in guard_names:
                ep.guards.append(base)
                ep.guard_kind = "mixin"

        body = bodies.get(sym.name, "")
        for attr in attr_names:
            am = re.search(rf"^\s*{re.escape(attr)}\s*=\s*\[([^\]]*)\]", body, re.M)
            if not am:
                continue
            for entry in (e.strip() for e in am.group(1).split(",") if e.strip()):
                name = _suffix(entry.split("(", 1)[0])
                if name in opening_names:
                    ep.opens_access = True
                elif name in guard_names:
                    ep.guards.append(name)
                    ep.guard_kind = "permission_classes"

        endpoints.append(ep)
    return endpoints


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def extract_frameworks(cache, base_dir: str | Path, language: str = "python",
                       paths: list[str] | None = None) -> PromotionResult:
    """Extract the framework surface from an already-parsed `ParseCache`.

    Split out from `promote()` so the incremental updater
    (`profile/incremental.py`) can run the same extraction over a cache holding
    only the files a PR touched. The alternative — a second copy of this loop —
    would let the full and incremental paths disagree about what an endpoint is,
    which is the one thing that must never differ between them.

    `paths` limits extraction to a subset; None means every parsed file.
    """
    catalog = load_catalog(language)
    verbs = _route_verbs(catalog)
    methods_re = _methods_re(catalog)
    result = PromotionResult(base_dir=Path(base_dir), cache=cache)
    wanted = set(paths) if paths is not None else None

    for path in sorted(cache.structural_index):
        if wanted is not None and path not in wanted:
            continue
        if cache.file_languages.get(path) != language:
            continue
        framework = _detect_framework(_source_of(cache, path), catalog)
        if not framework:
            continue
        result.frameworks[path] = framework
        fw_cfg = catalog["frameworks"][framework]
        result.endpoints.extend(
            _extract_function_endpoints(cache, path, framework, fw_cfg, catalog,
                                        verbs, methods_re)
        )
        result.endpoints.extend(
            _extract_class_endpoints(cache, path, framework, fw_cfg, catalog)
        )

    result.stats = {
        "files_parsed": len(cache.structural_index) if wanted is None else len(wanted),
        "parse_errors": len(cache.parse_errors),
        "endpoints": len(result.endpoints),
        "unguarded_endpoints": len(result.unguarded()),
        "frameworks": sorted(set(result.frameworks.values())),
    }
    return result


def promote(base_dir: str | Path, language: str = "python", config: dict | None = None
            ) -> PromotionResult:
    """Parse `base_dir` and extract its framework surface.

    Import style note: CAP is imported by fully-qualified submodule path. From
    the repo root `from cap_engine import ...` resolves the project *directory*
    as a namespace package and never runs `__init__.py` — see
    `tests/test_cap_smoke.py::test_import_style_guard`.
    """
    from cap_engine.environment.code_promoter import build_cache

    base_dir = Path(base_dir)
    cache = build_cache(str(base_dir), config)
    return extract_frameworks(cache, base_dir, language)
