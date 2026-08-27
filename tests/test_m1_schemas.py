"""M1 CAP-independent slice: profile/change contracts, pattern catalog, config.

Deliberately imports no `cap_engine` and makes no model calls — this is the part
of M1 that is buildable and testable before the CAP smoke test lands.
"""
from pathlib import Path

import pytest
import yaml

import pr_review
from pr_review.change.schema import (
    AnnotatedChangeSet,
    ChangeGroup,
    ContextBundle,
    DropRecord,
)
from pr_review.config import Config
from pr_review.profile.schema import (
    AccessControlRow,
    AuthzModel,
    ProjectProfile,
    Role,
)
from pr_review.schema import Severity
from typing import get_args

from pr_review.profile.schema import SinkClass

PATTERNS = Path(pr_review.__file__).parent / "profile" / "patterns" / "python.yaml"


# --------------------------------------------------------------------------
# ProjectProfile
# --------------------------------------------------------------------------

def _profile() -> ProjectProfile:
    return ProjectProfile(
        repo="o/r",
        profile_version="abc123",
        roles=[Role(name="admin"), Role(name="user")],
        authorization=AuthzModel(model="rbac", default_posture="deny"),
        access_control_matrix=[
            AccessControlRow(endpoint="/users/{id}", http_method="GET",
                             controller="UserView", required_roles=["user"],
                             auth_pattern="decorator:login_required",
                             enforcement="enforced"),
            AccessControlRow(endpoint="/admin/export", http_method="POST",
                             controller="AdminView", required_roles=["admin"],
                             auth_pattern="none", enforcement="declared_not_enforced"),
            AccessControlRow(endpoint="/health", http_method="GET",
                             controller="HealthView", enforcement="none"),
        ],
    )


def test_profile_roundtrip():
    p = _profile()
    again = ProjectProfile.model_validate_json(p.model_dump_json())
    assert again.profile_version == "abc123"
    assert again.authorization.model == "rbac"
    assert len(again.access_control_matrix) == 3


def test_profile_defaults_are_safe():
    """A bare profile must not claim enforcement it hasn't proven."""
    p = ProjectProfile(repo="o/r", profile_version="x")
    assert p.authorization.model == "unknown"
    assert p.authorization.default_posture == "unknown"
    assert p.build_kind == "full"
    assert p.access_control_matrix == []


def test_unguarded_endpoints_includes_declared_not_enforced():
    """`declared_not_enforced` is the higher-signal case — intent is on record."""
    rows = _profile().unguarded_endpoints()
    endpoints = {r.endpoint for r in rows}
    assert endpoints == {"/admin/export", "/health"}
    assert _profile().endpoints() == ["/admin/export", "/health", "/users/{id}"]


# --------------------------------------------------------------------------
# Change analysis
# --------------------------------------------------------------------------

def test_changeset_roundtrip_and_family_routing():
    cs = AnnotatedChangeSet(
        repo="o/r", pr_number=7, base_sha="b", head_sha="h",
        profile_version="abc123",
        groups=[
            ChangeGroup(id="g1", kind="security", files=["app/views.py"],
                        hunk_ids=["f1:h1"], touches=["endpoint", "authz"],
                        candidate_families=["Broken Access Control"],
                        projected_severity=Severity.HIGH, confidence=7,
                        significant=True, rationale="adds endpoint without a guard"),
            ChangeGroup(id="g2", kind="quality", files=["README.md"]),
        ],
        dropped=[DropRecord(path="docs/x.md", reason="docs_only")],
    )
    again = AnnotatedChangeSet.model_validate_json(cs.model_dump_json())
    assert again.planned_families() == {"Broken Access Control"}
    assert again.groups[1].projected_severity == Severity.INFO
    assert again.dropped[0].guardrail_considered is True


def test_drop_record_requires_a_reason():
    """Every drop is auditable — the filter is the #1 false-negative risk."""
    with pytest.raises(Exception):
        DropRecord(path="app/x.py")


def test_context_bundle_defaults_to_bounded_context():
    """No full-file access without an explicit escalation decision."""
    b = ContextBundle(group_id="g1")
    assert b.escalation == "none"
    assert b.enclosing_symbols == [] and b.neighbors == []
    assert not hasattr(b, "full_file")


# --------------------------------------------------------------------------
# Pattern catalog
# --------------------------------------------------------------------------

def test_pattern_catalog_loads():
    data = yaml.safe_load(PATTERNS.read_text())
    assert data["language"] == "python"
    assert set(data["frameworks"]) == {"flask", "fastapi", "django"}
    assert data["anchor_globs"]


def test_sink_classes_match_the_code_contract():
    """The YAML and the SinkClass Literal must not drift apart.

    A sink class present in only one of the two produces nodes nothing matches
    (or matchers with no data) — silently, at runtime. Fail here instead.
    """
    data = yaml.safe_load(PATTERNS.read_text())
    assert set(data["sinks"]) == set(get_args(SinkClass))
    # Sanitizers are a subset: there is no safe `eval`, and log output isn't
    # sanitized so much as it is not written.
    assert set(data["sanitizers"]) <= set(get_args(SinkClass))


def test_every_framework_declares_an_endpoint_and_auth_surface():
    data = yaml.safe_load(PATTERNS.read_text())
    for name, fw in data["frameworks"].items():
        assert fw.get("detect"), f"{name} has no detection markers"
        assert fw.get("endpoints"), f"{name} declares no endpoint surface"
        assert fw.get("auth"), f"{name} declares no auth surface"
        assert fw.get("sources"), f"{name} declares no request sources"


# Every key path the catalog declares, and the module that reads it. Verified by
# grep, not by reading the YAML's comments — `endpoints.decorators` carried a
# comment describing exactly how it was matched for as long as nothing matched it.
#
# `*` stands for a name the catalog author chooses (a framework, a sink class, a
# source group), so `sinks.*.calls` covers all nine sink classes.
_READ = {
    "frameworks.*.detect": "promote._detect_framework",
    "frameworks.*.endpoints.decorators": "promote._route_verbs",
    "frameworks.*.endpoints.method_kwarg": "promote._methods_re",
    "frameworks.*.endpoints.view_bases": "promote._extract_class_endpoints",
    "frameworks.*.auth.decorators": "promote._auth_names, classify",
    "frameworks.*.auth.mixins": "promote._auth_names, classify",
    "frameworks.*.auth.dependency_names": "promote._auth_names, classify",
    "frameworks.*.auth.dependency_calls": "promote._extract_function_endpoints",
    "frameworks.*.auth.router_kwarg": "promote._router_guards",
    "frameworks.*.auth.route_decorator_kwarg": "promote._extract_function_endpoints",
    "frameworks.*.auth.class_attributes": "promote._extract_class_endpoints",
    "frameworks.*.auth.opt_out_decorators": "promote._auth_names, classify",
    "frameworks.*.auth.permission_classes.enforcing": "promote._auth_names, classify",
    "frameworks.*.auth.permission_classes.opening": "promote._auth_names, classify",
    "frameworks.*.sources.attributes": "cpg._attribute_patterns",
    "sources.*.calls": "cpg._call_patterns",
    "sources.*.exact_calls": "cpg._call_patterns",
    "sources.*.attributes": "cpg._attribute_patterns",
    "sinks.*.calls": "cpg._call_patterns",
    "sinks.*.exact_calls": "cpg._call_patterns",
    "sanitizers.*.calls": "cpg._call_patterns",
    "sanitizers.*.exact_calls": "cpg._call_patterns",
    "sensitive_fields": "cpg (read whole, category names and all)",
    "anchor_globs": "drift",
}

# Declared and deliberately not read. Each needs a reason that survives being
# read aloud; "we might want it later" is not one, and anything that cannot get
# a real reason belongs in OPEN_ITEMS.md or deleted. This set is the whole point
# of the test: `endpoints.decorators` was inert for as long as it was, and the
# rest of this file turned out to have nine more of the same shape (§14.24).
_DECLARED_NOT_READ = {
    "version": "catalog format version; nothing dispatches on it while there is one format",
    "language": "documents which loader argument selects this file; the filename is what selects it",
    "frameworks.*.auth.middleware":
        "Django middleware is repo-wide configuration, not a per-endpoint guard; "
        "attributing it to endpoints would mark every view authenticated.",
    "frameworks.*.sources.param_annotations":
        "FastAPI `Body`/`Query` annotations mark a parameter as request-derived. "
        "cpg.py seeds taint from attribute chains and calls, not from parameter "
        "annotations, so there is no matcher to feed. Real gap.",
    "sources.*.trust":
        "A trust level per source group. Nothing weighs sources differently yet; "
        "confidence comes from the detector, not the catalog.",
    "sinks.*.cwe":
        "The CWE for a sink class. taxonomy/registry.py owns that mapping and is "
        "the single source of truth; two tables would drift.",
    "sinks.*.danger_kwarg":
        "e.g. `shell=True`. cpg.py matches call *names*, not their arguments — "
        "the same argument-extraction gap that defers Django route tables.",
    "sinks.*.conditional_calls":
        "`yaml.load` is safe with a `Loader=` argument and not otherwise. Same "
        "gap as danger_kwarg — and the nested `safe_when_kwarg` under it is part "
        "of this key, not a sibling of it.",
    "sanitizers.*.requires_containment_check":
        "Marks a sanitizer as sufficient only with a containment check "
        "(`os.path.realpath` needs a prefix test). Verifying that is 3c "
        "reachability work, not pattern matching.",
}


# Blocks keyed by a name the catalog author picks (a framework, a sink class, a
# source group) rather than by a structural key. Folded to `*` so one entry
# covers all nine sink classes instead of nine identical ones.
_NAME_KEYED = ("frameworks", "sinks", "sources", "sanitizers")


def _key_paths(node, classified: set[str], prefix: str = "") -> set[str]:
    """Key paths of the catalog, stopping at any path already classified.

    A classified path is a leaf here: saying `sinks.*.danger_kwarg` is inert
    settles the `{shell: true}` under it too. Without that, the walk descends
    into author-chosen *values* — `danger_kwarg.shell`, and four levels of
    `conditional_calls.yaml.load.safe_when_kwarg.Loader` — and the test would
    demand a justification per kwarg name rather than per key.
    """
    if prefix in classified or not isinstance(node, dict) or not node:
        return {prefix} if prefix else set()
    named = prefix in _NAME_KEYED
    out: set[str] = set()
    for key, value in node.items():
        step = "*" if named else key
        out |= _key_paths(value, classified, f"{prefix}.{step}" if prefix else step)
    return out


def test_no_catalog_key_is_silently_inert():
    """A declared key that nothing reads is worse than no key at all.

    `endpoints.decorators` sat in this file for the whole of M1 and M2 spelling
    out route decorators with receivers, while `promote.py` matched routes off a
    hardcoded verb set and never opened it (errata §14.24). It read as
    authoritative, so the fix for a route-matching bug looked like a YAML edit,
    and a YAML edit did nothing. That is the failure this test exists to prevent.

    Every key must be classified: read by a named module, or deliberately inert
    with a reason. Both directions fail — an unclassified key **and** a stale
    entry in either set, so deleting a key from the YAML without deleting its
    claim here is caught too.
    """
    classified = set(_READ) | set(_DECLARED_NOT_READ)
    declared = _key_paths(yaml.safe_load(PATTERNS.read_text()), classified)

    unclassified = declared - classified
    assert not unclassified, (
        f"catalog keys nothing classifies: {sorted(unclassified)}. Add each to "
        f"_READ with the module that reads it, or to _DECLARED_NOT_READ with a "
        f"reason it is allowed to be inert.")

    stale = classified - declared
    assert not stale, (
        f"classified keys the catalog no longer declares: {sorted(stale)}. "
        f"Remove them here too.")

    assert not (set(_READ) & set(_DECLARED_NOT_READ)), "a key cannot be both"


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

def test_config_m1_defaults():
    c = Config()
    assert c.languages == ["python"]
    assert c.budget.max_tokens_per_pr == 400_000
    assert c.budget.gate_fraction == 0.8
    assert c.profile.drift_file_pct == 0.25
    assert c.profile.drift_edge_pct == 0.15
    assert set(c.models.roles) == {"planner", "worker", "verifier", "triage"}


def test_role_models_carry_effort_not_temperature():
    """Current Claude models 400 on `temperature`; depth is `effort` now."""
    c = Config()
    planner = c.models.role("planner")
    assert planner.effort in {"low", "medium", "high", "xhigh", "max"}
    assert not hasattr(planner, "temperature")
    assert c.models.role("triage").effort == "low"   # cheap tier, shallow work


def test_unknown_role_names_the_available_roles():
    with pytest.raises(KeyError, match="planner"):
        Config().models.role("synthesizer")


def test_config_file_overrides_defaults(tmp_path):
    p = tmp_path / "pr_review.yaml"
    p.write_text(
        "languages: [python, go]\n"
        "budget: { max_tokens_per_pr: 100 }\n"
        "profile: { drift_file_pct: 0.5 }\n"
    )
    c = Config.load(p)
    assert c.languages == ["python", "go"]
    assert c.budget.max_tokens_per_pr == 100
    assert c.profile.drift_file_pct == 0.5
    # Untouched sections keep their defaults.
    assert c.gate.confidence_floor == 6
    assert c.models.role("worker").model_id.startswith("anthropic.")


def test_shipped_yaml_matches_the_schema():
    """pr_review.yaml is documentation as much as config — keep it loadable."""
    root = Path(pr_review.__file__).parent.parent / "pr_review.yaml"
    c = Config.load(root)
    assert c.models.provider == "bedrock"
    assert c.profile.cache_root == ".pr_review/cache"
