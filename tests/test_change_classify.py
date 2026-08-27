"""Change groups, CPG-driven `touches`, and family routing (phase-2 §4).

phase-2 §8 names the family-routing table as a unit test. The other thing pinned
here is the reason `guard_edits()` exists at all: the CPG is built at `base_sha`,
so a guard the PR *removes* is still in the graph and a guard it *adds* is absent
from it. Without the text pass, "someone deleted `@login_required`" — the single
highest-signal one-line change in a Python PR — produces no signal whatsoever.
"""
import pytest

pytest.importorskip(
    "cap_engine.environment.code_promoter",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from pr_review.change.classify import (  # noqa: E402
    GUARDRAIL_KINDS,
    SecurityIndex,
    Signal,
    classify_changes,
    guard_edits,
    route_families,
    weakened_security_test,
)
from pr_review.change.filter import filter_changes  # noqa: E402
from pr_review.extract.manifest import build_manifest  # noqa: E402
from pr_review.profile.security_profile import build_profile  # noqa: E402
from pr_review.schema import Severity  # noqa: E402
from pr_review.taxonomy import registry  # noqa: E402

FIXTURE = "tests/fixtures/sample_app"
PR_DIFF = "tests/fixtures/phase2_pr.diff"


@pytest.fixture(scope="module")
def built():
    return build_profile(FIXTURE, repo="o/r", base_sha="a" * 40)


@pytest.fixture(scope="module")
def pr():
    return build_manifest(repo="o/r", pr_number=7, diff_text=open(PR_DIFF).read(),
                          base_sha="b" * 40, head_sha="c" * 40)


@pytest.fixture(scope="module")
def changeset(pr, built):
    manifest, parsed = pr
    kept = filter_changes(manifest, parsed, cpg=built.cpg, profile=built.profile)
    return classify_changes(manifest, kept.kept, parsed, cpg=built.cpg,
                            profile=built.profile, dropped=kept.dropped)


def _group(changeset, path):
    return next(g for g in changeset.groups if path in g.files)


def _parsed(path: str, body: str, header="@@ -1,4 +1,4 @@"):
    from pr_review.extract.diff import parse_unified_diff
    return parse_unified_diff(
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n{header}\n{body}")[0]


# --------------------------------------------------------------------------
# The security index
# --------------------------------------------------------------------------

def test_index_reads_endpoints_sources_and_sinks_from_the_cpg(built):
    index = SecurityIndex(built.cpg, built.profile)
    assert {"endpoint", "source", "sink"} <= index.touches("app.py")
    assert "sensitive_field" in index.touches("models.py")


def test_signals_are_scoped_by_line(built):
    """A hunk at the top of app.py must not inherit the SQLi at the bottom."""
    index = SecurityIndex(built.cpg, built.profile)
    assert "source" not in index.touches("app.py", (1, 15))
    assert "source" in index.touches("app.py", (36, 43))


def test_line_less_signals_always_apply(built):
    """Path flags and profile rows with no line describe the file, not a region."""
    manifest, _ = build_manifest(repo="o/r", pr_number=1, diff_text=open(PR_DIFF).read())
    index = SecurityIndex(built.cpg, built.profile, manifest)
    assert "dependency" in index.touches("requirements.txt", (1, 4))


def test_path_shape_covers_files_the_cpg_cannot_know_about(built):
    """A file this PR *adds* has no node in a graph built from base_sha."""
    manifest, _ = build_manifest(
        repo="o/r", pr_number=1,
        diff_text="diff --git a/app/permissions.py b/app/permissions.py\n"
                  "new file mode 100644\n--- /dev/null\n+++ b/app/permissions.py\n"
                  "@@ -0,0 +1,1 @@\n+class IsOwner: pass\n")
    index = SecurityIndex(None, None, manifest)
    assert index.security_relevant("app/permissions.py")
    assert "authz" in index.touches("app/permissions.py")


def test_the_guardrail_set_is_narrower_than_the_touch_set():
    """`config` and `dependency` are not a security surface — if they were, the
    guardrail would veto the tier-1 rules that exist to act on them."""
    assert "dependency" not in GUARDRAIL_KINDS
    assert "config" not in GUARDRAIL_KINDS
    assert {"sanitizer", "permission"} <= GUARDRAIL_KINDS


def test_a_sanitizer_alone_makes_a_file_security_relevant(built):
    """Deleting one `shlex.quote` turns a safe call into command injection."""
    index = SecurityIndex(built.cpg, built.profile)
    index._signals["utils/shell.py"].append(Signal("sanitizer", 4, "shlex.quote"))
    assert index.security_relevant("utils/shell.py")
    assert index.touches("utils/shell.py") == set()      # not a routing key


def test_why_is_scoped_when_spans_are_given(built):
    index = SecurityIndex(built.cpg, built.profile)
    assert "public_index" in index.why("app.py")
    assert "public_index" not in index.why("app.py", [(36, 43)])


# --------------------------------------------------------------------------
# Guard edits — what the base_sha CPG structurally cannot carry
# --------------------------------------------------------------------------

def test_a_removed_decorator_is_detected():
    edits = guard_edits(_parsed("app.py", "-@login_required\n def search():\n"))
    assert [(e.kind, e.name) for e in edits] == [("guard_removed", "login_required")]


def test_adding_allowany_is_an_access_opening():
    """The catalog calls this "one of the highest-signal single-line changes in
    a Python PR"."""
    edits = guard_edits(_parsed(
        "views.py", "-    permission_classes = [IsAuthenticated]\n"
                    "+    permission_classes = [AllowAny]\n"))
    kinds = {(e.kind, e.name) for e in edits}
    assert ("access_opened", "AllowAny") in kinds
    assert ("guard_removed", "IsAuthenticated") in kinds


def test_an_unrelated_edit_produces_no_guard_edits():
    assert guard_edits(_parsed("app.py", "-    x = 1\n+    x = 2\n")) == []


def test_word_boundaries_are_respected():
    assert guard_edits(_parsed("app.py", "-    my_login_required_helper()\n")) == []


# --------------------------------------------------------------------------
# Weakened security tests
# --------------------------------------------------------------------------

def test_a_removed_403_assertion_routes_to_broken_access_control():
    hit, fams = weakened_security_test(_parsed(
        "tests/t.py", "-        assert resp.status_code == 403\n"))
    assert hit and fams == ["Broken Access Control"]


def test_a_removed_401_assertion_routes_to_authentication():
    hit, fams = weakened_security_test(_parsed(
        "tests/t.py", '-        assert resp.status_code == 401\n'))
    assert hit and "Authentication Failures" in fams


def test_adding_an_assertion_is_not_a_weakening():
    hit, _ = weakened_security_test(_parsed(
        "tests/t.py", "+        assert resp.status_code == 403\n"))
    assert not hit


def test_a_non_security_assertion_is_not_a_weakening():
    hit, _ = weakened_security_test(_parsed("tests/t.py", "-    assert add(1,2) == 3\n"))
    assert not hit


# --------------------------------------------------------------------------
# Family routing (phase-2 §8: "family-routing table")
# --------------------------------------------------------------------------

@pytest.mark.parametrize("touches,expected", [
    ({"endpoint", "authz"}, ["Broken Access Control"]),
    ({"endpoint"}, ["Broken Access Control"]),
    ({"auth"}, ["Authentication Failures"]),
    ({"sink"}, ["Injection"]),
    ({"source", "sink"}, ["Injection"]),
    ({"sensitive_field"}, ["Privacy / PII"]),
    ({"config"}, ["Security Misconfiguration"]),
    ({"dependency"}, ["Software Supply Chain"]),
    (set(), []),
])
def test_routing_table(touches, expected):
    assert route_families(touches) == expected


def test_a_sensitive_field_reaching_a_log_sink_routes_to_both():
    assert route_families({"sensitive_field", "sink"}, {"log"}) == [
        "Injection", "Logging & Alerting", "Privacy / PII"]


def test_a_deserialize_sink_adds_the_integrity_family():
    assert "Software/Data Integrity" in route_families({"sink"}, {"deserialize"})


def test_routing_is_validated_against_the_registry():
    with pytest.raises(KeyError):
        registry.validate_families(["Broken Acess Control"])


def test_every_routed_family_exists(changeset):
    for group in changeset.groups:
        registry.validate_families(group.candidate_families)


def test_supply_chain_is_routed_even_though_no_agent_runs_it(changeset):
    """§6: 3a's SCA handles it. Routing it anyway keeps the coverage denominator
    honest — a dependency bump is *handled*, not *skipped*."""
    group = _group(changeset, "requirements.txt")
    assert group.candidate_families == ["Software Supply Chain"]
    assert "Software Supply Chain" in registry.DETERMINISTIC_ONLY


# --------------------------------------------------------------------------
# The change set
# --------------------------------------------------------------------------

def test_the_guard_removal_group_is_high_and_significant(changeset):
    group = _group(changeset, "app.py")
    assert group.kind == "security"
    assert {"endpoint", "authz", "source"} <= set(group.touches)
    assert group.projected_severity == Severity.HIGH
    assert group.significant
    assert "guard_removed:login_required" in group.rationale


def test_the_allowany_group_routes_to_access_control(changeset):
    group = _group(changeset, "views.py")
    assert "Broken Access Control" in group.candidate_families
    assert group.projected_severity == Severity.HIGH
    assert "access_opened:AllowAny" in group.rationale


def test_the_sensitive_field_group_is_privacy_not_access_control(changeset):
    group = _group(changeset, "models.py")
    assert group.candidate_families == ["Privacy / PII"]
    assert group.touches == ["sensitive_field"]


def test_a_weakened_test_becomes_a_security_group(changeset):
    group = _group(changeset, "tests/test_access.py")
    assert group.kind == "security"
    assert "Broken Access Control" in group.candidate_families
    assert group.significant and group.confidence >= 7


def test_a_boring_change_is_convention_and_routes_nowhere(changeset):
    group = _group(changeset, "utils/strings.py")
    assert group.kind == "convention"
    assert group.candidate_families == []
    assert not group.significant


def test_dependency_changes_are_architecture(changeset):
    assert _group(changeset, "requirements.txt").kind == "architecture"


def test_groups_are_per_file(changeset):
    """Cross-file merging is deliberately not done — over-merging produces one
    enormous context bundle, the failure the tiered design exists to prevent."""
    assert all(len(g.files) == 1 for g in changeset.groups)


def test_group_ids_are_stable_and_unique(pr, built):
    manifest, parsed = pr
    kept = filter_changes(manifest, parsed, cpg=built.cpg, profile=built.profile)
    first = classify_changes(manifest, kept.kept, parsed, cpg=built.cpg, profile=built.profile)
    again = classify_changes(manifest, kept.kept, parsed, cpg=built.cpg, profile=built.profile)
    ids = [g.id for g in first.groups]
    assert ids == [g.id for g in again.groups]
    assert len(set(ids)) == len(ids)


def test_the_changeset_carries_the_audit_trail(changeset):
    assert {d.path for d in changeset.dropped} >= {"README.md", "poetry.lock"}
    assert changeset.profile_version == "a" * 40


def test_coverage_plan_is_the_phase_four_denominator(changeset):
    assert set(changeset.coverage_plan) == {g.id for g in changeset.groups}
    assert changeset.planned_families() == {
        f for g in changeset.groups for f in g.candidate_families}


def test_classification_degrades_without_a_profile_or_cpg(pr):
    """No CPG means no structure — but path shape and the guard-edit text pass
    still work, so the highest-signal change survives."""
    manifest, parsed = pr
    kept = filter_changes(manifest, parsed)
    changeset = classify_changes(manifest, kept.kept, parsed)
    group = _group(changeset, "app.py")
    assert "guard_removed:login_required" in group.rationale
    assert group.significant
