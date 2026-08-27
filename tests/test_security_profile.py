"""`ProjectProfile` assembly — M1's acceptance criterion (phase-1 §11).

"Cold-profile a Python repo -> valid ProjectProfile with a correct
access-control matrix and a CPG containing endpoints/sources/sinks."

The hand-labelled key lives in the docstrings of `tests/fixtures/sample_app/`.
"""
import pytest

pytest.importorskip(
    "cap_engine.environment.code_promoter",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from pr_review.models.fake import FakeInferenceProvider, plan_response  # noqa: E402
from pr_review.profile.security_profile import (  # noqa: E402
    _merge_agent_profile,
    build_profile,
)

FIXTURE = "tests/fixtures/sample_app"


@pytest.fixture(scope="module")
def floor():
    """No provider — the deterministic layer alone."""
    return build_profile(FIXTURE, repo="o/r", base_sha="abc123def456")


def _rows(build):
    return {r.controller: r for r in build.profile.access_control_matrix}


# --------------------------------------------------------------------------
# The floor stands on its own
# --------------------------------------------------------------------------

def test_profile_is_valid_without_any_model(floor):
    p = floor.profile
    assert p.repo == "o/r"
    assert p.profile_version == "abc123def456"
    assert p.build_kind == "full"
    assert sorted(p.tech_stack) == ["django", "fastapi", "flask"]


def test_matrix_covers_every_endpoint(floor):
    assert len(floor.profile.access_control_matrix) == 11
    assert len(_rows(floor)) == 11


def test_matrix_enforcement_matches_the_key(floor):
    rows = _rows(floor)
    enforced = {c for c, r in rows.items() if r.enforcement == "enforced"}
    assert enforced == {
        "get_profile", "search", "list_items", "ReportView", "BillingView",
    }
    assert {c for c, r in rows.items() if r.enforcement == "none"} == {
        "public_index", "admin_export", "get_item", "run_task",
        "PublicView", "LegacyView",
    }


def test_auth_pattern_records_the_mechanism_not_just_presence(floor):
    rows = _rows(floor)
    assert rows["get_profile"].auth_pattern == "decorator:login_required"
    assert rows["list_items"].auth_pattern == "dependency:get_current_user"
    assert rows["ReportView"].auth_pattern == "permission_classes:IsAuthenticated"
    assert rows["BillingView"].auth_pattern == "mixin:LoginRequiredMixin"
    assert rows["get_item"].auth_pattern == "none"


def test_structural_columns_are_populated(floor):
    row = _rows(floor)["admin_export"]
    assert row.file == "app.py" and row.line == 33
    assert row.http_method == "POST"


def test_floor_never_claims_declared_not_enforced(floor):
    """That value asserts something about *intent*. No structural pass can know
    it, and a wrong one is a finding a reviewer will chase. It is the agent
    layer's highest-value contribution — see phase-1 §5."""
    assert all(r.enforcement != "declared_not_enforced"
               for r in floor.profile.access_control_matrix)


def test_unresolved_routes_are_marked_not_invented(floor):
    """Django routes are unresolved; the row still carries its guard."""
    row = _rows(floor)["ReportView"]
    assert row.endpoint == "(unresolved:ReportView)"
    assert row.enforcement == "enforced"


def test_sensitive_fields_and_checks_carry_through(floor):
    p = floor.profile
    assert {f.name: f.classification for f in p.sensitive_fields} == {
        "email": "pii", "password_hash": "credential", "ssn": "pii",
    }
    assert {c.name for c in p.permission_checks} == {
        "login_required", "get_current_user", "IsAuthenticated", "LoginRequiredMixin",
    }


def test_io_channels_and_code_flows_are_paired(floor):
    p = floor.profile
    assert len(p.io_channels) == len(p.code_flows) == 11
    assert {c.kind for c in p.io_channels} == {"http_api"}
    assert p.io_channels[0].name == p.code_flows[0].channel


# --------------------------------------------------------------------------
# Honest gaps
# --------------------------------------------------------------------------

def test_absent_agent_layer_is_recorded_not_hidden(floor):
    """A silent blank reads as evidence of safety."""
    notes = " ".join(floor.profile.notes)
    assert "structural profile only" in notes
    assert "declared_not_enforced" in notes and "IDOR" in notes
    assert "role vocabulary not established" in notes
    assert "non-HTTP I/O channels" in notes


def test_taint_paths_are_surfaced_in_the_notes(floor):
    notes = " ".join(floor.profile.notes)
    assert "cursor.execute [sql]" in notes
    assert "subprocess.run [command]" in notes


def test_telemetry_records_the_cost_and_the_shape(floor):
    t = floor.telemetry
    assert t["endpoints"] == 11 and t["matrix_rows"] == 11
    assert t["taint_paths"] == 2 and t["parse_errors"] == 0
    assert t["agent_calls"] == 0 and t["tokens"] == 0     # no provider, no spend


# --------------------------------------------------------------------------
# With the agent layer
# --------------------------------------------------------------------------

def test_workflow_runs_and_the_floor_survives_it(tmp_path):
    """The fake cannot produce a real synthesis, so nothing merges — the point
    is that the profile is still complete and the gap is declared."""
    provider = FakeInferenceProvider(responses={"planner": plan_response()})
    build = build_profile(FIXTURE, repo="o/r", provider=provider,
                          output_dir=tmp_path / "out", log_dir=tmp_path / "logs")

    assert build.workflow_error == ""
    assert build.telemetry["agent_calls"] > 0
    assert build.telemetry["tokens"] > 0
    assert len(build.profile.access_control_matrix) == 11
    assert build.agent_rows_merged == 0
    assert "structural profile only" in " ".join(build.profile.notes)


def test_workflow_failure_degrades_to_the_floor(tmp_path):
    """A broken agent layer must not cost us the structural profile."""
    class Exploding(FakeInferenceProvider):
        def invoke(self, *a, **kw):
            raise RuntimeError("provider exploded")

    build = build_profile(FIXTURE, repo="o/r", provider=Exploding(),
                          output_dir=tmp_path / "out", log_dir=tmp_path / "logs")

    assert build.workflow_error
    assert len(build.profile.access_control_matrix) == 11
    assert "workflow did not complete" in " ".join(build.profile.notes)


# --------------------------------------------------------------------------
# The merge
# --------------------------------------------------------------------------

def test_merge_upgrades_judgement_but_not_structure(floor):
    """The agent may overwrite what it can judge. It may not overwrite route,
    file or line — facts it has no better access to and every chance to garble.
    """
    profile = floor.profile.model_copy(deep=True)
    before = {r.controller: (r.endpoint, r.file, r.line) for r in profile.access_control_matrix}

    merged = _merge_agent_profile(profile, {
        "description": "a demo app",
        "access_control_matrix": [{
            "controller": "get_item", "file": "api.py",
            "enforcement": "declared_not_enforced",
            "required_roles": ["user"],
            "auth_pattern": "dependency:get_current_user",
            "endpoint": "/WRONG", "file_": "nonsense", "line": 999,
        }],
    })

    row = {r.controller: r for r in profile.access_control_matrix}["get_item"]
    assert merged == 1
    assert row.enforcement == "declared_not_enforced"      # the lift
    assert row.required_roles == ["user"]
    assert (row.endpoint, row.file, row.line) == before["get_item"]   # structure held
    assert profile.description == "a demo app"


def test_merge_ignores_rows_for_endpoints_that_do_not_exist(floor):
    """A hallucinated endpoint must not enter the matrix."""
    profile = floor.profile.model_copy(deep=True)
    merged = _merge_agent_profile(profile, {
        "access_control_matrix": [
            {"controller": "imaginary_view", "file": "nope.py", "enforcement": "none"},
        ],
    })
    assert merged == 0
    assert len(profile.access_control_matrix) == 11


def test_merge_rejects_an_invalid_enforcement_value(floor):
    profile = floor.profile.model_copy(deep=True)
    _merge_agent_profile(profile, {
        "access_control_matrix": [
            {"controller": "get_item", "file": "api.py", "enforcement": "probably_fine"},
        ],
    })
    row = {r.controller: r for r in profile.access_control_matrix}["get_item"]
    assert row.enforcement == "none"
