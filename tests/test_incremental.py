"""Incremental profile update (phase-1 §6).

The property that matters is **equivalence**: patching the cached artifacts must
land in the same place a full rebuild would. If it does not, the cheap path is
producing a different — and therefore wrong — access-control matrix, which is
exactly the failure the drift design exists to avoid.

The second thing pinned here is the splice precondition. Patching per file is
only sound because no derived fact crosses a file boundary today. That is a
property of the current call-graph resolver, not a law, so it is asserted on
every run and the updater refuses rather than guesses.
"""
import shutil

import pytest

pytest.importorskip(
    "cap_engine.environment.code_promoter",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from pr_review.extract.manifest import build_manifest  # noqa: E402
from pr_review.profile.cpg import CPG, CPGNode  # noqa: E402
from pr_review.profile.drift import fingerprint_repo  # noqa: E402
from pr_review.profile.incremental import (  # noqa: E402
    NotSpliceable,
    drifted_by_size,
    partial_cache,
    update_profile,
)
from pr_review.profile.security_profile import build_profile  # noqa: E402

FIXTURE = "tests/fixtures/sample_app"


@pytest.fixture(scope="module")
def full():
    return build_profile(FIXTURE, repo="o/r", base_sha="a" * 40)


def _manifest(paths, base_sha="b" * 40, change="modified", **kw):
    diff = "".join(
        f"diff --git a/{p} b/{p}\n--- a/{p}\n+++ b/{p}\n@@ -1,2 +1,2 @@\n-x\n+y\n"
        for p in paths
    )
    manifest, _ = build_manifest(repo="o/r", pr_number=1, diff_text=diff,
                                 base_sha=base_sha, head_sha="c" * 40)
    for fc in manifest.files:
        fc.change = change
        for key, value in kw.items():
            setattr(fc, key, value)
    return manifest


def _clone(build):
    """A detached copy of the cached artifacts, as `cache.load()` would return."""
    return build.profile.model_copy(deep=True), CPG.from_dict(build.cpg.to_dict())


def _shape(profile, cpg):
    return (
        sorted((r.file, r.controller, r.endpoint, r.http_method, r.enforcement,
                tuple(r.required_roles)) for r in profile.access_control_matrix),
        sorted((n.kind, n.file, n.name, n.line) for n in cpg.graph.nodes()),
        sorted((a.id, b.id, r) for a, b, r in cpg.edges()),
        sorted((p.source.id, p.sink.id, tuple(p.symbols)) for p in cpg.taint_paths),
        sorted((f.name, f.classification) for f in profile.sensitive_fields),
        sorted(c.name for c in profile.permission_checks),
        sorted(c.name for c in profile.io_channels),
    )


# --------------------------------------------------------------------------
# Equivalence — the property the whole design rests on
# --------------------------------------------------------------------------

def test_patching_every_file_equals_a_full_rebuild(full):
    """The strongest form: touch everything, and the result must be identical
    to the build it was patched from."""
    profile, cpg = _clone(full)
    update_profile(profile, cpg, FIXTURE,
                   _manifest(["app.py", "api.py", "models.py", "views.py"]))
    assert _shape(profile, cpg) == _shape(full.profile, full.cpg)


def test_patching_one_file_equals_a_full_rebuild(full):
    profile, cpg = _clone(full)
    update_profile(profile, cpg, FIXTURE, _manifest(["app.py"]))
    assert _shape(profile, cpg) == _shape(full.profile, full.cpg)


def test_patching_twice_is_idempotent(full):
    profile, cpg = _clone(full)
    update_profile(profile, cpg, FIXTURE, _manifest(["views.py"]))
    update_profile(profile, cpg, FIXTURE, _manifest(["views.py"]))
    assert _shape(profile, cpg) == _shape(full.profile, full.cpg)


def test_untouched_files_keep_their_taint_paths(full):
    """`api.py` holds a planted command injection and is not in this manifest."""
    profile, cpg = _clone(full)
    update_profile(profile, cpg, FIXTURE, _manifest(["app.py"]))
    sinks = {(p.sink.file, p.sink.name) for p in cpg.taint_paths}
    assert ("api.py", "subprocess.run") in sinks
    assert ("app.py", "cursor.execute") in sinks


def test_only_the_touched_files_are_parsed(full):
    profile, cpg = _clone(full)
    result = update_profile(profile, cpg, FIXTURE, _manifest(["app.py"]))
    assert result.reparsed == ["app.py"]
    assert result.telemetry["files_reparsed"] == 1


# --------------------------------------------------------------------------
# Adds, deletes, renames
# --------------------------------------------------------------------------

def test_a_deleted_file_is_evicted_entirely(full):
    profile, cpg = _clone(full)
    update_profile(profile, cpg, FIXTURE, _manifest(["views.py"], change="deleted"))

    assert "views.py" not in cpg.files()
    assert not [r for r in profile.access_control_matrix if r.file == "views.py"]
    assert [r for r in profile.access_control_matrix if r.file == "app.py"]


def test_deleting_a_view_prunes_its_now_orphaned_permission(full):
    """`LoginRequiredMixin` guards only `views.py`, so nothing references it
    afterwards. `IsAuthenticated` is in the same file and goes with it."""
    profile, cpg = _clone(full)
    before = {n.name for n in cpg.nodes_of_kind("permission")}
    update_profile(profile, cpg, FIXTURE, _manifest(["views.py"], change="deleted"))
    after = {n.name for n in cpg.nodes_of_kind("permission")}

    assert "LoginRequiredMixin" in before and "LoginRequiredMixin" not in after
    assert "login_required" in after          # still guards app.py


def test_a_permission_shared_with_an_untouched_file_survives(full):
    """Eviction is per file; a guard another file still uses must not vanish."""
    profile, cpg = _clone(full)
    cpg.add(CPGNode(id="endpoint:other.py:keep", kind="endpoint", file="other.py",
                    name="keep", line=1, attrs={"guards": ["LoginRequiredMixin"]}))
    cpg.link("permission:LoginRequiredMixin", "endpoint:other.py:keep", "guards")

    update_profile(profile, cpg, FIXTURE, _manifest(["views.py"], change="deleted"))
    assert "LoginRequiredMixin" in {n.name for n in cpg.nodes_of_kind("permission")}


def test_a_renamed_file_evicts_its_old_path(full):
    profile, cpg = _clone(full)
    manifest = _manifest(["views.py"])
    manifest.files[0].change = "renamed"
    manifest.files[0].previous_path = "legacy_views.py"
    cpg.add(CPGNode(id="file:legacy_views.py", kind="file", file="legacy_views.py",
                    name="legacy_views.py"))

    update_profile(profile, cpg, FIXTURE, manifest)
    assert "legacy_views.py" not in cpg.files()
    assert "views.py" in cpg.files()


def test_a_file_missing_from_the_checkout_is_skipped_not_fatal(full):
    profile, cpg = _clone(full)
    result = update_profile(profile, cpg, FIXTURE, _manifest(["app.py", "gone.py"]))
    assert result.reparsed == ["app.py"]
    assert not result.telemetry["parse_errors"]


def test_a_new_file_is_picked_up(full, tmp_path):
    """CAP's own `ParseCache.refresh()` keys on mtime of *known* files, so it
    would never see this — which is why `partial_cache` exists."""
    checkout = tmp_path / "src"
    shutil.copytree(FIXTURE, checkout)
    (checkout / "extra.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        '@app.route("/new", methods=["GET"])\n'
        "def brand_new():\n    return {}\n"
    )
    profile, cpg = _clone(full)
    update_profile(profile, cpg, checkout, _manifest(["extra.py"], change="added"))

    assert "/new" in {r.endpoint for r in profile.access_control_matrix}
    assert "extra.py" in cpg.files()
    assert len(profile.access_control_matrix) == 12


def test_cost_does_not_grow_with_the_repository(tmp_path):
    """Principle #4 — "cost trends down across PRs on the same repo" — holds
    only if an incremental update is priced by the *change*, not by the repo.

    Timing is not asserted (it would be flaky); the invariant behind it is:
    one file changed means one file parsed, whatever the repo size, and the
    other 30 modules come through the splice untouched and identical.
    """
    checkout = tmp_path / "repo"
    shutil.copytree(FIXTURE, checkout)
    template = (checkout / "app.py").read_text()
    for i in range(30):
        (checkout / f"mod{i:02d}.py").write_text(
            template.replace("/public", f"/p{i}").replace("public_index", f"idx{i}")
            .replace("get_profile", f"prof{i}").replace("admin_export", f"exp{i}")
            .replace("def search", f"def search{i}").replace("_run_search", f"_rs{i}")
            .replace("_dump_all", f"_dump{i}"))

    built = build_profile(checkout, repo="o/r", base_sha="a" * 40)
    assert len(built.profile.access_control_matrix) == 131      # 11 + 30 * 4

    profile, cpg = _clone(built)
    result = update_profile(profile, cpg, checkout, _manifest(["mod00.py"]),
                            fingerprint=fingerprint_repo(built.promotion, "a" * 40))

    assert result.telemetry["files_reparsed"] == 1
    assert _shape(profile, cpg) == _shape(built.profile, built.cpg)


# --------------------------------------------------------------------------
# The splice precondition
# --------------------------------------------------------------------------

def test_the_built_cpg_is_spliceable(full):
    assert full.cpg.splice_violations() == []


def test_a_cross_file_edge_makes_the_graph_unspliceable(full):
    profile, cpg = _clone(full)
    cpg.link("sym:app.search", "sym:models.User.fetch", "calls")
    assert cpg.splice_violations()
    with pytest.raises(NotSpliceable):
        update_profile(profile, cpg, FIXTURE, _manifest(["app.py"]))


def test_a_cross_file_taint_path_makes_the_graph_unspliceable(full):
    profile, cpg = _clone(full)
    path = cpg.taint_paths[0]
    path.sink = cpg.node("sensitive_field:models.py:ssn")
    assert cpg.splice_violations()
    with pytest.raises(NotSpliceable):
        update_profile(profile, cpg, FIXTURE, _manifest(["app.py"]))


def test_the_pipeline_rebuilds_rather_than_splicing_an_unsafe_graph(tmp_path, full):
    """Declining must be loud and must not fail the review."""
    from pr_review import pipeline
    from pr_review.config import Config
    from pr_review.profile.cache import ProfileCache

    cfg = Config()
    cfg.profile.cache_root = str(tmp_path / "cache")
    profile, cpg = _clone(full)
    cpg.link("sym:app.search", "sym:models.User.fetch", "calls")
    ProfileCache("o/r", cfg.profile.cache_root).save(
        profile, fingerprint_repo(full.promotion, base_sha="a" * 40), cpg)

    result = pipeline.run_review(
        repo="o/r", pr_number=1,
        diff_text="diff --git a/models.py b/models.py\n--- a/models.py\n+++ b/models.py\n"
                  "@@ -1,3 +1,3 @@\n-\"\"\"Old.\"\"\"\n+\"\"\"New.\"\"\"\n",
        config=cfg, out_root=str(tmp_path / "runs"),
        base_dir=FIXTURE, base_sha="d" * 40, head_sha="e" * 40)

    import json
    meta = json.loads((result.out_dir / "telemetry.json").read_text())["meta"]
    assert meta["profile_action"] == "incremental"
    assert any("declined, rebuilding" in n for n in meta["filter_notes"])
    assert result.groups                       # the review still completed


# --------------------------------------------------------------------------
# Agent judgement
# --------------------------------------------------------------------------

def test_a_floor_only_profile_reports_no_lost_judgement(full):
    """Nothing was lifted, so re-deriving loses nothing — warning would be noise."""
    profile, cpg = _clone(full)
    assert profile.agent_rows_merged == 0
    result = update_profile(profile, cpg, FIXTURE, _manifest(["app.py"]))
    assert result.relifted_rows == []
    assert not any("agent judgement was dropped" in n for n in profile.notes)


def test_re_deriving_a_lifted_row_drops_it_to_the_floor_and_says_so(full):
    """The agent judged the *previous* version of this code, so keeping its
    verdict would be a stale finding a reviewer chases."""
    profile, cpg = _clone(full)
    profile.agent_rows_merged = 3
    row = next(r for r in profile.access_control_matrix if r.file == "app.py")
    row.enforcement = "declared_not_enforced"
    row.required_roles = ["admin"]

    result = update_profile(profile, cpg, FIXTURE, _manifest(["app.py"]))

    assert result.relifted_rows
    again = next(r for r in profile.access_control_matrix
                 if (r.file, r.controller) == (row.file, row.controller))
    assert again.enforcement in ("enforced", "none")
    assert any("agent judgement was dropped" in n for n in profile.notes)


def test_repo_level_agent_output_is_preserved(full):
    """It describes the project, not the touched files, and re-deriving it needs
    the agent."""
    profile, cpg = _clone(full)
    profile.description = "A billing service."
    profile.authorization.model = "rbac"
    profile.roles = []

    update_profile(profile, cpg, FIXTURE, _manifest(["app.py"]))
    assert profile.description == "A billing service."
    assert profile.authorization.model == "rbac"


def test_the_build_kind_records_how_it_was_made(full):
    profile, cpg = _clone(full)
    update_profile(profile, cpg, FIXTURE, _manifest(["app.py"]))
    assert profile.build_kind == "incremental"
    assert profile.profile_version == "a" * 40          # unchanged (phase-1 §6)


def test_notes_are_regenerated_not_appended(full):
    """A stale TAINT line is a claim about code that no longer exists."""
    profile, cpg = _clone(full)
    profile.notes.append("TAINT: a path that no longer exists")
    update_profile(profile, cpg, FIXTURE, _manifest(["app.py"]))
    assert "TAINT: a path that no longer exists" not in profile.notes
    assert any("INCREMENTAL UPDATE" in n for n in profile.notes)


# --------------------------------------------------------------------------
# The stat()-based drift net
# --------------------------------------------------------------------------

def test_size_drift_finds_a_file_the_pr_never_touched(full, tmp_path):
    """The PR's diff is only a proxy for how the base moved; a file that changed
    between the two bases without appearing in this PR would keep a stale row."""
    checkout = tmp_path / "src"
    shutil.copytree(FIXTURE, checkout)
    (checkout / "views.py").write_text(
        (checkout / "views.py").read_text().replace(
            "permission_classes = [IsAuthenticated]",
            "permission_classes = [AllowAny]  # opened between bases"))

    fingerprint = fingerprint_repo(full.promotion, base_sha="a" * 40)
    assert "views.py" in drifted_by_size(fingerprint, checkout)

    profile, cpg = _clone(full)
    update_profile(profile, cpg, checkout, _manifest(["app.py"]),
                   fingerprint=fingerprint)

    row = next(r for r in profile.access_control_matrix if r.controller == "ReportView")
    assert row.enforcement == "none"           # the opened guard was picked up


def test_size_drift_is_quiet_when_nothing_moved(full):
    fingerprint = fingerprint_repo(full.promotion, base_sha="a" * 40)
    assert drifted_by_size(fingerprint, FIXTURE) == []


def test_no_fingerprint_means_no_size_check(full):
    assert drifted_by_size(None, FIXTURE) == []


# --------------------------------------------------------------------------
# partial_cache
# --------------------------------------------------------------------------

def test_partial_cache_holds_only_what_was_asked_for():
    cache = partial_cache(FIXTURE, ["app.py"])
    assert set(cache.structural_index) == {"app.py"}
    assert cache._trees["app.py"][0] is not None


def test_partial_cache_populates_the_call_graph():
    """CAP's `refresh()` does not, which is the other reason it is unusable
    here — taint would silently disappear."""
    cache = partial_cache(FIXTURE, ["app.py"])
    assert "app.search" in cache.call_graph.forward


def test_partial_cache_populates_the_type_hierarchy():
    cache = partial_cache(FIXTURE, ["models.py"])
    assert "BaseModel" in cache.type_hierarchy


def test_partial_cache_records_unparseable_files_without_failing():
    cache = partial_cache(FIXTURE, ["app.py", "does-not-exist.py"])
    assert set(cache.structural_index) == {"app.py"}
    assert cache.parse_errors == []
