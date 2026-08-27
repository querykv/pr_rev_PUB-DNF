"""Drift decision and profile cache — phase-1 §6 and §8.

M1 acceptance (phase-1 §11): "re-run is warm (no re-parse); a dep-manifest change
triggers rebuild while a docstring change stays incremental".
"""
import json

import pytest

pytest.importorskip(
    "cap_engine.environment.code_promoter",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from pr_review.config import Config  # noqa: E402
from pr_review.extract.schema import DeltaManifest, FileChange  # noqa: E402
from pr_review.profile import cache as cache_mod  # noqa: E402
from pr_review.profile.cache import ProfileCache  # noqa: E402
from pr_review.profile.cpg import build_cpg  # noqa: E402
from pr_review.profile.drift import (  # noqa: E402
    RepoFingerprint,
    _matches_anchor,
    anchor_globs,
    decide,
    fingerprint_repo,
    touched_paths,
)
from pr_review.profile.promote import promote  # noqa: E402
from pr_review.profile.security_profile import build_profile  # noqa: E402

FIXTURE = "tests/fixtures/sample_app"


@pytest.fixture(scope="module")
def built():
    return build_profile(FIXTURE, repo="o/r", base_sha="a" * 40)


@pytest.fixture(scope="module")
def fingerprint(built):
    return fingerprint_repo(built.promotion, base_sha="a" * 40)


def _manifest(paths, base_sha="b" * 40, **flags):
    return DeltaManifest(
        repo="o/r", pr_number=1, base_sha=base_sha, head_sha="c" * 40,
        files=[FileChange(file_id=str(i), path=p, change="modified",
                          lang=flags.get("lang", "python"))
               for i, p in enumerate(paths)],
    )


# --------------------------------------------------------------------------
# Fingerprinting
# --------------------------------------------------------------------------

def test_fingerprint_captures_shape_and_counts(fingerprint):
    assert fingerprint.base_sha == "a" * 40
    assert fingerprint.file_count == 4
    assert fingerprint.total_size > 0
    assert fingerprint.total_edges > 0
    assert fingerprint.languages == ["python"]
    assert fingerprint.frameworks == ["django", "fastapi", "flask"]
    assert set(fingerprint.files) == {"app.py", "api.py", "models.py", "views.py"}


def test_fingerprint_carries_caps_structural_layers(fingerprint):
    """CAP's shape/surface/topology hashes are cheap change detection that is
    already stable against comment and docstring edits."""
    assert set(fingerprint.layers) == {"shape", "surface", "topology"}


def test_fingerprint_roundtrips(fingerprint):
    again = RepoFingerprint.from_dict(fingerprint.to_dict())
    assert again.layers == fingerprint.layers
    assert again.files["app.py"].edges == fingerprint.files["app.py"].edges


# --------------------------------------------------------------------------
# The decision
# --------------------------------------------------------------------------

def test_no_cache_is_a_cold_start():
    d = decide(_manifest(["app.py"]), None)
    assert d.action == "cold" and d.needs_full_build


def test_same_base_sha_is_warm(fingerprint):
    """The re-run case: no parsing at all."""
    d = decide(_manifest(["app.py"], base_sha="a" * 40), fingerprint)
    assert d.action == "warm" and not d.needs_full_build


def test_docstring_scale_change_stays_incremental(fingerprint):
    d = decide(_manifest(["models.py"]), fingerprint)
    assert d.action == "incremental"
    assert not d.needs_full_build


@pytest.mark.parametrize("path", [
    "requirements.txt", "pyproject.toml", "app/settings.py",
    "app/middleware.py", "api/permissions.py", "Dockerfile",
])
def test_anchor_file_forces_rebuild(fingerprint, path):
    """A dependency, settings or auth-middleware change invalidates conclusions
    drawn everywhere else, so churn thresholds do not get a vote."""
    d = decide(_manifest([path]), fingerprint)
    assert d.action == "rebuild"
    assert any("anchor" in r for r in d.reasons)


def test_file_churn_over_threshold_forces_rebuild(fingerprint):
    # 4 files cached; 2 changed = 50% > the 25% default
    d = decide(_manifest(["app.py", "api.py"]), fingerprint)
    assert d.action == "rebuild"
    assert any("file churn" in r for r in d.reasons)


def test_edge_churn_over_threshold_forces_rebuild(fingerprint):
    """app.py holds most of the call graph, so touching it alone moves edges
    past 15% without moving files past 25%."""
    cfg = Config()
    cfg.profile.drift_file_pct = 0.9        # take file churn out of the decision
    d = decide(_manifest(["app.py"]), fingerprint, cfg)
    assert d.action == "rebuild"
    assert any("edge churn" in r for r in d.reasons)


def test_new_language_forces_rebuild(fingerprint):
    d = decide(_manifest(["cmd/main.go"], lang="go"), fingerprint)
    assert d.action == "rebuild"
    assert any("language set changed" in r for r in d.reasons)


def test_thresholds_are_configurable(fingerprint):
    cfg = Config()
    cfg.profile.drift_file_pct = 0.9
    cfg.profile.drift_edge_pct = 0.9
    d = decide(_manifest(["models.py"]), fingerprint, cfg)
    assert d.action == "incremental"


def test_decision_reports_its_numbers(fingerprint):
    d = decide(_manifest(["app.py", "api.py"]), fingerprint)
    assert 0 < d.file_churn <= 1 and d.reasons


def test_binary_files_do_not_count_as_churn(fingerprint):
    m = _manifest(["app.py"])
    m.files.append(FileChange(file_id="9", path="logo.png", change="added",
                              is_binary=True))
    assert decide(m, fingerprint).file_churn == decide(_manifest(["app.py"]),
                                                       fingerprint).file_churn


def test_touched_paths_excludes_deletions_and_binaries():
    m = _manifest(["a.py", "b.py"])
    m.files[1].change = "deleted"
    m.files.append(FileChange(file_id="9", path="x.png", change="added", is_binary=True))
    assert touched_paths(m) == ["a.py"]


# --------------------------------------------------------------------------
# Anchors
# --------------------------------------------------------------------------

def test_anchor_globs_default_to_the_language_catalog():
    globs = anchor_globs(Config())
    assert "**/settings.py" in globs and "requirements*.txt" in globs


def test_config_anchor_globs_win():
    cfg = Config()
    cfg.profile.anchor_globs = ["only/this.py"]
    assert anchor_globs(cfg) == ["only/this.py"]


@pytest.mark.parametrize("path,hit", [
    ("requirements.txt", True), ("requirements-dev.txt", True),
    ("deep/nested/settings.py", True), ("app/urls.py", True),
    ("app/views.py", False), ("readme.md", False),
])
def test_anchor_matching(path, hit):
    assert _matches_anchor(path, anchor_globs(Config())) is hit


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

def test_save_and_load_roundtrip(tmp_path, built, fingerprint):
    cache = ProfileCache("o/r", tmp_path)
    path = cache.save(built.profile, fingerprint, built.cpg)
    assert path.name == "a" * 40

    entry = cache.load("a" * 40)
    assert entry is not None
    assert len(entry.profile.access_control_matrix) == 11
    assert entry.fingerprint.frameworks == ["django", "fastapi", "flask"]
    assert len(entry.cpg.taint_paths) == 2
    assert {n.kind for n in entry.cpg.nodes_of_kind("endpoint")} == {"endpoint"}


def test_cpg_survives_serialization(tmp_path, built, fingerprint):
    """Phase 2 reads the CPG from cache, so its queries must still work."""
    cache = ProfileCache("o/r", tmp_path)
    cache.save(built.profile, fingerprint, built.cpg)
    restored = cache.load("a" * 40).cpg

    assert {n.name for n in restored.unguarded_endpoints()} == {
        "public_index", "admin_export", "get_item", "run_task",
        "PublicView", "LegacyView",
    }
    assert restored.paths_to("sql")[0].sink.name == "cursor.execute"
    assert restored.stats()["nodes"] == built.cpg.stats()["nodes"]


def test_fingerprint_loads_without_the_profile(tmp_path, built, fingerprint):
    """The drift check must stay cheap — it should not have to deserialize the
    profile and CPG just to decide whether to reuse them."""
    cache = ProfileCache("o/r", tmp_path)
    cache.save(built.profile, fingerprint, built.cpg)
    fp = cache.load_fingerprint("a" * 40)
    assert fp is not None and fp.base_sha == "a" * 40


def test_corrupt_entry_reads_as_absent(tmp_path, built, fingerprint):
    """A cold start is always recoverable; raising would fail the review."""
    cache = ProfileCache("o/r", tmp_path)
    path = cache.save(built.profile, fingerprint, built.cpg)
    (path / "profile.json").write_text("{ not json")
    assert cache.load("a" * 40) is None
    assert cache.latest() is None


def test_schema_version_mismatch_reads_as_absent(tmp_path, built, fingerprint):
    cache = ProfileCache("o/r", tmp_path)
    path = cache.save(built.profile, fingerprint, built.cpg)
    meta = json.loads((path / "meta.json").read_text())
    meta["schema_version"] = 999
    (path / "meta.json").write_text(json.dumps(meta))
    assert cache.load("a" * 40) is None


def test_an_analyzer_change_invalidates_a_profile_built_by_the_old_one(tmp_path, built,
                                                                      fingerprint):
    """`profile_version` is the repo's sha and `SCHEMA_VERSION` is the file
    layout, so neither moves when an extraction rule is fixed. Without a third
    key, re-running the benchmark after fixing `promote.py` would have loaded
    profiles built by the buggy code and reported no change."""
    cache = ProfileCache("o/r", tmp_path)
    path = cache.save(built.profile, fingerprint, built.cpg)
    meta = json.loads((path / "meta.json").read_text())
    assert meta["analyzer_version"] == cache_mod.ANALYZER_VERSION

    meta["analyzer_version"] = cache_mod.ANALYZER_VERSION + 1
    (path / "meta.json").write_text(json.dumps(meta))
    assert cache.load("a" * 40) is None
    # The cheap drift read must reject it too, or a stale entry survives by the
    # back door that exists precisely to avoid deserializing the profile.
    assert cache.load_fingerprint("a" * 40) is None


def test_an_entry_predating_the_analyzer_key_is_stale(tmp_path, built, fingerprint):
    """The key was introduced *because* the analyzer had changed, so an entry
    written without it cannot be assumed current."""
    cache = ProfileCache("o/r", tmp_path)
    path = cache.save(built.profile, fingerprint, built.cpg)
    meta = json.loads((path / "meta.json").read_text())
    del meta["analyzer_version"]
    (path / "meta.json").write_text(json.dumps(meta))
    assert cache.load("a" * 40) is None


def test_repos_are_isolated(tmp_path, built, fingerprint):
    a = ProfileCache("o/r", tmp_path)
    b = ProfileCache("other/repo", tmp_path)
    a.save(built.profile, fingerprint, built.cpg)
    assert b.versions() == [] and b.latest() is None


def test_save_is_atomic_and_replaces_in_place(tmp_path, built, fingerprint):
    """Incremental updates write back to the same profile_version (phase-1 §6),
    so `01_profile.ref` stays a stable pointer."""
    cache = ProfileCache("o/r", tmp_path)
    cache.save(built.profile, fingerprint, built.cpg)
    cache.save(built.profile, fingerprint, built.cpg)
    assert cache.versions() == ["a" * 40]
    assert not list(cache.root.glob(".save-*"))


def test_write_ref_records_which_profile_a_run_used(tmp_path, built, fingerprint):
    cache = ProfileCache("o/r", tmp_path)
    path = cache.save(built.profile, fingerprint, built.cpg)
    ref = cache.write_ref(tmp_path / "run", path)
    data = json.loads(ref.read_text())
    assert ref.name == "01_profile.ref"
    assert data["profile_version"] == "a" * 40


def test_invalidate(tmp_path, built, fingerprint):
    cache = ProfileCache("o/r", tmp_path)
    cache.save(built.profile, fingerprint, built.cpg)
    assert cache.invalidate() == ["a" * 40]
    assert cache.versions() == [] and cache.latest() is None


# --------------------------------------------------------------------------
# The acceptance path, end to end
# --------------------------------------------------------------------------

def test_cold_then_warm(tmp_path, built, fingerprint):
    """phase-1 §11: profile once, and the second run reuses it with no parsing."""
    cache = ProfileCache("o/r", tmp_path)
    assert decide(_manifest(["app.py"]), cache.load_fingerprint()).action == "cold"

    cache.save(built.profile, fingerprint, built.cpg)

    warm = decide(_manifest(["app.py"], base_sha="a" * 40), cache.load_fingerprint())
    assert warm.action == "warm"

    entry = cache.load(built.profile.profile_version)
    assert len(entry.profile.access_control_matrix) == 11
