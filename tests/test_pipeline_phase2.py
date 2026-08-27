"""Pipeline wiring for Phases 1 and 2 (overview §8, phase-2 §1).

The run directory is the replay contract: `01_profile.ref` says which profile a
run used and `02_changeset.json` says what it looked at and what it did not.
These tests are about those artifacts existing, being complete, and — where a
phase was skipped — saying so rather than being silently absent.
"""
import json
from pathlib import Path

import pytest

pytest.importorskip(
    "cap_engine.environment.code_promoter",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from pr_review import pipeline  # noqa: E402
from pr_review.config import Config  # noqa: E402

FIXTURE = "tests/fixtures/sample_app"
PR_DIFF = "tests/fixtures/phase2_pr.diff"


def _config(tmp_path):
    cfg = Config()
    cfg.profile.cache_root = str(tmp_path / "cache")
    return cfg


def _run(tmp_path, **kwargs):
    return pipeline.run_review(
        repo="o/r", pr_number=7, diff_text=open(PR_DIFF).read(),
        config=kwargs.pop("config", None) or _config(tmp_path),
        out_root=str(tmp_path / "runs"),
        base_sha="a" * 40, head_sha="c" * 40, **kwargs,
    )


def _telemetry(result):
    return json.loads((result.out_dir / "telemetry.json").read_text())


def _files_parsed(tel) -> int:
    """How many files the profile phase actually parsed.

    A full build reports `files_parsed`; an incremental splice reports
    `files_reparsed`; a straight cache hit records no profile telemetry at all,
    which means it parsed nothing. All three collapse to one comparable number,
    which is what makes this usable as a work proxy in place of a stopwatch.
    """
    pt = tel["meta"].get("profile_telemetry") or {}
    return pt.get("files_parsed", pt.get("files_reparsed", 0))


# --------------------------------------------------------------------------
# Artifacts
# --------------------------------------------------------------------------

def test_the_run_writes_every_phase_artifact(tmp_path):
    result = _run(tmp_path, base_dir=FIXTURE)
    names = {p.name for p in result.out_dir.iterdir()}
    assert {"00_manifest.json", "01_profile.ref", "02_changeset.json",
            "02_context_bundles.json", "03d_findings.normalized.json",
            "telemetry.json"} <= names


def test_profile_ref_points_at_the_cached_profile(tmp_path):
    result = _run(tmp_path, base_dir=FIXTURE)
    ref = json.loads((result.out_dir / "01_profile.ref").read_text())
    assert ref["profile_version"] == "a" * 40
    assert ref["repo"] == "o/r"
    assert (tmp_path / "cache") in Path(ref["profile_path"]).parents
    assert json.loads((result.out_dir / "02_changeset.json").read_text())[
        "profile_version"] == "a" * 40


def test_changeset_records_both_what_was_analyzed_and_what_was_not(tmp_path):
    result = _run(tmp_path, base_dir=FIXTURE)
    data = json.loads((result.out_dir / "02_changeset.json").read_text())
    assert len(data["groups"]) == result.groups
    assert {d["path"] for d in data["dropped"]} >= {"README.md", "poetry.lock"}
    assert all(d["reason"] and d["detail"] for d in data["dropped"])


def test_context_bundles_are_serializable_and_complete(tmp_path):
    result = _run(tmp_path, base_dir=FIXTURE)
    bundles = json.loads((result.out_dir / "02_context_bundles.json").read_text())
    groups = {g["id"] for g in
              json.loads((result.out_dir / "02_changeset.json").read_text())["groups"]}
    assert {b["group_id"] for b in bundles} == groups
    assert all(b["escalation_reason"] for b in bundles)


# --------------------------------------------------------------------------
# The profile cache — phase-1 §11's warm re-run, end to end
# --------------------------------------------------------------------------

def test_the_second_run_is_warm(tmp_path):
    cfg = _config(tmp_path)
    first = _run(tmp_path, base_dir=FIXTURE, config=cfg)
    cold = _telemetry(first)                       # the re-run overwrites this file
    second = _run(tmp_path, base_dir=FIXTURE, config=cfg)
    warm = _telemetry(second)

    assert cold["meta"]["profile_action"] == "cold"
    assert warm["meta"]["profile_action"] == "warm"

    # Work, not wall-clock. This line used to read
    #     assert warm["phases"]["profile"] < cold["phases"]["profile"]
    # and it flaked (`OPEN_ITEMS.md` §20): a loaded machine can make a 2 ms warm
    # profile lose to a 90 ms cold one, and a red test on this project's
    # headline efficiency claim sends the reader hunting a regression that is not
    # there. Parsed files are what the stopwatch was a proxy FOR -- the warm run
    # is faster *because* it re-parses nothing -- so assert the cause. Same
    # claim, no dependency on machine load.
    assert _files_parsed(cold) >= 1
    assert _files_parsed(warm) < _files_parsed(cold)
    assert first.groups == second.groups and first.dropped == second.dropped


def test_a_warm_run_needs_no_checkout(tmp_path):
    cfg = _config(tmp_path)
    _run(tmp_path, base_dir=FIXTURE, config=cfg)
    result = _run(tmp_path, config=cfg)          # no base_dir at all
    assert _telemetry(result)["meta"]["profile_action"] == "warm"
    assert result.profile_version == "a" * 40


# --------------------------------------------------------------------------
# Degradation — a skipped phase must be loud
# --------------------------------------------------------------------------

def test_without_a_checkout_or_a_cache_phase_one_is_skipped_loudly(tmp_path):
    """A review that never built a profile has no matrix and no CPG, so its
    silence about broken access control is not evidence of absence."""
    result = _run(tmp_path)
    meta = _telemetry(result)["meta"]
    assert meta["profile_action"] == "skipped"
    assert any("PHASE 1 SKIPPED" in n for n in meta["filter_notes"])
    assert any("GUARDRAIL DEGRADED" in n for n in meta["filter_notes"])
    assert result.profile_version == ""


def test_phase_two_still_runs_without_a_profile(tmp_path):
    """Path shape and the guard-edit text pass survive; the run is degraded, not
    absent."""
    result = _run(tmp_path)
    groups = json.loads((result.out_dir / "02_changeset.json").read_text())["groups"]
    app = next(g for g in groups if "app.py" in g["files"])
    assert "guard_removed:login_required" in app["rationale"]


def test_one_directory_cannot_serve_as_both_sides(tmp_path):
    """Passing the same tree twice would make every file AST-equal to itself and
    drop the whole PR down to whatever the guardrail rescued."""
    same = _run(tmp_path, base_dir=FIXTURE, head_dir=FIXTURE)
    only_head = _run(tmp_path, config=_config(tmp_path), base_dir=FIXTURE)
    assert same.dropped == only_head.dropped
    assert same.groups == only_head.groups


def _incremental_run(tmp_path, cfg, pr_number=8, base_sha="d" * 40):
    return pipeline.run_review(
        repo="o/r", pr_number=pr_number,
        diff_text="diff --git a/models.py b/models.py\n--- a/models.py\n+++ b/models.py\n"
                  "@@ -1,3 +1,3 @@\n-\"\"\"Old.\"\"\"\n+\"\"\"New.\"\"\"\n",
        config=cfg, out_root=str(tmp_path / "runs"),
        base_dir=FIXTURE, base_sha=base_sha, head_sha="e" * 40)


def test_an_incremental_decision_patches_instead_of_rebuilding(tmp_path):
    """phase-1 §6: re-parse the touched files, patch in place. The profile is
    unchanged in content and only one file was re-parsed."""
    cfg = _config(tmp_path)
    first = _run(tmp_path, base_dir=FIXTURE, config=cfg)
    full = _telemetry(first)["meta"]["profile_telemetry"]

    result = _incremental_run(tmp_path, cfg)
    meta = _telemetry(result)["meta"]

    assert meta["profile_action"] == "incremental"
    assert meta["profile_telemetry"]["files_reparsed"] == 1     # not the whole repo
    assert meta["profile_telemetry"]["matrix_rows"] == full["matrix_rows"] == 11
    assert meta["profile_telemetry"]["taint_paths"] == 2
    # Phase 2 still routes off the patched profile.
    groups = json.loads((result.out_dir / "02_changeset.json").read_text())["groups"]
    assert [g["touches"] for g in groups] == [["sensitive_field"]]


def test_an_incremental_update_keeps_the_replay_pointer_stable(tmp_path):
    """`profile_version` is the last *full* build's commit and must not move —
    `01_profile.ref` points at it."""
    cfg = _config(tmp_path)
    _run(tmp_path, base_dir=FIXTURE, config=cfg)
    result = _incremental_run(tmp_path, cfg)
    ref = json.loads((result.out_dir / "01_profile.ref").read_text())
    assert ref["profile_version"] == "a" * 40          # not the PR's base "d"*40
    assert result.profile_version == "a" * 40


def test_a_patched_profile_goes_warm_next_time(tmp_path):
    """The fingerprint's base_sha *does* move, or the same base would be
    re-patched forever and the cache never reused."""
    cfg = _config(tmp_path)
    _run(tmp_path, base_dir=FIXTURE, config=cfg)
    _incremental_run(tmp_path, cfg)
    again = _incremental_run(tmp_path, cfg, pr_number=9)
    assert _telemetry(again)["meta"]["profile_action"] == "warm"


def test_an_incremental_update_declares_itself_in_the_profile(tmp_path):
    cfg = _config(tmp_path)
    _run(tmp_path, base_dir=FIXTURE, config=cfg)
    _incremental_run(tmp_path, cfg)
    notes = _telemetry(_incremental_run(tmp_path, cfg, pr_number=10,
                                        base_sha="f" * 40))["meta"]["filter_notes"]
    assert any("INCREMENTAL UPDATE" in n for n in notes)
    assert any("same-size edit" in n for n in notes)


# --------------------------------------------------------------------------
# Telemetry
# --------------------------------------------------------------------------

def test_telemetry_carries_the_filter_and_context_cost(tmp_path):
    result = _run(tmp_path, base_dir=FIXTURE)
    meta = _telemetry(result)["meta"]
    assert meta["filter"]["kept_files"] and meta["filter"]["dropped_files"]
    assert meta["context"]["bundles"] == result.groups
    assert set(meta["coverage_plan"]) == {
        g["id"] for g in
        json.loads((result.out_dir / "02_changeset.json").read_text())["groups"]}


def test_phase_timings_include_profile_and_change(tmp_path):
    phases = _telemetry(_run(tmp_path, base_dir=FIXTURE))["phases"]
    assert {"extract", "profile", "change", "detect", "report"} <= set(phases)


def test_token_cost_is_reported_as_unmeasured_not_low(tmp_path):
    """M1's standing caveat: the fake provider emits CAP's *guessed* Strands
    usage keys, so a zero here means "not measured", never "cheap"."""
    telemetry = _telemetry(_run(tmp_path, base_dir=FIXTURE))
    assert telemetry["tokens"] == {"input": 0, "output": 0}
    assert telemetry["meta"]["profile_telemetry"]["agent_calls"] == 0
