"""Pinning the pipeline's context for replay — Plan 3 Step 2.

The capture exists so the model passes vary only in the model. Two properties
make that true and both are tested here: it must carry nothing that knows the
answer, and it must be the same bytes twice.
"""
import json
from pathlib import Path

import pytest

from pr_review.benchmark import context_capture as cc
from pr_review.benchmark.runner import CaseRun, CorpusRun, case_run_dir
from pr_review.benchmark.schema import AdvisoryRef, BenchCase, CaseRef, Corpus, GTVuln, PRTask

BUNDLE = {
    "group_id": "g0",
    "hunks": [{"id": "f1:h1", "old_range": "1-5", "new_range": "1-5",
               "header": "", "added_lines": [3], "removed_lines": []}],
    "enclosing_symbols": [{"file": "a.py", "start_line": 1, "end_line": 5,
                           "symbol": "a.f", "content": "def f():\n    pass"}],
    "neighbors": [],
    "profile_slice": {"access_control_rows": [], "auth_summary": "",
                      "sensitive_fields": [], "source_nodes": [],
                      "sink_nodes": [], "sanitizer_nodes": []},
    "reachability_hints": [],
    "escalation": "none",
    "escalation_reason": "hunk, enclosing symbol and 1-hop neighbours are sufficient",
}

SECRET = "arbitrary local file write via crafted session archive"


def _case() -> BenchCase:
    return BenchCase(
        id="GHSA-test-0001:vuln", source="ghsa",
        ref=CaseRef(repo="o/r", pr_number=0, base_sha="b" * 40, head_sha="h" * 40),
        pr_task=PRTask(repo="o/r", pr_number=0),
        ground_truth=[GTVuln(cwe="CWE-22", file="a.py", spans=[[3, 3]],
                             note="lines the fix removed")],
        cwe=["CWE-22"],
        advisory=AdvisoryRef(ghsa_id="GHSA-test-0001", summary=SECRET,
                             cwes=["CWE-22"], package="r"),
    )


@pytest.fixture
def captured(tmp_path, monkeypatch):
    """A capture built over one case, with the pipeline stubbed out.

    The pipeline itself is exercised by the corpus runs; what needs a unit test
    is the decision about *what goes into the artifact*, which is the only place
    a leak could be introduced.
    """
    case = _case()
    run_dir = case_run_dir(tmp_path, case)
    run_dir.mkdir(parents=True)
    (run_dir / "02_context_bundles.json").write_text(json.dumps([BUNDLE]))

    monkeypatch.setattr(cc, "tempfile", type("T", (), {
        "mkdtemp": staticmethod(lambda prefix="": str(tmp_path))})())
    monkeypatch.setattr(cc, "shutil", type("S", (), {
        "rmtree": staticmethod(lambda *a, **k: None)})())
    monkeypatch.setattr(cc, "run_corpus", lambda *a, **k: CorpusRun(
        corpus_name="t", selection_criteria="x", runs=[CaseRun(case=case)]))
    corpus = Corpus(name="t", selection_criteria="x", cases=[case])
    return case, cc.capture(corpus, progress=False)


def test_a_capture_carries_no_ground_truth(captured):
    """The leakage rule of `PIVOT_PLAN.md` §1.4, applied to the artifact.

    The prompt is guarded separately. This guards the file the prompt is built
    from, because a producer that reads a leaky artifact is leaky no matter how
    careful its template is.
    """
    case, data = captured
    blob = cc.dumps(data)
    for forbidden, what in ((SECRET, "the advisory summary"),
                            ("ground_truth", "the ground-truth key"),
                            ("lines the fix removed", "the ground-truth note"),
                            ("GHSA-test-0001\"", "the advisory id as a value")):
        assert forbidden not in blob, f"the capture leaks {what}"


def test_a_capture_entry_holds_only_the_declared_fields(captured):
    """An allow-list, not a deny-list.

    A test that greps for today's secrets passes the moment a new field carries
    tomorrow's. Pinning the key set means adding anything at all to a case entry
    has to be a decision someone makes here.
    """
    case, data = captured
    assert set(data["cases"][case.id]) == {
        "repo", "pr_number", "base_sha", "head_sha", "bundles", "stats"}


def test_a_capture_names_what_produced_it(captured):
    case, data = captured
    assert data["capture_version"] == cc.CAPTURE_VERSION
    assert data["analyzer_version"] and data["code_sha"]


def test_serialization_is_stable_under_key_order(captured):
    """`sort_keys` is what makes two captures comparable at all."""
    case, data = captured
    shuffled = {k: data[k] for k in reversed(list(data))}
    assert cc.dumps(shuffled) == cc.dumps(data)


def test_a_failed_case_is_recorded_rather_than_dropped(tmp_path, monkeypatch):
    """A shorter capture reads as a shorter corpus, which is a different claim."""
    case = _case()
    monkeypatch.setattr(cc, "tempfile", type("T", (), {
        "mkdtemp": staticmethod(lambda prefix="": str(tmp_path))})())
    monkeypatch.setattr(cc, "shutil", type("S", (), {
        "rmtree": staticmethod(lambda *a, **k: None)})())
    monkeypatch.setattr(cc, "run_corpus", lambda *a, **k: CorpusRun(
        corpus_name="t", selection_criteria="x",
        runs=[CaseRun(case=case, error="ValueError: no checkout")]))
    data = cc.capture(Corpus(name="t", selection_criteria="x", cases=[case]),
                      progress=False)
    assert data["cases"][case.id] == {"error": "ValueError: no checkout"}
    with pytest.raises(ValueError, match="failed at capture time"):
        cc.bundles_for(data, case.id)


def test_a_capture_from_another_version_is_refused_not_read(tmp_path, captured):
    case, data = captured
    p = tmp_path / "c.json"
    p.write_text(cc.dumps({**data, "capture_version": cc.CAPTURE_VERSION + 1}))
    with pytest.raises(ValueError, match="capture_version"):
        cc.load(p)
    p.write_text(cc.dumps(data))
    assert cc.load(p)["corpus"] == "t"


def test_bundles_come_back_as_objects_and_an_unknown_case_is_an_error(captured):
    case, data = captured
    bundles = cc.bundles_for(data, case.id)
    assert [b.group_id for b in bundles] == ["g0"]
    assert bundles[0].enclosing_symbols[0].symbol == "a.f"
    with pytest.raises(KeyError):
        cc.bundles_for(data, "not-a-case")


def test_case_run_dir_agrees_with_the_pipelines_own_naming(tmp_path):
    """Two modules composing the same path, checked against each other.

    `pipeline._run_dir` creates the directory as a side effect, so it cannot be
    used as a lookup; `case_run_dir` mirrors it. §14.55 is what happens when the
    naming is wrong, so the mirror gets a test rather than a comment.
    """
    from pr_review.pipeline import _run_dir
    from pr_review.benchmark.runner import _case_slug

    case = _case()
    mine = case_run_dir(tmp_path, case)
    theirs = _run_dir(str(tmp_path / _case_slug(case.id)), case.ref.repo,
                      case.pr_task.pr_number, case.ref.head_sha)
    assert mine == theirs


# ---------------------------------------------------------------------------
# The committed capture — the artifact the arm replays
# ---------------------------------------------------------------------------

CONTEXT_DIR = Path(__file__).resolve().parents[1] / "benchmark/context"
COMMITTED = sorted(CONTEXT_DIR.glob("*.json"))


@pytest.fixture(scope="module", params=[p.name for p in COMMITTED])
def committed(request):
    """Every committed capture, not a named one.

    Parametrized on 2026-08-26 when `negative.json` landed: the guards below were
    written for `labelled.json` by name, so a second pinned artifact would have
    arrived with none of them. Discovering the files means the next capture is
    guarded the moment it is committed rather than the moment someone remembers.
    """
    return cc.load(CONTEXT_DIR / request.param)


def test_there_is_a_capture_for_every_corpus_an_llm_arm_can_run():
    """The list this file guards is not allowed to quietly shrink."""
    assert {p.stem for p in COMMITTED} >= {"labelled", "negative"}


def test_the_committed_capture_names_a_clean_commit(committed):
    """A pinned artifact whose provenance reads `<sha>-dirty` cannot be reproduced,
    which is the whole reason for pinning it.

    `head_sha()` reports a dirty tree honestly, so the failure mode is not a wrong
    sha — it is a capture nobody can rebuild, committed and trusted anyway.
    """
    sha = committed["code_sha"]
    assert "dirty" not in sha and "unknown" not in sha, (
        f"the {committed['corpus']} capture was taken from a {sha} tree. "
        "Commit first, re-capture, then commit the capture.")


def test_the_committed_capture_matches_this_builds_analyzer_version(committed):
    """`ANALYZER_VERSION` decides the profile, the profile decides the CPG, and the
    CPG is what the bundles are cut from.

    So a bump silently invalidates this file. The standing rule is to bump it when
    `promote.py`, `cpg.py` or `patterns/*.yaml` change; this makes the capture part
    of what a bump costs, instead of a stale artifact wearing a current filename.
    """
    from pr_review.profile.cache import ANALYZER_VERSION

    assert committed["analyzer_version"] == ANALYZER_VERSION, (
        f"the capture was built at analyzer v{committed['analyzer_version']}, this "
        f"build is v{ANALYZER_VERSION}. Re-capture: the bundles came from a "
        "different CPG.")


def test_the_committed_capture_covers_its_whole_corpus(committed):
    """Which corpus is read off the capture, not assumed from the filename.

    `context_arm.preflight` refuses a run whose capture misses cases, so this is
    the same guarantee checked one layer earlier — at commit time rather than at
    spend time.
    """
    from pr_review.benchmark import corpus as corpus_mod

    corpus = corpus_mod.load(f"benchmark/corpus/{committed['corpus']}.json")
    assert set(committed["cases"]) == {c.id for c in corpus.cases}
    assert not [k for k, v in committed["cases"].items() if "error" in v]


def test_every_ordered_list_in_the_committed_capture_is_ordered(committed):
    """§14.57 checked against the artifact, not just the code path.

    Re-capturing inside the suite would cost ten minutes, so byte-identity stays a
    measurement (§4q). This is the cheap half that still catches the thing that
    matters: a capture regenerated from an unsorted build.
    """
    checked = 0
    for case_id in committed["cases"]:
        for bundle in cc.bundles_for(committed, case_id):
            keys = [(s.file, s.start_line, s.symbol or "") for s in bundle.neighbors]
            assert keys == sorted(keys), f"{case_id}: neighbours unsorted"
            checked += len(keys) > 1
            for name in ("source_nodes", "sink_nodes", "sanitizer_nodes"):
                rows = getattr(bundle.profile_slice, name)
                got = [(r["file"], r["line"], r["name"]) for r in rows]
                assert got == sorted(got), f"{case_id}: {name} unsorted"
                checked += len(got) > 1
    assert checked > 10, (
        f"only {checked} lists in the committed capture had two or more entries, "
        "so this test can barely distinguish sorted from unsorted (§14.57)")
