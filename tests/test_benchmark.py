"""The benchmark harness — scoring rules, the ablation, and the runner seam.

Grouped by the property being protected. Most of these guard against a benchmark
that reports a *better* number than the tool deserves, because that is the
failure mode a measuring instrument has: nobody investigates a flattering
result. So the tests here mostly assert that something is counted against us —
that a pre-existing finding is excluded rather than credited, that a near miss is
not a true positive, that a relation-table match is labelled as one.

Nothing here touches the network. The corpus builder's GitHub calls are exercised
only through their pure parts; anything needing a remote is skipped, the same
bargain `test_detect_m2.py` makes for missing scanner binaries.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pr_review.benchmark import corpus as corpus_mod
from pr_review.benchmark import scope
from pr_review.benchmark.metrics import (
    Rate,
    ablation_metrics,
    labelled_metrics,
    negative_metrics,
    pair_metrics,
)
from pr_review.benchmark.report import (
    render_scorecard,
    write_scorecard,
    precheck_scorecard,
    scorecard_target,
)
from pr_review.benchmark.runner import (
    CaseRun,
    CorpusRun,
    _isolated,
    detect_telemetry,
    rescore,
    run_case,
)
from pr_review.benchmark.schema import BenchCase, CaseRef, Corpus, GTVuln, PRTask
from pr_review.benchmark.scoring import (
    CaseScore,
    FindingVerdict,
    ablate_filter,
    cwe_match,
    score_case,
)
from pr_review.config import Config
from pr_review.schema import (
    DetectorKind,
    Evidence,
    Finding,
    Location,
    Provenance,
    Remediation,
    Severity,
    Taxonomy,
)

FIXTURES = Path(__file__).parent / "fixtures"
M2_BASE = FIXTURES / "m2_base"
M2_HEAD = FIXTURES / "m2_head"


def _finding(*, internal="INJ-SQLI", cwe=("CWE-89",), path="app/views.py",
             start=10, end=10, severity=Severity.HIGH, introduced=True,
             tool="structural") -> Finding:
    return Finding(
        id=f"f-{internal}-{path}-{start}",
        fingerprint=f"fp-{internal}-{path}-{start}",
        title=f"{internal} at {path}:{start}",
        taxonomy=Taxonomy(internal=internal, family="Injection",
                          owasp_2025="A05", cwe=list(cwe)),
        severity=severity,
        confidence=7,
        introduced_by_pr=introduced,
        location=Location(file=path, start_line=start, end_line=end),
        evidence=[Evidence(file=path, lines=str(start), snippet="x", why="y")],
        remediation=Remediation(summary="fix it"),
        provenance=Provenance(detector=DetectorKind.STRUCTURAL, tool=tool),
    )


def _case(*, cid="c1", ground_truth=None) -> BenchCase:
    return BenchCase(
        id=cid, source="negative" if not ground_truth else "ghsa",
        ref=CaseRef(repo="o/r", pr_number=1, base_sha="b" * 40, head_sha="h" * 40),
        pr_task=PRTask(repo="o/r", pr_number=1),
        ground_truth=ground_truth or [],
    )


# ---------------------------------------------------------------------------
# The negative-set rule
# ---------------------------------------------------------------------------

def test_every_introduced_finding_on_clean_code_is_a_false_positive():
    score = score_case(_case(), [_finding(), _finding(start=20)])
    assert (score.tp, score.fn, score.fp) == (0, 0, 2)


def test_pre_existing_findings_are_excluded_not_counted_against_us():
    """The repository's backlog is not this tool's noise.

    `findings/delta.py` demotes a pre-existing finding to `status=pre_existing`
    and the gate ignores it. Counting it as a false positive would make the tool
    score worse on an old repository than on a new one for reasons having
    nothing to do with the detectors.
    """
    score = score_case(_case(), [_finding(), _finding(start=20, introduced=False)])
    assert score.fp == 1
    assert score.skipped_pre_existing == 1
    assert score.scored_findings == 1


def test_the_endpoint_stratum_prices_missing_authz_against_the_right_denominator():
    """The corpus-wide average answers a different question than §3.2 asked.

    Most merged PRs touch no endpoint, so `BAC-MISSING-AUTHZ` cannot fire in
    them. Averaging over all of them reports that rule at near-zero — true, and
    not a measurement of it. The stratum restricts to PRs where the detector
    actually saw an endpoint.
    """
    quiet = score_case(_case(cid="no-endpoints"), [])
    quiet.context = {"endpoints": 0}
    noisy = score_case(_case(cid="endpoints"), [
        _finding(internal="BAC-MISSING-AUTHZ", cwe=("CWE-862",), start=5),
        _finding(internal="BAC-MISSING-AUTHZ", cwe=("CWE-862",), start=9),
    ])
    noisy.context = {"endpoints": 4}

    m = negative_metrics([quiet, noisy])
    # Corpus-wide, the rule looks like 1 alarm per PR.
    assert m.fp_per_pr.value == 1.0
    # Restricted to PRs that could produce it, 2 per PR over 4 endpoints.
    assert m.endpoint_cases == 1 and m.endpoints_seen == 4
    assert m.fp_per_endpoint_pr.value == 2.0
    assert m.missing_authz_per_endpoint.value == 0.5


def test_the_stratum_is_derived_not_selected():
    """If no run saw an endpoint the stratum is empty rather than zero.

    An empty denominator has to read as "this corpus cannot answer that", not as
    a clean bill of health for the rule.
    """
    quiet = score_case(_case(), [])
    quiet.context = {"endpoints": 0}
    m = negative_metrics([quiet])
    assert m.endpoint_cases == 0
    assert m.missing_authz_per_endpoint.value is None
    assert "n/a" in m.missing_authz_per_endpoint.render()


def test_a_silent_detector_scores_perfectly_on_the_negative_set():
    """The reason this number may never be published on its own.

    Nothing in the negative set can distinguish a precise tool from one that
    reports nothing, which is why `report.py` prints that sentence next to the
    result rather than in a footnote.
    """
    score = score_case(_case(), [])
    assert score.fp == 0
    m = negative_metrics([score])
    assert m.fp_per_pr.value == 0.0
    assert m.clean_rate.value == 1.0


# ---------------------------------------------------------------------------
# The labelled-set rule: taxonomy AND location
# ---------------------------------------------------------------------------

def test_true_positive_needs_both_taxonomy_and_overlap():
    gt = GTVuln(cwe="CWE-89", file="app/views.py", spans=[(8, 14)])
    score = score_case(_case(ground_truth=[gt]), [_finding(start=10, end=10)])
    assert (score.tp, score.fp, score.fn, score.near_miss) == (1, 0, 0, 0)


def test_right_file_wrong_lines_is_a_near_miss_not_a_true_positive():
    """§3 tracks localization separately because the two defects differ.

    A near miss is a localization bug — the class was right, the reviewer is
    sent to the wrong place. Folding it into TP would claim an accuracy the
    output does not have.
    """
    gt = GTVuln(cwe="CWE-89", file="app/views.py", spans=[(80, 90)])
    score = score_case(_case(ground_truth=[gt]), [_finding(start=10, end=10)])
    assert (score.tp, score.near_miss, score.fn) == (0, 1, 1)


def test_wrong_taxonomy_on_the_right_lines_is_a_false_positive():
    gt = GTVuln(cwe="CWE-89", file="app/views.py", spans=[(8, 14)])
    finding = _finding(internal="CRY-WEAK-ALGO", cwe=("CWE-327",), start=10)
    score = score_case(_case(ground_truth=[gt]), [finding])
    assert (score.tp, score.fp, score.fn) == (0, 1, 1)


def test_a_covered_ground_truth_row_is_never_counted_as_missed():
    """Two ground-truth rows in one file, one finding covering the first.

    The row a finding covers is found, regardless of which row wins the
    best-match comparison for that finding. Tying the two together let a
    genuinely-detected row be scored as a false negative when another row
    outranked it, which understates recall.
    """
    gts = [
        GTVuln(cwe="CWE-89", file="app/views.py", spans=[(8, 14)]),
        GTVuln(cwe="CWE-89", file="app/views.py", spans=[(50, 60)]),
    ]
    score = score_case(_case(ground_truth=gts), [_finding(start=10, end=10)])
    assert score.tp == 1
    assert score.fn == 1
    assert score.missed[0].spans == [(50, 60)]


def test_an_unfound_ground_truth_row_is_a_false_negative():
    gt = GTVuln(cwe="CWE-89", file="app/other.py", spans=[(1, 5)])
    score = score_case(_case(ground_truth=[gt]), [])
    assert score.fn == 1
    assert score.missed[0].file == "app/other.py"


# ---------------------------------------------------------------------------
# The CWE relation table — the place a benchmark cheats
# ---------------------------------------------------------------------------

def test_exact_and_related_cwe_matches_are_distinguishable():
    assert cwe_match(["CWE-78"], "CWE-78") == "exact_cwe"
    assert cwe_match(["CWE-78"], "CWE-77") == "related_cwe"
    assert cwe_match(["CWE-78"], "CWE-89") is None


def test_cwe_spelling_variants_normalize():
    """Advisories spell it every way; a parse failure would read as a miss."""
    for spelling in ("89", "cwe-89", "CWE_89", " CWE-89 "):
        assert cwe_match(["CWE-89"], spelling) == "exact_cwe"


def test_the_scorecard_reports_how_many_tps_the_relation_table_bought():
    gt = GTVuln(cwe="CWE-77", file="app/views.py", spans=[(8, 14)])
    finding = _finding(internal="INJ-CMD", cwe=("CWE-78",), start=10)
    m = labelled_metrics([score_case(_case(ground_truth=[gt]), [finding])])
    assert m.tp == 1
    assert m.tp_related_cwe == 1 and m.tp_exact_cwe == 0
    assert m.relation_table_share.value == 1.0


def test_unrelated_cwes_do_not_match_through_the_table():
    """Guards against a widening that would raise every number at once."""
    assert cwe_match(["CWE-89"], "CWE-22") is None
    assert cwe_match(["CWE-532"], "CWE-798") is None


# ---------------------------------------------------------------------------
# Rates carry their denominators
# ---------------------------------------------------------------------------

def test_a_rate_cannot_be_rendered_without_its_n():
    assert Rate(3, 4).render(2) == "0.75 (3/4)"
    assert Rate(0, 0).render() == "n/a (0 cases)"


def test_precision_over_no_findings_is_not_reported_as_zero():
    """An empty denominator is "we do not know", not a score of 0.0."""
    m = labelled_metrics([score_case(_case(ground_truth=[]), [])])
    assert m.precision.value is None
    assert m.f1 is None


# ---------------------------------------------------------------------------
# The filter ablation
# ---------------------------------------------------------------------------

def test_ablation_finds_a_dropped_ground_truth_file():
    case = _case(ground_truth=[GTVuln(cwe="CWE-89", file="app/views.py",
                                      spans=[(1, 5)])])
    changeset = {"dropped": [
        {"path": "app/views.py", "reason": "docs_only", "guardrail_considered": False},
        {"path": "README.md", "reason": "docs_only", "guardrail_considered": True},
    ]}
    ablation = ablate_filter(case, changeset)
    assert ablation.dropped_gt_files == ["app/views.py"]
    assert ablation.kept == 0
    m = ablation_metrics([ablation])
    assert m.recall_after_filter.value == 0.0
    # The distinction DropRecord.guardrail_considered exists to make.
    assert m.dropped_without_guardrail == 1


def test_ablation_is_clean_when_the_filter_kept_the_vuln_file():
    case = _case(ground_truth=[GTVuln(cwe="CWE-89", file="app/views.py",
                                      spans=[(1, 5)])])
    ablation = ablate_filter(case, {"dropped": [{"path": "README.md",
                                                 "reason": "docs_only"}]})
    assert ablation.dropped_gt_files == []
    assert ablation_metrics([ablation]).recall_after_filter.value == 1.0


# ---------------------------------------------------------------------------
# The runner drives the real pipeline
# ---------------------------------------------------------------------------

def test_runner_drives_run_review_and_reads_back_its_artifacts(tmp_path):
    """The harness must measure the shipping entry point, not a copy of it.

    Errata §14.18's lesson one level up: a harness that reimplements the
    detector sweep validates the harness author's model of the pipeline. This
    asserts the three artifacts a scorecard is built from actually arrive.
    """
    case = BenchCase(
        id="m2-fixture", source="negative",
        ref=CaseRef(repo="o/r", pr_number=9, base_sha="b" * 40, head_sha="h" * 40),
        pr_task=PRTask(
            repo="o/r", pr_number=9,
            diff_text=(FIXTURES / "m2_pr.diff").read_text(),
            base_dir=str(M2_BASE), head_dir=str(M2_HEAD),
        ),
    )
    run = run_case(case, Config(), tmp_path)
    assert run.ok, run.error
    assert run.verdict in {"flagged", "approved"}
    assert run.findings, "the m2 fixture is known to produce findings"
    # Per-detector AdapterRun statuses — the thing that distinguishes "scanned
    # and found nothing" from "binary absent". Nested under `meta` by Telemetry.
    assert detect_telemetry(run), "no per-detector telemetry reached the harness"
    assert "secrets" in detect_telemetry(run)
    # `02_changeset.json` is what the ablation queries.
    assert "dropped" in run.changeset


def test_runner_refuses_one_tree_for_both_sides(tmp_path):
    """`pipeline._source_reader` treats identical dirs as head-only, which would
    make every file AST-equal to itself and silently drop the whole PR. Over a
    corpus that would read as a flawless false-positive rate."""
    case = BenchCase(
        id="same-tree", source="negative",
        ref=CaseRef(repo="o/r", pr_number=9, base_sha="b" * 40, head_sha="h" * 40),
        pr_task=PRTask(repo="o/r", pr_number=9, diff_text="",
                       base_dir=str(M2_HEAD), head_dir=str(M2_HEAD)),
    )
    run = run_case(case, Config(), tmp_path)
    assert not run.ok
    assert "same tree" in run.error


def test_a_failing_case_does_not_end_the_corpus_run(tmp_path):
    case = BenchCase(
        id="missing-tree", source="negative",
        ref=CaseRef(repo="o/r", pr_number=1, base_sha="b" * 40, head_sha="h" * 40),
        pr_task=PRTask(repo="o/r", pr_number=1, diff_text="",
                       base_dir=str(tmp_path / "nope"),
                       head_dir=str(tmp_path / "also-nope")),
    )
    run = run_case(case, Config(), tmp_path)
    assert not run.ok and "does not exist" in run.error


# ---------------------------------------------------------------------------
# Pinning and reproducibility
# ---------------------------------------------------------------------------

def test_a_corpus_without_selection_criteria_is_refused(tmp_path):
    """It is printed verbatim in every scorecard and is the reader's only
    defense against a corpus picked to flatter the tool."""
    bad = Corpus(name="x", selection_criteria="   ")
    with pytest.raises(corpus_mod.CorpusError, match="selection_criteria"):
        corpus_mod.save(bad, tmp_path / "c.json")


def test_a_pinned_corpus_round_trips(tmp_path):
    original = Corpus(name="negative", selection_criteria="ten Python web repos",
                      cases=[_case(cid="a"), _case(cid="b")])
    path = corpus_mod.save(original, tmp_path / "c.json")
    assert corpus_mod.load(path).cases[1].id == "b"


def test_every_pinned_case_carries_what_re_derivation_needs():
    """§4's `repo_snapshot: str` is a local path, which pins nothing."""
    case = _case()
    for field in ("repo", "pr_number", "base_sha", "head_sha"):
        assert getattr(case.ref, field), f"{field} is what makes the case re-derivable"


# ---------------------------------------------------------------------------
# The scorecard states its own limits
# ---------------------------------------------------------------------------

def test_the_scorecard_carries_the_honesty_clauses_in_its_body():
    """These are load-bearing sentences, not decoration — a reader who quotes a
    number from this document must find the caveat attached to it."""
    run = CorpusRun(corpus_name="negative",
                    selection_criteria="ten Python web repos",
                    scores=[score_case(_case(), [_finding()])])
    text = render_scorecard(run)
    assert "UNMEASURED" in text                 # never a 0 for cost
    assert "upper bound" in text                # the negative set's limit
    assert "3a only" in text.lower()            # scope
    assert "not comparable" in text.lower()     # vs the §7 / Gemini figure
    assert "ten Python web repos" in text       # selection criteria, verbatim


def test_the_ablation_section_states_that_the_filter_does_not_gate_detection():
    case = _case(ground_truth=[GTVuln(cwe="CWE-89", file="a.py", spans=[(1, 2)])])
    run = CorpusRun(corpus_name="labelled", selection_criteria="x",
                    scores=[score_case(case, [])],
                    ablations=[ablate_filter(case, {"dropped": []})])
    text = render_scorecard(run)
    assert "does not gate" in text
    assert "M3" in text


def test_a_rerun_on_the_same_day_cannot_delete_the_run_it_is_compared_against(tmp_path):
    """Results are keyed by date, but measure -> fix -> measure happens inside
    one day. Silently overwriting would destroy the baseline at exactly the
    moment it started to matter."""
    run = CorpusRun(corpus_name="negative", selection_criteria="x",
                    scores=[score_case(_case(), [])])
    first = write_scorecard(run, root=tmp_path)

    with pytest.raises(FileExistsError):
        write_scorecard(run, root=tmp_path)

    labelled = write_scorecard(run, root=tmp_path, label="after-fix")
    assert labelled != first and labelled.exists() and first.exists()
    assert write_scorecard(run, root=tmp_path, overwrite=True) == first


def test_the_collision_is_discoverable_before_the_run_not_after_it(tmp_path):
    """§4. The refusal above is correct; its timing was not. It fires when
    `write_scorecard` is reached, which is after `run_corpus` returns -- 844
    seconds on 2026-08-08, producing a scorecard on stdout and no dump."""
    run = CorpusRun(corpus_name="negative", selection_criteria="x",
                    scores=[score_case(_case(), [])])
    precheck_scorecard("negative", tmp_path)          # nothing there yet
    write_scorecard(run, root=tmp_path)

    with pytest.raises(FileExistsError, match="rather than now"):
        precheck_scorecard("negative", tmp_path)

    # A different label is the documented escape, and it must still be free.
    precheck_scorecard("negative", tmp_path, label="after-fix")


def test_two_corpora_under_one_label_collide_on_the_dump_not_the_scorecard(tmp_path):
    """The actual §4 failure, which is why checking only the markdown is not
    enough: the second corpus writes `labelled.md`, which is free, but `run.json`
    is one per DIRECTORY and is already taken. The run that is lost is the
    expensive half."""
    run = CorpusRun(corpus_name="negative", selection_criteria="x",
                    scores=[score_case(_case(), [])])
    write_scorecard(run, root=tmp_path, label="shared")

    md, dump = scorecard_target("labelled", tmp_path, label="shared")
    assert not md.exists() and dump.exists(), "the premise: only the dump collides"

    with pytest.raises(FileExistsError, match="run.json"):
        precheck_scorecard("labelled", tmp_path, label="shared")

    # `dump=False` is a rescore that is deliberately not re-pinning its source,
    # so it may land in a directory whose dump is already there.
    precheck_scorecard("labelled", tmp_path, label="shared", dump=False)


def test_the_scorecard_names_the_commit_it_measured():
    """On a pinned corpus the code is the only variable, so it is the only thing
    that distinguishes two scorecards."""
    run = CorpusRun(corpus_name="negative", selection_criteria="x",
                    scores=[score_case(_case(), [])])
    assert "Code under measurement" in render_scorecard(run)


def test_detector_status_counts_reach_the_scorecard():
    """A false-positive rate over a corpus where semgrep never ran is a rate for
    a tool that never ran, and nothing else in the document would say so."""
    run = CorpusRun(corpus_name="negative", selection_criteria="x",
                    scores=[score_case(_case(), [])],
                    detector_status={"semgrep": {"missing_tool": 12}})
    assert "missing_tool: 12" in render_scorecard(run)


# ---------------------------------------------------------------------------
# The in-scope stratum — derived from the detectors, never hand-listed
# ---------------------------------------------------------------------------

def test_the_scope_set_is_read_out_of_the_detectors_own_tables():
    """A hand-maintained list of "CWEs we cover" is a number-flattering edit
    waiting to happen. This reads the sink map, the secrets rules and the SARIF
    mapping tables instead — so if a refactor renames one, the set shrinks and
    these fail rather than the scorecard reporting a better number."""
    ids = scope.detector_internal_ids()
    # One per detector family, so no single table can go missing quietly.
    for expected in ("INJ-SQLI",            # structural sink map
                     "BAC-MISSING-AUTHZ",   # structural access control
                     "SEC-AWS-KEY",         # secrets rules
                     "SC-VULN-DEP",         # sca, through the mapping tables
                     "CFG-IAC"):            # iac fallback
        assert expected in ids, f"{expected} vanished from the derived scope set"
    assert len(scope.in_scope_cwes()) > 10


def test_classes_with_no_detector_are_out_of_scope():
    """Half a recent advisory sample is these. Counting them against the tool
    measures the roadmap, not the detectors."""
    for cwe in ("CWE-400", "CWE-1333", "CWE-834", "CWE-455", "CWE-61"):
        assert not scope.is_in_scope(cwe), f"{cwe} has no 3a detector"


def test_scope_uses_the_same_cwe_relations_as_scoring():
    """Deciding scope by string equality while scoring decides truth by the
    relation table would let a case be scored against a rule the stratum says is
    out of reach, or the reverse."""
    # CWE-78 is reachable through the CWE-77/78 group, not by exact match.
    assert scope.is_in_scope("CWE-78")
    assert scope.is_in_scope("CWE-22")


def test_an_out_of_scope_miss_does_not_lower_in_scope_recall():
    gt_reach = GTVuln(cwe="CWE-89", file="a.py", spans=[(1, 5)])
    gt_out = GTVuln(cwe="CWE-1333", file="b.py", spans=[(1, 5)])
    found = _finding(cwe=("CWE-89",), path="a.py", start=2, end=2)
    score = score_case(_case(cid="p1", ground_truth=[gt_reach, gt_out]), [found])

    m = labelled_metrics([score])
    assert (m.tp, m.fn) == (1, 1)
    assert m.recall.render() == "0.500 (1/2)"
    # The CWE-1333 row is a milestone boundary, not a detector defect.
    assert m.in_scope_recall.render() == "1.000 (1/1)"
    assert m.out_of_scope_fn == 1
    assert m.out_of_scope_cwes == {"CWE-1333": 1}


# ---------------------------------------------------------------------------
# Detected, then attributed to the baseline
# ---------------------------------------------------------------------------

def test_a_miss_the_detector_actually_found_is_distinguished_from_one_it_did_not():
    """`recall` prices both at zero, and they have different fixes. Measured on
    the first labelled run: 93 findings landed in a ground-truth file this way."""
    gt = GTVuln(cwe="CWE-89", file="a.py", spans=[(10, 20)])
    on_the_lines = _finding(cwe=("CWE-89",), path="a.py", start=12, end=12,
                            introduced=False)
    score = score_case(_case(cid="c", ground_truth=[gt]), [on_the_lines])

    assert score.fn == 1                      # still a miss: it never scored
    assert score.baseline.overlapping == [gt]  # ...but the detector found it
    assert score.baseline.file_only == []

    m = labelled_metrics([score])
    assert m.recall.render() == "0.000 (0/1)"
    assert m.reached_the_right_file.render() == "1.000 (1/1)"


def test_the_right_file_and_the_right_lines_are_counted_apart():
    """One would have been a true positive but for delta scoping and argues
    about attribution; the other was only ever a near miss and argues about
    localization."""
    gt = GTVuln(cwe="CWE-89", file="a.py", spans=[(10, 20)])
    elsewhere = _finding(cwe=("CWE-89",), path="a.py", start=400, end=400,
                         introduced=False)
    score = score_case(_case(cid="c", ground_truth=[gt]), [elsewhere])
    assert score.baseline.file_only == [gt] and score.baseline.overlapping == []


def test_a_credited_row_is_not_also_owed_to_the_baseline():
    """Otherwise the columns stop summing to the ground-truth total."""
    gt = GTVuln(cwe="CWE-89", file="a.py", spans=[(10, 20)])
    score = score_case(_case(cid="c", ground_truth=[gt]), [
        _finding(cwe=("CWE-89",), path="a.py", start=12, end=12),
        _finding(cwe=("CWE-89",), path="a.py", start=15, end=15, introduced=False),
    ])
    assert score.tp == 1 and score.fn == 0
    assert score.baseline.total == 0


def test_a_wrong_taxonomy_in_the_right_file_is_not_a_baseline_attribution():
    gt = GTVuln(cwe="CWE-89", file="a.py", spans=[(10, 20)])
    unrelated = _finding(cwe=("CWE-611",), path="a.py", start=12, end=12,
                         introduced=False)
    score = score_case(_case(cid="c", ground_truth=[gt]), [unrelated])
    assert score.baseline.total == 0


def test_a_labelled_dump_keeps_pre_existing_findings_and_a_negative_one_does_not():
    """They answer a recall question on a labelled case and are read by nothing
    on a negative one — where one of them was 1.25 MB."""
    labelled = _corpus_run(labelled=True).to_dict()["cases"][0]
    negative = _corpus_run(labelled=False).to_dict()["cases"][0]

    assert len(labelled["findings"]) == 2          # introduced + pre-existing
    assert len(negative["findings"]) == 1          # introduced only
    assert labelled["pre_existing"] == negative["pre_existing"] == 1


# ---------------------------------------------------------------------------
# The paired control
# ---------------------------------------------------------------------------

def _pair_scores(*, vuln_tp: bool, control_fp: bool):
    gt = [GTVuln(cwe="CWE-89", file="a.py", spans=[(1, 5)])]
    vuln = score_case(_case(cid="G:vuln", ground_truth=gt),
                      [_finding(path="a.py", start=2, end=2)] if vuln_tp else [])
    control = score_case(_case(cid="G:control"),
                         [_finding(path="a.py", start=2, end=2)] if control_fp else [])
    pair_of = {"G:vuln": "G", "G:control": "G"}
    labelled_of = {"G:vuln": True, "G:control": False}
    return pair_metrics([vuln, control], pair_of, labelled_of)


def test_only_flagging_the_vulnerable_side_and_not_the_fix_counts():
    """The point of the control: a detector that fires on the file in both
    states scores identical recall to one that found the vulnerability."""
    assert _pair_scores(vuln_tp=True, control_fp=False).detected_and_control_clean == 1
    assert _pair_scores(vuln_tp=True, control_fp=False).discriminated.render(2) == "1.00 (1/1)"


def test_a_detector_that_fires_on_both_sides_is_not_a_success():
    m = _pair_scores(vuln_tp=True, control_fp=True)
    assert m.detected_but_control_also_flagged == 1
    assert m.detected_and_control_clean == 0
    assert m.discriminated.render(2) == "0.00 (0/1)"


def test_a_missed_vulnerability_is_a_miss_however_quiet_the_control():
    m = _pair_scores(vuln_tp=False, control_fp=False)
    assert (m.missed, m.detected_and_control_clean) == (1, 0)


def test_a_half_finished_pair_is_excluded_rather_than_counted():
    """A case that errored leaves one side. Scoring the survivor would make an
    infrastructure failure look like a detection result."""
    gt = [GTVuln(cwe="CWE-89", file="a.py", spans=[(1, 5)])]
    only_vuln = score_case(_case(cid="G:vuln", ground_truth=gt), [])
    m = pair_metrics([only_vuln], {"G:vuln": "G"}, {"G:vuln": True})
    assert (m.pairs, m.unpaired) == (0, 1)
    assert m.discriminated.render() == "n/a (0 cases)"


# ---------------------------------------------------------------------------
# Profile isolation
# ---------------------------------------------------------------------------

def test_cold_profiles_gives_each_case_its_own_cache(tmp_path):
    """`drift.decide()` reads the latest fingerprint for a repo, not one
    matching this case. On a paired corpus the two halves differ by one commit,
    so the second would patch the first's profile — one side of every pair built
    cold, the other patched."""
    base = Config()
    a = _isolated(base, tmp_path, _case(cid="G:vuln"))
    b = _isolated(base, tmp_path, _case(cid="G:control"))

    assert a.profile.cache_root != b.profile.cache_root
    # ...and the caller's config is untouched, or case 3 would inherit case 2's.
    assert base.profile.cache_root == Config().profile.cache_root


def test_the_scorecard_says_whether_profiles_were_isolated():
    """It changes what was measured, not just how fast, so a reader comparing
    two scorecards has to be able to see it."""
    run = CorpusRun(corpus_name="labelled", selection_criteria="x",
                    scores=[score_case(_case(), [])], cold_profiles=True)
    assert "isolated per case" in render_scorecard(run)
    assert "isolated per case" not in render_scorecard(
        CorpusRun(corpus_name="labelled", selection_criteria="x",
                  scores=[score_case(_case(), [])]))


# ---------------------------------------------------------------------------
# Serialization — a run costs hours, a scoring rule is an opinion
# ---------------------------------------------------------------------------

def _corpus_run(*, labelled=False) -> CorpusRun:
    """A CorpusRun in the shape `run_corpus` leaves it, scores included."""
    gt = [GTVuln(cwe="CWE-89", file="app/views.py", spans=[(10, 10)])]
    case = _case(cid="c1", ground_truth=gt if labelled else None)
    case.pr_task.diff_text = "x" * 5000
    run = CorpusRun(corpus_name="negative", selection_criteria="ten repos",
                    started_at="2026-08-07T10:00:00", code_sha="abc1234",
                    wall_s=1244.0)
    run.runs = [CaseRun(
        case=case,
        findings=[_finding(), _finding(start=20, introduced=False)],
        changeset={"dropped": [{"path": "app/views.py", "reason": "docs-only"}],
                   "groups": [{"id": "g1"}, {"id": "g2"}]},
        telemetry={"meta": {"detect": {
            "structural": {"status": "ran", "endpoints": 7, "taint_paths": 1},
            "semgrep": {"status": "missing_tool", "files": 0},
            "baseline": {"source": "cache"},
        }}},
        verdict="flagged", wall_s=12.5, changed_files=2,
    )]
    from pr_review.benchmark.runner import _score_all
    _score_all(run)
    return run


def test_a_run_round_trips_to_identical_metrics():
    """The dump exists so a scoring change costs seconds, which is only true if
    replaying it reproduces the run exactly."""
    original = _corpus_run(labelled=True)
    replayed = rescore(original.to_dict())

    # The rendered numbers, not just the objects: the scorecard is what anyone
    # actually reads, and it is what a rescore has to reproduce.
    def metric_lines(run: CorpusRun) -> list[str]:
        return [ln for ln in render_scorecard(run).splitlines()
                if ln.startswith("- **")]
    assert len(metric_lines(original)) > 5, "nothing was compared"
    assert metric_lines(replayed) == metric_lines(original)

    assert [s.case_id for s in replayed.scores] == [s.case_id for s in original.scores]
    assert replayed.scores[0].tp == original.scores[0].tp
    assert replayed.scores[0].fp == original.scores[0].fp
    assert replayed.scores[0].endpoints == original.scores[0].endpoints
    assert replayed.scores[0].skipped_pre_existing == 1
    assert replayed.scores[0].context == original.scores[0].context
    assert replayed.detector_status == original.detector_status
    # The ablation reads the drop records, which means they survived the dump.
    assert replayed.ablations[0].dropped_gt_files == ["app/views.py"]


def test_the_dump_drops_the_diff_but_keeps_the_ground_truth():
    """`diff_text` is 7 MB on the negative corpus and is re-derivable from the
    pinned corpus; the ground truth is the one thing that is not."""
    run = _corpus_run(labelled=True)
    dumped = run.to_dict()
    case = dumped["cases"][0]["case"]
    assert case["pr_task"]["diff_text"] == ""
    assert case["ground_truth"][0]["cwe"] == "CWE-89"
    # ...and the run it was taken from was not mutated on the way out, or a
    # dump would quietly destroy the corpus it was dumped from.
    assert len(run.runs[0].case.pr_task.diff_text) == 5000


def test_the_dump_keeps_pre_existing_findings_as_a_count_not_as_objects():
    """Nothing downstream reads a pre-existing finding, and they are not free:
    one in the netbox corpus carries a 1.25 MB evidence snippet. The *count* is
    reported, so it has to survive; the objects do not."""
    run = _corpus_run()
    assert run.scores[0].skipped_pre_existing == 1

    dumped = run.to_dict()
    case = dumped["cases"][0]
    assert [f["introduced_by_pr"] for f in case["findings"]] == [True]
    assert case["pre_existing"] == 1

    replayed = rescore(dumped)
    assert replayed.scores[0].skipped_pre_existing == 1
    assert "excluded from scoring: 1" in render_scorecard(replayed)


def test_rescoring_recomputes_rather_than_replaying_a_stored_verdict(monkeypatch):
    """The whole point is that a scoring rule can change. If the dump carried
    verdicts instead of findings, this would keep reporting the old answer."""
    from pr_review.benchmark import scoring

    gt = [GTVuln(cwe="CWE-89", file="app/views.py", spans=[(10, 10)])]
    case = _case(cid="c1", ground_truth=gt)
    run = CorpusRun(corpus_name="labelled", selection_criteria="x")
    # CWE-611 is unrelated to the ground truth's CWE-89 under the shipped table.
    run.runs = [CaseRun(case=case, findings=[_finding(cwe=("CWE-611",))])]
    from pr_review.benchmark.runner import _score_all
    _score_all(run)
    assert (run.scores[0].tp, run.scores[0].fp) == (0, 1)

    dump = run.to_dict()
    monkeypatch.setattr(scoring, "_CWE_GROUPS",
                        (frozenset({"CWE-89", "CWE-611"}),))
    replayed = rescore(dump)
    assert (replayed.scores[0].tp, replayed.scores[0].fp) == (1, 0)


def test_a_dump_from_an_older_build_is_refused_not_silently_rescored():
    """A dump written before the dump carried what scoring now reads would be
    rescored against absent fields, and the result would look like a finding."""
    stale = _corpus_run().to_dict()
    stale["dump_version"] = 0
    with pytest.raises(ValueError, match="dump_version|version"):
        rescore(stale)


def test_a_rescored_scorecard_names_the_run_it_replayed(tmp_path):
    """Two cards can disagree because the code moved or because the scoring
    moved. The document has to say which."""
    replayed = rescore(_corpus_run().to_dict())
    text = render_scorecard(replayed)
    assert "Rescored" in text
    assert "abc1234" in text                 # the sha that produced the findings
    assert "not re-executed" in text


def test_the_run_dump_lands_beside_the_scorecard_and_is_not_clobbered(tmp_path):
    """`run.json` is the expensive artifact; the scorecard is a render of it.
    Blind spot #9 was true because only the render was kept."""
    run = _corpus_run()
    path = write_scorecard(run, root=tmp_path)
    dump = path.parent / "run.json"
    assert dump.exists()
    assert json.loads(dump.read_text())["cases"][0]["case"]["id"] == "c1"

    with pytest.raises(FileExistsError):
        write_scorecard(run, root=tmp_path)


# ---------------------------------------------------------------------------
# Arm 2b wiring: model spend must reach the dump, and a run that predates it
# must still rescore. Cost is not a scored quantity, which is why it is not
# guarded by _DUMP_VERSION.
# ---------------------------------------------------------------------------

class _FakeAccountingProvider:
    def __init__(self):
        self.calls = []

    def complete(self, messages, tools=None, **cfg):
        self.calls.append(cfg)
        return '{}'

    def accounting(self, since: int = 0):
        calls = self.calls[since:]
        return {"calls": len(calls), "cost_usd": 0.01 * len(calls),
                "uncached_tokens": 100 * len(calls),
                "cached_tokens": 6000 * len(calls),
                "models": ["haiku"], "tool_denials": 0, "effort": []}


def test_provider_accounting_is_duck_typed():
    from pr_review.benchmark.runner import _provider_accounting
    assert _provider_accounting(None) == {}
    assert _provider_accounting(object()) == {}
    p = _FakeAccountingProvider()
    p.complete([], model_id="x")
    assert _provider_accounting(p)["calls"] == 1


def test_accounting_since_isolates_one_cases_spend():
    """A per-case cost and a corpus total from one ledger, so the two cannot
    disagree the way two ledgers would."""
    from pr_review.benchmark.runner import _provider_accounting
    p = _FakeAccountingProvider()
    p.complete([], model_id="x")
    mark = len(p.calls)
    p.complete([], model_id="x")
    assert _provider_accounting(p, mark)["calls"] == 1     # just this case
    assert _provider_accounting(p)["calls"] == 2           # the whole run


def test_model_cost_survives_the_dump_round_trip():
    from pr_review.benchmark.runner import CaseRun
    from pr_review.benchmark.schema import BenchCase, CaseRef, PRTask
    case = BenchCase(id="c1", source="negative",
                     ref=CaseRef(repo="o/r", pr_number=1, base_sha="a", head_sha="b"),
                     pr_task=PRTask(repo="o/r", pr_number=1))
    run = CaseRun(case=case, model_cost={"calls": 2, "cost_usd": 0.03})
    assert CaseRun.from_dict(run.to_dict()).model_cost == {"calls": 2, "cost_usd": 0.03}


def test_a_dump_written_before_cost_existed_still_loads():
    """The eighteen existing runs. Absent cost is accurate for them -- no model
    ran -- so this must not raise, and must not invent a zero."""
    from pr_review.benchmark.runner import CaseRun
    from pr_review.benchmark.schema import BenchCase, CaseRef, PRTask
    case = BenchCase(id="c1", source="negative",
                     ref=CaseRef(repo="o/r", pr_number=1, base_sha="a", head_sha="b"),
                     pr_task=PRTask(repo="o/r", pr_number=1))
    old = CaseRun(case=case).to_dict()
    del old["model_cost"]
    assert CaseRun.from_dict(old).model_cost == {}


def test_an_unknown_triage_provider_is_refused():
    from pr_review.benchmark.__main__ import _build_triage_provider
    assert _build_triage_provider("none") is None
    assert _build_triage_provider("") is None
    with pytest.raises(SystemExit):
        _build_triage_provider("gpt-9")


def test_the_cost_line_reports_what_the_run_actually_spent():
    """It was a constant, and on 2026-08-21 it printed "no model is invoked
    anywhere in this harness" on a scorecard for a run that made 33 calls and
    cost $0.95. A hardcoded honesty notice is honest only until the thing it
    describes changes."""
    from pr_review.benchmark.report import render_cost
    from pr_review.benchmark.runner import CorpusRun

    run = CorpusRun(corpus_name="x", selection_criteria="y")
    assert "UNMEASURED" in render_cost(run)          # no model ran: still true

    run.model_accounting = {"calls": 33, "cost_usd": 0.9537,
                            "uncached_tokens": 80794,
                            "cached_tokens": 239553,
                            "models": ["haiku"], "effort": ["low"]}
    out = render_cost(run)
    assert "MEASURED" in out and "UNMEASURED" not in out
    assert "33 model call" in out and "0.9537" in out
    # Both numbers, because either alone misleads.
    assert "80,794" in out and "239,553" in out


def test_the_cost_line_refuses_to_call_the_uncached_bucket_ours():
    """§14.44. This line printed "**11,975** ours (prompt + answer) plus
    **617,290** of CLI transport overhead" for arm 3. Both labels were wrong:
    our prompt is in the cached figure. A renderer that swapped one mislabelled
    pair for another would repeat the error, so the wording is pinned."""
    from pr_review.benchmark.report import render_cost
    from pr_review.benchmark.runner import CorpusRun

    run = CorpusRun(corpus_name="x", selection_criteria="y")
    run.model_accounting = {"calls": 52, "cost_usd": 2.561129,
                            "uncached_tokens": 11975, "cached_tokens": 617290,
                            "models": ["sonnet"], "effort": ["low"]}
    out = render_cost(run)
    assert "neither bucket alone names a party" in out
    # The ours/theirs split is still reported -- it is the useful number -- but
    # only as derived from a calibration, never as something this run measured.
    assert "Derived, not measured here" in out
    assert "379,600" in out                        # 52 x 7,300 of harness
    assert "249,665" in out                        # the remainder, ours
    # And the claim that produced the defect must not come back.
    assert "ours (prompt + answer)" not in out


def test_the_derived_split_subtracts_from_the_total_not_the_cached_bucket():
    """Arm 2b falsified the first repair. Its 33 haiku triage calls put 80,794
    tokens in the *uncached* bucket -- our prompts, below haiku's minimum
    cacheable length -- and only 239,553 cached. Subtracting a 240,900-token
    floor from the cached bucket alone reported **0 tokens of our own content**
    for a run that had plainly sent some.

    So the floor comes off the total, and it is capped at the cached bucket
    because a cached-by-construction floor cannot exceed it."""
    from pr_review.benchmark.report import render_cost
    from pr_review.benchmark.runner import CorpusRun

    run = CorpusRun(corpus_name="x", selection_criteria="y")
    run.model_accounting = {"calls": 33, "cost_usd": 0.953741,
                            "uncached_tokens": 80794, "cached_tokens": 239553,
                            "models": ["haiku"], "effort": []}
    out = render_cost(run)
    assert "~**239,553** of the total is harness" in out   # capped, not 240,900
    assert "~**80,794** is ours" in out                    # not 0


def test_old_dumps_still_render_their_cost_line():
    """The five runs stored on 2026-08-21 carry the old key names. The numbers
    were always cached/uncached -- only the labels were wrong -- so this is a
    rename, not a migration, and re-rendering them must not need a re-run."""
    from pr_review.benchmark.report import render_cost
    from pr_review.benchmark.runner import CorpusRun

    run = CorpusRun(corpus_name="x", selection_criteria="y")
    run.model_accounting = {"calls": 33, "cost_usd": 0.9537,
                            "content_tokens": 80794,
                            "transport_overhead_tokens": 239553,
                            "models": ["haiku"], "effort": ["low"]}
    out = render_cost(run)
    assert "80,794" in out and "239,553" in out
    assert "MEASURED" in out


def test_a_zero_call_accounting_still_reads_as_unmeasured():
    """`{"calls": 0}` means no model ran, which is the UNMEASURED case -- not a
    measured zero."""
    from pr_review.benchmark.report import render_cost
    from pr_review.benchmark.runner import CorpusRun
    run = CorpusRun(corpus_name="x", selection_criteria="y")
    run.model_accounting = {"calls": 0, "cost_usd": 0.0}
    assert "UNMEASURED" in render_cost(run)


# -- delta scoping, the axis nothing reported -------------------------------

def test_suppression_reports_what_delta_scoping_removed():
    """§14.46. `findings/delta.py` drops 86% of the detectors' raw output on the
    negative corpus and 97% on the labelled one, and until 2026-08-22 the only
    trace in a scorecard was a line saying how many were "excluded from
    scoring". Every metric here was aimed at recall — the axis this tool is
    worst at — so its largest effect had no number anywhere."""
    from pr_review.benchmark.metrics import negative_metrics

    scores = [
        CaseScore(case_id="a", labelled=False, scored_findings=1,
                  skipped_pre_existing=7,
                  verdicts=[FindingVerdict(_finding(), "fp")]),
        CaseScore(case_id="b", labelled=False, scored_findings=0,
                  skipped_pre_existing=2),
    ]
    m = negative_metrics(scores)
    assert m.raw_findings == 10                       # 1 reported + 9 dropped
    assert m.suppression.render(3) == "0.900 (9/10)"
    assert m.fp_per_pr.render(2) == "0.50 (1/2)"
    assert m.fp_per_pr_unscoped.render(2) == "5.00 (10/2)"


def test_the_unscoped_rate_is_marked_derived_not_measured():
    """It is the arithmetic of turning scoping off, not a run with it off. A
    genuinely unscoped run also loses Semgrep's own `--baseline-commit` scoping,
    so the real figure is this or worse — and `no-baseline.yaml` measures the
    middle tier rather than this one."""
    from pr_review.benchmark.metrics import negative_metrics
    from pr_review.benchmark.report import render_delta_scoping

    m = negative_metrics([
        CaseScore(case_id="a", labelled=False, scored_findings=1,
                  skipped_pre_existing=7,
                  verdicts=[FindingVerdict(_finding(), "fp")])])
    out = "\n".join(render_delta_scoping(m, None))
    assert "derived" in out.lower()
    assert "arithmetic, not a run" in out


def test_the_ladder_warns_that_the_middle_tier_lost_a_true_finding():
    """§14.48. Hunk scoping's gate-relevant rate (0.00) is *better* than the
    full pipeline's (0.02) because it dropped the one correct HIGH on the
    corpus — an SCA finding at a lockfile line the PR did not literally edit.
    A reader comparing the two columns without that sentence concludes the
    degraded mode is safer, which is backwards."""
    from pr_review.benchmark.metrics import negative_metrics
    from pr_review.benchmark.report import render_delta_scoping

    m = negative_metrics([
        CaseScore(case_id="a", labelled=False, scored_findings=1,
                  skipped_pre_existing=7,
                  verdicts=[FindingVerdict(_finding(), "fp")])])
    out = "\n".join(render_delta_scoping(m, None))
    assert "not the bottom tier with less noise" in out
    assert "diff the finding sets before believing it" in out.lower()
    assert "gained five medium alarms and lost one HIGH" in out


def test_the_scorecard_refuses_to_call_suppression_a_moat():
    """Two claims, and the second was added after an experiment falsified the
    first draft of this section within the hour (§14.47).

    `llm-diff-baseline.md` asks the model for vulnerabilities the diff
    "introduces **or leaves present in the code shown**", so arm 3 was told to
    report pre-existing issues and then scored as wrong for each — its
    `pre_existing = 0` is the prompt's doing. But the section originally went on
    to say the two kinds of arm were "not comparable on this axis", which read
    as *only a base-tree scan can do this*. Asked the other way the model
    reported **0 · 0 · 1 false alarms on 26 control PRs across three passes**,
    at or below the pipeline's 1. The suppression figures are real; the moat is
    not.

    The middle clause is the one that moved. It read "0 false alarms ... below
    the pipeline's 1" until 2026-08-24, when p3 produced one and put the
    pipeline's 1 inside arm 3b's range instead of above it (§14.51). Every
    document was corrected that day; this renderer and the HTML one were not,
    so both kept emitting the falsified wording for a day (§14.52). Both retired
    readings are now pinned below, which is the only thing that makes a killed
    claim stay dead."""
    from pr_review.benchmark.metrics import negative_metrics
    from pr_review.benchmark.report import render_delta_scoping

    m = negative_metrics([
        CaseScore(case_id="a", labelled=False, scored_findings=1,
                  skipped_pre_existing=7,
                  verdicts=[FindingVerdict(_finding(), "fp")])])
    out = "\n".join(render_delta_scoping(m, None))
    assert "leaves present in the code shown" in out
    assert "0 · 0 · 1 of 26 across three passes" in out
    assert "at or below" in out
    assert "not** a capability only it can have" in out
    # The claims the experiments killed must not come back -- §14.47's, then
    # §14.51's.
    assert "not comparable on this axis" not in out
    # Strip the qualified form first: "at or below" contains "below".
    assert "below this" not in out.replace("at or below this", "")


def test_no_findings_at_all_renders_no_scoping_section():
    """A corpus where nothing fired has nothing to say about suppression, and
    `Rate(0, 0)` would render as a rate rather than as an absence."""
    from pr_review.benchmark.metrics import negative_metrics
    from pr_review.benchmark.report import render_delta_scoping
    m = negative_metrics([CaseScore(case_id="a", labelled=False)])
    assert render_delta_scoping(m, None) == []


def test_labelled_metrics_carries_its_own_suppression():
    """The labelled corpus asks a different question with the same number: not
    "how much noise did the baseline pass remove" but "did it remove too much
    from a case that does contain a real vulnerability". 97% there.

    This exists because a falsification pass found the fields had no test:
    deleting the `skipped_pre_existing` tally in `labelled_metrics` left the
    whole suite green (§14.41 — code that is not wired passes tests too)."""
    from pr_review.benchmark.metrics import labelled_metrics

    scores = [
        CaseScore(case_id="a", labelled=True, scored_findings=1,
                  skipped_pre_existing=20),
        CaseScore(case_id="b", labelled=True, scored_findings=0,
                  skipped_pre_existing=15),
    ]
    m = labelled_metrics(scores)
    assert m.scored_findings == 1
    assert m.skipped_pre_existing == 35
    assert m.raw_findings == 36
    assert m.suppression.render(3) == "0.972 (35/36)"


def test_the_scorecard_actually_renders_the_scoping_section():
    """`render_delta_scoping` returning the right list is not the same as
    `render_scorecard` calling it. The second falsification pass found exactly
    this: removing the call left every unit test green."""
    from pr_review.benchmark.report import render_scorecard
    from pr_review.benchmark.runner import CorpusRun

    run = CorpusRun(corpus_name="negative", selection_criteria="c")
    run.runs = [CaseRun(case=_case(cid="x"))]
    run.scores = [CaseScore(case_id="x", labelled=False, scored_findings=1,
                            skipped_pre_existing=7,
                            verdicts=[FindingVerdict(_finding(), "fp")])]
    out = render_scorecard(run)
    assert "## Delta scoping — what the baseline pass removes" in out
    assert "0.875 (7/8)" in out
    # And it sits before the section it explains.
    assert out.index("Delta scoping") < out.index("False positives on known-clean")


def test_the_published_total_spend_still_matches_the_stored_runs():
    """§14.53: the one figure in REPORT.md that cannot be corrected in place.

    A total is a claim about a set, and the set grows. $5.46 was correct on
    2026-08-21; arm 3b's first pass added $1.86 on 08-22 and was never folded
    in; the 08-24 update then added the replication passes' $2.26 to that stale
    base and published $7.72 against a true $9.58. Every local edit was correct.
    No local check could have caught it.

    So this is deliberately the one test here that goes RED when new work lands
    rather than when code breaks -- a new paid run genuinely invalidates the
    published total, and that is the signal. It is the opposite decision from
    the drift ledger's (report, never fail), and for the opposite reason: an
    unpublished edit is the normal state of the tree, while a total that no
    longer sums its own set is never correct.

    If this fails after a benchmark run: recompute, do not increment.
    """
    import json
    import re
    from pathlib import Path

    total = 0.0
    for run in sorted(Path("benchmark/results").glob("*/run.json")):
        d = json.loads(run.read_text())
        acct = d.get("model_accounting") or {}
        total += acct.get("cost_usd") or acct.get("total_cost_usd") or sum(
            (c.get("model_cost") or 0.0) for c in d.get("cases", []))

    # BENCHMARK_STATUS.md, not REPORT.md, since 2026-08-26: the report's cost
    # section is now about what drives cost, and the accounting total moved to the
    # measurement record. The guard followed the number rather than being retired.
    report = Path("BENCHMARK_STATUS.md").read_text()
    # The row is labelled "derivable from the stored runs" since 2026-08-26,
    # because a second row now names spend that is NOT derivable (§14.60). The
    # pattern is anchored on that phrase so it can never silently match the
    # other one -- a test that read the un-derivable row would be checking an
    # estimate against a sum and calling it agreement.
    m = re.search(r"\|\s*\*\*total, derivable from the stored runs\*\*\s*\|"
                  r"\s*\*\*\$([0-9]+\.[0-9]{2})\*\*\s*\|", report)
    assert m, "BENCHMARK_STATUS.md §4w.2 no longer prints a derivable-total row"
    published = float(m.group(1))

    assert round(total, 2) == published, (
        f"BENCHMARK_STATUS.md §4w.2 publishes ${published:.2f}; the stored runs sum to "
        f"${total:.4f}. A new paid run has landed since that figure was written. "
        f"Recompute the breakdown -- do not add the difference to the old total, "
        f"which is exactly how $7.72 happened (errata §14.53).")


def test_the_report_still_names_the_spend_that_has_no_stored_run():
    """The gap §14.60 opened must stay visible in the document.

    252 paid calls wrote no artifact, so the published total is complete only as
    a sum of what survived. A future tidy-up that removed the caveat would leave
    a figure that *looks* like the whole bill and cannot be told from one, which
    is worse than the gap itself. This fails if the disclosure goes.

    Delete this test only when the unrecorded passes are re-run and the gap is
    genuinely closed -- not when the sentence becomes inconvenient. It moved from
    `REPORT.md` to `BENCHMARK_STATUS.md` on 2026-08-26 when the report's cost
    section was rewritten around what drives cost; **moving a disclosure is not
    removing it, and the test moved with it** rather than being deleted, which is
    the distinction this docstring exists to keep.
    """
    from pathlib import Path

    report = Path("BENCHMARK_STATUS.md").read_text()
    assert "spent with no stored run" in report
    assert "§14.60" in report
    assert "not derivable" in report


# ---------------------------------------------------------------------------
# `--keep-runs`: one directory per case (§14.55)
# ---------------------------------------------------------------------------

def test_two_cases_sharing_a_head_commit_keep_separate_run_directories(tmp_path, monkeypatch):
    """`pipeline._run_dir` keys a run on `<repo>/<pr>-<head_sha[:12]>`.

    Unique for a real pull request. Not unique for a corpus of reverse-applied
    fixes, where two advisories against one repository can land on the same head
    commit from different bases. Both cases wrote one directory and the second
    replaced the first, so `--keep-runs` came back holding one case's artifacts
    under both names.
    """
    from pr_review.benchmark import runner

    seen = []

    def fake_run_review(**kw):
        seen.append(kw["out_root"])
        raise RuntimeError("stop here -- the directory is what is under test")

    monkeypatch.setattr(runner, "run_review", fake_run_review)
    shared = dict(repo="o/r", pr_number=7, head_sha="h" * 40)
    for cid, base in (("GHSA-aaa:vuln", "b" * 40), ("GHSA-bbb:vuln", "c" * 40)):
        case = BenchCase(id=cid, source="ghsa",
                         ref=CaseRef(base_sha=base, **shared),
                         pr_task=PRTask(repo="o/r", pr_number=7))
        runner.run_case(case, Config(), tmp_path)

    assert len(set(seen)) == 2, (
        f"both cases were handed the same run root: {seen}. The second would "
        "overwrite the first and --keep-runs would lose a case (§14.55).")


def test_the_collision_this_guards_against_is_still_present_in_the_corpus():
    """A guard whose hazard has gone away is a guard nobody can evaluate.

    If the labelled corpus is ever rebuilt without colliding pairs, this fails
    and says so, rather than leaving the test above passing for a reason that
    stopped being true.
    """
    from pr_review.benchmark.runner import _case_slug

    corpus = corpus_mod.load("benchmark/corpus/labelled.json")
    pipeline_keys = {(c.ref.repo, c.ref.pr_number, c.ref.head_sha[:12])
                     for c in corpus.cases}
    assert len(pipeline_keys) < len(corpus.cases), (
        "the labelled corpus no longer contains two cases sharing a head "
        "commit; §14.55's hazard is gone and this pair of tests should be "
        "re-read rather than kept passing by accident")
    assert len({_case_slug(c.id) for c in corpus.cases}) == len(corpus.cases)
