"""The CWE relation table, and the recall that ignores it (§4u, `OPEN_ITEMS.md` §27).

Two changes landed together on 2026-08-26 and they are deliberately not the same
change:

  * `_CWE_GROUPS` gained ONE pair, `{CWE-59, CWE-61}`, after a measurement — the
    only entry in that table added from evidence rather than from reading the
    taxonomy. It fixes the largest single instance.
  * `recall_ignoring_cwe` exists because a hand-list cannot fix the *class*. It
    makes the residual vocabulary gap visible instead of resolving it by decree.

The tests below pin both, and — more importantly — pin the RULE that let the one
pair in while keeping others out, because that rule is what stops this table
growing by convenience.
"""
import json
from pathlib import Path

import pytest

from pr_review.benchmark.llm_arm import _EMITTABLE_CWES, reachable_ground_truth
from pr_review.benchmark.metrics import labelled_metrics
from pr_review.benchmark.schema import BenchCase, CaseRef, GTVuln, PRTask
from pr_review.benchmark.scoring import _CWE_GROUPS, cwe_match, score_case
from pr_review.detect.normalize import make_finding
from pr_review.schema import DetectorKind, Severity

ROOT = Path(__file__).resolve().parents[1]


def _case(gt_cwe="CWE-59", file="a.py", spans=((10, 14),)) -> BenchCase:
    return BenchCase(
        id="GHSA-test:vuln", source="ghsa",
        ref=CaseRef(repo="o/r", pr_number=1, base_sha="b" * 40, head_sha="h" * 40),
        pr_task=PRTask(repo="o/r", pr_number=1),
        ground_truth=[GTVuln(cwe=gt_cwe, file=file, spans=[list(s) for s in spans])])


def _finding(cwe="CWE-61", file="a.py", start=12, end=12):
    f = make_finding(internal="TOOL-UNMAPPED", title="t", severity=Severity.HIGH,
                     confidence=5, detector=DetectorKind.AGENT, tool="test",
                     rule_id=cwe, path=file, start_line=start, end_line=end, why="w")
    return f.model_copy(update={
        "taxonomy": f.taxonomy.model_copy(update={"cwe": [cwe, *f.taxonomy.cwe]})})


# --------------------------------------------------------------------------
# The pair itself
# --------------------------------------------------------------------------

def test_cwe_61_is_related_to_its_parent_cwe_59_in_both_directions():
    """44 findings across six stored passes turned on exactly this, both ways."""
    assert cwe_match(["CWE-61"], "CWE-59") == "related_cwe"
    assert cwe_match(["CWE-59"], "CWE-61") == "related_cwe"


def test_the_pair_turns_a_located_row_into_a_matched_one():
    score = score_case(_case(gt_cwe="CWE-59"), [_finding(cwe="CWE-61")])
    assert [g.cwe for g in score.matched] == ["CWE-59"]
    assert score.missed == []
    assert score.verdicts[0].label == "tp"
    assert score.verdicts[0].match_kind == "related_cwe"


def test_an_unrelated_cwe_is_still_a_false_positive():
    """The falsification for the pair: it must relate CWE-59 and CWE-61 and
    nothing else. The same probe found `gt CWE-200, model said CWE-89` eleven
    times, and that one is a real model error, not a hierarchy gap."""
    score = score_case(_case(gt_cwe="CWE-200"), [_finding(cwe="CWE-89")])
    assert score.matched == []
    assert score.verdicts[0].label == "fp"


# --------------------------------------------------------------------------
# The rule that admitted it — this is the part worth pinning
# --------------------------------------------------------------------------

def test_neither_id_in_the_new_pair_is_emittable_by_any_detector():
    """WHY THE PAIR WAS ALLOWED IN, as an assertion rather than a claim.

    The standing rule is "do not widen this table to flatter an arm", and its
    mechanism is that `scope.py` reads the same table, so a wider group moves
    recall on both sides. This pair is safe precisely because no detector can
    emit either id, so `reachable_ground_truth` cannot change.

    If a future detector starts emitting CWE-59 or CWE-61, this test goes red —
    which is correct: the pair would then move arm 2's ceiling, and that is a
    decision to retake, not a fact to rediscover.
    """
    assert "CWE-59" not in _EMITTABLE_CWES
    assert "CWE-61" not in _EMITTABLE_CWES


def test_the_pair_leaves_the_pipeline_ceiling_where_it_was():
    from pr_review.benchmark import corpus as corpus_mod
    corp = corpus_mod.load(ROOT / "benchmark/corpus/labelled.json")
    rows = [g for c in corp.cases for g in c.ground_truth]
    assert len(rows) == 36, "the corpus moved; re-derive the ceiling before trusting it"
    assert sum(1 for g in rows if reachable_ground_truth(g.cwe)) == 9


def test_the_rejected_group_would_have_moved_the_ceiling():
    """`{CWE-77, 78, 88}` was rejected on the test above, not on taste.

    Kept as a test so the reasoning survives: CWE-78 IS emittable, so relating
    CWE-88 to it makes ground-truth CWE-88 rows reachable and moves arm 2's
    ceiling from 9 to 11. Asserting the *mechanism* means a future reader can
    see why one pair went in and another did not.
    """
    assert "CWE-78" in _EMITTABLE_CWES
    assert not any({"CWE-88"} & g and "CWE-77" in g for g in _CWE_GROUPS
                   if "CWE-88" in g), "CWE-88 must not be related to CWE-78 here"


# --------------------------------------------------------------------------
# The recall that ignores the table
# --------------------------------------------------------------------------

def test_a_row_can_be_located_without_being_matched():
    """The whole point of the second number."""
    score = score_case(_case(gt_cwe="CWE-200"), [_finding(cwe="CWE-89")])
    assert score.matched == []
    assert [g.cwe for g in score.located] == ["CWE-200"]


def test_locating_needs_the_right_file_and_the_right_lines():
    wrong_file = score_case(_case(), [_finding(cwe="CWE-89", file="b.py")])
    assert wrong_file.located == []
    wrong_lines = score_case(_case(), [_finding(cwe="CWE-89", start=99, end=99)])
    assert wrong_lines.located == []


def test_recall_ignoring_cwe_is_never_below_recall():
    """A row that matched with a CWE necessarily overlapped without one."""
    scores = [score_case(_case(gt_cwe="CWE-59"), [_finding(cwe="CWE-61")]),
              score_case(_case(gt_cwe="CWE-200"), [_finding(cwe="CWE-89")]),
              score_case(_case(gt_cwe="CWE-22"), [])]
    m = labelled_metrics(scores)
    assert m.recall.num == 1 and m.recall.den == 3
    assert m.recall_ignoring_cwe.num == 2 and m.recall_ignoring_cwe.den == 3
    assert m.recall_ignoring_cwe.num >= m.recall.num


def test_the_two_numbers_agree_when_the_taxonomy_never_gets_in_the_way():
    """The pipeline emits fixed ids, so its two recalls are equal by
    construction. That contrast is the reading: the gap is a property of an arm
    that names CWEs freely, not of the corpus."""
    data = json.loads((ROOT / "benchmark/results/2026-08-24-labelled-freshbaseline"
                       / "run.json").read_text())
    from pr_review.benchmark.runner import rescore
    m = labelled_metrics(rescore(data).scores)
    assert m.recall.num == m.recall_ignoring_cwe.num


def test_the_llm_arms_show_a_real_gap_between_the_two():
    """And the LLM arm does not — 17-18 matched against 27-29 located.

    Pinned against a stored run so that a change to the relation table, the
    scorer or the corpus moves this number visibly rather than quietly.
    """
    from pr_review.benchmark.runner import rescore
    data = json.loads((ROOT / "benchmark/results/2026-08-21-arm3-llm-p1"
                       / "run.json").read_text())
    m = labelled_metrics(rescore(data).scores)
    assert m.recall.num == 18 and m.recall.den == 36
    assert m.recall_ignoring_cwe.num == 29
