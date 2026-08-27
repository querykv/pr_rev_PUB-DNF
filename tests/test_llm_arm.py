"""Arm 3 — the raw single-prompt LLM baseline. No model is called here."""
import pytest

from pr_review.benchmark.llm_arm import (
    PROMPT_PATH,
    TOOL,
    _CWE_TO_INTERNAL,
    load_prompt,
    reachable_ground_truth,
    to_findings,
)
from pr_review.benchmark.scoring import cwe_match
from pr_review.schema import Severity


def _reply(*rows):
    import json
    return json.dumps({"findings": list(rows)})


_ROW = {"file": "app/db.py", "start_line": 42, "end_line": 44, "cwe": "CWE-89",
        "severity": "high", "title": "SQLi", "why": "interpolated"}


def test_a_well_formed_reply_becomes_findings():
    fs, notes = to_findings(_reply(_ROW), None)
    assert len(fs) == 1 and not notes
    f = fs[0]
    assert f.location.file == "app/db.py"
    assert (f.location.start_line, f.location.end_line) == (42, 44)
    assert f.severity is Severity.HIGH
    assert f.provenance.tool == TOOL
    assert f.taxonomy.family == "Injection"


def test_a_fenced_reply_is_read():
    fs, _ = to_findings("here you go:\n```json\n" + _reply(_ROW) + "\n```\n", None)
    assert len(fs) == 1


def test_an_empty_finding_list_is_a_real_answer():
    fs, notes = to_findings('{"findings": []}', None)
    assert fs == [] and notes == []


def test_unreadable_output_is_reported_not_silently_empty():
    fs, notes = to_findings("I could not analyse this.", None)
    assert fs == [] and notes


# -- the fairness fix -------------------------------------------------------

def test_a_cwe_outside_the_taxonomy_is_kept_and_still_matches_ground_truth():
    """The bug this pins: TOOL-UNMAPPED carries `cwe: []`, and cwe_match reads
    exactly that list. Without preserving the reported CWE, a model that
    correctly answered CWE-400 on a CWE-400 case scored as a FALSE POSITIVE --
    and 21 of the labelled corpus's 33 ground-truth rows are outside the
    taxonomy, so the arm would have been capped at 36% recall by construction."""
    row = dict(_ROW, cwe="CWE-400")
    fs, notes = to_findings(_reply(row), None)
    assert len(fs) == 1
    assert "CWE-400" in fs[0].taxonomy.cwe
    assert cwe_match(fs[0].taxonomy.cwe, "CWE-400") == "exact_cwe"
    assert any("outside the taxonomy" in n for n in notes)


def test_an_unknown_cwe_does_not_crash_the_arm():
    """`lookup()` raises on an id absent from the registry, so the fallback has
    to be TOOL-UNMAPPED rather than an invented one."""
    fs, _ = to_findings(_reply(dict(_ROW, cwe="CWE-99999")), None)
    assert len(fs) == 1 and fs[0].taxonomy.family == "Unmapped"


def test_a_missing_cwe_is_still_a_finding():
    fs, notes = to_findings(_reply({k: v for k, v in _ROW.items() if k != "cwe"}), None)
    assert len(fs) == 1 and notes


# -- what must NOT be silently dropped --------------------------------------

@pytest.mark.parametrize("bad,why", [
    ({**_ROW, "file": ""}, "named no file"),
    ({**_ROW, "start_line": 0}, "no usable start_line"),
    ({**_ROW, "start_line": "not a number"}, "no usable start_line"),
])
def test_unusable_rows_are_noted_rather_than_vanishing(bad, why):
    """An arm that quietly discarded a third of the model's output would report
    a false-positive rate for a different experiment."""
    fs, notes = to_findings(_reply(bad), None)
    assert fs == []
    assert any(why in n for n in notes)


# -- the CWE index ----------------------------------------------------------

def test_the_index_prefers_the_id_a_cwe_is_primary_for():
    """CWE-94 belongs to code injection, not to the hidden-text id that lists
    it second. First-wins would resolve it by table order, which is not a
    judgement."""
    assert _CWE_TO_INTERNAL["CWE-94"] == "INJ-CODE-EXEC"
    assert _CWE_TO_INTERNAL["CWE-89"] == "INJ-SQLI"
    assert _CWE_TO_INTERNAL["CWE-22"] == "BAC-PATH-TRAVERSAL"


def test_every_mapped_cwe_appears_in_its_targets_own_list():
    """The invariant that keeps scoring correct for mapped CWEs."""
    from pr_review.taxonomy.registry import _TABLE
    for cwe, internal in _CWE_TO_INTERNAL.items():
        assert cwe in {c.upper() for c in _TABLE[internal]["cwe"]}


def test_the_reachable_stratum_separates_vocabulary_from_detection():
    assert reachable_ground_truth("CWE-89") is True
    assert reachable_ground_truth("CWE-23") is True      # via _CWE_GROUPS
    assert reachable_ground_truth("CWE-400") is False    # no detector can say it


# -- the artifact -----------------------------------------------------------

def test_the_prompt_is_a_committed_file():
    """The arm's reproducibility claim rests on it being in version control."""
    assert PROMPT_PATH.exists()
    text = load_prompt()
    assert "start_line" in text and "cwe" in text
    assert "findings" in text


# -- arm 3b: the prompt is part of the arm's identity ------------------------

def test_the_introduced_only_prompt_is_a_committed_file():
    """Same rule as the baseline prompt. §14.46 turns on the exact wording of
    these two files, so the claim that the difference is one instruction has to
    be checkable from the repository."""
    from pr_review.benchmark.llm_arm import PROMPTS_DIR, load_prompt

    def flat(text):                       # the prompts hard-wrap; the claim is
        return " ".join(text.lower().split())   # about wording, not line breaks

    baseline = flat(load_prompt())
    variant_body = flat(load_prompt(
        PROMPTS_DIR / "llm-diff-introduced-only.md").split("-->")[1])
    # The sentence that made arm 3 report pre-existing findings, and its absence.
    assert "introduces or leaves present in the code shown" in baseline
    assert "leaves present in the code shown" not in variant_body
    assert "this diff introduces" in variant_body
    assert "out of scope" in variant_body


def test_a_missing_prompt_variant_raises_rather_than_falling_back():
    """Silently running the baseline prompt when the variant is missing would
    mislabel the run: `CorpusRun.arm` would say `introduced-only` over an arm
    that asked the opposite question."""
    from pr_review.benchmark.llm_arm import load_prompt

    with pytest.raises(FileNotFoundError):
        load_prompt("/nonexistent/prompt.md")


def test_the_arm_string_records_which_prompt_ran():
    """Two runs of "arm 3" with different prompts are different experiments, and
    a stored run has to say which one it is — the scorecard reads `arm`."""
    from pathlib import Path

    from pr_review.benchmark.llm_arm import PROMPTS_DIR, run_llm_arm
    from pr_review.benchmark.schema import Corpus

    corpus = Corpus(name="x", selection_criteria="y", language="python", cases=[])

    class _P:
        calls: list = []

        def complete(self, messages, tools=None, **cfg):
            return '{"findings": []}'

    default = run_llm_arm(corpus, _P(), progress=False)
    variant = run_llm_arm(corpus, _P(), progress=False,
                          prompt_path=PROMPTS_DIR / "llm-diff-introduced-only.md")
    assert default.arm == "llm-diff:low:llm-diff-baseline"
    assert variant.arm == "llm-diff:low:llm-diff-introduced-only"


def test_the_prompt_variant_reaches_the_provider():
    """§14.41: a parameter that is threaded but never used passes every test
    that only checks the parameter exists. This asserts the bytes arrive."""
    from pr_review.benchmark.llm_arm import PROMPTS_DIR, review_case
    from pr_review.benchmark.schema import BenchCase, CaseRef, PRTask

    seen = {}

    class _P:
        def complete(self, messages, tools=None, **cfg):
            seen["system"] = messages[0]["content"]
            return '{"findings": []}'

    case = BenchCase(id="c", source="ghsa",
                     ref=CaseRef(repo="o/r", pr_number=1, base_sha="a" * 40,
                                 head_sha="b" * 40),
                     pr_task=PRTask(repo="o/r", pr_number=1,
                                    diff_text="--- a\n+++ b\n+x = 1\n"))
    review_case(case, _P(),
                prompt_path=PROMPTS_DIR / "llm-diff-introduced-only.md")
    body = " ".join(seen["system"].lower().split("-->")[1].lower().split())
    assert "this diff introduces" in body
    assert "or leaves present" not in body
