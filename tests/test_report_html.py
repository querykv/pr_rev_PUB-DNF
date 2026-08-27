"""The HTML comparison scorecard.

The bias here matches `report.py`'s: most of these assert that something the
page *must* say is present, or that something it must never emit is absent.
A comparison page's failure mode is not a crash -- it is a number that renders
beautifully and means something other than what the column header claims.
"""
from __future__ import annotations

import re

import pytest

from pr_review.benchmark.metrics import Rate
from pr_review.benchmark.report_html import (
    Arm,
    _e,
    recall_ceiling,
    render_comparison,
    write_comparison,
)
from pr_review.benchmark.runner import CaseRun, CorpusRun
from pr_review.benchmark.schema import BenchCase, CaseRef, GTVuln, PRTask
from pr_review.benchmark.scoring import CaseScore, FindingVerdict
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


def _finding(path="app/views.py", start=1) -> Finding:
    return Finding(
        id=f"f-{path}-{start}", fingerprint=f"fp-{path}-{start}",
        title="t",
        taxonomy=Taxonomy(internal="INJ-SQLI", family="Injection",
                          owasp_2025="A05", cwe=["CWE-89"]),
        severity=Severity.HIGH, confidence=7, introduced_by_pr=True,
        location=Location(file=path, start_line=start, end_line=start),
        evidence=[Evidence(file=path, lines=str(start), snippet="x", why="y")],
        remediation=Remediation(summary="fix it"),
        provenance=Provenance(detector=DetectorKind.STRUCTURAL, tool="structural"),
    )


def _case(cid: str, *, labelled: bool = True, path: str = "app/views.py",
          cwe: str = "CWE-89", pair: str = "") -> BenchCase:
    return BenchCase(
        id=cid, source="ghsa",
        ref=CaseRef(repo="o/r", pr_number=1, base_sha="a" * 40, head_sha="b" * 40),
        pr_task=PRTask(repo="o/r", pr_number=1, title="t"),
        ground_truth=[GTVuln(cwe=cwe, file=path, spans=[(1, 5)])] if labelled else [],
        pair_id=pair,
    )


def _run(cases, scores, **kw) -> CorpusRun:
    run = CorpusRun(corpus_name=kw.pop("corpus_name", "labelled"),
                    selection_criteria=kw.pop("criteria", "the 80 newest advisories"),
                    **kw)
    run.runs = [CaseRun(case=c) for c in cases]
    run.scores = scores
    return run


def _scored_arm(label="pipeline", *, tp=1, rows=2, in_scope=1, **kw) -> Arm:
    """One labelled case whose ground truth is partly matched."""
    cases, scores = [], []
    for i in range(rows):
        c = _case(f"c{i}")
        cases.append(c)
        gt = c.ground_truth[0]
        s = CaseScore(case_id=c.id, labelled=True)
        if i < tp:
            s.verdicts = [FindingVerdict(finding=_finding(), label="tp",
                                         matched=gt, match_kind="exact")]
            s.matched = [gt]
        else:
            s.missed = [gt]
        s.scored_findings = 1
        scores.append(s)
    return Arm(label=label, run=_run(cases, scores), **kw)


# -- escaping ----------------------------------------------------------------

_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "</td></tr></table><h1>owned",
    "<style>body{display:none}</style>",
    "&lt;already escaped&gt;",
]


def _tags(page: str) -> list[str]:
    return re.findall(r"<\s*/?\s*([a-zA-Z][a-zA-Z0-9]*)", page)


@pytest.mark.parametrize("payload", _PAYLOADS)
def test_no_field_can_open_a_tag_of_its_own(payload):
    """`report/markdown.py` shipped this hole once: a finding's evidence closed
    the code fence it was inside and the rest of the document was the payload's
    to write (`M1_STATUS.md` §5.2). Every string on this page comes from a repo
    path, a CWE id, an advisory note or a pinned corpus's selection criteria --
    all third-party text. HTML is a worse place to lose that argument.

    The check is structural rather than a blocklist. Asserting `"onerror="` is
    absent would fail on the *correctly escaped* page, because escaped text may
    legitimately contain those characters; and any blocklist is a list of the
    payloads somebody thought of. So: drive the payload through every
    interpolation the page has, and require the resulting tag structure to be
    **identical** to a benign render. A payload that cannot change the tag
    structure cannot introduce an element or an attribute.
    """
    def render(value):
        arm = _scored_arm(value, note=value, source=value)
        arm.run.corpus_name = value
        arm.run.selection_criteria = value
        arm.run.code_sha = value
        return render_comparison([arm], title=value)

    hostile = render(payload)
    benign = render("benign")

    assert _tags(hostile) == _tags(benign)
    # The raw payload never survives verbatim, and the escaped form is present:
    # this is data and must still be shown to the reader.
    assert payload not in hostile
    assert _e(payload) in hostile


def test_every_fetchable_url_on_the_page_is_a_constant():
    """The structural test above proves no *new* attribute appears. This proves
    the attributes that fetch are a fixed, auditable set rather than anything a
    corpus string could reach: the two Google Fonts preconnects and the one
    stylesheet, and nothing else.

    Checked rather than assumed. Linking a run directory or an advisory URL is a
    natural later addition and is exactly the change that would put third-party
    text into an `href`, where escaping alone does not save you from
    `javascript:`.
    """
    hostile = "javascript:alert(1)"
    arm = _scored_arm(hostile, note=hostile, source=hostile)
    arm.run.corpus_name = hostile
    arm.run.selection_criteria = hostile
    arm.run.code_sha = hostile
    out = render_comparison([arm], title=hostile)

    urls = set(re.findall(r'(?:href|src|srcset|formaction)\s*=\s*"([^"]*)"', out))
    assert urls == {
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com",
        "https://fonts.googleapis.com/css2?family=Newsreader:ital,opsz,wght@"
        "0,6..72,400;0,6..72,600;1,6..72,400&family=IBM+Plex+Sans:wght@"
        "400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap",
    }
    assert "<a " not in out.lower() and "<iframe" not in out.lower()
    assert "url(" not in out


def test_the_escape_helper_covers_attributes_too():
    """`quote=False` would pass a text-node test and still break out of an
    attribute, which is where `source` and the bar widths land."""
    assert _e('a"b') == "a&quot;b"
    assert _e("a'b") == "a&#x27;b"
    assert _e(None) == ""


# -- the honesty carries -----------------------------------------------------

def test_the_recall_ceiling_is_drawn_and_stated():
    """§14.45. 27 of 36 ground-truth rows are outside the taxonomy, so a bar
    against a full-width 1.0 is a lie told by a layout choice. (The numbers
    below are synthetic; the real corpus is pinned in
    `test_the_ceiling_is_derived_from_the_rows_recall_divides_by`.)"""
    arm = _scored_arm(rows=4, tp=1)
    arm.labelled.in_scope_rows = 1          # 1 of 4 reachable -> ceiling 0.25
    out = render_comparison([arm])
    assert "ceiling" in out.lower()
    assert "0.250" in out                   # stated, not only drawn
    assert 'class="bar"' in out
    assert re.search(r'<b style="left:25\.0%"', out)


def test_a_missing_ceiling_does_not_invent_one():
    """No labelled arm means no ground truth, so there is no ceiling to draw.
    Defaulting to 1.0 would assert a reachable maximum nobody measured."""
    arm = Arm(label="negatives only",
              run=_run([_case("n0", labelled=False)],
                       [CaseScore(case_id="n0", labelled=False)],
                       corpus_name="negative"))
    assert recall_ceiling([arm]) is None
    out = render_comparison([arm])
    assert "Read every recall figure against its ceiling" not in out


def test_every_rate_keeps_its_denominator():
    """`metrics.Rate.render()` refuses to print a ratio without its n, and this
    page must not reformat around that."""
    out = render_comparison([_scored_arm(rows=4, tp=1)])
    assert "0.250 (1/4)" in out
    assert not re.search(r">\s*0\.250\s*<", out)     # never the bare number


def test_an_unscored_arm_gets_no_findings_columns():
    """Errata §14.40: arm 2b's findings ARE the deterministic arm's findings,
    because `pipeline.py` builds detect from the manifest rather than from the
    filter's kept set. Printing them again double-counts one measurement."""
    scored = _scored_arm("pipeline")
    cost_only = _scored_arm("pipeline + triage", scored=False,
                            note="Cost only. Confirmed at n=50.")
    cost_only.run.model_accounting = {
        "calls": 33, "cost_usd": 0.9537, "uncached_tokens": 80794,
        "cached_tokens": 239553, "models": ["haiku"], "effort": [],
    }
    out = render_comparison([scored, cost_only])
    assert "not a findings measurement" in out
    assert "Confirmed at n=50." in out
    # Its cost still appears -- that is the whole reason the arm exists.
    assert "0.9537" in out
def test_variance_is_a_spread_and_never_a_mean():
    """The deterministic arms produce identical scorecards on a re-run, so a
    range across LLM passes is a difference in kind. Averaging it away would
    hide the finding rather than summarize it."""
    passes = []
    for i, tp in enumerate((1, 1, 0)):
        a = _scored_arm(f"pass {i + 1}", rows=3, tp=tp)
        a.run.arm = "llm-diff:low"
        passes.append(a)
    out = render_comparison(passes)
    assert "Run-to-run variance" in out
    assert "Spread" in out
    assert "0.333" in out                          # the spread, 1/3 - 0/3
    # Every pass's own value is printed. A page that reported only a central
    # tendency would show one number where the finding is that there are three.
    assert out.count("0.333 (1/3)") >= 2 and out.count("0.000 (0/3)") >= 1
    assert "pass 1" in out and "pass 2" in out and "pass 3" in out


def test_one_pass_is_not_a_variance_measurement():
    arm = _scored_arm("only pass")
    arm.run.arm = "llm-diff:low"
    assert "Run-to-run variance" not in render_comparison([arm])
def test_the_page_names_the_temporal_holdout_and_the_scope():
    out = render_comparison([_scored_arm()])
    assert "temporal holdout" in out


def test_an_empty_comparison_refuses_rather_than_renders():
    with pytest.raises(ValueError):
        render_comparison([])


def test_write_comparison_creates_its_parent(tmp_path):
    out = write_comparison([_scored_arm()], tmp_path / "deep" / "c.html")
    assert out.exists() and out.read_text().startswith("<title>")


# -- the ceiling, against the real corpus ------------------------------------

def test_the_ceiling_is_derived_from_the_rows_recall_divides_by():
    """§14.45. The documented ceiling was 0.364, computed over `BenchCase.cwe`
    advisory tags (33, 12 in scope). `recall` divides by `ground_truth` rows
    (36, 9 in scope), so the real ceiling is 0.250 -- and the two populations
    are close enough to look interchangeable.

    This pins both counts against the pinned corpus so the next person to quote
    a ceiling has an assertion to disagree with rather than a paragraph. It is
    the whole lesson of that entry: a figure that will be compared against
    another figure must be *computed* from the same object, never quoted.
    """
    import json
    from pathlib import Path

    from pr_review.benchmark.schema import Corpus
    from pr_review.benchmark.scope import in_scope_cwes, is_in_scope

    corpus_path = Path("benchmark/corpus/labelled.json")
    if not corpus_path.exists():                     # pragma: no cover
        pytest.skip("pinned corpus not present")

    corpus = Corpus.model_validate_json(corpus_path.read_text())
    labelled = [c for c in corpus.cases if c.labelled]
    rows = [gt for c in labelled for gt in c.ground_truth]
    scope = in_scope_cwes()

    assert len(rows) == 36
    assert sum(1 for r in rows if is_in_scope(r.cwe, scope)) == 9

    # The population the wrong figure came from, pinned so the confusion is
    # documented by something that runs.
    tags = [w for c in labelled for w in c.cwe]
    assert len(tags) == 33
    assert sum(1 for w in tags if is_in_scope(w, scope)) == 12


def test_the_page_never_hardcodes_a_ceiling():
    """`recall_ceiling` takes it off the metrics object the recall column comes
    from. Had it taken a constant -- the obvious way to write it, since the
    number was 'already known' -- the page and the docs would have agreed
    forever and §14.45 would still be undiscovered."""
    import inspect

    from pr_review.benchmark import report_html

    src = inspect.getsource(report_html.recall_ceiling)
    assert "0.364" not in src and "0.25" not in src
    assert "in_scope_rows" in src and "gt_rows" in src


# -- delta scoping on the comparison page ------------------------------------

def _pipeline_arm(label, corpus, scored, dropped, arm="deterministic"):
    """An arm whose scores carry a scoped/dropped split."""
    cases = [_case(f"{label}-{i}") for i in range(2)]
    scores = [
        CaseScore(case_id=cases[0].id, labelled=True,
                  scored_findings=scored, skipped_pre_existing=dropped),
        CaseScore(case_id=cases[1].id, labelled=False),
    ]
    a = Arm(label=label, run=_run(cases, scores, corpus_name=corpus))
    a.run.arm = arm
    return a
def test_the_scoping_table_names_each_arms_corpus():
    """The first version of this read `negative or labelled`, which on the
    labelled corpus means the *control half* — so it put 87 findings over 50
    negative-corpus PRs in one column with 36 over 26 control PRs. Same
    cross-population error as §14.42/§14.43/§14.45, one table later."""
    a = _pipeline_arm("pipeline", "labelled", scored=2, dropped=70)
    b = _pipeline_arm("triage", "negative", scored=12, dropped=75)
    out = render_comparison([a, b])
    i = out.index("Delta scoping")
    table = out[i:out.index("</table>", i)]
    assert ">labelled<" in table and ">negative<" in table


def test_scoping_counts_the_whole_run_not_one_stratum():
    """One arm is one run over one corpus, so the run is the unit."""
    a = _pipeline_arm("pipeline", "labelled", scored=2, dropped=70)
    assert a.scoping == (72, 70)
def test_no_scoping_section_when_no_arm_has_a_baseline():
    llm = _pipeline_arm("llm", "labelled", scored=18, dropped=0,
                        arm="llm-diff:low")
    assert "Delta scoping" not in render_comparison([llm])


def test_a_negative_corpus_arm_keeps_its_false_alarm_number():
    """Arm 2c runs the negative corpus: it IS a findings measurement — its
    false-alarm rate is the whole point — there is simply no ground truth to
    score recall against. That is a different statement from arm 2b's, whose
    findings *are* the deterministic arm's (§14.40), and collapsing the two
    hides a real number behind someone else's caveat."""
    cases = [_case("n0", labelled=False), _case("n1", labelled=False)]
    scores = [CaseScore(case_id=cases[0].id, labelled=False,
                        scored_findings=16, skipped_pre_existing=71,
                        verdicts=[FindingVerdict(_finding(), "fp")]),
              CaseScore(case_id=cases[1].id, labelled=False)]
    arm = Arm(label="hunk scoping",
              run=_run(cases, scores, corpus_name="negative"))
    assert arm.labelled is None and arm.negative is not None
    out = render_comparison([arm])
    assert "no ground truth" in out
    assert "not a findings measurement" not in out


def test_the_headline_table_names_each_arms_corpus():
    """Same guard as the scoping table. 0.32 over 50 known-clean merged PRs and
    0.12 over 26 post-fix control halves are different populations; reading them
    down one column is the §14.42/§14.45 error in a layout."""
    a = _pipeline_arm("pipeline", "labelled", scored=2, dropped=70)
    cases = [_case("n0", labelled=False)]
    b = Arm(label="hunk", run=_run(
        cases, [CaseScore(case_id="n0", labelled=False, scored_findings=16,
                          skipped_pre_existing=71)], corpus_name="negative"))
    out = render_comparison([a, b])
    head = out[out.index("<h2>Headline"):out.index("</table>", out.index("<h2>Headline"))]
    assert ">labelled<" in head and ">negative<" in head

    # Header and body must agree on width. Checking only that the corpus *cell*
    # exists let a mutant delete the <th> and misalign every column beneath it,
    # which is a worse bug than the one this test was written for: silently
    # shifted headers relabel real numbers.
    ths = len(re.findall(r"<th[ >]", head))
    rows = re.findall(r"<tr>((?:\s*<td.*?)+)</tr>", head, re.S)
    for row in rows:
        width = sum(int(re.search(r'colspan="(\d+)"', c).group(1)) if "colspan" in c
                    else 1
                    for c in re.findall(r"<td[^>]*>", row))
        assert width == ths, f"row has {width} columns against {ths} headers"


# -- the floor's provenance reaches the reader (OPEN_ITEMS.md §21) -----------

def test_the_floor_report_matches_the_floor_the_split_actually_used():
    """§21. This message used to say "understates harness by ~477 per call",
    which was true while the arithmetic used the constant regardless of version.
    Now `floor_for` selects the measured floor, so that sentence would describe
    a gap the code had already closed -- this project's commonest defect, a
    claim left standing after the thing under it changed (Plan 2 §L5). Four
    states, and each says what the split actually did."""
    from pr_review.benchmark.report import floor_provenance
    from pr_review.models.claude_cli import (
        TRANSPORT_FLOOR_CLI_VERSION, TRANSPORT_FLOOR_TOKENS, floor_for)

    # 1. The calibrated build: nothing to say.
    assert floor_provenance({"cli_version": TRANSPORT_FLOOR_CLI_VERSION}) == ""

    # 2. A build that WAS measured: the split used that floor, so the message
    #    reports which floor -- and must not claim a gap.
    known = floor_provenance({"cli_version": "2.1.241", "calls": 52})
    assert "MEASURED for this build" in known and "7,777" in known
    assert "understates" not in known and "overstates" not in known
    assert floor_for({"cli_version": "2.1.241"}) == 7_777

    # 3. Recorded but never calibrated: the constant is a fallback, and the
    #    message must say the split is an extrapolation rather than invent one.
    unmeasured = floor_provenance({"cli_version": "2.1.239", "calls": 52})
    assert "never calibrated" in unmeasured and "extrapolation" in unmeasured
    assert floor_for({"cli_version": "2.1.239"}) == TRANSPORT_FLOOR_TOKENS

    # 4. The state that matters most: a run stored before the field existed.
    #    Silence would read as agreement.
    for acct in ({}, {"cli_version": None}, {"cli_version": ""}):
        assert "UNRECORDED" in floor_provenance(acct)
def test_a_run_with_no_version_prices_exactly_as_the_constant_does():
    """The property that makes this change inert on everything already stored.

    No `run.json` written before 2026-08-24 carries `cli_version`, so every one
    of them must price exactly as it did before `floor_for` existed. Asserted
    here rather than assumed, because "it should not have moved" is precisely
    the claim that is never checked."""
    from pr_review.models.claude_cli import TRANSPORT_FLOOR_TOKENS, floor_for

    for acct in ({}, None, {"calls": 52}, {"cli_version": None, "calls": 52}):
        assert floor_for(acct) == TRANSPORT_FLOOR_TOKENS


# ---------------------------------------------------------------------------
# Retired 2026-08-26 with the page content they asserted — recorded, not
# silently deleted, so a future reader can tell "removed on purpose" from
# "never written".
# ---------------------------------------------------------------------------
#
#   test_the_cost_columns_refuse_the_ours_and_theirs_reading
#   test_two_arms_on_different_builds_show_their_floors_and_say_why
#       guarded the §14.44 callout: `cached`/`uncached` are not ours-and-theirs,
#       and the `ours` column is DERIVED from a calibrated floor rather than
#       measured. **That column is still on the page and its caveat is not.**
#       The explanation survives in `REPORT.md` §4.
#
#   test_the_limits_come_before_the_cost_tables
#       guarded "What this does not say". Its four limits survive as `REPORT.md`
#       §7.2.
#
#   test_an_llm_arm_shows_no_baseline_pass_rather_than_zero
#   test_the_scoping_section_says_the_llm_prompt_asked_for_pre_existing
#   test_the_delta_cell_does_not_tell_the_context_arm_it_sees_only_the_diff
#       guarded the delta table's no-baseline rows, which are gone: the table now
#       lists only arms that HAVE a baseline pass. That removes the "empty row
#       read as a zero" hazard by construction rather than by caveat, which is
#       the stronger fix.
#
# `_LIMITS` and `_provenance_section` are deliberately kept in the module,
# unreferenced by the page and one call away from returning.
