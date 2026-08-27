"""The CI regression gate (`benchmark/gate.py`).

Built in memory rather than against the stored `benchmark/results/*/run.json`,
because the gate's job is to react to *differences* and a fixture pair with a
known difference is the only way to assert what it reacts to. The stored runs are
exercised once at the bottom, where the question is whether the real dump shape
still loads.
"""
import json

import pytest

from pr_review.benchmark import gate as gate_mod
from pr_review.benchmark.gate import GateError, gate_files


# A minimal but *real* dump: `CorpusRun.from_dict` validates the case through
# the `BenchCase` model and `_score_all` re-derives every number, so a hand-built
# dict has to be shaped like the thing the runner writes.
def _case(cid, *, findings=(), ground_truth=(), pair_id="", detect=None,
          dropped=(), error=""):
    return {
        "case": {
            "id": cid,
            "source": "negative" if not ground_truth else "ghsa",
            "ref": {"repo": "o/r", "pr_number": 1, "base_sha": "a" * 40,
                    "head_sha": "b" * 40, "merged_at": "", "url": ""},
            "pr_task": {"repo": "o/r", "pr_number": 1, "diff_text": "",
                        "base_dir": "", "head_dir": "", "title": "t", "body": ""},
            "ground_truth": list(ground_truth),
            "cwe": [], "published": None, "language": "python",
            "advisory": None, "pair_id": pair_id,
        },
        "findings": list(findings),
        "pre_existing": 0,
        "verdict": "pass",
        "wall_s": 0.1,
        "error": error,
        "changed_files": 1,
        "dropped": list(dropped),
        "detect": detect or {"secrets": {"status": "ran"}},
    }


def _finding(fid, *, severity="medium", cwe="CWE-78", file="app.py", line=10,
             internal="INJ-CMD"):
    return {
        "id": fid, "fingerprint": fid,
        "title": f"finding {fid}",
        "taxonomy": {"internal": internal, "family": "injection",
                     "owasp_2025": "A03", "cwe": [cwe], "asvs": []},
        "severity": severity, "cvss_vector": None, "confidence": 7,
        "status": "candidate", "introduced_by_pr": True,
        "location": {"file": file, "start_line": line, "end_line": line,
                     "symbol": "f"},
        "data_flow": [], "evidence": [],
        "remediation": {"summary": "fix it", "patch": None},
        "provenance": {"detector": "structural", "tool": "structural",
                       "rule_id": "r1"},
        "created_at": "2026-08-08T00:00:00",
    }


def _run(cases, *, name="negative", cold=False, sha="abc-dirty", errors=()):
    return {
        "dump_version": 2,
        "corpus_name": name,
        "selection_criteria": "a fixture",
        "started_at": "2026-08-08T00:00:00",
        "wall_s": 1.0,
        "code_sha": sha,
        "cold_profiles": cold,
        "detector_status": {},          # rebuilt from per-case `detect`
        "errors": [list(e) for e in errors],
        "cases": cases,
    }


def _write(tmp_path, name, doc):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return p


def _gate(tmp_path, baseline, current, **kw):
    return gate_files(_write(tmp_path, "base.json", baseline),
                      _write(tmp_path, "cur.json", current), **kw)


# ---------------------------------------------------------------------------
# The comparison is refused before it can mislead
# ---------------------------------------------------------------------------

def test_an_unscored_run_is_a_refusal_not_a_pass(tmp_path):
    """Every ratchet is an inequality against the baseline, so zero against zero
    satisfies all of them at once.

    This is not hypothetical: the first draft of `gate.py` loaded runs with
    `CorpusRun.from_dict`, which does not re-derive `scores`, and it reported
    "PASS — 7 checks" on two real corpora it had never scored.
    """
    with pytest.raises(GateError, match="no scored cases"):
        _gate(tmp_path, _run([]), _run([_case("x")]))


def test_different_corpora_are_refused(tmp_path):
    with pytest.raises(GateError, match="different corpora"):
        _gate(tmp_path, _run([_case("x")], name="negative"),
              _run([_case("x")], name="labelled"))


def test_a_cold_profile_run_is_not_compared_to_a_warm_one(tmp_path):
    """`--cold-profiles` changes what is measured, not just how long it takes."""
    with pytest.raises(GateError, match="cold_profiles"):
        _gate(tmp_path, _run([_case("x")], cold=True),
              _run([_case("x")], cold=False))


def test_a_changed_case_set_is_refused(tmp_path):
    """Every rate is per case, so a different case set is a different denominator
    — which is also why `run --limit` cannot be gated against a full baseline."""
    with pytest.raises(GateError, match="different cases"):
        _gate(tmp_path, _run([_case("x"), _case("y")]), _run([_case("x")]))


def test_a_stale_dump_says_re_pin_rather_than_crashing(tmp_path):
    """A dump the current build cannot read is not a regression, and a traceback
    at this point reads like one."""
    old = _run([_case("x")])
    old["dump_version"] = 1
    with pytest.raises(GateError, match="Re-pin"):
        _gate(tmp_path, old, _run([_case("x")]))


def test_an_unreadable_file_is_a_refusal(tmp_path):
    with pytest.raises(GateError, match="cannot read"):
        gate_files(tmp_path / "nope.json", _write(tmp_path, "c.json",
                                                  _run([_case("x")])))


# ---------------------------------------------------------------------------
# Invariants — did the measurement happen?
# ---------------------------------------------------------------------------

def _named(result, fragment):
    return next(c for c in result.checks if fragment in c.name)


def test_a_detector_going_quiet_fails_even_with_no_new_findings(tmp_path):
    """The lesson `sca` taught: it ran once in 102 cases for a whole milestone,
    and every scorecard in that period reported a clean SCA false-positive rate
    over a corpus where SCA had not run. Fewer findings is not evidence of less
    noise if the detector stopped looking."""
    ran = {"secrets": {"status": "ran"}, "sca": {"status": "ran"}}
    quiet = {"secrets": {"status": "ran"}, "sca": {"status": "not_applicable"}}
    result = _gate(tmp_path, _run([_case("x", detect=ran)]),
                   _run([_case("x", detect=quiet)]))
    assert not result.passed
    assert not _named(result, "'sca' still runs").passed
    # and nothing else complained: no finding count moved.
    assert [c.name for c in result.failures] == ["detector 'sca' still runs"]


def test_a_detector_running_more_often_is_not_a_regression(tmp_path):
    """Which is what adding five lockfile formats did: `ran: 1` -> `ran: 10`."""
    less = {"secrets": {"status": "ran"}, "sca": {"status": "not_applicable"}}
    more = {"secrets": {"status": "ran"}, "sca": {"status": "ran"}}
    result = _gate(tmp_path, _run([_case("x", detect=less)]),
                   _run([_case("x", detect=more)]))
    assert result.passed


def test_a_new_case_error_fails(tmp_path):
    """An errored case produces no verdict, so it silently leaves the corpus and
    every rate below is over a smaller denominator than it claims. Two cases
    here, not one: a run whose *only* case errored has no scores at all and is
    refused earlier, by `_scored`."""
    result = _gate(tmp_path, _run([_case("x"), _case("y")]),
                   _run([_case("x"), _case("y", error="boom")],
                        errors=[("y", "boom")]))
    assert not _named(result, "no case errors").passed


def test_the_filter_eating_ground_truth_fails(tmp_path):
    """`ablate_filter` reads the drop records; a ground-truth file dropped before
    the detectors read it is a miss nothing downstream can recover."""
    gt = [{"cwe": "CWE-78", "file": "app.py", "spans": [[10, 12]]}]
    kept = _case("v", ground_truth=gt, pair_id="p")
    eaten = _case("v", ground_truth=gt, pair_id="p",
                  dropped=[{"path": "app.py", "reason": "vendored"}])
    result = _gate(tmp_path, _run([kept], name="labelled"),
                   _run([eaten], name="labelled"))
    assert not _named(result, "noise filter").passed


# ---------------------------------------------------------------------------
# Ratchets — counts, never rates
# ---------------------------------------------------------------------------

def test_a_new_high_severity_false_positive_fails(tmp_path):
    result = _gate(tmp_path, _run([_case("x")]),
                   _run([_case("x", findings=[_finding("f1", severity="high")])]))
    assert not _named(result, "gate-relevant").passed


def test_one_new_medium_false_positive_is_allowed_and_two_are_not(tmp_path):
    """One, not zero: a real improvement can surface one more true finding in
    code nobody flagged, which is what `fastapi#16141` turned out to be."""
    base = _run([_case("x")])
    one = _run([_case("x", findings=[_finding("f1")])])
    two = _run([_case("x", findings=[_finding("f1"), _finding("f2")])])
    assert _gate(tmp_path, base, one).passed
    assert not _gate(tmp_path, base, two).passed
    # and the tolerance is a knob, not a constant
    assert _gate(tmp_path, base, two, max_new_findings=2).passed


def test_losing_the_only_true_positive_fails(tmp_path):
    """Recall's numerator is one finding in one repository. As a *rate* that is
    0.028 and no tolerance can be built on it; as a count it is exact."""
    gt = [{"cwe": "CWE-78", "file": "app.py", "spans": [[10, 12]]}]
    found = _case("v", ground_truth=gt, findings=[_finding("f1")])
    missed = _case("v", ground_truth=gt)
    result = _gate(tmp_path, _run([found], name="labelled"),
                   _run([missed], name="labelled"))
    assert not result.passed
    assert not _named(result, "true positives do not disappear").passed


def test_losing_pair_discrimination_fails(tmp_path):
    """The pair is the unit that separates "found the vulnerability" from
    "always fires on this file"."""
    gt = [{"cwe": "CWE-78", "file": "app.py", "spans": [[10, 12]]}]
    vuln = _case("v", ground_truth=gt, pair_id="p", findings=[_finding("f1")])
    clean_control = _case("c", pair_id="p")
    noisy_control = _case("c", pair_id="p", findings=[_finding("f2")])

    good = _run([vuln, clean_control], name="labelled")
    bad = _run([vuln, noisy_control], name="labelled")
    result = _gate(tmp_path, good, bad)
    assert not _named(result, "discriminated pairs").passed


def test_an_identical_run_passes_every_check(tmp_path):
    """The floor: a no-op change must not fail anything, or the gate is noise."""
    cases = [_case("x", findings=[_finding("f1")]), _case("y")]
    result = _gate(tmp_path, _run(cases), _run(cases))
    assert result.passed, [c.name for c in result.failures]
    assert len(result.checks) > 5


# ---------------------------------------------------------------------------
# Rates are reported, never gated
# ---------------------------------------------------------------------------

def test_rates_are_reported_but_cannot_fail_the_gate(tmp_path):
    """The design claim, asserted: false positives per PR doubles here — 1/2 to
    2/2 — and the run still passes, because two findings is within the allowed
    growth of one... and the *rate* was never consulted."""
    base = _run([_case("x", findings=[_finding("f1")]), _case("y")])
    worse = _run([_case("x", findings=[_finding("f1")]),
                  _case("y", findings=[_finding("f2")])])
    result = _gate(tmp_path, base, worse)
    assert result.passed
    assert result.reported["false positives per PR"] == "1.000 (2/2)"
    assert "0.500 (1/2)" not in result.reported.values()


def test_the_verdict_serializes(tmp_path):
    result = _gate(tmp_path, _run([_case("x")]), _run([_case("x")]))
    doc = json.loads(json.dumps(gate_mod.as_dict(result)))
    assert doc["passed"] is True
    assert doc["corpus"] == "negative"
    assert all({"name", "passed", "detail"} <= set(c) for c in doc["checks"])
    assert "PASS" in gate_mod.render(result)


# ---------------------------------------------------------------------------
# The real dumps still load
# ---------------------------------------------------------------------------

def test_the_pinned_runs_load_and_compare():
    """Guards the fixture above against drifting from what the runner writes.

    Uses the two negative runs either side of the lockfile change, whose one
    difference is known: SCA started running, and found a real HIGH in
    `fastapi#16141` (gitpython 3.1.57, fixed in 3.1.58). The gate is *supposed*
    to fail that — a true finding still changes the number a baseline pins, and
    re-pinning is the answer, not tuning the finding away.
    """
    pytest.importorskip("yaml")
    base = "benchmark/results/2026-08-08-selfpair/run.json"
    cur = "benchmark/results/2026-08-08-lockfiles/run.json"
    result = gate_files(base, cur)

    assert [c.name for c in result.failures] == [
        "gate-relevant false positives do not increase"]
    assert _named(result, "'sca' still runs").passed        # ran 0 -> ran 10
    assert result.reported["false positives per PR"] == "0.240 (12/50)"
