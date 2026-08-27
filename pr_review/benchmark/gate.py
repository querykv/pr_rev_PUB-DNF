"""CI regression gate — compare a fresh corpus run against a pinned baseline
(`plan/benchmark.md` §6).

GATES ON COUNTS, NOT RATES, AND THAT IS THE WHOLE DESIGN. §6 asks for a gate that
"fails if P/R/FP regress beyond tolerances", which assumes rates stable enough for
a tolerance to mean something. They are not, and pretending otherwise would make
the tolerance rather than the measurement decide the outcome:

  * recall is **1/36**, carried entirely by one true positive in one repository.
    A float tolerance wide enough to survive normal variation is wider than the
    whole signal; one narrow enough to catch a regression fires on nothing else.
  * false positives are 12/50 on the negative corpus, so a single finding moves
    FP/PR by 0.02 — the same distance as the gate-relevant number in total.

Integers do not have that problem. "The true positive disappeared" and "a new
HIGH appeared" are exact statements about exact quantities, they are the
statements a reviewer actually wants, and they stay meaningful at n = 1. So the
rates are computed, printed with their denominators, and never consulted for a
verdict.

THE OTHER HALF IS THAT THE MEASUREMENT HAPPENED AT ALL. Every expensive lesson on
this branch was a detector going quiet rather than a number going bad: `sca` ran
**once in 102 cases** for a whole milestone because `extract/deps.py` did not read
`uv.lock`, and every scorecard in that period reported a clean SCA false-positive
rate over a corpus where SCA had not run. A gate that only watches findings would
have called that a pass, twice. So a detector's `ran` count dropping is a hard
failure in its own right, ranked above any finding count.

NO SMOKE SUBSET, DELIBERATELY. §6 also asks for "a fast smoke subset on every PR,
the full suite nightly". `run --limit N` slices `corpus.cases[:N]`, which changes
every denominator and splits the labelled corpus's `:vuln`/`:control` pairs down
the middle — the pair is the unit that discriminates, so half a pair measures
nothing. A subset run therefore cannot be compared against a full baseline, and
this gate refuses to try (see `_comparable`). Building a pair-aware, stratified
smoke subset is real work with its own sampling argument; it is not wiring.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from pr_review.benchmark.metrics import (
    AblationMetrics,
    LabelledMetrics,
    NegativeMetrics,
    PairMetrics,
    ablation_metrics,
    labelled_metrics,
    negative_metrics,
    pair_metrics,
)
from pr_review.benchmark import runner as runner_mod
from pr_review.benchmark.runner import CorpusRun, rescore

# How many additional findings a change may introduce before the gate fails.
# One, not zero: the negative corpus is 50 real merged PRs and a legitimate
# detector improvement can surface one more true finding in code nobody flagged —
# which is exactly what `fastapi#16141` turned out to be (gitpython 3.1.57, fixed
# in 3.1.58). Zero would make the gate fail on the tool getting better. Anything
# larger stops being a ratchet.
DEFAULT_MAX_NEW_FINDINGS = 1


class GateError(Exception):
    """The comparison could not be made. Distinct from the comparison failing."""


@dataclass
class Check:
    """One verdict. `delta` is baseline -> current in the units being gated."""
    name: str
    passed: bool
    detail: str
    baseline: str = ""
    current: str = ""

    def render(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        move = f"  {self.baseline} -> {self.current}" if self.baseline else ""
        return f"  [{mark}] {self.name}{move}\n         {self.detail}"


@dataclass
class GateResult:
    corpus: str
    baseline_sha: str = ""
    current_sha: str = ""
    checks: list[Check] = field(default_factory=list)
    reported: dict[str, str] = field(default_factory=dict)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.passed]

    @property
    def passed(self) -> bool:
        return not self.failures


# ---------------------------------------------------------------------------
# Comparability — refuse rather than mislead
# ---------------------------------------------------------------------------

def _load(path: str | Path, role: str) -> CorpusRun:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise GateError(f"cannot read the {role} run at {path}: {exc}") from exc
    # Checked before scoring so a version mismatch is reported as what it is. The
    # advice differs: a stale dump is re-pinned, a malformed one is a bug, and
    # `from_dict` raises the same `ValueError` for both — as does every pydantic
    # validation error underneath it.
    version = data.get("dump_version")
    if version != runner_mod._DUMP_VERSION:
        raise GateError(
            f"the {role} run at {path} is version {version!r} and this build "
            f"reads {runner_mod._DUMP_VERSION}. It was written before the dump "
            f"carried what scoring now reads, so gating against it would compare "
            f"missing fields. Re-pin it: re-run that corpus on a known-good "
            f"commit and gate against the new file.")

    try:
        # `rescore`, not `from_dict`. A `CorpusRun` loaded from a dump carries no
        # `scores` and no `detector_status` — both are re-derived, deliberately,
        # so the replay path computes them the same way the live path did. The
        # first draft of this called `from_dict` and every count on both sides was
        # zero, so all seven checks passed by comparing nothing to nothing. That
        # is the exact failure this module was written to catch, and it caught it
        # here first; `_scored` below is the guard that came out of it.
        return rescore(data)
    except ValueError as exc:
        raise GateError(
            f"the {role} run at {path} is the right version but could not be "
            f"scored: {exc}") from exc


def _scored(run: CorpusRun, role: str) -> None:
    """An empty run compares equal to anything, including another empty run.

    Written after the gate passed seven checks on two runs it had never scored.
    Every ratchet is `current >= baseline` or `current <= baseline`, so zero
    against zero satisfies all of them at once and reports PASS in a loud voice.
    A comparison with no data is not a pass; it is not a comparison.
    """
    if not run.scores:
        raise GateError(
            f"the {role} run has no scored cases. Either the corpus ran empty or "
            f"the dump could not be scored — and an unscored run passes every "
            f"check by comparing zero to zero.")


def _comparable(baseline: CorpusRun, current: CorpusRun) -> None:
    """Two runs are comparable only if they measured the same thing.

    Every check below is a denominator. Comparing across a difference in any of
    them produces a number that looks like a regression and is arithmetic.
    """
    _scored(baseline, "baseline")
    _scored(current, "current")

    if baseline.corpus_name != current.corpus_name:
        raise GateError(
            f"different corpora: baseline is {baseline.corpus_name!r}, current is "
            f"{current.corpus_name!r}. There is nothing to compare.")

    if baseline.cold_profiles != current.cold_profiles:
        raise GateError(
            f"baseline ran with cold_profiles={baseline.cold_profiles} and the "
            f"current run with cold_profiles={current.cold_profiles}. That flag "
            f"changes what is measured, not just how long it takes: without it a "
            f"second case in a repository is scored against the first case's "
            f"patched profile. Re-run one of them to match.")

    base_ids = {r.case.id for r in baseline.runs}
    cur_ids = {r.case.id for r in current.runs}
    if base_ids != cur_ids:
        missing = sorted(base_ids - cur_ids)[:5]
        added = sorted(cur_ids - base_ids)[:5]
        raise GateError(
            f"the two runs cover different cases "
            f"({len(base_ids)} baseline, {len(cur_ids)} current; "
            f"missing={missing} added={added}). Every rate here is per case, so a "
            f"changed case set changes every denominator. This is also why "
            f"`run --limit` cannot be gated against a full baseline.")


# ---------------------------------------------------------------------------
# Metric extraction
# ---------------------------------------------------------------------------

@dataclass
class _Snapshot:
    """The counts a gate compares, pulled out of a scored run."""
    negative: NegativeMetrics
    labelled: LabelledMetrics
    pairs: PairMetrics
    ablation: AblationMetrics
    detector_ran: dict[str, int]
    errors: int


def snapshot(run: CorpusRun) -> _Snapshot:
    """Reduce a run to the numbers the gate reads.

    The `labelled` split matches `report.render_scorecard` exactly: a `:control`
    case carries no ground truth, so it is scored on the negative branch. That is
    why the labelled corpus reports a false-positive rate at all — it is over the
    26 controls, not the 26 vulnerable sides.
    """
    negatives = [s for s in run.scores if not s.labelled]
    labelled = [s for s in run.scores if s.labelled]
    pair_of = {r.case.id: r.case.pair_id for r in run.runs if r.case.pair_id}
    labelled_of = {r.case.id: r.case.labelled for r in run.runs}
    return _Snapshot(
        negative=negative_metrics(negatives),
        labelled=labelled_metrics(labelled),
        pairs=(pair_metrics(run.scores, pair_of, labelled_of)
               if pair_of else PairMetrics()),
        ablation=ablation_metrics(run.ablations) if run.ablations else AblationMetrics(),
        detector_ran={name: counts.get("ran", 0)
                      for name, counts in (run.detector_status or {}).items()},
        errors=len(run.errors),
    )


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------

def _invariants(base: _Snapshot, cur: _Snapshot) -> list[Check]:
    """Did the measurement happen? Ranked above any finding count."""
    checks = [Check(
        name="no case errors",
        passed=cur.errors <= base.errors,
        detail=("a case that raised produced no verdict, so every rate below is "
                "over a smaller corpus than it claims"),
        baseline=str(base.errors), current=str(cur.errors),
    )]

    for name in sorted(set(base.detector_ran) | set(cur.detector_ran)):
        was, now = base.detector_ran.get(name, 0), cur.detector_ran.get(name, 0)
        checks.append(Check(
            name=f"detector {name!r} still runs",
            passed=now >= was,
            detail=("a detector going quiet reads as a clean scorecard. `sca` ran "
                    "once in 102 cases for a whole milestone and every report in "
                    "that period looked fine"),
            baseline=f"ran {was}", current=f"ran {now}",
        ))

    # The filter is not load-bearing at M2 (errata §14.19) — it does not gate what
    # the detectors see. This watches the number now so the day it does becomes a
    # visible event rather than a silent one.
    checks.append(Check(
        name="noise filter drops no ground truth",
        passed=cur.ablation.dropped <= base.ablation.dropped,
        detail=("a ground-truth file dropped before the detectors read it is a "
                "miss nothing downstream can recover"),
        baseline=f"{base.ablation.dropped} dropped of {base.ablation.gt_files}",
        current=f"{cur.ablation.dropped} dropped of {cur.ablation.gt_files}",
    ))
    return checks


def _ratchets(base: _Snapshot, cur: _Snapshot, max_new: int) -> list[Check]:
    """Integer ratchets. Noise may not grow; signal may not shrink."""
    return [
        Check(
            name="gate-relevant false positives do not increase",
            passed=cur.negative.gate_relevant <= base.negative.gate_relevant,
            detail=("HIGH and CRITICAL are what can fail someone's build; a new "
                    "one is a different problem from a new report line"),
            baseline=str(base.negative.gate_relevant),
            current=str(cur.negative.gate_relevant),
        ),
        Check(
            name=f"false positives grow by at most {max_new}",
            passed=cur.negative.findings <= base.negative.findings + max_new,
            detail=("counted, not averaged — with n=50 a rate hides whether one "
                    "case changed or twenty did"),
            baseline=str(base.negative.findings),
            current=str(cur.negative.findings),
        ),
        Check(
            name="true positives do not disappear",
            passed=cur.labelled.tp >= base.labelled.tp,
            detail=("the whole numerator is currently one finding, so this is a "
                    "1-case ratchet and that is precisely why it is a count"),
            baseline=str(base.labelled.tp), current=str(cur.labelled.tp),
        ),
        Check(
            name="in-scope true positives do not disappear",
            passed=cur.labelled.in_scope_tp >= base.labelled.in_scope_tp,
            detail="the stratum where a 3a detector could have named the CWE",
            baseline=str(base.labelled.in_scope_tp),
            current=str(cur.labelled.in_scope_tp),
        ),
        Check(
            name="discriminated pairs do not decrease",
            passed=(cur.pairs.detected_and_control_clean
                    >= base.pairs.detected_and_control_clean),
            detail=("found the vulnerable side and stayed quiet on the fixed one "
                    "— the only unambiguous success the corpus can express"),
            baseline=str(base.pairs.detected_and_control_clean),
            current=str(cur.pairs.detected_and_control_clean),
        ),
    ]


def _reported(cur: _Snapshot) -> dict[str, str]:
    """Rates. Printed with denominators, never consulted for a verdict.

    Every numerator here is currently under five. They are the numbers a human
    reads to understand the run; they are not numbers a machine should rule on.
    """
    # `Rate.render` is the only formatter used, deliberately: it refuses to print
    # a ratio without its denominator, which is the whole reason these are safe
    # to show next to a verdict they did not decide.
    out = {
        "false positives per PR": cur.negative.fp_per_pr.render(),
        "gate-relevant per PR": cur.negative.gate_relevant_per_pr.render(),
        "clean rate": cur.negative.clean_rate.render(),
        "missing-authz per endpoint": cur.negative.missing_authz_per_endpoint.render(),
    }
    if cur.labelled.cases:
        out["precision"] = cur.labelled.precision.render()
        out["recall"] = cur.labelled.recall.render()
        out["in-scope recall"] = cur.labelled.in_scope_recall.render()
        out["localization"] = cur.labelled.localization.render()
    if cur.pairs.pairs:
        out["pair discrimination"] = cur.pairs.discriminated.render()
    if cur.ablation.gt_files:
        out["recall after filter"] = cur.ablation.recall_after_filter.render()
    return out


def gate(baseline: CorpusRun, current: CorpusRun,
         max_new_findings: int = DEFAULT_MAX_NEW_FINDINGS) -> GateResult:
    """Compare two scored runs. Raises `GateError` if they are not comparable."""
    _comparable(baseline, current)
    base, cur = snapshot(baseline), snapshot(current)
    return GateResult(
        corpus=current.corpus_name,
        baseline_sha=baseline.code_sha,
        current_sha=current.code_sha,
        checks=_invariants(base, cur) + _ratchets(base, cur, max_new_findings),
        reported=_reported(cur),
    )


def gate_files(baseline_path: str | Path, current_path: str | Path,
               max_new_findings: int = DEFAULT_MAX_NEW_FINDINGS) -> GateResult:
    return gate(_load(baseline_path, "baseline"), _load(current_path, "current"),
                max_new_findings)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def render(result: GateResult) -> str:
    lines = [
        f"regression gate — {result.corpus}",
        f"  baseline {result.baseline_sha or '(unknown)'}"
        f" -> current {result.current_sha or '(unknown)'}",
        "",
        "gated (counts):",
    ]
    lines += [c.render() for c in result.checks]
    lines += ["", "reported, not gated (rates — every numerator is under five):"]
    lines += [f"  {name:<30} {value}" for name, value in result.reported.items()]
    lines += [""]
    if result.passed:
        lines.append(f"PASS — {len(result.checks)} checks")
    else:
        lines.append(f"FAIL — {len(result.failures)} of {len(result.checks)} checks")
        lines += [f"       {c.name}: {c.baseline} -> {c.current}"
                  for c in result.failures]
    return "\n".join(lines)


def as_dict(result: GateResult) -> dict:
    """Machine-readable form. `report.py` renders markdown for people and has no
    reason to grow a second audience; this is the only JSON in the harness."""
    return {
        "corpus": result.corpus,
        "passed": result.passed,
        "baseline_sha": result.baseline_sha,
        "current_sha": result.current_sha,
        "checks": [asdict(c) for c in result.checks],
        "reported": result.reported,
    }
