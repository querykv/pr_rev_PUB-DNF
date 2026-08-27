"""Aggregation (`plan/benchmark.md` §1).

Turns per-case verdicts into the numbers a scorecard prints. Two rules run
through all of it:

**Every rate carries its denominator.** A precision of 0.83 over 6 findings and
one over 600 are different claims, and a table that shows only the ratio lets the
reader assume the second. `Rate` keeps the numerator and denominator together and
renders them together, so no call site can drop the n by accident.

**The aggregate is the least useful number here.** "11 findings per PR" does not
tell anyone what to do; "`BAC-MISSING-AUTHZ` accounts for 8 of those 11" tells
them exactly what to fix. So the breakdowns by taxonomy id, detector and severity
are not extras — they are the output, and the headline is the summary of them.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from pr_review.benchmark.scope import in_scope_cwes, is_in_scope
from pr_review.benchmark.scoring import CaseScore, FilterAblation
from pr_review.schema import Severity

# Severity levels at or above the gate's default floor (`config.GateConfig`).
# A false positive that can fail someone's build is a different problem from one
# that adds a line to a report, and averaging them hides the only one that costs
# a team anything.
_GATE_RELEVANT = {Severity.HIGH.value, Severity.CRITICAL.value}


@dataclass(frozen=True)
class Rate:
    """A ratio that refuses to be quoted without its denominator."""
    num: int
    den: int

    @property
    def value(self) -> float | None:
        return (self.num / self.den) if self.den else None

    def render(self, places: int = 3) -> str:
        if self.den == 0:
            return "n/a (0 cases)"
        return f"{self.value:.{places}f} ({self.num}/{self.den})"


@dataclass
class NegativeMetrics:
    """§2c: the false-positive picture on known-clean PRs.

    THE AGGREGATE HIDES THE RULE WE MOST NEED TO PRICE. `M2_STATUS.md` §3.2's
    named worry is that `BAC-MISSING-AUTHZ` fires on every unguarded endpoint in
    a changed file, including deliberately public ones. Most merged PRs touch no
    endpoint at all, so that rule cannot fire in them, and averaging over the
    whole corpus reports it at near-zero — a number that is arithmetically true
    and answers a different question than the one asked.

    So the endpoint-touching cases are counted as their own stratum. The
    stratification is derived from what the structural detector actually saw
    (`telemetry.detect.structural.endpoints`), **not** from how the corpus was
    picked: biasing selection toward endpoint files would make the headline
    unrepresentative, while deriving the stratum afterwards leaves both numbers
    honest.
    """
    cases: int = 0
    findings: int = 0
    gate_relevant: int = 0
    clean_cases: int = 0                       # PRs with zero findings
    # What delta scoping removed. `skipped_pre_existing` is the count
    # `findings/delta.py` attributed to the base tree; `findings` is what
    # survived. Their sum is what the detectors actually produced, and until
    # 2026-08-22 nothing reported it -- see `suppression` below and §14.46.
    skipped_pre_existing: int = 0
    by_internal: dict[str, int] = field(default_factory=dict)
    by_detector: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    per_case: dict[str, int] = field(default_factory=dict)
    # The endpoint stratum (see the class docstring).
    endpoint_cases: int = 0
    endpoint_findings: int = 0
    endpoints_seen: int = 0
    missing_authz: int = 0

    @property
    def fp_per_endpoint_pr(self) -> Rate:
        """False positives per PR *in which the detector saw an endpoint*."""
        return Rate(self.endpoint_findings, self.endpoint_cases)

    @property
    def missing_authz_per_endpoint(self) -> Rate:
        """`BAC-MISSING-AUTHZ` alarms per endpoint the detector actually saw.

        The direct form of §3.2's question: of the endpoints in changed files,
        what share did we flag as missing authorization on clean code?
        """
        return Rate(self.missing_authz, self.endpoints_seen)

    @property
    def fp_per_pr(self) -> Rate:
        return Rate(self.findings, self.cases)

    @property
    def gate_relevant_per_pr(self) -> Rate:
        return Rate(self.gate_relevant, self.cases)

    @property
    def raw_findings(self) -> int:
        """Everything the detectors produced, before delta scoping."""
        return self.findings + self.skipped_pre_existing

    @property
    def suppression(self) -> Rate:
        """The share of raw findings `findings/delta.py` attributed to the base
        tree.

        THIS IS THE PIPELINE'S LARGEST MEASURED EFFECT AND IT WAS UNREPORTED.
        Every metric in this module was aimed at recall, which is the axis this
        tool is worst at, so the one axis it is unambiguously good at had no
        number anywhere -- 75 of 87 findings removed on the negative corpus, and
        the scorecard said only that 75 were "excluded from scoring". Errata
        §14.46.
        """
        return Rate(self.skipped_pre_existing, self.raw_findings)

    @property
    def fp_per_pr_unscoped(self) -> Rate:
        """False positives per PR if every raw finding were reported.

        DERIVED, NOT MEASURED. This is the arithmetic of turning delta scoping
        off, not a run with it off: a real unscoped run would also lose the
        baseline's effect on Semgrep's own `--baseline-commit` scoping, so the
        true figure is this or worse. `benchmark/configs/no-baseline.yaml`
        measures the middle tier -- hunk-based scoping, what the tool does when
        no base checkout exists -- and that one is a run.
        """
        return Rate(self.raw_findings, self.cases)

    @property
    def clean_rate(self) -> Rate:
        """Share of clean PRs the tool says nothing about.

        Arguably the number a team feels most directly: it is how often the tool
        stays quiet when there is nothing to say.
        """
        return Rate(self.clean_cases, self.cases)


@dataclass
class LabelledMetrics:
    """§2a: precision and recall against fixing-commit ground truth."""
    cases: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    near_miss: int = 0
    tp_exact_cwe: int = 0
    tp_related_cwe: int = 0
    by_family_tp: dict[str, int] = field(default_factory=dict)
    by_family_fn: dict[str, int] = field(default_factory=dict)
    # The in-scope stratum (`benchmark/scope.py`). Roughly half this corpus is
    # CWEs no 3a detector emits, so the flat recall figure prices a milestone
    # boundary as a detector failure.
    in_scope_tp: int = 0
    in_scope_fn: int = 0
    # Ground-truth ROWS, the unit recall is actually about. `tp`/`fn` above are
    # finding-level and stay that way for precision — see `recall`.
    gt_rows: int = 0
    gt_matched: int = 0
    # Rows located regardless of what the finding called them (§4u, §27).
    gt_located: int = 0
    in_scope_rows: int = 0
    in_scope_matched: int = 0
    out_of_scope_fn: int = 0
    out_of_scope_cwes: dict[str, int] = field(default_factory=dict)
    # Misses the detector actually found, which `delta.py` attributed to the
    # base tree — see `scoring.BaselineAttribution`.
    baseline_overlapping: int = 0
    baseline_file_only: int = 0

    # Delta scoping, as on the negative side. Kept separately because the two
    # corpora answer different questions with it: here it is "how much did the
    # baseline pass remove from a case that does contain a real vulnerability",
    # which is the number that says whether it removes too much.
    scored_findings: int = 0
    skipped_pre_existing: int = 0

    @property
    def precision(self) -> Rate:
        return Rate(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> Rate:
        """Ground-truth rows found, over ground-truth rows that exist.

        THIS COUNTED THE WRONG UNIT UNTIL 2026-08-21. It was
        `Rate(self.tp, self.tp + self.fn)`, and those are different things:
        `tp` counts **findings** (one verdict per finding, in `score_case`)
        while `fn` counts **ground-truth rows** (`score.missed`). Two findings
        matching one row scored tp=2, fn=0 — so the denominator grew with the
        number of findings an arm produced, and recall rose for reporting the
        same defect twice.

        Invisible while only the pipeline was measured: it produced exactly one
        true positive, where the two units coincide, and every stored run shows
        a denominator of exactly 36. The LLM baseline made it visible on first
        contact — denominators of 41, 39 and 38 against a corpus with 36 rows —
        and the inflation was ~20% in its favour, in the direction of the arm
        this project would least like to lose to.

        `precision` is untouched: a false positive really is a property of a
        finding, so finding-level is the right unit there.
        """
        return Rate(self.gt_matched, self.gt_rows)

    @property
    def recall_ignoring_cwe(self) -> Rate:
        """Rows some finding pointed at, with the CWE label ignored entirely.

        Reported ALONGSIDE `recall`, never instead of it. The gap between the
        two is the measurement's own vocabulary error, and printing both is what
        stops a reader having to guess which one a headline meant.

        Added 2026-08-26 after the same probe that added `_CWE_GROUPS`'s
        CWE-59/61 entry. That entry fixed the largest measured instance; this
        number exists because a hand-list cannot fix the class, and because
        "did the tool point at the vulnerable lines" is a question worth
        answering separately from "did it agree with the advisory's label".

        It is an upper bound on recall and can only ever be >= it -- a row that
        matched with a CWE necessarily overlapped without one.
        """
        return Rate(self.gt_located, self.gt_rows)

    @property
    def f1(self) -> float | None:
        p, r = self.precision.value, self.recall.value
        if not p or not r:
            return None
        return 2 * p * r / (p + r)

    @property
    def localization(self) -> Rate:
        """Of everything that matched a label, how much landed on the lines.

        §1's "localization accuracy": is the finding actionable, or does it merely
        name the right file?
        """
        return Rate(self.tp, self.tp + self.near_miss)

    @property
    def relation_table_share(self) -> Rate:
        """How many true positives the CWE relation table bought.

        If this is most of them, the headline is a property of
        `scoring._CWE_GROUPS` rather than of the detectors, and the reader has to
        be able to see that.
        """
        return Rate(self.tp_related_cwe, self.tp)

    @property
    def raw_findings(self) -> int:
        return self.scored_findings + self.skipped_pre_existing

    @property
    def suppression(self) -> Rate:
        return Rate(self.skipped_pre_existing, self.raw_findings)

    @property
    def in_scope_recall(self) -> Rate:
        """Recall over ground truth some 3a detector could have named.

        The honest reading of this milestone. The flat `recall` above counts a
        CWE-1333 miss against detectors that do not model resource consumption
        at all, which measures the roadmap rather than the tool.
        """
        return Rate(self.in_scope_matched, self.in_scope_rows)

    @property
    def reached_the_right_file(self) -> Rate:
        """Ground truth some finding named, whether or not it was scored.

        The union of true positives, near misses, and misses the detector found
        but `delta.py` blamed on the baseline. It is **not** a quality claim —
        naming a file is not naming a defect — but with recall this low the
        interesting question is whether the detectors are blind or merely
        mis-aimed, and this separates the two.
        """
        found = (self.tp + self.near_miss
                 + self.baseline_overlapping + self.baseline_file_only)
        return Rate(found, self.tp + self.near_miss + self.fn)


@dataclass
class AblationMetrics:
    """§3's filter leak check. See `scoring.FilterAblation` for the M2 caveat."""
    cases: int = 0
    gt_files: int = 0
    dropped: int = 0
    dropped_without_guardrail: int = 0
    examples: list[tuple[str, str, str]] = field(default_factory=list)  # case, path, reason

    @property
    def recall_after_filter(self) -> Rate:
        return Rate(self.gt_files - self.dropped, self.gt_files)


def negative_metrics(scores: list[CaseScore]) -> NegativeMetrics:
    m = NegativeMetrics(cases=len(scores))
    internal: Counter = Counter()
    detector: Counter = Counter()
    severity: Counter = Counter()
    for score in scores:
        fps = [v for v in score.verdicts if v.label == "fp"]
        m.findings += len(fps)
        m.skipped_pre_existing += score.skipped_pre_existing
        m.per_case[score.case_id] = len(fps)
        if not fps:
            m.clean_cases += 1
        if score.endpoints:
            m.endpoint_cases += 1
            m.endpoints_seen += score.endpoints
            m.endpoint_findings += len(fps)
        m.missing_authz += sum(1 for v in fps if v.internal == "BAC-MISSING-AUTHZ")
        for v in fps:
            internal[v.internal] += 1
            detector[v.detector] += 1
            sev = v.finding.severity.value
            severity[sev] += 1
            if sev in _GATE_RELEVANT:
                m.gate_relevant += 1
    m.by_internal = dict(internal.most_common())
    m.by_detector = dict(detector.most_common())
    m.by_severity = dict(severity.most_common())
    return m


def labelled_metrics(scores: list[CaseScore]) -> LabelledMetrics:
    m = LabelledMetrics(cases=len(scores))
    tp_fam: Counter = Counter()
    fn_fam: Counter = Counter()
    oos_fam: Counter = Counter()
    # Computed once: `in_scope_cwes()` walks several detector tables, and doing
    # it per ground-truth row would make the cost quadratic in corpus size for
    # a set that cannot change during a run.
    scope = in_scope_cwes()
    for score in scores:
        m.tp += score.tp
        m.fp += score.fp
        m.fn += score.fn
        m.near_miss += score.near_miss
        for v in score.verdicts:
            if v.label != "tp":
                continue
            tp_fam[v.finding.taxonomy.family] += 1
            if v.match_kind == "exact_cwe":
                m.tp_exact_cwe += 1
            elif v.match_kind == "related_cwe":
                m.tp_related_cwe += 1
            if v.matched is not None and is_in_scope(v.matched.cwe, scope):
                m.in_scope_tp += 1
        for gt in score.missed:
            fn_fam[gt.cwe] += 1
            if is_in_scope(gt.cwe, scope):
                m.in_scope_fn += 1
            else:
                m.out_of_scope_fn += 1
                oos_fam[gt.cwe] += 1
        # Row-level tallies, independent of how many findings touched each row.
        located = {(g.file, tuple(map(tuple, g.spans)), g.cwe) for g in score.located}
        for gt in score.matched:
            m.gt_rows += 1
            m.gt_matched += 1
            m.gt_located += 1
            if is_in_scope(gt.cwe, scope):
                m.in_scope_rows += 1
                m.in_scope_matched += 1
        for gt in score.missed:
            m.gt_rows += 1
            # A row can be missed by `recall` and still LOCATED: right file,
            # right lines, a CWE the relation table does not connect. That gap
            # is precisely what this pair of numbers exists to show.
            if (gt.file, tuple(map(tuple, gt.spans)), gt.cwe) in located:
                m.gt_located += 1
            if is_in_scope(gt.cwe, scope):
                m.in_scope_rows += 1
        m.baseline_overlapping += len(score.baseline.overlapping)
        m.baseline_file_only += len(score.baseline.file_only)
        m.scored_findings += score.scored_findings
        m.skipped_pre_existing += score.skipped_pre_existing
    m.by_family_tp = dict(tp_fam.most_common())
    m.by_family_fn = dict(fn_fam.most_common())
    m.out_of_scope_cwes = dict(oos_fam.most_common())
    return m


@dataclass
class PairMetrics:
    """§2c's paired control, which is what makes a reverted fix worth scoring.

    A labelled case built by reverting a fix presents the vulnerability in the
    easiest possible way: the vulnerable lines are essentially the whole diff.
    Recall alone therefore cannot separate **"the detector found the
    vulnerability"** from **"the detector always fires on this file"** — and the
    second would score identically while being worthless.

    The control holds the file constant and removes only the vulnerability. So
    the pair, not either half, is the unit that answers the question, and only
    `detected_and_control_clean` is an unambiguous success.
    """
    pairs: int = 0
    detected_and_control_clean: int = 0
    detected_but_control_also_flagged: int = 0
    missed: int = 0
    unpaired: int = 0
    examples: list[tuple[str, str]] = field(default_factory=list)  # pair_id, outcome

    @property
    def discriminated(self) -> Rate:
        """Pairs where the tool told the vulnerable side from the fixed one."""
        return Rate(self.detected_and_control_clean, self.pairs)


def pair_metrics(scores: list[CaseScore], pair_of: dict[str, str],
                 labelled_of: dict[str, bool]) -> PairMetrics:
    """Join the two halves of each advisory on `BenchCase.pair_id`.

    `pair_of` and `labelled_of` are passed in rather than read off the scores
    because `CaseScore` deliberately does not carry the case — it carries the
    verdicts, which is what scoring needs. The caller has both.
    """
    m = PairMetrics()
    by_pair: dict[str, dict[str, CaseScore]] = {}
    for score in scores:
        pid = pair_of.get(score.case_id, "")
        if not pid:
            continue
        side = "vuln" if labelled_of.get(score.case_id) else "control"
        by_pair.setdefault(pid, {})[side] = score

    for pid, sides in sorted(by_pair.items()):
        vuln = sides.get("vuln")
        control = sides.get("control")
        if vuln is None or control is None:
            m.unpaired += 1
            continue
        m.pairs += 1
        if vuln.tp == 0:
            outcome = "missed"
            m.missed += 1
        elif control.fp == 0:
            outcome = "detected, control clean"
            m.detected_and_control_clean += 1
        else:
            outcome = "detected, but control also flagged"
            m.detected_but_control_also_flagged += 1
        m.examples.append((pid, outcome))
    return m


def ablation_metrics(ablations: list[FilterAblation]) -> AblationMetrics:
    m = AblationMetrics(cases=len(ablations))
    for a in ablations:
        m.gt_files += a.gt_files
        m.dropped += len(a.dropped_gt_files)
        for path in a.dropped_gt_files:
            reason = a.drop_reasons.get(path, "")
            m.examples.append((a.case_id, path, reason))
            # A drop the guardrail never looked at is a different bug from one it
            # looked at and allowed — `DropRecord.guardrail_considered` exists to
            # tell them apart, and only the first is a hole in the guardrail.
            if not a.guardrail_considered.get(path, False):
                m.dropped_without_guardrail += 1
    return m
