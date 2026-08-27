"""Findings <-> ground truth (`plan/benchmark.md` §3).

TWO SCORING RULES, BECAUSE THERE ARE TWO QUESTIONS

*Negative set* (§2c, `ground_truth == []`): known-clean code, so every finding
the tool attributes to the PR is a false positive. There is no recall to compute
— a detector that reports nothing scores perfectly here, which is why this number
must never be published alone.

*Labelled set* (§2a): a true positive requires **compatible taxonomy AND location
overlap** with the fixing commit's changed lines. Right file, wrong lines is
tracked separately as a near miss (§3) rather than folded into either column,
because the two failures have different fixes — a near miss is a localization bug
and an FP is a precision bug.

ONLY `introduced_by_pr` FINDINGS ARE SCORED. `findings/delta.py` already
separates what the PR is answerable for from what it inherited, and pre-existing
findings are demoted to `status=pre_existing` and never gate. Counting them would
price the repository's backlog rather than this tool's noise, and would make a
detector look worse on an old repo than on a new one for reasons having nothing
to do with the detector.

THE CWE RELATION TABLE IS THE PLACE THIS CHEATS

§3 says "compatible taxonomy (same CWE family)" and leaves "family" undefined.
Defined too widely, every finding matches every label and precision goes to 1.0
without a line of detector work. So the table below is explicit, small, and
justified per group, exact match is the default, and `MatchKind` records which
of the two fired so `report.py` can show how many TPs the table bought. If most
of them came from the relation table rather than from exact CWE, the reader needs
to see that, and so do we.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pr_review.benchmark.schema import BenchCase, GTVuln
from pr_review.schema import Finding

MatchKind = Literal["exact_cwe", "related_cwe"]
Label = Literal["tp", "fp", "near_miss"]


# Groups of CWE ids we treat as the same defect for matching purposes. Each group
# is a parent/child or specialization relation in MITRE's own hierarchy, not a
# loose thematic grouping — "both are injection" is not a reason to be in here.
#
# Widening this table raises every precision and recall number in every scorecard
# without changing the tool. Treat an addition as a reviewed change with a stated
# justification, the same standard `detect/normalize.py:_EXACT` holds itself to.
_CWE_GROUPS: tuple[frozenset[str], ...] = (
    # CWE-77 command injection is the parent of CWE-78 OS command injection.
    frozenset({"CWE-77", "CWE-78"}),
    # CWE-94 code injection; CWE-95 eval injection is its child.
    frozenset({"CWE-94", "CWE-95"}),
    # CWE-22 path traversal and its directional children.
    frozenset({"CWE-22", "CWE-23", "CWE-35", "CWE-36"}),
    # Authorization: CWE-285 improper authorization is the parent of both
    # CWE-862 missing and CWE-863 incorrect; CWE-639 (IDOR) is a child of 863.
    frozenset({"CWE-285", "CWE-862", "CWE-863", "CWE-639"}),
    # Hardcoded credentials: CWE-259 hardcoded password is a child of CWE-798.
    frozenset({"CWE-798", "CWE-259"}),
    # Crypto: CWE-327 broken algorithm, CWE-328 weak hash, CWE-326 inadequate
    # key strength — siblings under the same weakness class.
    frozenset({"CWE-326", "CWE-327", "CWE-328"}),
    # Vulnerable third-party component, which MITRE has spelled several ways
    # over the years and advisories still use inconsistently.
    frozenset({"CWE-937", "CWE-1035", "CWE-1104", "CWE-1395"}),
    # XSS and server-side template injection overlap in the reflected case:
    # CWE-1336 SSTI frequently manifests as CWE-79 in advisory labelling.
    frozenset({"CWE-79", "CWE-1336"}),
    # Link resolution: CWE-61 UNIX symlink following is a child of CWE-59
    # improper link resolution. ADDED 2026-08-26, and the only entry here added
    # after a measurement rather than from reading the taxonomy.
    #
    # Across six stored LLM passes, 44 findings landed in the right file on
    # overlapping lines and were scored false positive on this pair alone, in
    # both directions -- the largest single source of mis-scoring in the corpus
    # and its most common vulnerability class (BENCHMARK_STATUS.md §4u,
    # OPEN_ITEMS.md §27).
    #
    # WHY THIS ONE AND NOT THE OTHERS THE SAME PROBE FOUND. The standing rule is
    # "do not widen this table to flatter an arm", and its mechanism is that
    # `benchmark/scope.py` reads it too, so a wider group moves recall on both
    # sides. Measured before adding: neither CWE-59 nor CWE-61 is emittable by
    # any detector, so `reachable_ground_truth` cannot change and arm 2's
    # ceiling stays at 9/36. {CWE-77, 78, 88} was rejected on exactly that test
    # -- CWE-78 IS emittable, and adding it moved the ceiling 9 -> 11.
    # `.claude/handoff/cwe-relation-probe.py` re-derives both results.
    frozenset({"CWE-59", "CWE-61"}),
)


def _norm_cwe(cwe: str) -> str:
    """`89`, `cwe-89`, `CWE_89` -> `CWE-89`. Advisories spell it every way."""
    s = (cwe or "").strip().upper().replace("_", "-")
    if not s:
        return ""
    if s.startswith("CWE-"):
        return s
    if s.startswith("CWE"):
        return f"CWE-{s[3:].lstrip('-')}"
    return f"CWE-{s}"


def cwe_match(finding_cwes: list[str], gt_cwe: str) -> MatchKind | None:
    """Is `gt_cwe` compatible with any of a finding's CWE ids?

    Exact intersection first, so a scorecard can report how much of its precision
    survives without the relation table at all.
    """
    gt = _norm_cwe(gt_cwe)
    ours = {_norm_cwe(c) for c in finding_cwes if c}
    if not gt or not ours:
        return None
    if gt in ours:
        return "exact_cwe"
    for group in _CWE_GROUPS:
        if gt in group and ours & group:
            return "related_cwe"
    return None


# ---------------------------------------------------------------------------
# Per-case scoring
# ---------------------------------------------------------------------------

@dataclass
class FindingVerdict:
    finding: Finding
    label: Label
    matched: GTVuln | None = None
    match_kind: MatchKind | None = None

    @property
    def internal(self) -> str:
        return self.finding.taxonomy.internal

    @property
    def detector(self) -> str:
        return self.finding.provenance.tool


@dataclass
class BaselineAttribution:
    """Ground truth the detector found and `delta.py` then blamed on the base.

    THE DISTINCTION THIS EXISTS TO DRAW. A missed ground-truth row can fail in
    two completely different ways: no detector ever produced a finding for it,
    or a detector produced exactly the right finding and the delta stage
    attributed it to the baseline, so it never reached scoring. They have
    different causes and different fixes, and `recall` prices them identically
    at zero.

    On a negative corpus the question cannot arise — excluding pre-existing
    findings is unambiguously right there, since counting a repository's backlog
    as this tool's noise would make an old repo score worse than a new one for
    reasons having nothing to do with the detectors. On a labelled corpus the
    same exclusion silently absorbs detections.

    `overlapping` would have been a true positive had it been attributed to the
    PR; `file_only` would have been a near miss. Keeping them apart matters
    because they argue for different work — the first for the delta stage, the
    second for localization.
    """
    overlapping: list[GTVuln] = field(default_factory=list)
    file_only: list[GTVuln] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.overlapping) + len(self.file_only)


@dataclass
class CaseScore:
    case_id: str
    labelled: bool
    verdicts: list[FindingVerdict] = field(default_factory=list)
    matched: list = field(default_factory=list)      # GTVuln rows some finding hit
    missed: list[GTVuln] = field(default_factory=list)      # false negatives
    # Rows some finding LOCATED, whatever it called them: right file,
    # overlapping lines, CWE ignored entirely. Always a superset of `matched`.
    #
    # It exists because `_CWE_GROUPS` is a hand-list and cannot keep up with a
    # taxonomy of ~940 ids, so every advisory that labels a defect one level up
    # or down from where a model would is a silent false positive. Adding the
    # one measured pair (§4u) fixed the largest instance; this separates the
    # remaining question -- "found the defect" from "labelled it our way" --
    # rather than resolving it by decree. A reader can then see how much of any
    # gap between arms is detection and how much is vocabulary.
    located: list[GTVuln] = field(default_factory=list)
    scored_findings: int = 0        # introduced findings considered
    skipped_pre_existing: int = 0   # excluded by the rule in the module docstring
    baseline: BaselineAttribution = field(default_factory=BaselineAttribution)
    # What the run *could* have found, filled by the runner from telemetry.
    # A rule cannot produce a false positive in a PR where nothing it looks at
    # exists, so an aggregate over PRs that touch no endpoint at all silently
    # prices `BAC-MISSING-AUTHZ` at zero. See `metrics.NegativeMetrics`.
    context: dict = field(default_factory=dict)

    @property
    def endpoints(self) -> int:
        return int(self.context.get("endpoints", 0) or 0)

    @property
    def tp(self) -> int:
        return sum(1 for v in self.verdicts if v.label == "tp")

    @property
    def fp(self) -> int:
        return sum(1 for v in self.verdicts if v.label == "fp")

    @property
    def near_miss(self) -> int:
        return sum(1 for v in self.verdicts if v.label == "near_miss")

    @property
    def fn(self) -> int:
        return len(self.missed)


def _introduced(findings: list[Finding]) -> tuple[list[Finding], int]:
    kept = [f for f in findings if f.introduced_by_pr]
    return kept, len(findings) - len(kept)


def score_case(case: BenchCase, findings: list[Finding], *,
               pre_existing: int | None = None) -> CaseScore:
    """Classify one case's findings against its ground truth (or lack of it).

    `pre_existing` lets a caller state the excluded count instead of having it
    derived from `findings`. The replay path in `runner.py` needs this: its
    dump keeps introduced findings in full and pre-existing ones as a count,
    because `introduced_by_pr` is a *pipeline* output that this rule only ever
    partitions on and never recomputes. Left unset, the count is derived as
    before, so the live path is unchanged.
    """
    scored, skipped = _introduced(findings)
    if pre_existing is not None:
        skipped = pre_existing
    result = CaseScore(case_id=case.id, labelled=case.labelled,
                       scored_findings=len(scored), skipped_pre_existing=skipped)

    if not case.labelled:
        # The negative set. No ground truth exists, so there is nothing to match
        # against and nothing to miss: every surviving finding is a false alarm.
        result.verdicts = [FindingVerdict(f, "fp") for f in scored]
        return result

    matched_gt: set[int] = set()
    located_gt: set[int] = set()
    for f in scored:
        best: tuple[GTVuln, MatchKind, int] | None = None
        for idx, gt in enumerate(case.ground_truth):
            if gt.file != f.location.file:
                continue
            # Recorded before the taxonomy is consulted, which is the whole
            # point: this is the question a reader asks first -- did anything
            # point at the vulnerable lines at all?
            if gt.covers(f.location.start_line, f.location.end_line):
                located_gt.add(idx)
            kind = cwe_match(f.taxonomy.cwe, gt.cwe)
            if kind is None:
                continue
            overlap = gt.covers(f.location.start_line, f.location.end_line)
            # A ground-truth row is found the moment *any* finding matches its
            # taxonomy and covers its lines. This is deliberately independent of
            # which row wins `best` below: tying the two together would let a
            # genuinely-detected row be counted as a miss because some other row
            # scored higher for the same finding, which understates recall.
            if overlap:
                matched_gt.add(idx)
            # Prefer a real overlap over a near miss, and an exact CWE over a
            # related one, so a finding is judged by its best available match
            # rather than by whichever ground-truth row happened to come first.
            rank = (2 if overlap else 1) * (2 if kind == "exact_cwe" else 1)
            if best is None or rank > best[2]:
                best = (gt, kind, rank)
        if best is None:
            result.verdicts.append(FindingVerdict(f, "fp"))
            continue
        gt, kind, rank = best
        overlapped = gt.covers(f.location.start_line, f.location.end_line)
        result.verdicts.append(FindingVerdict(
            f, "tp" if overlapped else "near_miss", matched=gt, match_kind=kind))

    # Symmetric with `missed`, and the unit `recall` is actually about. Before
    # 2026-08-21 only `missed` existed, so recall's denominator was built from
    # finding-level `tp` plus row-level `fn` — two different things added
    # together. See `metrics.LabelledMetrics.recall`.
    result.matched = [gt for i, gt in enumerate(case.ground_truth) if i in matched_gt]
    result.missed = [gt for i, gt in enumerate(case.ground_truth) if i not in matched_gt]
    result.located = [gt for i, gt in enumerate(case.ground_truth) if i in located_gt]
    result.baseline = baseline_attribution(
        case, [f for f in findings if not f.introduced_by_pr], result.missed)
    return result


def baseline_attribution(case: BenchCase, pre_existing: list[Finding],
                         missed: list[GTVuln]) -> BaselineAttribution:
    """Which misses had a matching finding that scoring never saw.

    Only rows already counted as missed are considered: a row a finding was
    credited for is not also owed to the baseline, and counting it twice would
    make the columns stop summing to the ground-truth total.
    """
    out = BaselineAttribution()
    for gt in missed:
        best: str | None = None
        for f in pre_existing:
            if gt.file != f.location.file:
                continue
            if cwe_match(f.taxonomy.cwe, gt.cwe) is None:
                continue
            if gt.covers(f.location.start_line, f.location.end_line):
                best = "overlap"
                break
            best = best or "file"
        if best == "overlap":
            out.overlapping.append(gt)
        elif best == "file":
            out.file_only.append(gt)
    return out


# ---------------------------------------------------------------------------
# The filter recall ablation (§3, "per-stage ablations")
# ---------------------------------------------------------------------------

@dataclass
class FilterAblation:
    """Did the Phase-2 noise filter drop a file carrying the vulnerability?

    IMPORTANT CAVEAT, and `report.py` prints it: at M2 the filter does **not**
    gate what the detectors see. `pipeline.py` builds the detect stage from the
    manifest and every parsed file, not from `filtered.kept`, so a dropped file
    is still scanned and a finding in it still reaches the report. The filter's
    drops decide what Phase-3b agents get routed to, which arrives at M3.

    So this measures a stage before it becomes load-bearing. That is worth doing
    — the "100% recall" claim in `M1_STATUS.md` §1 rests on one hand-built 10-file
    PR — but a scorecard that implied a live leak had been closed would be wrong.
    """
    case_id: str
    gt_files: int = 0
    dropped_gt_files: list[str] = field(default_factory=list)
    drop_reasons: dict[str, str] = field(default_factory=dict)
    guardrail_considered: dict[str, bool] = field(default_factory=dict)

    @property
    def kept(self) -> int:
        return self.gt_files - len(self.dropped_gt_files)


def ablate_filter(case: BenchCase, changeset: dict) -> FilterAblation:
    """Query `02_changeset.json`'s drop records for ground-truth files.

    A read of an artifact the pipeline already writes, rather than a flag that
    changes how the pipeline runs. That keeps the ablation from perturbing the
    thing it measures, and it is why the verifier ablation at M4 costs almost
    nothing to add: same shape, different artifact.
    """
    gt_files = case.gt_files()
    ablation = FilterAblation(case_id=case.id, gt_files=len(gt_files))
    for record in changeset.get("dropped", []) or []:
        path = record.get("path", "")
        if path in gt_files:
            ablation.dropped_gt_files.append(path)
            ablation.drop_reasons[path] = record.get("reason", "")
            ablation.guardrail_considered[path] = bool(
                record.get("guardrail_considered", False))
    return ablation
