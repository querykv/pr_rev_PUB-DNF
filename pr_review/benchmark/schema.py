"""The benchmark data contract (`plan/benchmark.md` §4).

§4 sketches `BenchCase` and `GTVuln` and names a `PRTask` it never defines. This
module is that sketch made real, with one deliberate addition described below.
The contract is written out in full now, at M2, so the M6 build extends it rather
than re-litigating it — the same reason `pr_review/schema.py` froze the `Finding`
contract at M0 while only the secrets detector populated it.

THE ADDITION: PINNING. §4 gives `BenchCase.repo_snapshot: str  # path/ref to
pre-fix tree`, which is a *local path*. A local path is not a corpus: it says
nothing about which commit of which repository produced it, so a number computed
from it cannot be re-derived by anyone, including us next month. `CaseRef`
carries `repo`, `pr_number`, `base_sha` and `head_sha`, and the checkout is
materialized *from* those by `vcs/checkout.py:GitCheckout` rather than recorded
after the fact. This is the same shape as errata §14.13 and §14.16: a property the
plan requires in one section (§5's "corpus pinned", §6's reproducibility) with no
field for it in another.

WHY `ground_truth` IS A LIST AND MAY BE EMPTY. An empty list is not missing data,
it is the negative set (§2c): a merged PR from a healthy repo, where every finding
counts against precision. `BenchCase.labelled` reads the distinction so no call
site has to remember which emptiness means what.

WHERE THE LABEL CAME FROM IS A SEPARATE QUESTION FROM WHICH TREES THESE ARE.
`CaseRef` answers the second and `AdvisoryRef` the first, and they are kept apart
deliberately. A GHSA case is synthesized by reverting a fixing commit, so its
`base_sha` is the *fixed* tree and its `head_sha` is the *vulnerable* one — the
reverse of what those names suggest to anyone who has only seen the negative set.
`AdvisoryRef.construction` is what says so, in the artifact, rather than in a
convention a reader has to already know.
"""
from __future__ import annotations

from datetime import date

from pydantic import BaseModel, Field


class CaseRef(BaseModel):
    """What a case *is*, independent of any tree on this disk.

    Everything needed to rebuild the case from scratch on another machine. If a
    field here is empty the case is not reproducible and `corpus.py` refuses to
    pin it.
    """
    repo: str                        # "owner/name"
    pr_number: int
    base_sha: str
    head_sha: str
    merged_at: str = ""              # ISO8601, from the GitHub API
    url: str = ""

    def slug(self) -> str:
        return f"{self.repo.replace('/', '__')}#{self.pr_number}"


class PRTask(BaseModel):
    """The synthesized review task — §4's `pr_task`, which §4 leaves undefined.

    It is exactly the input `pipeline.run_review()` takes, and that is the point:
    the harness must drive the shipping entry point, not a convenient subset of
    it. `diff_text` is stored rather than re-fetched so a pinned case survives a
    force-push or a deleted branch.
    """
    repo: str
    pr_number: int
    diff_text: str = ""
    base_dir: str = ""               # checkout at base_sha  (--base-dir)
    head_dir: str = ""               # checkout at head_sha  (--head-dir)
    title: str = ""
    body: str = ""                   # UNTRUSTED — the sentinel scans it


class GTVuln(BaseModel):
    """One ground-truth vulnerability (§4).

    `lines` is the fixing commit's changed lines on the *vulnerable* side, which
    is what §2a defines as the ground-truth location. Stored as a list of
    (start, end) spans rather than §4's string, because scoring computes overlap
    against `Finding.location` and parsing a range string at every comparison is
    how an off-by-one gets in.
    """
    cwe: str                         # "CWE-89"
    file: str
    spans: list[tuple[int, int]] = []
    note: str = ""

    def covers(self, start: int, end: int) -> bool:
        return any(s <= end and start <= e for s, e in self.spans)


class AdvisoryRef(BaseModel):
    """The advisory a labelled case was synthesized from.

    Carried on the case so a number can be traced back to the published
    vulnerability it claims to represent, and so the curation log in
    `benchmark/corpus/labelled.md` can be checked against the pinned JSON rather
    than trusted.

    It is also where the advisory *text* stays. `PRTask.body` is deliberately
    empty for these cases: the summary names the vulnerability, and feeding it to
    a surface a Phase-3b agent reads would leak the answer into the input
    (`benchmark.md` §3, "avoid samples whose fix text leaks the answer").
    Scoring can see this; the pipeline cannot.
    """
    ghsa_id: str
    cve_id: str = ""
    cwes: list[str] = []
    package: str = ""
    summary: str = ""                # never reaches PRTask — see above
    fix_commit: str = ""             # F, the commit that fixed it
    vuln_commit: str = ""            # P = F^, the last vulnerable commit
    construction: str = ""           # "reverse_fix" | "post_fix_control"
    advisory_url: str = ""


class BenchCase(BaseModel):
    """One unit of evaluation (§4)."""
    id: str
    source: str                      # "negative" | "ghsa" | "cvefixes" | "owasp"
    ref: CaseRef
    pr_task: PRTask
    ground_truth: list[GTVuln] = []  # [] for negatives — see the module docstring
    cwe: list[str] = []
    published: date | None = None    # for §3's pre/post-cutoff temporal split
    language: str = "python"
    advisory: AdvisoryRef | None = None
    # Joins the two halves of a §2c pair — the reverted fix and the fix itself.
    # Recall alone cannot tell "found the vulnerability" from "always fires on
    # this file"; the pair can, and `metrics.PairMetrics` is what reads this.
    pair_id: str = ""

    @property
    def labelled(self) -> bool:
        """True when this case carries ground truth to score recall against.

        `not labelled` means the negative set, where the scoring rule is "every
        introduced finding is a false positive" — a different question, not a
        degraded version of the same one.
        """
        return bool(self.ground_truth)

    def gt_files(self) -> set[str]:
        return {g.file for g in self.ground_truth}


class Corpus(BaseModel):
    """A pinned, committed set of cases.

    `selection_criteria` is not documentation. A corpus chosen to flatter the
    tool is the classic benchmark failure and the only defense is showing how it
    was picked, so `report.py` prints this verbatim into every scorecard and
    `corpus.py` refuses to write a corpus without it.
    """
    name: str
    selection_criteria: str
    built_at: str = ""
    cases: list[BenchCase] = Field(default_factory=list)

    def labelled(self) -> list[BenchCase]:
        return [c for c in self.cases if c.labelled]

    def negatives(self) -> list[BenchCase]:
        return [c for c in self.cases if not c.labelled]
