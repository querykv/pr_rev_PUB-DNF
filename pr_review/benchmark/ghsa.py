"""GitHub Security Advisories -> labelled cases (`plan/benchmark.md` §2a, §2c).

Pass 1 measured precision on known-clean PRs. It cannot measure recall, by
construction: a detector that reports nothing scores perfectly on a negative
set. This module builds the other half — cases where a real, published
vulnerability is present and its location is known.

WHY THIS LIVES BESIDE `corpus.py` AND NOT IN A `loaders/` PACKAGE

§4 sketches `loaders/` with one module per dataset. `corpus.py` already holds
the negative loader, and a `loaders/` directory containing a single module while
its sibling loader sits outside it is worse than either convention. `save`,
`load` and `rehydrate` are `Corpus`-generic and are reused from `corpus.py`
unchanged — `rehydrate` in particular already works here, since it only
re-`ensure`s both shas.

THE CONSTRUCTION: A FIX, RUN BACKWARDS

§2a says the pre-fix state is vulnerable ground truth and the post-fix state is
the clean control. Turning that into something this tool can review needs a
*PR*, because every detector here is diff-scoped and delta-scoped. So each
advisory becomes two cases, from the fixing commit F and its parent P:

    A  base=tree(F) head=tree(P)  diff = F->P   the fix, reverted
    B  base=tree(P) head=tree(F)  diff = P->F   the fix itself

A is a pull request that *introduces* the vulnerability, so `findings/delta.py`
marks the finding `introduced_by_pr` and scoring can see it. B is §2c's
"post-fix version, known clean": every finding on it is a false positive.

**A's recall number is an upper bound, and B is why it is worth having.** In a
reverted fix the vulnerable lines are essentially the whole diff, where a real
vulnerability-introducing PR buries them in unrelated change — so A is the
easiest possible presentation of the defect. What A alone cannot distinguish is
"the detector found the vulnerability" from "the detector always fires on this
file". B holds the file constant and removes only the vulnerability, so the pair
answers that and the single case does not.

WHAT IS DELIBERATELY NOT DONE HERE

No filtering to CWEs the 3a detectors can emit. Roughly a third of recent `pip`
advisories are CWE-400, CWE-1333 and CWE-200, which no detector in this
milestone covers, and dropping them would be the corpus-flattering failure
`Corpus.selection_criteria` exists to prevent. It is also the error errata
§14.20 already ruled on from the other side: a stratum is **derived after the
fact, never selected for**. `metrics.py` reports them as a stratum.

NO NEW DEPENDENCIES, same bargain as `corpus.py`: `urllib` from the stdlib, and
git for anything only git can answer.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from pr_review.benchmark.corpus import CorpusError, _token
from pr_review.benchmark.schema import (
    AdvisoryRef,
    BenchCase,
    CaseRef,
    Corpus,
    GTVuln,
    PRTask,
)
from pr_review.extract.diff import parse_unified_diff
from pr_review.vcs.checkout import CheckoutError, GitCheckout

_API = "https://api.github.com"

# Ground truth is a claim about *source*. A fix commit routinely carries a
# changelog entry, a version bump and a regression test alongside the change
# itself — the sampled pymdown-extensions fix touched all three — and admitting
# those would enter "the changelog" as a vulnerability and dilute recall with
# rows no detector could ever match. `benchmark.md` §7's "CVE labels are noisy"
# arriving concretely.
_GT_SUFFIXES = (".py",)
_GT_EXCLUDED = re.compile(
    r"(^|/)(tests?|testing|docs?|examples?|benchmarks?)/|"
    r"(^|/)(test_[^/]+|[^/]+_test|conftest|setup|noxfile|changelog|changes)\.py$",
    re.IGNORECASE,
)

_COMMIT_REF = re.compile(
    r"^https://github\.com/(?P<repo>[^/]+/[^/]+)/commit/(?P<sha>[0-9a-f]{7,40})/?$")

# Lines a fix touches *in support of* the fix, which are not themselves the
# vulnerability. Measured on the first real build: an `import` the fix adds, the
# version bump that ships it, and the comment explaining it appeared as
# "ground truth" in 7 of 28 advisories — `from math import ceil`,
# `__version__ = "0.19.2"`, a six-line comment block.
#
# A span is dropped only when *every* line in it is one of these, so a span
# mixing an import with real code survives intact. The claim being made is
# narrow and holds for every CWE in this corpus: an import statement is a
# declaration of availability, and the vulnerability is in the use.
_SUPPORTING = (
    re.compile(r"^\s*(import|from)\s+\S"),               # import / from-import
    re.compile(r"^\s*_*version(_info)?_*\s*[:=]", re.I),  # __version__ = ...
    re.compile(r"^\s*#"),                                # comment
    re.compile(r"^\s*$"),                                # blank
)


def _supporting(lines: list[str]) -> bool:
    """True when every line is scaffolding rather than the defect itself."""
    if not lines:
        return False
    return all(any(p.match(ln) for p in _SUPPORTING) for ln in lines)


# ---------------------------------------------------------------------------
# The advisory feed
# ---------------------------------------------------------------------------

def _get_paged(url: str) -> tuple[str, str]:
    """A page of results plus the cursor for the next one.

    `/advisories` pages by **cursor**, not by `page`. Passing `page=2` returns
    page 1 again, silently — which reads as a corpus three times larger than it
    is, with every case triplicated. Measured, not assumed: three `page=N`
    requests returned 300 rows containing 100 distinct advisories.
    """
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "pr-review-benchmark",
    })
    if _token():
        req.add_header("Authorization", f"Bearer {_token()}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            link = resp.headers.get("Link", "") or ""
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            raise CorpusError(
                "GitHub rate limit reached. Unauthenticated requests are capped "
                "at 60/hour; set GH_TOKEN to raise it."
            ) from exc
        raise CorpusError(f"GET {url} failed: {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise CorpusError(f"GET {url} failed: {exc.reason}") from exc

    nxt = ""
    for part in link.split(","):
        if 'rel="next"' in part:
            m = re.search(r"<([^>]+)>", part)
            if m:
                nxt = m.group(1)
    return body, nxt


def list_advisories(ecosystem: str = "pip", limit: int = 100) -> list[dict]:
    """Reviewed advisories for one ecosystem, newest first.

    `type=reviewed` restricts to advisories GitHub has curated, which is what
    makes `cwes` and `source_code_location` reliable enough to build ground
    truth from. Newest-first also makes the set **post-cutoff** for any model we
    would later evaluate, which is §3's contamination control obtained for free
    rather than engineered.
    """
    url = (f"{_API}/advisories?ecosystem={urllib.parse.quote(ecosystem)}"
           f"&type=reviewed&per_page=100&sort=published&direction=desc")
    out: list[dict] = []
    while url and len(out) < limit:
        body, url = _get_paged(url)
        batch = json.loads(body)
        if not batch:
            break
        out.extend(batch)
        time.sleep(0.2)
    return out[:limit]


def fix_commit(advisory: dict) -> tuple[str, str]:
    """`(repo, sha)` of the fixing commit, or `("", "")`.

    Only a commit reference **into the advisory's own source repository**
    counts. Advisories routinely reference commits in unrelated repositories —
    a downstream distributor's packaging fix, a mirror — and building a case
    from one of those would pin a tree the advisory says nothing about.
    """
    src = (advisory.get("source_code_location") or "").rstrip("/")
    if not src.startswith("https://github.com/"):
        return "", ""
    repo = src[len("https://github.com/"):]
    if repo.count("/") != 1:
        return "", ""
    for ref in advisory.get("references") or []:
        m = _COMMIT_REF.match((ref or "").strip())
        if m and m.group("repo").lower() == repo.lower():
            return repo, m.group("sha")
    return "", ""


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

def _spans(linenos: list[int]) -> list[tuple[int, int]]:
    """Contiguous runs of line numbers, as (start, end) inclusive."""
    out: list[tuple[int, int]] = []
    for n in sorted(set(linenos)):
        if out and n == out[-1][1] + 1:
            out[-1] = (out[-1][0], n)
        else:
            out.append((n, n))
    return out


def ground_truth(forward_diff: str, cwe: str) -> list[GTVuln]:
    """Candidate ground truth from the *forward* fix diff.

    Parsed with `extract/diff.py:parse_unified_diff` rather than a second
    parser, because `RemovedLine.lineno` is already numbered in the OLD file —
    which is P, which is the vulnerable case's head. That is exactly the
    numbering `Finding.location` carries, so there is no re-mapping to get wrong.

    A fix that only *adds* (a guard inserted, nothing deleted) has no removed
    lines. Its ground truth is the hunk's old-side range: the vulnerability is
    the absence of the added code, and the absence sits where the code went.

    These are **candidates**. `benchmark/corpus/labelled.md` records the hand
    pass that trims them, because an automated span is a guess about which
    changed lines were the vulnerable ones and a benchmark may not guess about
    its own answers.
    """
    out: list[GTVuln] = []
    for pf in parse_unified_diff(forward_diff):
        # `ParsedFile.path` is the NEW path, which here is the *fixed* tree.
        # Ground truth names a location in the vulnerable tree, so a rename has
        # to be followed back — otherwise the span points at a path that does
        # not exist on the side being scored, and every finding in the file
        # scores as a miss.
        path = pf.previous_path or pf.path
        if pf.binary:
            continue
        if not path.endswith(_GT_SUFFIXES) or _GT_EXCLUDED.search(path):
            continue
        if pf.change == "added":
            # The fix created this file, so nothing in it existed on the
            # vulnerable side and there is no location to point at.
            continue
        removed = {r.lineno: r.text for h in pf.hunks for r in h.removed}
        if removed:
            spans = [s for s in _spans(list(removed))
                     if not _supporting([removed[n] for n in range(s[0], s[1] + 1)
                                         if n in removed])]
            note = "lines the fix removed"
        else:
            # Nothing was deleted, so the vulnerability is the absence of what
            # the fix added and the location is where it went. Judge these by
            # the *added* text for the same reason: a hunk that only inserts an
            # import block marks no defect.
            spans = [(h.old_start, max(h.old_start, h.old_start + h.old_len - 1))
                     for h in pf.hunks
                     if h.old_len and not _supporting([a.text for a in h.added])]
            note = "the fix only added; span is the insertion point"
        if spans:
            out.append(GTVuln(cwe=cwe, file=path, spans=spans, note=note))
    return out


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------

def _git(mirror: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(mirror), *args],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise CorpusError(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()}")
    return proc.stdout


def parent_of(mirror: Path, sha: str) -> str:
    """`sha^`, refusing a merge.

    Reverting a merge commit reverts an entire branch, not a fix, so the diff
    would be nothing like the PR this case claims to be and the ground-truth
    spans would be scattered across unrelated work.
    """
    line = _git(mirror, "rev-list", "--parents", "-n", "1", sha).split()
    if len(line) < 2:
        raise CorpusError(f"{sha[:12]} has no parent (root commit)")
    if len(line) > 2:
        raise CorpusError(f"{sha[:12]} is a merge commit ({len(line) - 1} parents)")
    return line[1]


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    """One advisory, resolved far enough to accept or reject with a reason."""
    ghsa_id: str
    repo: str = ""
    fix_sha: str = ""
    vuln_sha: str = ""
    cwe: str = ""
    files: list[str] = field(default_factory=list)
    rejected: str = ""


def _first_cwe(advisory: dict) -> str:
    for entry in advisory.get("cwes") or []:
        cid = (entry or {}).get("cwe_id") or ""
        if cid:
            return cid
    return ""


def _published(advisory: dict) -> date | None:
    raw = (advisory.get("published_at") or "")[:10]
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


def _pair(advisory: dict, repo: str, fix_sha: str, vuln_sha: str,
          forward: str, reverse: str, gt: list[GTVuln],
          fixed_tree: Path, vuln_tree: Path) -> list[BenchCase]:
    """The two cases an advisory becomes. See the module docstring.

    The trees are named for their *content*, not their role, because the roles
    swap between the two cases and `base`/`head` naming here is how this gets
    built backwards. The vulnerable case's base is the fixed tree.
    """
    ghsa = advisory.get("ghsa_id") or ""
    cwes = [c.get("cwe_id") for c in (advisory.get("cwes") or []) if c.get("cwe_id")]
    package = ""
    for vuln in advisory.get("vulnerabilities") or []:
        package = ((vuln or {}).get("package") or {}).get("name") or ""
        if package:
            break

    def advisory_ref(construction: str) -> AdvisoryRef:
        return AdvisoryRef(
            ghsa_id=ghsa, cve_id=advisory.get("cve_id") or "", cwes=cwes,
            package=package, summary=advisory.get("summary") or "",
            fix_commit=fix_sha, vuln_commit=vuln_sha,
            construction=construction, advisory_url=advisory.get("html_url") or "",
        )

    published = _published(advisory)
    common = dict(source="ghsa", cwe=cwes, published=published,
                  language="python", pair_id=ghsa)

    # `pr_number` is 0: these are synthesized, and borrowing the fixing PR's
    # number would label a reverted fix with the number of the thing it reverts.
    # The two cases still land in different run directories, which key on the
    # head sha.
    return [
        BenchCase(
            id=f"{ghsa}:vuln",
            ref=CaseRef(repo=repo, pr_number=0, base_sha=fix_sha,
                        head_sha=vuln_sha,
                        url=advisory.get("html_url") or ""),
            pr_task=PRTask(
                repo=repo, pr_number=0, diff_text=reverse,
                base_dir=str(fixed_tree), head_dir=str(vuln_tree),
                # Neutral, and the body stays empty: the advisory summary names
                # the vulnerability, and the body is a surface a Phase-3b agent
                # reads. See `AdvisoryRef`.
                title=f"Revert {fix_sha[:12]}", body="",
            ),
            ground_truth=gt, advisory=advisory_ref("reverse_fix"), **common,
        ),
        BenchCase(
            id=f"{ghsa}:control",
            ref=CaseRef(repo=repo, pr_number=0, base_sha=vuln_sha,
                        head_sha=fix_sha,
                        url=advisory.get("html_url") or ""),
            pr_task=PRTask(
                repo=repo, pr_number=0, diff_text=forward,
                base_dir=str(vuln_tree), head_dir=str(fixed_tree),
                title=f"Apply {fix_sha[:12]}", body="",
            ),
            ground_truth=[], advisory=advisory_ref("post_fix_control"), **common,
        ),
    ]


def load_exclusions(path: str | Path) -> dict[str, str]:
    """`GHSA-id` or `owner/repo@sha`, one per line with `# reason`.

    Hand curation has to reject cases the automated rules cannot — a fix that
    is really a bulk refactor, an advisory whose CWE does not describe what the
    diff does. Editing the pinned JSON to remove them would be the obvious
    route and would destroy the property the whole corpus design exists for:
    `CaseRef` carries repo and both shas so any case can be rebuilt, and a
    hand-edited corpus cannot be rebuilt by the command that claims to build
    it. A committed exclusion list keeps the build reproducible and puts the
    reason somewhere a reader will find it.

    **Two key forms, because the unusable thing is sometimes the commit.**
    Excluding by advisory id alone was tried first and leaks: several
    advisories can share one fixing commit, so rejecting one id frees a
    per-repo slot that the *next* id on the same commit walks straight into.
    Observed on the real build — two bulk refactors came back under four GHSA
    ids between them. Keying on `owner/repo@sha` says what is actually true.
    """
    out: dict[str, str] = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ident, _, reason = line.partition("#")
        ident = ident.strip()
        if ident:
            out[ident] = reason.strip() or "excluded by hand (no reason recorded)"
    return out


def build_labelled_corpus(
    *,
    ecosystem: str = "pip",
    advisories: int = 40,
    per_repo: int = 2,
    name: str = "labelled",
    selection_criteria: str,
    cache_root: str | Path = ".pr_review/cache",
    max_diff_bytes: int = 400_000,
    controls: bool = True,
    exclude: dict[str, str] | None = None,
    progress: bool = True,
) -> tuple[Corpus, list[Candidate]]:
    """Assemble a labelled corpus, and return the rejections alongside it.

    The `Candidate` list is not a debugging aid — it is the input to the
    curation log. A corpus is only as trustworthy as the account of what was
    *not* put in it, and a builder that silently skipped two thirds of what it
    saw would leave no way to tell selection from luck.
    """
    corpus = Corpus(name=name, selection_criteria=selection_criteria,
                    built_at=datetime.now(timezone.utc).isoformat())
    candidates: list[Candidate] = []
    git = GitCheckout(cache_root=cache_root)
    seen_repos: dict[str, int] = {}
    # One commit routinely fixes several advisories at once — a coordinated
    # release, or one patch closing two reported issues. Admitting both would
    # pin the *same* trees, diff and ground truth twice under different GHSA
    # ids, weighting that commit at double in both the recall numerator and its
    # denominator. Measured on the first real build: 28 advisories, 27 commits.
    seen_commits: set[tuple[str, str]] = set()

    exclude = exclude or {}
    for advisory in list_advisories(ecosystem, limit=advisories):
        ghsa = advisory.get("ghsa_id") or "?"
        cand = Candidate(ghsa_id=ghsa)
        candidates.append(cand)

        if ghsa in exclude:
            cand.rejected = f"excluded by hand: {exclude[ghsa]}"
            continue

        repo, sha = fix_commit(advisory)
        cand.repo, cand.fix_sha = repo, sha
        cand.cwe = _first_cwe(advisory)
        if not repo or not sha:
            cand.rejected = "no fixing-commit reference into the advisory's own repo"
            continue

        # Checked before the per-repo cap: an excluded commit must not consume
        # a slot, and it must stay excluded however many advisory ids point at
        # it. See `load_exclusions`.
        commit_key = next(
            (k for k in (f"{repo}@{sha}", f"{repo}@{sha[:12]}") if k in exclude), "")
        if commit_key:
            cand.rejected = f"excluded by hand: {exclude[commit_key]}"
            continue
        if not cand.cwe:
            cand.rejected = "no CWE — nothing to match a finding's taxonomy against"
            continue
        if (repo, sha) in seen_commits:
            cand.rejected = (f"same fixing commit as an advisory already "
                             f"accepted ({repo}@{sha[:12]})")
            continue
        if seen_repos.get(repo, 0) >= per_repo:
            cand.rejected = f"per-repo cap ({per_repo}) already reached for {repo}"
            continue

        try:
            fixed_tree = git.ensure(repo, sha)       # tree(F)
            mirror = git.mirror_dir(repo)
            parent = parent_of(mirror, sha)
            cand.vuln_sha = parent
            vuln_tree = git.ensure(repo, parent)     # tree(P)
            forward = _git(mirror, "diff", parent, sha)
            reverse = _git(mirror, "diff", sha, parent)
        except (CorpusError, CheckoutError) as exc:
            cand.rejected = str(exc)
            if progress:
                print(f"   {ghsa} skipped: {exc}", flush=True)
            continue

        if len(forward) > max_diff_bytes:
            cand.rejected = (f"fix diff is {len(forward)} bytes "
                             f"(> {max_diff_bytes}); too large to hand-verify")
            continue

        gt = ground_truth(forward, cand.cwe)
        if not gt:
            cand.rejected = "fix touches no reviewable Python source outside tests/docs"
            continue
        cand.files = [g.file for g in gt]

        pair = _pair(advisory, repo, sha, parent, forward, reverse, gt,
                     fixed_tree=fixed_tree.path, vuln_tree=vuln_tree.path)
        corpus.cases.extend(pair if controls else pair[:1])
        seen_repos[repo] = seen_repos.get(repo, 0) + 1
        seen_commits.add((repo, sha))
        if progress:
            print(f"   {ghsa} ok · {cand.cwe} · {repo}@{sha[:12]} · "
                  f"{len(gt)} file(s)", flush=True)

    return corpus, candidates


def curation_log(candidates: list[Candidate], corpus: Corpus) -> str:
    """A markdown account of every advisory seen, accepted or not.

    Written next to the pinned corpus. `Corpus.selection_criteria` states the
    intent; this states what actually happened, which is the part a reader can
    check.
    """
    kept = [c for c in candidates if not c.rejected]
    lines = [
        f"# Labelled corpus — curation log ({corpus.name})",
        "",
        f"**Built:** {corpus.built_at} · **advisories examined:** "
        f"{len(candidates)} · **accepted:** {len(kept)} · "
        f"**cases pinned:** {len(corpus.cases)}",
        "",
        "**Selection criteria, verbatim from the pinned corpus:**",
        "",
        f"> {corpus.selection_criteria}",
        "",
        "Every advisory the builder examined is listed, accepted or rejected "
        "with its reason. A corpus is only as trustworthy as the account of "
        "what was left out of it.",
        "",
        "## Accepted",
        "",
        "| GHSA | CWE | Repo | Fix commit | Ground-truth files |",
        "|---|---|---|---|---|",
    ]
    for c in kept:
        lines.append(f"| `{c.ghsa_id}` | {c.cwe} | `{c.repo}` | "
                     f"`{c.fix_sha[:12]}` | {', '.join(f'`{f}`' for f in c.files)} |")
    lines += ["", "## Rejected", "",
              "| GHSA | Repo | Reason |", "|---|---|---|"]
    for c in candidates:
        if c.rejected:
            lines.append(f"| `{c.ghsa_id}` | `{c.repo or '—'}` | {c.rejected} |")
    lines += [
        "",
        "## Hand verification",
        "",
        "**This file is generated and is rewritten by every build. The hand "
        "verification lives in `labelled-verification.md` beside it**, the same "
        "split `benchmark/results/<date>/` already uses between the generated "
        "`negative.md` and the hand-written `analysis.md`.",
        "",
        "The spans above are **candidates**, derived from the lines the fix "
        "removed. Each accepted case still needs a human to confirm that the "
        "advisory's CWE is what the diff actually fixes, that the fix commit is "
        "the whole fix rather than one of several, and that the spans cover the "
        "vulnerable lines and nothing else. Cases dropped on inspection go in "
        "`labelled-excluded.txt`, which is applied with `--exclude` so the "
        "corpus stays rebuildable.",
        "",
    ]
    return "\n".join(lines)
