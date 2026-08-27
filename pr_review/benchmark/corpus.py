"""Corpus construction and pinning (`plan/benchmark.md` §2c, §4 `loaders/`).

Builds the **negative set**: real merged PRs from healthy Python repositories,
where every finding the tool attributes to the PR counts against precision.

WHY REAL PRs AND NOT SYNTHESIZED ONES. The detectors are diff-scoped (they read
added lines) and delta-scoped (they compare against a base checkout). A corpus
that is not PR-shaped exercises neither, and would measure a code path we do not
ship. Synthesizing "PRs" from consecutive commits is cheaper and produces
something systematically smaller and tidier than what arrives at review time.

THE MERGE BASE IS NOT THE BASE BRANCH TIP, AND THIS COSTS A REAL NUMBER

A PR's `.diff` is the three-dot diff: merge-base(base, head) → head. The API's
`base.sha` is the base *branch*, which on a PR merged days after it opened has
moved on. Materializing that as `--base-dir` would hand `findings/delta.py` a
tree the diff was never computed against: the baseline pass would scan file
content that does not correspond to the diff's "before" side, fingerprints would
not match, and pre-existing findings would be scored as introduced. That failure
is silent and in the noisy direction — exactly the shape errata §14.17 records
for the base-side source reader — and here it would land directly on the
false-positive number this corpus exists to produce. So the merge base is
computed with git, locally, in the mirror `GitCheckout` already maintains.

NO NEW DEPENDENCIES. `urllib` from the stdlib rather than `requests`: the
project's runtime deps are pydantic, typer and pyyaml, and a benchmark harness is
a poor reason to widen them.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pr_review.benchmark.schema import BenchCase, CaseRef, Corpus, PRTask
from pr_review.vcs.checkout import CheckoutError, GitCheckout

_API = "https://api.github.com"
_UA = "pr-review-benchmark"


class CorpusError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

def _token() -> str:
    """`GH_TOKEN` if present. Unauthenticated works and is rate-limited to 60/hr."""
    return os.environ.get("GH_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")


def _get(url: str, accept: str = "application/vnd.github+json",
         timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={
        "Accept": accept,
        "User-Agent": _UA,
        **({"Authorization": f"Bearer {_token()}"} if _token() else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 403 and "rate limit" in (exc.reason or "").lower():
            raise CorpusError(
                "GitHub rate limit reached. Unauthenticated requests are capped "
                "at 60/hour; set GH_TOKEN to raise it."
            ) from exc
        raise CorpusError(f"GET {url} failed: {exc.code} {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise CorpusError(f"GET {url} failed: {exc.reason}") from exc


def list_merged_prs(repo: str, limit: int = 10, page_size: int = 50) -> list[dict]:
    """Recently-updated merged PRs, newest first.

    Merged rather than merely closed: a closed-unmerged PR was often rejected
    *because* it was bad, which is not the "healthy code that passed review"
    population §2c is asking for.
    """
    out: list[dict] = []
    page = 1
    while len(out) < limit and page <= 5:
        url = (f"{_API}/repos/{repo}/pulls?state=closed&per_page={page_size}"
               f"&page={page}&sort=updated&direction=desc")
        batch = json.loads(_get(url))
        if not batch:
            break
        out.extend(pr for pr in batch if pr.get("merged_at"))
        page += 1
        time.sleep(0.2)
    return out[:limit]


def fetch_diff(repo: str, pr_number: int) -> str:
    """The PR's unified diff.

    From `github.com/.../pull/N.diff` rather than the API: it is not counted
    against the API rate limit, which is what makes a 50-case corpus buildable
    without a token.
    """
    return _get(f"https://github.com/{repo}/pull/{pr_number}.diff",
                accept="text/plain", timeout=60)


# ---------------------------------------------------------------------------
# Materialization
# ---------------------------------------------------------------------------

@dataclass
class Checkouts:
    base_dir: Path
    head_dir: Path
    merge_base: str


def materialize(repo: str, base_sha: str, head_sha: str,
                cache_root: str | Path = ".pr_review/cache") -> Checkouts:
    """Extract both sides of a PR, with the base at the **merge base**."""
    git = GitCheckout(cache_root=cache_root)
    # Fetch both endpoints first; the mirror needs them before it can relate them.
    head = git.ensure(repo, head_sha)
    git.ensure(repo, base_sha)

    mirror = git.mirror_dir(repo)
    proc = subprocess.run(
        ["git", "-C", str(mirror), "merge-base", base_sha, head_sha],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise CorpusError(
            f"no merge base for {base_sha[:12]}..{head_sha[:12]} in {repo}: "
            f"{proc.stderr.strip()}"
        )
    merge_base = proc.stdout.strip()
    base = git.ensure(repo, merge_base)
    return Checkouts(base_dir=base.path, head_dir=head.path, merge_base=merge_base)


# ---------------------------------------------------------------------------
# Building and pinning
# ---------------------------------------------------------------------------

def build_negative_corpus(
    repos: list[str],
    per_repo: int = 5,
    *,
    name: str = "negative",
    selection_criteria: str,
    language: str = "python",
    cache_root: str | Path = ".pr_review/cache",
    progress: bool = True,
) -> Corpus:
    """Assemble a pinned negative corpus from real merged PRs.

    `language` is **corpus metadata only** — the pipeline takes its language
    from `config.languages`, never from the case (`detect/runner.py`,
    `change/classify.py`). It is a parameter rather than the hardcoded
    `"python"` it used to be because the IaC corpus contains no Python, and a
    scorecard that says otherwise is wrong about the thing it is measuring.
    """
    corpus = Corpus(name=name, selection_criteria=selection_criteria,
                    built_at=datetime.now(timezone.utc).isoformat())
    for repo in repos:
        if progress:
            print(f"== {repo}", flush=True)
        try:
            prs = list_merged_prs(repo, limit=per_repo * 3)
        except CorpusError as exc:
            print(f"   skipped: {exc}", flush=True)
            continue

        added = 0
        for pr in prs:
            if added >= per_repo:
                break
            number = pr.get("number")
            base_sha = ((pr.get("base") or {}).get("sha") or "")
            head_sha = ((pr.get("head") or {}).get("sha") or "")
            if not (number and base_sha and head_sha):
                continue
            try:
                diff = fetch_diff(repo, number)
                checkouts = materialize(repo, base_sha, head_sha, cache_root)
            except (CorpusError, CheckoutError) as exc:
                # A head commit on a deleted fork branch is unfetchable and
                # ordinary. Skipping is right; skipping *silently* is not, so
                # the reason is printed and the case is simply absent from the
                # pinned corpus rather than present and broken.
                if progress:
                    print(f"   #{number} skipped: {exc}", flush=True)
                continue
            if not diff.strip():
                continue

            corpus.cases.append(BenchCase(
                id=f"{repo.replace('/', '__')}#{number}",
                source="negative",
                ref=CaseRef(
                    repo=repo, pr_number=number,
                    # The merge base, not the branch tip — see the module
                    # docstring. This is the tree the diff was computed against.
                    base_sha=checkouts.merge_base,
                    head_sha=head_sha,
                    merged_at=pr.get("merged_at") or "",
                    url=pr.get("html_url") or "",
                ),
                pr_task=PRTask(
                    repo=repo, pr_number=number, diff_text=diff,
                    base_dir=str(checkouts.base_dir),
                    head_dir=str(checkouts.head_dir),
                    title=pr.get("title") or "",
                    body=pr.get("body") or "",
                ),
                ground_truth=[],       # the negative set, by definition
                language=language,
            ))
            added += 1
            if progress:
                print(f"   #{number} ok ({len(diff)} bytes)", flush=True)
    return corpus


def save(corpus: Corpus, path: str | Path) -> Path:
    """Pin the corpus to disk.

    `diff_text` and the checkout paths are stored too. The diff because a
    force-push or a deleted fork branch can make a pinned case unfetchable
    later, and a corpus that evaporates is not a corpus; the paths because they
    are cheap to rewrite and save a re-extraction on the next run.
    """
    if not corpus.selection_criteria.strip():
        raise CorpusError(
            "refusing to pin a corpus with no selection_criteria: it is printed "
            "verbatim in every scorecard and is the reader's only defense "
            "against a corpus chosen to flatter the tool."
        )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(corpus.model_dump_json(indent=2))
    return path


def load(path: str | Path) -> Corpus:
    return Corpus.model_validate_json(Path(path).read_text())


def rehydrate(corpus: Corpus, cache_root: str | Path = ".pr_review/cache") -> Corpus:
    """Re-extract checkouts for a pinned corpus on a machine that lacks them.

    The pinned JSON carries absolute paths from the machine that built it. This
    walks the pins and rebuilds each tree from its sha, which is what makes a
    committed corpus reproducible somewhere else rather than merely recorded.
    """
    git = GitCheckout(cache_root=cache_root)
    for case in corpus.cases:
        base = git.ensure(case.ref.repo, case.ref.base_sha)
        head = git.ensure(case.ref.repo, case.ref.head_sha)
        case.pr_task.base_dir = str(base.path)
        case.pr_task.head_dir = str(head.path)
    return corpus
