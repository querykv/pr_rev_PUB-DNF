"""Repo checkout — materialize `<repo>@<sha>` as a directory on disk.

Phase 1 declares its input as "repo checkout @ base_sha" (phase-1 §1) and CAP's
`build_cache(stats_dir)` walks a real directory, but nothing in the plan's
component tables produces one — `GitHubAdapter` only shells `gh api` and
`gh pr diff`. This module is that missing producer.

Two implementations:

- `LocalCheckout` — an already-present working tree. The offline path, mirroring
  `--diff-file`: it is what runs when there is no network, and what the tests
  use.
- `GitCheckout` — a bare mirror under the profile cache plus `git archive` into
  `<cache>/<repo>/src/<sha>`. Second sight of the same sha is warm, which is
  half of why Phase 1 is affordable at all (phase-1 §7 "baseline reuse").

`git archive` rather than `git worktree` on purpose: we only ever read the tree,
and an extracted archive is a plain directory with no worktree bookkeeping to
leak, lock, or prune.
"""
from __future__ import annotations

import shutil
import subprocess
import tarfile
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

DEFAULT_REMOTE_TEMPLATE = "https://github.com/{repo}.git"


class CheckoutError(RuntimeError):
    pass


@dataclass
class CheckoutResult:
    path: Path
    sha: str
    warm: bool          # already materialized — no fetch, no extract


class RepoCheckout(ABC):
    @abstractmethod
    def ensure(self, repo: str, sha: str) -> CheckoutResult:
        """Return a directory holding `repo` at `sha`."""


def _run(args: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise CheckoutError(
            f"{' '.join(args[:3])}... failed ({proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout


def _slug(repo: str) -> str:
    return repo.replace("/", "__")


class LocalCheckout(RepoCheckout):
    """A working tree that already exists on disk (offline mode).

    If the directory is a git repo the requested sha is verified; if it is not,
    the path is trusted. Trusting an arbitrary directory is deliberate — it is
    how the tool stays runnable with no network and no `gh`, the same bargain
    `--diff-file` makes for Phase 0.
    """

    def __init__(self, path: str | Path, verify: bool = True) -> None:
        self.path = Path(path)
        self.verify = verify

    def ensure(self, repo: str, sha: str) -> CheckoutResult:
        if not self.path.is_dir():
            raise CheckoutError(f"--repo-path is not a directory: {self.path}")
        if self.verify and sha and (self.path / ".git").exists():
            head = _run(["git", "-C", str(self.path), "rev-parse", "HEAD"]).strip()
            if not head.startswith(sha) and not sha.startswith(head[: len(sha)]):
                raise CheckoutError(
                    f"{self.path} is at {head[:12]}, not the requested {sha[:12]}. "
                    f"Check out the base commit, or pass verify=False to profile "
                    f"the working tree as-is."
                )
        return CheckoutResult(path=self.path, sha=sha, warm=True)


class GitCheckout(RepoCheckout):
    """Clone-and-extract into the profile cache, warm on repeat.

    Layout under `cache_root`:
        <slug>/git/          bare mirror, fetched incrementally
        <slug>/src/<sha12>/  extracted tree, the thing Phase 1 walks
    """

    def __init__(
        self,
        cache_root: str | Path = ".pr_review/cache",
        remote_template: str = DEFAULT_REMOTE_TEMPLATE,
    ) -> None:
        self.cache_root = Path(cache_root)
        self.remote_template = remote_template

    # -- paths -------------------------------------------------------------

    def _mirror_dir(self, repo: str) -> Path:
        return self.cache_root / _slug(repo) / "git"

    def mirror_dir(self, repo: str) -> Path:
        """The bare mirror's path, for callers that need git itself.

        `ensure()` answers "give me this tree", which is all Phase 1 wants. The
        benchmark corpus has a question only git can answer — a PR's three-dot
        diff is computed against the **merge base** of its two branches, not
        against the base branch tip, and materializing the wrong one would make
        `findings/delta.py` compare a finding against a baseline built from a
        tree the diff never referenced. Exposed rather than reimplemented so
        there stays one mirror layout in the codebase.
        """
        return self._mirror_dir(repo)

    def _src_dir(self, repo: str, sha: str) -> Path:
        return self.cache_root / _slug(repo) / "src" / sha[:12]

    # -- fork PRs ----------------------------------------------------------

    def fetch_pull_ref(self, repo: str, pr_number: int) -> None:
        """Make a fork PR's head reachable in the base repo's mirror.

        A FALLBACK, and measured to be one (errata §14.41). This was written
        on the theory that a fork's head lives only in the contributor's
        repository and neither strategy in `_fetch` could reach it. **Against
        GitHub that theory is false**: forks share an object network and the
        server honours reachable-SHA1-in-want, so the single-sha fetch pulls an
        open fork PR head into a fresh mirror in ~1s. Measured on
        `pallets/flask#5660`, and 12 of 30 recent merged flask PRs are from
        forks, so the sample was not exotic.

        Kept for remotes where the assumption does not hold -- a plain file://
        remote refuses arbitrary shas, as `_fetch`'s own comment notes -- and
        for a head that has been force-pushed away. It is not "fork support",
        because forks need no support.
        """
        mirror = self._ensure_mirror(repo)
        _run(["git", "-C", str(mirror), "fetch", "--quiet", "--filter=blob:none",
              "origin", f"+refs/pull/{pr_number}/head:refs/remotes/origin/pr/{pr_number}"])

    # -- steps -------------------------------------------------------------

    def _ensure_mirror(self, repo: str) -> Path:
        mirror = self._mirror_dir(repo)
        if not (mirror / "HEAD").exists():
            mirror.mkdir(parents=True, exist_ok=True)
            _run(["git", "init", "--bare", "--quiet", str(mirror)])
            _run(["git", "-C", str(mirror), "remote", "add", "origin",
                  self.remote_template.format(repo=repo)])
        return mirror

    def _fetch(self, mirror: Path, sha: str) -> None:
        if self._has_commit(mirror, sha):
            return
        # Fetching one commit is much cheaper, but needs the server to allow
        # reachable-SHA1-in-want. GitHub does; a plain file:// remote does not.
        # Fall back to a full fetch rather than failing.
        try:
            _run(["git", "-C", str(mirror), "fetch", "--quiet", "--filter=blob:none",
                  "origin", sha])
        except CheckoutError:
            _run(["git", "-C", str(mirror), "fetch", "--quiet", "origin",
                  "+refs/heads/*:refs/remotes/origin/*"])
        if not self._has_commit(mirror, sha):
            raise CheckoutError(f"commit {sha[:12]} not found in {mirror} after fetch")

    @staticmethod
    def _has_commit(mirror: Path, sha: str) -> bool:
        proc = subprocess.run(
            ["git", "-C", str(mirror), "cat-file", "-e", f"{sha}^{{commit}}"],
            capture_output=True, text=True,
        )
        return proc.returncode == 0

    def _extract(self, mirror: Path, sha: str, target: Path) -> None:
        """Extract atomically: a crashed run must not leave a half-tree.

        A partially-extracted directory would look warm on the next run and
        silently profile an incomplete repo — a wrong answer rather than an
        error, which is the worse failure.
        """
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(dir=target.parent, prefix=".extract-"))
        try:
            tar_path = staging / "tree.tar"
            _run(["git", "-C", str(mirror), "archive", "--format=tar",
                  f"--output={tar_path}", sha])
            tree = staging / "tree"
            tree.mkdir()
            with tarfile.open(tar_path) as tf:
                tf.extractall(tree, filter="data")
            tar_path.unlink()
            tree.rename(target)
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    # -- api ---------------------------------------------------------------

    def ensure(self, repo: str, sha: str) -> CheckoutResult:
        if not sha:
            raise CheckoutError("GitCheckout needs an explicit sha")
        target = self._src_dir(repo, sha)
        if target.is_dir() and any(target.iterdir()):
            return CheckoutResult(path=target, sha=sha, warm=True)
        mirror = self._ensure_mirror(repo)
        self._fetch(mirror, sha)
        self._extract(mirror, sha, target)
        return CheckoutResult(path=target, sha=sha, warm=False)
