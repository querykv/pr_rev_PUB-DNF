"""Repo checkout tests — no network: the "remote" is a local git repo."""
import subprocess

import pytest

from pr_review.vcs.checkout import (
    CheckoutError,
    GitCheckout,
    LocalCheckout,
)


def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def origin(tmp_path):
    """A real git repo with two commits, standing in for GitHub."""
    src = tmp_path / "origin"
    src.mkdir()
    _git("init", "--quiet", "--initial-branch=main", cwd=src)
    _git("config", "user.email", "t@example.com", cwd=src)
    _git("config", "user.name", "T", cwd=src)

    (src / "app.py").write_text("def one():\n    return 1\n")
    _git("add", "-A", cwd=src)
    _git("commit", "--quiet", "-m", "first", cwd=src)
    first = subprocess.run(["git", "rev-parse", "HEAD"], cwd=src,
                           capture_output=True, text=True).stdout.strip()

    (src / "app.py").write_text("def one():\n    return 2\n")
    (src / "extra.py").write_text("x = 1\n")
    _git("add", "-A", cwd=src)
    _git("commit", "--quiet", "-m", "second", cwd=src)
    second = subprocess.run(["git", "rev-parse", "HEAD"], cwd=src,
                            capture_output=True, text=True).stdout.strip()

    return {"path": src, "first": first, "second": second}


# --------------------------------------------------------------------------
# GitCheckout
# --------------------------------------------------------------------------

def test_materializes_the_requested_sha(tmp_path, origin):
    co = GitCheckout(cache_root=tmp_path / "cache",
                     remote_template=str(origin["path"]))
    res = co.ensure("o/r", origin["first"])

    assert res.warm is False
    assert (res.path / "app.py").read_text() == "def one():\n    return 1\n"
    # The second commit's file must not be present — we asked for the first.
    assert not (res.path / "extra.py").exists()


def test_second_sight_of_the_same_sha_is_warm(tmp_path, origin):
    """Warm re-use is half of why Phase 1 is affordable (phase-1 §7)."""
    co = GitCheckout(cache_root=tmp_path / "cache",
                     remote_template=str(origin["path"]))
    first = co.ensure("o/r", origin["second"])
    again = co.ensure("o/r", origin["second"])

    assert first.warm is False and again.warm is True
    assert first.path == again.path


def test_two_shas_of_one_repo_share_a_mirror_but_not_a_tree(tmp_path, origin):
    cache = tmp_path / "cache"
    co = GitCheckout(cache_root=cache, remote_template=str(origin["path"]))
    a = co.ensure("o/r", origin["first"])
    b = co.ensure("o/r", origin["second"])

    assert a.path != b.path
    assert (b.path / "extra.py").exists()
    assert len(list((cache / "o__r" / "git").glob("HEAD"))) == 1


def test_repos_are_isolated_from_each_other(tmp_path, origin):
    """Cross-repo isolation — caches keyed by repo, no bleed (phase-1 §8)."""
    cache = tmp_path / "cache"
    co = GitCheckout(cache_root=cache, remote_template=str(origin["path"]))
    co.ensure("o/r", origin["first"])
    co.ensure("other/repo", origin["first"])

    assert (cache / "o__r").is_dir()
    assert (cache / "other__repo").is_dir()


def test_unknown_sha_is_an_error_not_an_empty_tree(tmp_path, origin):
    co = GitCheckout(cache_root=tmp_path / "cache",
                     remote_template=str(origin["path"]))
    with pytest.raises(CheckoutError, match="not found"):
        co.ensure("o/r", "0" * 40)


def test_missing_sha_is_rejected(tmp_path):
    with pytest.raises(CheckoutError, match="explicit sha"):
        GitCheckout(cache_root=tmp_path).ensure("o/r", "")


def test_no_partial_tree_survives_a_failed_extract(tmp_path, origin):
    """A half-extracted tree would look warm next run and profile a partial repo.

    That is a wrong answer rather than an error, so the extract stages into a
    temp dir and renames. Assert no staging residue is left behind on failure.
    """
    cache = tmp_path / "cache"
    co = GitCheckout(cache_root=cache, remote_template=str(origin["path"]))
    with pytest.raises(CheckoutError):
        co.ensure("o/r", "0" * 40)

    src_root = cache / "o__r" / "src"
    leftovers = list(src_root.glob(".extract-*")) if src_root.exists() else []
    assert leftovers == []


# --------------------------------------------------------------------------
# LocalCheckout
# --------------------------------------------------------------------------

def test_local_checkout_returns_the_tree_as_warm(tmp_path, origin):
    res = LocalCheckout(origin["path"]).ensure("o/r", origin["second"])
    assert res.warm is True
    assert res.path == origin["path"]


def test_local_checkout_rejects_a_sha_mismatch(origin):
    """Silently profiling the wrong commit would poison the cache under a
    profile_version that claims to be the base sha."""
    with pytest.raises(CheckoutError, match="not the requested"):
        LocalCheckout(origin["path"]).ensure("o/r", origin["first"])


def test_local_checkout_can_skip_verification(origin):
    res = LocalCheckout(origin["path"], verify=False).ensure("o/r", origin["first"])
    assert res.path == origin["path"]


def test_local_checkout_trusts_a_non_git_directory(tmp_path):
    """Offline mode: a plain directory of sources is a legitimate input."""
    d = tmp_path / "plain"
    d.mkdir()
    (d / "a.py").write_text("x = 1\n")
    res = LocalCheckout(d).ensure("o/r", "deadbeef")
    assert res.path == d


def test_local_checkout_rejects_a_missing_path(tmp_path):
    with pytest.raises(CheckoutError, match="not a directory"):
        LocalCheckout(tmp_path / "nope").ensure("o/r", "abc")


# ---------------------------------------------------------------------------
# Auto-materialization on the online path. Until 2026-08-21 vcs/checkout.py was
# imported by benchmark/ghsa.py and nothing else, so `pr-review review <url>`
# produced an M0-grade run while GitCheckout sat proven and unwired.
# ---------------------------------------------------------------------------

from pathlib import Path

import pytest

from pr_review import cli
from pr_review.vcs.checkout import CheckoutError, CheckoutResult, GitCheckout


class _FakeCheckout:
    """Records what was asked for; optionally fails the head until a pull ref
    is fetched, which is how a fork PR behaves."""

    def __init__(self, cache_root, head_needs_pull_ref=False):
        self.cache_root = cache_root
        self.head_needs_pull_ref = head_needs_pull_ref
        self.pull_refs: list = []
        self.asked: list = []

    def ensure(self, repo, sha):
        self.asked.append(sha)
        if self.head_needs_pull_ref and sha == "head" and not self.pull_refs:
            raise CheckoutError(f"commit {sha} not found after fetch")
        return CheckoutResult(path=Path(f"/x/{sha}"), sha=sha, warm=False)

    def fetch_pull_ref(self, repo, pr_number):
        self.pull_refs.append((repo, pr_number))


def _patch(monkeypatch, fake):
    monkeypatch.setattr(cli, "GitCheckout", lambda cache_root: fake)


def test_both_trees_are_materialized_from_the_shas_already_fetched(monkeypatch):
    fake = _FakeCheckout(".cache")
    _patch(monkeypatch, fake)
    base, head, info = cli._materialize(
        "o/r", 7, {"base_sha": "base", "head_sha": "head"}, ".cache")
    assert (base, head) == ("/x/base", "/x/head")
    assert info["auto"] is True
    assert fake.asked == ["base", "head"]


def test_an_unreachable_head_recovers_by_fetching_the_pull_ref(monkeypatch):
    """A FALLBACK, and measured to be one -- see errata §14.41.

    This was written for fork PRs on the theory that a fork's head is not in
    the base repo. Against GitHub that theory is false: forks share an object
    network and the server honours reachable-SHA1-in-want, so `_fetch`'s
    single-sha strategy pulls an *open* fork PR head into a completely fresh
    mirror in 1.2s. Verified end to end on `pallets/flask#5660`.

    The path is kept for the remotes where the assumption does not hold -- a
    plain file:// remote refuses arbitrary shas, as `_fetch`'s own comment
    already notes -- but it is unexercised against GitHub, and calling it "fork
    support" would be claiming a fix for a break that does not occur."""
    fake = _FakeCheckout(".cache", head_needs_pull_ref=True)
    _patch(monkeypatch, fake)
    base, head, info = cli._materialize(
        "o/r", 7, {"base_sha": "base", "head_sha": "head"}, ".cache")
    assert fake.pull_refs == [("o/r", 7)]
    assert head == "/x/head"
    assert info["auto"] is True


def test_an_identical_base_and_head_is_refused_with_a_reason(monkeypatch):
    """`pipeline._source_reader` would make every file AST-equal to itself and
    drop the whole PR. Refuse here, not three phases later."""
    _patch(monkeypatch, _FakeCheckout(".cache"))
    base, head, info = cli._materialize(
        "o/r", 7, {"base_sha": "same", "head_sha": "same"}, ".cache")
    assert (base, head) == (None, None)
    assert "same commit" in info["skipped"]


def test_missing_shas_are_refused_rather_than_guessed(monkeypatch):
    _patch(monkeypatch, _FakeCheckout(".cache"))
    _, _, info = cli._materialize("o/r", 7, {}, ".cache")
    assert "no base/head sha" in info["skipped"]


def test_warmth_is_reported_because_principle_4_needs_it_on_the_real_path(monkeypatch):
    class _Warm(_FakeCheckout):
        def ensure(self, repo, sha):
            return CheckoutResult(path=Path(f"/x/{sha}"), sha=sha, warm=True)
    _patch(monkeypatch, _Warm(".cache"))
    _, _, info = cli._materialize(
        "o/r", 7, {"base_sha": "b", "head_sha": "h"}, ".cache")
    assert info["base"]["warm"] and info["head"]["warm"]


def test_fetch_pull_ref_asks_git_for_the_github_published_ref(monkeypatch):
    """GitHub publishes refs/pull/<n>/head on the base repo for exactly this."""
    seen = []
    monkeypatch.setattr("pr_review.vcs.checkout._run",
                        lambda args, cwd=None: seen.append(args) or "")
    co = GitCheckout(cache_root="/tmp/does-not-matter")
    monkeypatch.setattr(co, "_ensure_mirror", lambda repo: Path("/m"))
    co.fetch_pull_ref("o/r", 42)
    assert any("+refs/pull/42/head:refs/remotes/origin/pr/42" in a for a in seen[-1])
