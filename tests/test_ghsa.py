"""The GHSA loader — case construction, ground truth, and the leak control.

No network. The "remote" is a local git repository holding a vulnerable commit
and the commit that fixes it, the same bargain `test_checkout.py` makes; the
advisory feed is a canned dict in the shape the API returns.

These mostly guard against building the pair **backwards**, which is the failure
this construction invites: `base_sha` on a labelled case is the *fixed* tree and
`head_sha` is the *vulnerable* one, the reverse of every other case in the
corpus. Getting it wrong produces a corpus that runs cleanly, reports zero
recall, and looks like a detector problem.
"""
from __future__ import annotations

import subprocess

import pytest

from pr_review.benchmark import ghsa
from pr_review.benchmark.corpus import CorpusError
from pr_review.vcs.checkout import GitCheckout

VULN = """\
import os


def render(request):
    name = request.GET["name"]
    os.system("echo " + name)
    return name
"""

FIXED = """\
import os
import shlex


def render(request):
    name = request.GET["name"]
    os.system("echo " + shlex.quote(name))
    return name
"""


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   text=True)


def _rev(cwd, ref="HEAD") -> str:
    return subprocess.run(["git", "rev-parse", ref], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def origin(tmp_path):
    """A repo whose second commit fixes the vulnerability in its first."""
    src = tmp_path / "origin"
    src.mkdir()
    _git(src, "init", "--quiet", "-b", "main")
    _git(src, "config", "user.email", "t@e.st")
    _git(src, "config", "user.name", "T")

    (src / "app").mkdir()
    (src / "app" / "views.py").write_text(VULN)
    (src / "CHANGELOG.md").write_text("# Changelog\n")
    (src / "tests").mkdir()
    (src / "tests" / "test_views.py").write_text("def test_ok():\n    pass\n")
    _git(src, "add", "-A")
    _git(src, "commit", "--quiet", "-m", "initial")
    vuln_sha = _rev(src)

    (src / "app" / "views.py").write_text(FIXED)
    (src / "CHANGELOG.md").write_text("# Changelog\n\n- Fix command injection\n")
    (src / "tests" / "test_views.py").write_text(
        "def test_ok():\n    pass\n\n\ndef test_quoted():\n    pass\n")
    _git(src, "add", "-A")
    _git(src, "commit", "--quiet", "-m", "escape the shell argument")
    fix_sha = _rev(src)

    return {"path": src, "vuln_sha": vuln_sha, "fix_sha": fix_sha}


def _advisory(origin, *, repo="o/r") -> dict:
    return {
        "ghsa_id": "GHSA-test-0001",
        "cve_id": "CVE-2026-00001",
        "summary": "Command injection in render() via the name parameter",
        "html_url": "https://github.com/advisories/GHSA-test-0001",
        "published_at": "2026-08-01T00:00:00Z",
        "cwes": [{"cwe_id": "CWE-78", "name": "OS Command Injection"}],
        "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "demo"}}],
        "source_code_location": f"https://github.com/{repo}",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-00001",
            f"https://github.com/{repo}/commit/{origin['fix_sha']}",
        ],
    }


@pytest.fixture(autouse=True)
def local_remote(origin, monkeypatch):
    """Point `GitCheckout` at the local repo instead of github.com.

    The loader builds its own `GitCheckout`, so the seam is the constructor
    rather than an argument. Nothing else about the checkout path is stubbed —
    the mirror, the fetch and the `git archive` extraction all really run.
    """
    original = GitCheckout.__init__

    def patched(self, cache_root=".pr_review/cache", remote_template=None):
        original(self, cache_root=cache_root,
                 remote_template=f"file://{origin['path']}")
    monkeypatch.setattr(GitCheckout, "__init__", patched)


@pytest.fixture
def built(tmp_path, origin, local_remote, monkeypatch):
    """A corpus built from the local repo, with the advisory feed stubbed."""
    adv = _advisory(origin)
    monkeypatch.setattr(ghsa, "list_advisories", lambda *a, **k: [adv])
    corpus, candidates = ghsa.build_labelled_corpus(
        advisories=1,
        selection_criteria="one synthetic advisory over a local repo",
        cache_root=tmp_path / "cache",
        progress=False,
    )
    return corpus, candidates, adv


# ---------------------------------------------------------------------------
# Resolving the advisory
# ---------------------------------------------------------------------------

def test_only_a_commit_in_the_advisorys_own_repo_counts(origin):
    """Advisories reference a distributor's packaging fix or a mirror as often
    as their own fix; building from one would pin a tree the advisory says
    nothing about."""
    adv = _advisory(origin)
    adv["references"] = [f"https://github.com/someone/else/commit/{'a' * 40}"]
    assert ghsa.fix_commit(adv) == ("", "")

    adv["references"].append(f"https://github.com/o/r/commit/{origin['fix_sha']}")
    assert ghsa.fix_commit(adv) == ("o/r", origin["fix_sha"])


def test_a_merge_commit_is_refused(tmp_path, origin):
    """Reverting a merge reverts a branch, not a fix — the diff would be nothing
    like the PR the case claims to be."""
    src = origin["path"]
    _git(src, "checkout", "--quiet", "-b", "side", origin["vuln_sha"])
    (src / "other.py").write_text("x = 1\n")
    _git(src, "add", "-A")
    _git(src, "commit", "--quiet", "-m", "side")
    _git(src, "checkout", "--quiet", "main")
    _git(src, "merge", "--quiet", "--no-ff", "-m", "merge side", "side")
    merge_sha = _rev(src)

    with pytest.raises(CorpusError, match="merge commit"):
        ghsa.parent_of(src, merge_sha)


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

def test_ground_truth_lines_are_numbered_in_the_vulnerable_tree(origin):
    """`RemovedLine.lineno` is old-side, and old is P, and P is the case's head.
    If this drifts to new-side numbering every finding becomes a near miss."""
    forward = subprocess.run(
        ["git", "diff", origin["vuln_sha"], origin["fix_sha"]],
        cwd=origin["path"], check=True, capture_output=True, text=True).stdout
    gt = ghsa.ground_truth(forward, "CWE-78")

    assert [g.file for g in gt] == ["app/views.py"]
    # `os.system("echo " + name)` is line 6 of the vulnerable file.
    assert gt[0].covers(6, 6)
    assert VULN.splitlines()[5].strip() == 'os.system("echo " + name)'


def test_changelogs_and_tests_never_become_ground_truth(origin):
    """A fix commit routinely carries a changelog entry, a version bump and a
    regression test. Admitting them enters 'the changelog' as a vulnerability
    and dilutes recall with rows no detector could ever match."""
    forward = subprocess.run(
        ["git", "diff", origin["vuln_sha"], origin["fix_sha"]],
        cwd=origin["path"], check=True, capture_output=True, text=True).stdout
    files = {g.file for g in ghsa.ground_truth(forward, "CWE-78")}
    assert "CHANGELOG.md" not in files
    assert "tests/test_views.py" not in files


def test_a_fix_that_only_adds_still_gets_a_location():
    """A guard inserted with nothing deleted has no removed lines. The
    vulnerability is the absence of that guard, and the absence sits where the
    guard went."""
    diff = (
        "diff --git a/app/api.py b/app/api.py\n"
        "--- a/app/api.py\n"
        "+++ b/app/api.py\n"
        "@@ -10,6 +10,7 @@ def handler(request):\n"
        " def handler(request):\n"
        "+    require_admin(request.user)\n"
        "     return delete_everything()\n"
    )
    gt = ghsa.ground_truth(diff, "CWE-862")
    assert gt and gt[0].file == "app/api.py"
    assert gt[0].spans and gt[0].spans[0][0] == 10
    assert "only added" in gt[0].note


def test_a_renamed_file_is_named_by_its_vulnerable_side_path():
    """`ParsedFile.path` is the new path, which is the fixed tree. A span on a
    path that does not exist on the side being scored is an automatic miss."""
    diff = (
        "diff --git a/app/old.py b/app/new.py\n"
        "similarity index 90%\n"
        "rename from app/old.py\n"
        "rename to app/new.py\n"
        "--- a/app/old.py\n"
        "+++ b/app/new.py\n"
        "@@ -3,3 +3,3 @@\n"
        "-    eval(payload)\n"
        "+    ast.literal_eval(payload)\n"
    )
    gt = ghsa.ground_truth(diff, "CWE-94")
    assert [g.file for g in gt] == ["app/old.py"]


def test_imports_version_bumps_and_comments_are_not_ground_truth():
    """A fix ships with an import, a version bump and a comment explaining it.
    Seven of the first 28 real advisories offered one of those as ground truth
    — `from math import ceil`, `__version__ = "0.19.2"`, a comment block. A
    detector cannot flag an import, so scoring against one is a guaranteed
    miss recorded against the detector."""
    diff = (
        "diff --git a/pkg/thing.py b/pkg/thing.py\n"
        "--- a/pkg/thing.py\n"
        "+++ b/pkg/thing.py\n"
        "@@ -1,4 +1,4 @@\n"
        "-import os\n"
        "-from math import ceil\n"
        "+import os\n"
        "+from math import ceil, floor\n"
        "@@ -20,3 +20,3 @@\n"
        "-__version__ = \"1.2.3\"\n"
        "+__version__ = \"1.2.4\"\n"
        "@@ -40,3 +40,3 @@\n"
        "-# explain the guard\n"
        "+# explain the guard better\n"
        "@@ -60,3 +60,3 @@\n"
        "-    os.system(cmd)\n"
        "+    subprocess.run(shlex.split(cmd))\n"
    )
    gt = ghsa.ground_truth(diff, "CWE-78")
    assert len(gt) == 1
    # Only the line that is actually the vulnerability survives.
    assert gt[0].spans == [(60, 60)]


def test_a_span_mixing_an_import_with_real_code_survives_intact():
    """The rule drops a span only when *every* line in it is scaffolding."""
    diff = (
        "diff --git a/pkg/thing.py b/pkg/thing.py\n"
        "--- a/pkg/thing.py\n"
        "+++ b/pkg/thing.py\n"
        "@@ -10,3 +10,3 @@\n"
        "-import pickle\n"
        "-    return pickle.loads(blob)\n"
        "+import json\n"
        "+    return json.loads(blob)\n"
    )
    gt = ghsa.ground_truth(diff, "CWE-502")
    assert gt[0].spans == [(10, 11)]


def test_an_added_import_block_is_not_an_insertion_point():
    """An added-only hunk marks where a missing guard belonged — unless all it
    added was an import, in which case it marks nothing."""
    diff = (
        "diff --git a/pkg/thing.py b/pkg/thing.py\n"
        "--- a/pkg/thing.py\n"
        "+++ b/pkg/thing.py\n"
        "@@ -1,3 +1,4 @@\n"
        " import os\n"
        "+import shlex\n"
        "@@ -30,3 +30,4 @@\n"
        " def run(cmd):\n"
        "+    validate(cmd)\n"
    )
    gt = ghsa.ground_truth(diff, "CWE-78")
    assert gt[0].spans == [(30, 32)]


def test_hand_exclusions_are_read_with_their_reasons(tmp_path):
    path = tmp_path / "excluded.txt"
    path.write_text(
        "# a comment line\n"
        "\n"
        "GHSA-aaaa-bbbb-cccc  # bulk refactor; spans mark plumbing\n"
        "GHSA-dddd-eeee-ffff\n"
    )
    loaded = ghsa.load_exclusions(path)
    assert loaded["GHSA-aaaa-bbbb-cccc"] == "bulk refactor; spans mark plumbing"
    assert "no reason recorded" in loaded["GHSA-dddd-eeee-ffff"]
    assert len(loaded) == 2


def test_excluding_a_commit_holds_however_many_advisories_point_at_it(
        tmp_path, origin, monkeypatch):
    """Excluding by advisory id alone leaks: several advisories can share one
    fixing commit, so rejecting one id frees a per-repo slot the next id on the
    same commit walks straight into. Two real bulk refactors came back under
    four GHSA ids between them."""
    first = _advisory(origin)
    twin = _advisory(origin)
    twin["ghsa_id"] = "GHSA-test-0042"          # different id, same fix commit

    monkeypatch.setattr(ghsa, "list_advisories", lambda *a, **k: [first, twin])
    corpus, candidates = ghsa.build_labelled_corpus(
        advisories=2, per_repo=5,
        selection_criteria="two advisories on one excluded commit",
        exclude={f"o/r@{origin['fix_sha']}": "bulk refactor"},
        cache_root=tmp_path / "cache", progress=False)

    assert corpus.cases == []
    assert all("bulk refactor" in c.rejected for c in candidates)


def test_an_excluded_advisory_is_rejected_with_its_reason(
        tmp_path, origin, monkeypatch):
    """Hand curation has to reject what the mechanical rules cannot judge, and
    the corpus has to stay rebuildable from the same command afterwards."""
    adv = _advisory(origin)
    monkeypatch.setattr(ghsa, "list_advisories", lambda *a, **k: [adv])
    corpus, candidates = ghsa.build_labelled_corpus(
        advisories=1, selection_criteria="one, excluded",
        exclude={"GHSA-test-0001": "spans mark plumbing, not the defect"},
        cache_root=tmp_path / "cache", progress=False)

    assert corpus.cases == []
    assert "spans mark plumbing" in candidates[0].rejected
    assert "excluded by hand" in candidates[0].rejected


# ---------------------------------------------------------------------------
# The pair
# ---------------------------------------------------------------------------

def test_the_vulnerable_case_reviews_the_fix_run_backwards(built):
    """The construction in one assertion: base is the FIXED tree, head is the
    VULNERABLE one, and the diff adds the vulnerable line."""
    corpus, _, _ = built
    vuln = next(c for c in corpus.cases if c.id.endswith(":vuln"))

    assert vuln.ref.base_sha != vuln.ref.head_sha
    assert vuln.advisory.construction == "reverse_fix"
    assert vuln.ref.base_sha == vuln.advisory.fix_commit
    assert vuln.ref.head_sha == vuln.advisory.vuln_commit
    # The PR under review re-introduces the unescaped call.
    added = [ln for ln in vuln.pr_task.diff_text.splitlines()
             if ln.startswith("+") and not ln.startswith("+++")]
    assert any('os.system("echo " + name)' in ln for ln in added)
    assert not any("shlex.quote" in ln for ln in added)


def test_the_control_is_the_same_fix_forwards_and_carries_no_ground_truth(built):
    """§2c's post-fix control. Recall alone cannot tell 'found the
    vulnerability' from 'always fires on this file'; holding the file constant
    and removing only the vulnerability can."""
    corpus, _, _ = built
    control = next(c for c in corpus.cases if c.id.endswith(":control"))
    vuln = next(c for c in corpus.cases if c.id.endswith(":vuln"))

    assert control.ground_truth == []
    assert not control.labelled
    assert control.advisory.construction == "post_fix_control"
    # The two cases are the same pair of trees, with the roles swapped.
    assert control.ref.base_sha == vuln.ref.head_sha
    assert control.ref.head_sha == vuln.ref.base_sha
    assert control.pr_task.base_dir == vuln.pr_task.head_dir
    assert control.pr_task.head_dir == vuln.pr_task.base_dir


def test_both_halves_share_a_pair_id(built):
    corpus, _, _ = built
    assert {c.pair_id for c in corpus.cases} == {"GHSA-test-0001"}
    assert len(corpus.cases) == 2


def test_the_advisory_text_never_reaches_a_surface_the_pipeline_reads(built):
    """`benchmark.md` §3: avoid samples whose fix text leaks the answer. The
    summary names the vulnerability and `PRTask.body` is read by the sentinel
    now and by Phase-3b agents at M3."""
    corpus, _, adv = built
    for case in corpus.cases:
        assert case.pr_task.body == ""
        assert "injection" not in case.pr_task.title.lower()
        assert adv["summary"] not in case.pr_task.title
    # ...and it is still recorded, where scoring can see it.
    assert corpus.cases[0].advisory.summary == adv["summary"]


def test_the_case_carries_what_the_temporal_split_needs(built):
    corpus, _, _ = built
    case = corpus.cases[0]
    assert case.published is not None and case.published.year == 2026
    assert case.cwe == ["CWE-78"]
    assert case.source == "ghsa"


# ---------------------------------------------------------------------------
# The curation log
# ---------------------------------------------------------------------------

def test_rejections_are_recorded_with_their_reason(tmp_path, origin, monkeypatch):
    """A corpus is only as trustworthy as the account of what was left out."""
    good = _advisory(origin)
    no_cwe = _advisory(origin)
    no_cwe["ghsa_id"], no_cwe["cwes"] = "GHSA-test-0002", []
    no_commit = _advisory(origin)
    no_commit["ghsa_id"], no_commit["references"] = "GHSA-test-0003", []

    monkeypatch.setattr(ghsa, "list_advisories",
                        lambda *a, **k: [good, no_cwe, no_commit])
    corpus, candidates = ghsa.build_labelled_corpus(
        advisories=3, selection_criteria="three synthetic advisories",
        cache_root=tmp_path / "cache", progress=False)

    by_id = {c.ghsa_id: c for c in candidates}
    assert not by_id["GHSA-test-0001"].rejected
    assert "CWE" in by_id["GHSA-test-0002"].rejected
    assert "fixing-commit" in by_id["GHSA-test-0003"].rejected

    log = ghsa.curation_log(candidates, corpus)
    assert "GHSA-test-0002" in log and "GHSA-test-0003" in log
    assert "three synthetic advisories" in log
    assert "CANDIDATES" in log or "candidates" in log


def test_two_advisories_sharing_one_fix_commit_are_pinned_once(
        tmp_path, origin, monkeypatch):
    """One commit routinely closes several advisories. Admitting both would pin
    the same trees, diff and ground truth twice under different GHSA ids —
    double-weighting that commit in the recall numerator *and* its denominator.

    Found on the first real build: 28 advisories resolved to 27 commits.
    """
    first = _advisory(origin)
    twin = _advisory(origin)
    twin["ghsa_id"] = "GHSA-test-0042"          # same repo, same fix commit

    monkeypatch.setattr(ghsa, "list_advisories", lambda *a, **k: [first, twin])
    corpus, candidates = ghsa.build_labelled_corpus(
        advisories=2, per_repo=5,               # cap must not be what rejects it
        selection_criteria="two advisories, one fix",
        cache_root=tmp_path / "cache", progress=False)

    assert len(corpus.cases) == 2               # one pair, not two
    assert "same fixing commit" in next(
        c for c in candidates if c.ghsa_id == "GHSA-test-0042").rejected


def test_the_per_repo_cap_is_enforced(tmp_path, origin, monkeypatch):
    """Recent pip advisories are heavily concentrated — one repo was 32 of 100
    in the sample this loader was built against, and the per-repo cap was 37 of
    52 rejections on the first real build."""
    first = _advisory(origin)

    # A *different* fixing commit in the same repo, so the cap is what rejects
    # this one and not the same-commit rule above it.
    src = origin["path"]
    (src / "app" / "views.py").write_text(FIXED.replace("shlex.quote", "quote"))
    _git(src, "add", "-A")
    _git(src, "commit", "--quiet", "-m", "a second, unrelated fix")
    second = _advisory(origin)
    second["ghsa_id"] = "GHSA-test-0009"
    second["references"] = [f"https://github.com/o/r/commit/{_rev(src)}"]

    monkeypatch.setattr(ghsa, "list_advisories", lambda *a, **k: [first, second])
    corpus, candidates = ghsa.build_labelled_corpus(
        advisories=2, per_repo=1, selection_criteria="two from one repo",
        cache_root=tmp_path / "cache", progress=False)

    assert len(corpus.cases) == 2                     # one advisory, two cases
    assert "per-repo cap" in next(
        c for c in candidates if c.ghsa_id == "GHSA-test-0009").rejected
