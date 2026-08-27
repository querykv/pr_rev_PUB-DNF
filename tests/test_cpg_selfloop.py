"""A pattern is not a taint flow to itself (`profile/cpg.py:_self_pairing`).

Three catalog patterns are legitimately both a source and a sink — `open`
(filesystem/path), `requests.get` and `httpx.get` (network/http_outbound) —
because `open(p)`'s **argument** is a path sink while `open(f).read()`'s
**return value** is untrusted data. The node builder does not distinguish those
positions, so every `open(x)` emits both roles and `_taint`'s cross product
pairs them with each other.

Measured on the pass-2 labelled corpus, in two steps, because the first was
too narrow:

- refusing only the *same call site* (`open`@29 with itself) removed 6
  introduced and 42 pre-existing paths and took the corpus 11 -> 8 false
  positives;
- refusing the *same pattern* at any distance (`open`@29 with `open`@38) took
  it 8 -> 1. All 8 survivors of the first guard were this shape.

The run first read those 11 as "the detector fires on security regression
tests", because 10 of them sat in test files. That was a population, not a
cause: 42 of the same shape sat in non-test code, and test code simply calls
`open()` more.

The guard is narrow on purpose, and the last two tests are the ones that
matter: a real flow is routinely written on one line, and
`os.system(request.args["cmd"])` is the single most valuable finding this
detector makes.
"""
from __future__ import annotations

import pytest

pytest.importorskip(
    "cap_engine.environment.code_promoter",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from pr_review.profile.cpg import build_cpg  # noqa: E402
from pr_review.profile.promote import promote  # noqa: E402

SELF_LOOP = '''\
"""A dual-role call, alone in its function: `open` is both a filesystem source
and a path sink, so before the guard this produced a path from line 3 to line 3."""


def write_fixture(dest):
    with open(dest, "w") as handle:
        handle.write("x")
'''

CROSS_LINE = '''\
"""The same defect at a distance: two `open` calls in one function. Pairing
them claims the contents read at the first reach the path argument at the
second, which co-location does not establish."""


def copy_fixture(src, dest):
    with open(src) as handle:
        data = handle.read()
    with open(dest, "w") as out:
        out.write(data)
'''

REAL_FLOW_ON_ONE_LINE = '''\
"""Source and sink at the same position, and a genuine flow. Matching a
self-loop on file+line alone would silently delete this class."""
import os

from flask import request


def run():
    os.system(request.args["cmd"])
'''

TWO_PATTERNS = '''\
"""Two different dual-role-adjacent patterns, which must still pair. This is
the shape of pass 2's only true positive: source `tarfile.open`, sink
`tar.extractall`."""
import tarfile


def unpack(archive, dest):
    tar = tarfile.open(archive)
    tar.extractall(dest)
'''

OPEN_FEEDS_ANOTHER_SINK = '''\
"""`open` keeps its source role for *other* sinks. Refusing the whole role,
rather than only the self-pairing, would delete this."""
import os


def run(config_path):
    with open(config_path) as handle:
        cmd = handle.read()
    os.system(cmd)
'''


def _cpg(tmp_path, name: str, source: str):
    app = tmp_path / name
    app.mkdir()
    (app / "mod.py").write_text(source)
    return build_cpg(promote(str(app)))


def test_a_dual_role_call_does_not_taint_itself(tmp_path):
    graph = _cpg(tmp_path, "loop", SELF_LOOP)
    selfloops = [p for p in graph.taint_paths
                 if p.source.file == p.sink.file
                 and p.source.line == p.sink.line
                 and p.source.name == p.sink.name]
    assert selfloops == [], f"a call tainted itself: {selfloops}"
    assert graph.paths_to("path") == []


def test_the_same_pattern_does_not_pair_across_lines_either(tmp_path):
    """Two `open` calls in one function are co-located, not connected. `_taint`
    pairs by reachability in the call tree, so the "flow" it would report is
    evidence only that the function opens two files."""
    graph = _cpg(tmp_path, "cross", CROSS_LINE)
    assert graph.paths_to("path") == [], (
        f"open->open paired across lines: {graph.taint_paths}")


def test_a_real_flow_written_on_one_line_survives(tmp_path):
    """A source and a *different* sink at the same line are still a path, and
    this is the most valuable finding the detector makes."""
    graph = _cpg(tmp_path, "flow", REAL_FLOW_ON_ONE_LINE)
    cmd = graph.paths_to("command")
    assert len(cmd) == 1, f"the command-injection flow was lost: {graph.taint_paths}"
    assert cmd[0].source.name == "request.args"
    assert cmd[0].sink.name == "os.system"
    assert cmd[0].source.line == cmd[0].sink.line, (
        "this fixture exists to cover the same-line case; it is no longer same-line")


def test_two_different_patterns_still_pair(tmp_path):
    """Pass 2's only true positive in miniature. If this breaks, the guard has
    stopped discriminating between a pattern and itself."""
    graph = _cpg(tmp_path, "two", TWO_PATTERNS)
    paths = graph.paths_to("path")
    assert len(paths) == 1, f"the tar-extraction flow was lost: {graph.taint_paths}"
    assert paths[0].source.name == "tarfile.open"
    assert paths[0].sink.name == "tar.extractall"


def test_open_keeps_its_source_role_for_other_sinks(tmp_path):
    """Only the self-pairing is refused, not the role. Deleting `open` from the
    source list would have been the tempting wider fix and would cost this."""
    graph = _cpg(tmp_path, "feed", OPEN_FEEDS_ANOTHER_SINK)
    cmd = graph.paths_to("command")
    assert len(cmd) == 1, f"open no longer seeds taint into other sinks: {graph.taint_paths}"
    assert cmd[0].source.name == "open"
    assert cmd[0].sink.name == "os.system"
