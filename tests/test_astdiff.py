"""Formatting-only detection (phase-2 §3, tier 1; a named M1 test in §8).

A wrong "yes" here is a dropped file and an invisible vulnerability, so most of
these tests are about the check *declining* rather than answering.
"""
import pytest

from pr_review.change import astdiff
from pr_review.extract.diff import parse_unified_diff

pytestmark = pytest.mark.skipif(
    not astdiff.parses("python"),
    reason="tree-sitter python grammar not installed",
)


def _file(body: str, path="app.py"):
    diff = (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -1,6 +1,6 @@\n{body}")
    return parse_unified_diff(diff)[0]


# --------------------------------------------------------------------------
# AST equality
# --------------------------------------------------------------------------

def test_whitespace_and_comments_are_equal():
    before = "def f(a,b):\n    # old comment\n    return a+b\n"
    after = "def f(a, b):\n    # a completely different comment\n\n    return a + b\n"
    assert astdiff.ast_equal(before, after)


def test_docstring_changes_are_equal():
    """A bare string expression is evaluated and discarded wherever it appears."""
    before = 'def f():\n    """Old."""\n    return 1\n'
    after = 'def f():\n    """New, and much longer."""\n    return 1\n'
    assert astdiff.ast_equal(before, after)


def test_a_changed_literal_is_not_formatting():
    assert not astdiff.ast_equal("TIMEOUT = 30\n", "TIMEOUT = 3000\n")


def test_a_changed_string_value_is_not_formatting():
    """Distinguishes a real string edit from a docstring edit."""
    assert not astdiff.ast_equal('q = "SELECT 1"\n', 'q = "DROP TABLE users"\n')


def test_reindentation_changes_the_tree_in_python():
    """Indentation is block structure, not whitespace — the case a naive
    strip-and-compare would get catastrophically wrong."""
    before = "def f(x):\n    if x:\n        log(x)\n    return 1\n"
    after = "def f(x):\n    if x:\n        log(x)\n        return 1\n"
    assert not astdiff.ast_equal(before, after)


def test_removing_a_decorator_is_not_formatting():
    before = "@login_required\ndef view():\n    return 1\n"
    after = "def view():\n    return 1\n"
    assert not astdiff.ast_equal(before, after)


def test_a_parse_error_never_reports_equal():
    """Two files that both fail to parse are not thereby the same file."""
    assert astdiff.normalized_ast("def f(:\n") is None
    assert not astdiff.ast_equal("def f(:\n", "def f(:\n")


def test_an_unsupported_language_declines():
    assert astdiff.normalized_ast("fn main() {}", "rust") is None
    assert not astdiff.ast_equal("a", "a", "rust")


# --------------------------------------------------------------------------
# The diff-only check
# --------------------------------------------------------------------------

def test_comment_only_hunks_are_inert():
    pf = _file("-# old note\n+# new note\n+\n")
    assert astdiff.inert_hunks(pf, "python")


def test_a_code_line_disqualifies_the_hunk():
    pf = _file("-# old note\n+debug = True\n")
    assert not astdiff.inert_hunks(pf, "python")


def test_a_hash_line_inside_a_string_is_not_a_comment():
    """The heuristic's one unsound case, closed by the after-version."""
    after = 'QUERY = """\n# not a comment\nSELECT 1\n"""\n'
    pf = _file("+# not a comment\n")
    assert astdiff.inert_hunks(pf, "python") is True          # without the source
    assert astdiff.inert_hunks(pf, "python", after_source=after) is False


def test_an_unparseable_after_version_declines_rather_than_drops():
    pf = _file("+# a comment\n")
    assert astdiff.inert_hunks(pf, "python", after_source="def f(:\n") is False


def test_a_file_with_no_hunks_is_not_inert():
    pf = _file("")
    assert not astdiff.inert_hunks(pf, "python")


def test_an_unsupported_language_is_never_inert():
    pf = _file("+// a comment\n", path="main.rs")
    assert not astdiff.inert_hunks(pf, "rust")


# --------------------------------------------------------------------------
# Control flow — the full_file escalation trigger
# --------------------------------------------------------------------------

@pytest.mark.parametrize("body,expected", [
    ("+    if user.is_admin:\n", True),
    ("+    raise PermissionDenied()\n", True),
    ("+    except ValueError:\n", True),
    ("-    return None\n", True),                     # an exit path disappeared
    ("+    return value.title()\n", False),           # every function has one
    ("+    total = a + b\n", False),
])
def test_control_flow_detection(body, expected):
    pf = _file(body)
    assert astdiff.hunk_touches_control_flow(pf.hunks[0]) is expected


def test_a_new_file_never_escalates():
    """The hunks already are the whole file, so `full_file` adds no context."""
    pf = _file("+def f(x):\n+    if x:\n+        return 1\n")
    assert astdiff.hunk_touches_control_flow(pf.hunks[0]) is True
    assert astdiff.hunk_touches_control_flow(pf.hunks[0], file_is_new=True) is False


# --------------------------------------------------------------------------
# String-line mapping
# --------------------------------------------------------------------------

def test_string_lines_covers_multiline_literals():
    lines = astdiff.string_lines('x = 1\nq = """\nabc\n"""\n')
    assert {2, 3, 4} <= lines and 1 not in lines


def test_string_lines_declines_on_a_parse_error():
    assert astdiff.string_lines("def f(:\n") is None
