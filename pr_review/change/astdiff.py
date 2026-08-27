"""Formatting-only detection (phase-2-change-analysis.md §3, tier 1).

Answers one question for the noise filter: *did this change alter the program,
or only how it is written?* A wrong "yes" is a dropped file, which is the
pipeline's #1 false-negative risk, so every check here fails **closed** — no
answer means "not formatting-only", never "safe to drop".

TWO CHECKS, BECAUSE ONE SIDE IS OFTEN ALL WE HAVE

`ast_equal(before, after)` is the exact one the plan names: parse both versions,
compare normalized trees. It needs both file versions, which needs a checkout at
`base_sha` *and* at `head_sha`.

`inert_hunks(...)` is the check that works with the diff alone: every changed
line is blank or a comment. It exists because the common path — an offline
`--diff-file` run, or a fork PR we have not fetched — has no base checkout at
all, and "we could not check" would otherwise mean the cheapest and most common
noise (comment churn) is never filtered.

The comment check has one unsound case: a line beginning with `#` *inside* a
multi-line string is not a comment, and dropping it would be dropping a real
string change. `string_lines()` closes it whenever the after-version is
available — a single side is enough, and that is the side a head checkout gives
us for free.

INTERACTION WITH THE INJECTION SENTINEL (cross-cutting §9.3)
The sentinel scans diff comments and strings for text aimed at the agents. It
must therefore run against the **manifest**, before this filter — a
comment-only hunk is exactly where an injection attempt lives, and it is exactly
what tier 1 drops. `safety/sentinel.py` is not built yet; this note is here so
the ordering is fixed before it is.

This module deliberately imports tree-sitter directly rather than through
`cap_engine`: it compares two strings, needs no ParseCache, and keeping it out
of the CAP-coupled set is free.
"""
from __future__ import annotations

from functools import lru_cache

from pr_review.extract.diff import ParsedFile, ParsedHunk

# Line-comment markers by language. Block comments are not handled — a change
# inside one falls through to "not formatting-only", which is the safe side.
_COMMENT_MARKERS = {
    "python": ("#",),
    "ruby": ("#",),
    "go": ("//",),
    "java": ("//",),
    "javascript": ("//",),
    "typescript": ("//",),
}

_TS_MODULES = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "java": "tree_sitter_java",
}


class ParserUnavailable(Exception):
    """No tree-sitter grammar for this language in this environment."""


@lru_cache(maxsize=8)
def _parser(language: str):
    import importlib

    import tree_sitter

    module_name = _TS_MODULES.get(language)
    if module_name is None:
        raise ParserUnavailable(f"no tree-sitter grammar configured for {language!r}")
    try:
        grammar = importlib.import_module(module_name)
    except ImportError as exc:                       # pragma: no cover - env-dependent
        raise ParserUnavailable(str(exc)) from exc
    return tree_sitter.Parser(tree_sitter.Language(grammar.language()))


def parses(language: str) -> bool:
    """Whether this environment can answer AST questions for `language`."""
    try:
        _parser(language)
        return True
    except Exception:                                # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Normalized AST
# ---------------------------------------------------------------------------

def _is_ignorable(node) -> bool:
    """Nodes whose content cannot change behaviour.

    Comments, and bare string expressions — a docstring, or any string evaluated
    and discarded. Both are inert wherever they appear, so position does not
    need checking.
    """
    if node.type == "comment":
        return True
    if node.type == "expression_statement" and node.named_child_count == 1:
        return node.named_children[0].type in ("string", "concatenated_string")
    return False


def normalized_ast(source: str, language: str = "python") -> str | None:
    """A canonical rendering of `source`'s structure, or None if unanswerable.

    Whitespace never appears — tree-sitter does not emit nodes for it, and
    Python's significant indentation shows up as block *structure*, so a real
    re-indentation still changes this string. Leaf text is included verbatim, so
    a changed literal or identifier is a difference.

    Returns None on a parse error rather than a best-effort string: two files
    that both fail to parse are not thereby equal.
    """
    try:
        tree = _parser(language).parse(source.encode("utf-8"))
    except ParserUnavailable:
        return None
    except Exception:                                # noqa: BLE001
        return None
    if tree.root_node.has_error:
        return None

    out: list[str] = []

    def walk(node) -> None:
        if _is_ignorable(node):
            return
        if node.child_count == 0:
            text = node.text.decode("utf-8", "replace")
            if text:
                out.append(text)
            return
        out.append("(" + node.type)
        for child in node.children:
            walk(child)
        out.append(")")

    walk(tree.root_node)
    return " ".join(out)


def ast_equal(before: str, after: str, language: str = "python") -> bool:
    """True when the two versions differ only in comments and formatting.

    False when either side cannot be parsed — the check must never claim
    equality it did not establish.
    """
    a = normalized_ast(before, language)
    if a is None:
        return False
    return a == normalized_ast(after, language)


# ---------------------------------------------------------------------------
# Diff-only check: are the changed lines inert?
# ---------------------------------------------------------------------------

def string_lines(source: str, language: str = "python") -> set[int] | None:
    """1-based line numbers covered by a string literal.

    Used to disqualify the comment heuristic where it is unsound: a `#` line
    inside a triple-quoted string is data, not a comment. None means "could not
    determine", which callers must treat as "do not use the heuristic".
    """
    try:
        tree = _parser(language).parse(source.encode("utf-8"))
    except Exception:                                # noqa: BLE001
        return None
    if tree.root_node.has_error:
        return None

    lines: set[int] = set()
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ("string", "concatenated_string"):
            lines.update(range(node.start_point[0] + 1, node.end_point[0] + 2))
            continue
        stack.extend(node.children)
    return lines


def _line_is_inert(text: str, markers: tuple[str, ...]) -> bool:
    stripped = text.strip()
    return not stripped or stripped.startswith(markers)


def inert_hunks(parsed: ParsedFile, language: str,
                after_source: str | None = None) -> bool:
    """True when every changed line in the file is blank or a comment.

    `after_source` is optional but strongly preferred: without it, a `#` line
    inside a multi-line string reads as a comment. With it, any added line that
    falls inside a string literal disqualifies the file.
    """
    markers = _COMMENT_MARKERS.get(language)
    if not markers or not parsed.hunks:
        return False

    changed = [
        (line.lineno, line.text, side)
        for hunk in parsed.hunks
        for side, lines in (("+", hunk.added), ("-", hunk.removed))
        for line in lines
    ]
    if not changed:
        return False
    if not all(_line_is_inert(text, markers) for _n, text, _s in changed):
        return False

    if after_source is not None:
        in_string = string_lines(after_source, language)
        if in_string is None:
            return False                 # could not verify -> do not drop
        if any(side == "+" and n in in_string for n, _t, side in changed):
            return False
    return True


# Keywords that are unambiguously a branch, loop or exception edge. Their
# presence on either side of a hunk means the shape of control flow changed.
_BRANCH_KEYWORDS = {
    "python": ("if ", "elif ", "else:", "raise", "try:", "except", "finally:",
               "assert ", "while ", "for ", "continue", "break", "with "),
}

# `return` is treated separately: it opens almost every function body, so
# counting it outright escalates every new helper to `full_file` and the tier
# stops meaning anything. It only signals a control-flow change when it is
# *removed* (an exit path disappeared) or sits alongside a branch keyword (an
# early return was added to existing logic).
_EXIT_KEYWORDS = {"python": ("return", "yield ", "sys.exit", "abort(")}


def hunk_touches_control_flow(hunk: ParsedHunk, language: str = "python",
                              file_is_new: bool = False) -> bool:
    """Whether a hunk adds or removes control flow — the `full_file` escalation
    trigger (phase-2 §5).

    Textual on purpose. The structural signal (the hunk overlaps a guarded
    endpoint or a CPG `guards` edge) is computed in `context.py` from the graph;
    this catches the rest — a flipped condition, a swallowed exception, a
    deleted early return — which has no CPG node of its own but is exactly the
    case where the surrounding logic decides whether the change is safe.

    `file_is_new` suppresses the escalation entirely: for an added file the hunks
    already *are* the file, so "give the agent the whole file" is not additional
    context, it is the same bytes under a more expensive label.
    """
    if file_is_new:
        return False
    branches = _BRANCH_KEYWORDS.get(language)
    exits = _EXIT_KEYWORDS.get(language)
    if not branches:
        return False

    added = [l.text.strip() for l in hunk.added]
    removed = [l.text.strip() for l in hunk.removed]
    if any(text.startswith(branches) for text in added + removed):
        return True
    return bool(exits) and any(text.startswith(exits) for text in removed)
