"""Unified-diff parser (phase-0-extraction.md §3.2).

Pure stdlib. Returns an internal representation that carries the *content* of
both added and removed lines alongside the structural hunk info used to build
the DeltaManifest.

WHY REMOVED-LINE CONTENT IS RETAINED
M0 kept only removed line *numbers*, because the secrets detector reads added
lines. Phase 2 needs both sides:

  - `extract/deps.py` computes a `DepDelta`'s `removed` and `changed` maps, and
    "changed" is only expressible as (old version -> new version).
  - the tier-1 formatting-only check compares before against after; with removed
    text discarded, a hunk cannot be reconstructed at all.

This content stays in the in-memory `ParsedFile` and never enters the serialized
`DeltaManifest` — which keeps the manifest's promise of carrying no source. It
is untrusted like added-line text and must be wrapped (`safety/wrap.py`) before
reaching any prompt.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


@dataclass
class AddedLine:
    lineno: int  # line number in the NEW file
    text: str


@dataclass
class RemovedLine:
    lineno: int  # line number in the OLD file
    text: str


@dataclass
class ParsedHunk:
    old_start: int
    old_len: int
    new_start: int
    new_len: int
    header: str
    added: list[AddedLine] = field(default_factory=list)
    removed: list[RemovedLine] = field(default_factory=list)
    # Every line in the hunk as (tag, text), tag in {"+", "-", " "}, in file
    # order. Context lines are retained because the lockfile parsers in
    # `extract/deps.py` are block scanners: a `poetry.lock` version bump changes
    # only the `version = "..."` line, and the `name = "..."` line that says
    # which package it belongs to arrives as context. Without it, the commonest
    # dependency change in the ecosystem parses to nothing.
    body: list[tuple[str, str]] = field(default_factory=list)

    @property
    def removed_linenos(self) -> list[int]:
        return [r.lineno for r in self.removed]

    def side(self, which: str) -> list[str]:
        """The hunk as it reads before ("old") or after ("new") the change."""
        keep = {"old": (" ", "-"), "new": (" ", "+")}[which]
        return [text for tag, text in self.body if tag in keep]

    @property
    def old_range(self) -> str | None:
        if self.old_len == 0:
            return None
        return f"{self.old_start}-{self.old_start + self.old_len - 1}"

    @property
    def new_range(self) -> str | None:
        if self.new_len == 0:
            return None
        return f"{self.new_start}-{self.new_start + self.new_len - 1}"


@dataclass
class ParsedFile:
    path: str
    previous_path: str | None
    change: str  # added | modified | deleted | renamed
    binary: bool
    hunks: list[ParsedHunk] = field(default_factory=list)


def _strip_prefix(p: str) -> str:
    if p in ("/dev/null", ""):
        return p
    for pre in ("a/", "b/"):
        if p.startswith(pre):
            return p[2:]
    return p


def parse_unified_diff(text: str) -> list[ParsedFile]:
    files: list[ParsedFile] = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if not line.startswith("diff --git "):
            i += 1
            continue
        # ---- header block ----
        m = re.match(r"^diff --git a/(.+) b/(.+)$", line)
        a_path = m.group(1) if m else None
        b_path = m.group(2) if m else None
        change = "modified"
        previous_path = None
        binary = False
        minus_path = plus_path = None
        i += 1
        while i < n and not lines[i].startswith("@@") and not lines[i].startswith("diff --git "):
            h = lines[i]
            if h.startswith("new file mode"):
                change = "added"
            elif h.startswith("deleted file mode"):
                change = "deleted"
            elif h.startswith("rename from "):
                change = "renamed"
                previous_path = h[len("rename from "):].strip()
            elif h.startswith("rename to "):
                change = "renamed"
            elif h.startswith("--- "):
                minus_path = _strip_prefix(h[4:].strip())
            elif h.startswith("+++ "):
                plus_path = _strip_prefix(h[4:].strip())
            elif h.startswith("Binary files") or h.startswith("GIT binary patch"):
                binary = True
            i += 1

        if plus_path == "/dev/null":
            change = "deleted"
        elif minus_path == "/dev/null":
            change = "added"

        path = (
            b_path
            or (plus_path if plus_path and plus_path != "/dev/null" else None)
            or (minus_path if minus_path and minus_path != "/dev/null" else None)
            or a_path
            or "UNKNOWN"
        )
        pf = ParsedFile(path=path, previous_path=previous_path, change=change, binary=binary)

        # ---- hunks ----
        while i < n and lines[i].startswith("@@"):
            hm = _HUNK_RE.match(lines[i])
            if not hm:
                i += 1
                continue
            old_start = int(hm.group(1))
            old_len = int(hm.group(2)) if hm.group(2) is not None else 1
            new_start = int(hm.group(3))
            new_len = int(hm.group(4)) if hm.group(4) is not None else 1
            hunk = ParsedHunk(old_start, old_len, new_start, new_len, hm.group(5).strip())
            old_ln = old_start
            new_ln = new_start
            i += 1
            while i < n and not lines[i].startswith("@@") and not lines[i].startswith("diff --git "):
                hl = lines[i]
                if hl.startswith("\\"):  # "\ No newline at end of file"
                    i += 1
                    continue
                tag = hl[:1]
                content = hl[1:]
                if tag == "+":
                    hunk.added.append(AddedLine(new_ln, content))
                    hunk.body.append(("+", content))
                    new_ln += 1
                elif tag == "-":
                    hunk.removed.append(RemovedLine(old_ln, content))
                    hunk.body.append(("-", content))
                    old_ln += 1
                else:  # context (' ') or empty
                    hunk.body.append((" ", content))
                    old_ln += 1
                    new_ln += 1
                i += 1
            pf.hunks.append(hunk)
        files.append(pf)
    return files
