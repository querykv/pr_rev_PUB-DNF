"""Build a DeltaManifest from PR metadata + a parsed unified diff (phase-0 §3)."""
from __future__ import annotations

import hashlib
from pathlib import Path

from pr_review.extract import classify
from pr_review.extract.deps import extract_dep_deltas
from pr_review.extract.diff import ParsedFile, parse_unified_diff
from pr_review.extract.schema import DeltaManifest, FileChange, Hunk
from pr_review.util import normalize_path

# large-diff guard thresholds (phase-0 §3.6)
MAX_FILES = 300
MAX_HUNKS = 2000
MAX_ADDITIONS = 20000


def _file_id(path: str) -> str:
    return hashlib.sha1(normalize_path(path).encode()).hexdigest()[:12]


HEADER_BYTES = 2048


def _head_text(pf: ParsedFile, head_dir: Path | None) -> str | None:
    """The first `HEADER_BYTES` of the file as it exists AFTER the change, for
    `classify.is_generated`'s header check. `None` when nothing can be read.

    Two sources, in order, and the fallback is not a nicety:

    1. **The checkout**, when there is one. Complete and authoritative.
    2. **The diff itself**, when there is not. A generated file's marker sits at
       line 1, so it is in the diff only when the first hunk reaches line 1 --
       true for 3 of the 10 docker-library cases in the IaC corpus and false for
       the rest, which touch lines further down. Partial by construction.

    The fallback exists because Phase 0 must work with a diff and no checkout:
    that is arm 2c, `--no-checkout`, a measured configuration and not a
    degraded one. Requiring a checkout here would quietly change what that arm
    measures.
    """
    if head_dir is not None:
        try:
            with open(Path(head_dir) / pf.path, "rb") as fh:
                return fh.read(HEADER_BYTES).decode("utf-8", "ignore")
        except OSError:
            pass                      # deleted, renamed, or not in this tree
    if not pf.hunks:
        return None
    first = pf.hunks[0]
    if first.new_start > classify._HEADER_LINES:
        return None                   # the header is entirely above the hunk
    # Pad so line N of this string IS line N of the file. The first hunk of a
    # docker-library Dockerfile starts at line 4, in the MIDDLE of the header --
    # requiring it to start at line 1 found nothing, and shifting the text up
    # would put the marker in the window under a wrong line number. Padding
    # keeps the window honest in both directions.
    pad = "\n" * (first.new_start - 1)
    # Context and added lines, in file order; removed lines are the OLD file.
    body = "\n".join(text for tag, text in first.body if tag != "-")
    return (pad + body)[:HEADER_BYTES]


def _to_file_change(pf: ParsedFile,
                    head_dir: Path | None = None) -> tuple[FileChange, int, int]:
    fid = _file_id(pf.path)
    hunks: list[Hunk] = []
    additions = 0
    deletions = 0
    for n, h in enumerate(pf.hunks, start=1):
        additions += len(h.added)
        deletions += len(h.removed_linenos)
        hunks.append(
            Hunk(
                id=f"{fid}:h{n}",
                old_range=h.old_range,
                new_range=h.new_range,
                header=h.header,
                added_lines=[a.lineno for a in h.added],
                removed_lines=list(h.removed_linenos),
            )
        )
    fc = FileChange(
        file_id=fid,
        path=pf.path,
        previous_path=pf.previous_path,
        change=pf.change,
        lang=classify.detect_lang(pf.path),
        is_test=classify.is_test(pf.path),
        is_generated=classify.is_generated(pf.path, _head_text(pf, head_dir)),
        is_binary=pf.binary or classify.is_binary_ext(pf.path),
        is_lockfile=classify.is_lockfile(pf.path),
        is_dep_manifest=classify.is_dep_manifest(pf.path),
        is_iac=classify.is_iac(pf.path),
        hunks=hunks,
        size_delta=additions - deletions,
    )
    return fc, additions, deletions


def build_manifest(
    *,
    repo: str,
    pr_number: int,
    diff_text: str,
    title: str = "",
    body: str = "",
    author: str = "",
    base_sha: str = "",
    head_sha: str = "",
    base_ref: str = "",
    head_ref: str = "",
    from_fork: bool = False,
    labels: list[str] | None = None,
    head_dir: str | Path | None = None,
) -> tuple[DeltaManifest, list[ParsedFile]]:
    """Returns the manifest plus the parsed files (whose added-line content the
    detectors consume — kept out of the serialized manifest)."""
    parsed = parse_unified_diff(diff_text)
    files: list[FileChange] = []
    total_add = total_del = total_hunks = 0
    for pf in parsed:
        fc, add, dele = _to_file_change(pf, head_dir)
        files.append(fc)
        total_add += add
        total_del += dele
        total_hunks += len(fc.hunks)

    oversize = len(files) > MAX_FILES or total_hunks > MAX_HUNKS or total_add > MAX_ADDITIONS
    manifest = DeltaManifest(
        repo=repo,
        pr_number=pr_number,
        title=title,
        body=body,
        author=author,
        labels=labels or [],
        base_sha=base_sha,
        head_sha=head_sha,
        base_ref=base_ref,
        head_ref=head_ref,
        from_fork=from_fork,
        files=files,
        dep_deltas=extract_dep_deltas(parsed),
        stats={
            "files": len(files),
            "additions": total_add,
            "deletions": total_del,
            "hunks": total_hunks,
        },
        oversize=oversize,
    )
    return manifest, parsed
