"""Which sources a published page was built from, and whether they have moved.

WHY THIS EXISTS (`OPEN_ITEMS.md` §24)

Two generators render sources in this repository into pages published outside
it: `benchmark/results/comparison.sh` -> the scorecard, and `render_report.py`
-> the report page. Nothing connected a change in a source to a re-run of its
generator, so `REPORT.md` could be edited, committed and left showing a previous
version of the argument on the published page. The whole suite stays green,
because no test knows the page exists.

It has already failed twice here. The 2026-08-22 renderer was written to a
session scratchpad and lost; and the ceiling correction of 2026-08-22 reached
seven documents and none of the source, leaving three docstrings quoting a
number the documents had already retired (errata §14.50).

WHAT THIS DELIBERATELY IS NOT

It is **not a test that fails**. Rendering is a deliberate act and an edit that
has not been published yet is the normal state of the repository between a fix
and its landing; a red suite there teaches people to ignore a red suite. It
reports, and the reader decides.

It also does not check the live page over the network. Artifacts are private by
default and the CSP forbids it. The point is to catch drift **locally, before
publishing**, which is where it is cheap.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

# Beside the pages themselves rather than in the repo root: this is bookkeeping
# for generated artifacts, and it belongs where they land.
LEDGER = Path("benchmark/results/.rendered.json")


def repo_relative(path: str | Path) -> str:
    """A ledger key that means the same thing on someone else's checkout.

    Every other key here is repository-relative, because `digest` resolves keys
    against the working directory and both generators run from the repo root.
    A `__file__`, though, is absolute -- so recording one writes
    `/Users/somebody/PR Review 2026/...` into a **committed** file, and on any
    other checkout that path digests to None and the ledger reports drift on a
    source that never moved.

    That failure is worse than the one this module exists to catch. A drift
    report is only useful while it is rare; one that fires on every clone is
    noise, and the reader learns to skip the line -- which is the same reason
    `check` reports instead of failing (see the module docstring).

    Falls back to the path as given when it is outside the tree, because a
    wrong-but-readable key still digests, while raising here would take down a
    render over bookkeeping.
    """
    root = Path(__file__).resolve().parents[2]
    try:
        return str(Path(path).resolve().relative_to(root))
    except ValueError:
        return str(path)


def digest(path: str | Path) -> str | None:
    """sha256 of a source file, or None if it is not readable.

    None is a real state -- a source that was renamed or deleted since the last
    render -- and it must stay distinguishable from "unchanged".
    """
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _load(ledger: Path) -> dict:
    try:
        return json.loads(ledger.read_text())
    except (OSError, ValueError):
        return {}


def record(output: str | Path, sources: list[str | Path],
           ledger: Path | None = None) -> dict:
    """Note that `output` was just built from `sources` as they are right now.

    Raises on a source that cannot be read. Recording `None` for it would make
    the ledger agree with itself forever -- unreadable then, unreadable now,
    therefore "unchanged" -- which is the silent pass this module exists to
    prevent, and which the first version of this function did on its first run
    because it was handed display names rather than paths.
    """
    ledger = Path(ledger or LEDGER)
    entries = {str(s): digest(s) for s in sources}
    unreadable = sorted(k for k, v in entries.items() if v is None)
    if unreadable:
        raise ValueError(
            f"cannot record {output}: unreadable source(s) {unreadable}. A "
            f"ledger entry of None would compare equal to itself and report no "
            f"drift forever. Pass paths, not labels.")
    data = _load(ledger)
    data[str(output)] = entries
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return data


def drift(output: str | Path | None = None, ledger: Path | None = None) -> list[str]:
    """Human-readable lines for every source that has moved since its render.

    Empty means every recorded page is current -- or that nothing has been
    recorded, which is why `check` prints the two cases differently. A ledger
    with no entry for a page is not evidence that the page is up to date.
    """
    data = _load(Path(ledger or LEDGER))
    out: list[str] = []
    for page, sources in sorted(data.items()):
        if output is not None and str(output) != page:
            continue
        for src, was in sorted(sources.items()):
            now = digest(src)
            if now == was:
                continue
            if now is None:
                out.append(f"{page}: source {src} is missing or unreadable")
            else:
                out.append(f"{page}: {src} changed since it was last rendered")
    return out


def check(output: str | Path | None = None, ledger: Path | None = None) -> str:
    """The message a generator prints, or "" when there is nothing to say."""
    lines = drift(output, ledger)
    if not lines:
        return ""
    return ("\nPUBLICATION DRIFT -- a published page is behind its source:\n  "
            + "\n  ".join(lines)
            + "\n  Re-run its generator and republish with the artifact's existing"
              " `url`, or the link people hold will keep showing the old version."
              " See OPEN_ITEMS.md §24.\n")
