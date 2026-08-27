"""Pin the pipeline's context so model passes replay against fixed input.

WHY THE CONTEXT IS CAPTURED INSTEAD OF REBUILT PER PASS

The context-fed arm has two halves and only one of them is being measured. The
pipeline half is deterministic; the model half is not, which is why the arm runs
three passes at all (§14.51 is the entry about a one-pass headline that did not
survive two more). If every pass rebuilds its own bundles, a difference between
passes could be the model *or* the pipeline, and nothing in the result says
which. Capturing once and replaying fixes the pipeline half at a known value, so
the spread across passes measures exactly the thing spread is supposed to
measure.

Three consequences that are the point rather than side effects:

- **The arm is reproducible by someone without the checkouts.** The capture is a
  committed artifact; a third party can replay the passes against it without
  30 GB of repositories and a warm profile cache.
- **Passes are cheap.** No pipeline run per pass.
- **The context is auditable as a thing.** `BENCHMARK_STATUS.md` §4p censused
  the bundles; that census can be re-run against this file and get the same
  answer, which is what makes the census a claim about the arm rather than about
  one afternoon's run directory.

WHAT IS DELIBERATELY NOT IN HERE

No findings, no ground truth, no advisory text. The capture holds what the
pipeline produces for an unseen PR and nothing that knows the answer — the
leakage rule the arm inherits from `PIVOT_PLAN.md` §1.4, applied to the artifact
rather than to the prompt. `test_a_capture_carries_no_ground_truth` pins it.

DETERMINISM IS AN ASSERTION HERE, NOT A HOPE

`runner._isolated`'s docstring records that the profile cache is stateful across
cases: on a corpus with two cases in one repository the second can take the
incremental branch and patch the first's profile. If that reached the bundles,
two captures of the same corpus would differ and this file would be pinning
noise. `capture_is_byte_identical_on_a_second_run` in the test suite is the
check; the answer is recorded in §4q rather than assumed here.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from pr_review.benchmark.runner import case_run_dir, head_sha, run_corpus
from pr_review.benchmark.schema import Corpus
from pr_review.change.context import bundle_stats
from pr_review.change.schema import ContextBundle
from pr_review.config import Config
from pr_review.profile.cache import ANALYZER_VERSION

# Bumped when the shape changes, so a producer reading an older capture says so
# instead of quietly finding fields missing.
CAPTURE_VERSION = 1


def capture(corpus: Corpus, config: Config | None = None,
            limit: int | None = None, progress: bool = True) -> dict:
    """Run the pipeline over `corpus` and collect the context bundles per case."""
    config = config or Config.load()
    root = Path(tempfile.mkdtemp(prefix="context-capture-"))
    cases: dict[str, dict] = {}
    try:
        run = run_corpus(corpus, config=config, out_root=root, limit=limit,
                         progress=progress, arm="context-capture")
        for case_run in run.runs:
            case = case_run.case
            if not case_run.ok:
                # Kept as an entry rather than dropped: a producer must be able
                # to tell "this case has no context" from "this case is not in
                # the corpus", and a silently shorter capture reads as the second.
                cases[case.id] = {"error": case_run.error}
                continue
            raw = json.loads(
                (case_run_dir(root, case) / "02_context_bundles.json").read_text())
            # Validated on the way in, not on the way out. A capture that cannot
            # be read back as `ContextBundle` is a broken artifact, and the place
            # to discover that is here rather than three passes later.
            bundles = [ContextBundle.model_validate(b) for b in raw]
            cases[case.id] = {
                "repo": case.ref.repo,
                "pr_number": case.pr_task.pr_number,
                "base_sha": case.ref.base_sha,
                "head_sha": case.ref.head_sha,
                "bundles": [b.model_dump(mode="json") for b in bundles],
                "stats": bundle_stats(bundles),
            }
    finally:
        shutil.rmtree(root, ignore_errors=True)

    return {
        "capture_version": CAPTURE_VERSION,
        "corpus": corpus.name,
        # What produced it. `head_sha()` reports a dirty tree as dirty, so a
        # capture never names a commit that does not contain its own code.
        "code_sha": head_sha(),
        # A bump invalidates every profile, and profiles decide the CPG the
        # bundles are cut from -- so a capture from a different analyzer version
        # is a different measurement wearing the same filename.
        "analyzer_version": ANALYZER_VERSION,
        "cases": cases,
    }


def dumps(data: dict) -> str:
    """Serialize a capture. `sort_keys` is what makes two runs comparable.

    Without it the artifact's byte-identity would depend on pydantic field
    declaration order, so a harmless reordering in `change/schema.py` would read
    as the pipeline having changed its output.
    """
    return json.dumps(data, indent=1, sort_keys=True) + "\n"


def load(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text())
    version = data.get("capture_version")
    if version != CAPTURE_VERSION:
        raise ValueError(
            f"{path} is capture_version {version!r}, this build reads "
            f"{CAPTURE_VERSION}. Re-capture rather than reading it anyway: the "
            "fields a producer needs may not be there.")
    return data


def bundles_for(data: dict, case_id: str) -> list[ContextBundle]:
    """The captured context for one case, back as objects."""
    entry = data["cases"].get(case_id)
    if entry is None:
        raise KeyError(f"{case_id} is not in this capture ({data['corpus']})")
    if "error" in entry:
        raise ValueError(f"{case_id} failed at capture time: {entry['error']}")
    return [ContextBundle.model_validate(b) for b in entry["bundles"]]
