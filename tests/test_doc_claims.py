"""Claims the documents make about the repository, checked against it.

The status docs are the handoff mechanism, not a changelog, which means a
number in them is load-bearing: someone picking this project up reads the
README's count before they run anything, and a count that is quietly one short
teaches them the docs are approximate.

The test count has now gone stale twice — once on 2026-08-24 (written as 797
while the suite finished at 799) and again at `e7615f1`, which added the
total-spend guard and left every document saying 799. Both were found by hand,
late. Errata §14.54.

The rule this enforces is the one §14.53 established for money: **the change and
the number it moves land in the same commit.** A test that adds itself to the
suite without touching the documents is now a red suite, in the same way a paid
run without a recomputed total is.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Every place a document states the size of the suite. Adding a site here is
# cheaper than discovering a fourth one has been drifting for a week.
COUNT_CLAIMS = (
    ("README.md", r"\|\s*\*\*Tests\*\*\s*\|\s*(\d+) passing\s*\|", "the Status table"),
    ("README.md", r"^tests/\s+(\d+) tests$", "the source-tree map"),
    ("BENCHMARK_STATUS.md", r"\*\*(\d+) tests pass\*\*", "§1"),
    ("CONTINUATION.md", r"\|\s*`tests/`\s*\|\s*\d+ files, (\d+) tests", "§3's inventory"),
)


def _collected() -> int:
    """Ask pytest, rather than counting `def test_` by hand.

    A regex over the source would miss parametrization and count commented-out
    definitions, and the number the documents publish is the number a reader
    gets when they run the suite. `--collect-only` imports the test modules but
    runs nothing, so this does not recurse.
    """
    r = subprocess.run([sys.executable, "-m", "pytest", str(ROOT / "tests"),
                        "-q", "--collect-only", "-p", "no:cacheprovider"],
                       capture_output=True, text=True, cwd=ROOT)
    m = re.search(r"(\d+) tests? collected", r.stdout)
    assert m, f"could not read a collection count from pytest:\n{r.stdout[-2000:]}"
    return int(m.group(1))


def test_every_document_that_states_the_test_count_states_the_right_one():
    collected = _collected()
    wrong = []
    for name, pattern, where in COUNT_CLAIMS:
        text = (ROOT / name).read_text()
        m = re.search(pattern, text, re.M)
        assert m, f"{name} no longer states a test count where {where} did"
        if int(m.group(1)) != collected:
            wrong.append(f"  {name} ({where}): says {m.group(1)}")
    assert not wrong, (
        f"the suite collects {collected} tests; these documents disagree:\n"
        + "\n".join(wrong)
        + "\n\nUpdate them in the commit that moved the count, not afterwards "
          "-- afterwards is how §14.54 happened, twice.")


def test_every_document_that_states_the_stored_run_count_states_the_right_one():
    """The same decay, one directory over.

    `benchmark/results/` holds three pre-serialization scorecards with no
    `run.json` beside them, so the count the documents publish is deliberately
    the number of runs whose figures can be re-derived -- which is also exactly
    what `test_the_published_total_spend_still_matches_the_stored_runs` sums.
    Tying the documents to that glob keeps the two definitions from drifting
    apart the way the test count did (§14.54).
    """
    runs = len(list((ROOT / "benchmark/results").glob("*/run.json")))
    claims = (("README.md", r"Three pinned corpora, (\d+) stored runs"),
              ("README.md", r"^  results/\s+(\d+) stored runs"),
              ("CONTINUATION.md", r"\((\d+) stored runs in `benchmark/results/`"))
    wrong = []
    for name, pattern in claims:
        m = re.search(pattern, (ROOT / name).read_text(), re.M)
        assert m, f"{name} no longer states a stored-run count matching {pattern!r}"
        if int(m.group(1)) != runs:
            wrong.append(f"  {name}: says {m.group(1)}")
    assert not wrong, (
        f"benchmark/results/ holds {runs} runs with a run.json; these disagree:\n"
        + "\n".join(wrong))


def test_the_documented_test_file_count_matches_the_directory():
    files = len(list((ROOT / "tests").glob("test_*.py")))
    m = re.search(r"\|\s*`tests/`\s*\|\s*(\d+) files,", (ROOT / "CONTINUATION.md").read_text())
    assert m, "CONTINUATION.md §3 no longer states a test-file count"
    assert int(m.group(1)) == files, (
        f"tests/ holds {files} test files; CONTINUATION.md §3 says {m.group(1)}")
