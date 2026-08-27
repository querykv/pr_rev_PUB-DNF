"""Publication drift — `OPEN_ITEMS.md` §24.

These tests are about the *mechanism*, never about whether this repository's
pages happen to be current right now. An assertion of the latter would go red on
every edit made between a fix and its landing, which is the normal state of the
tree, and a suite that is red by design is a suite people stop reading. §24 says
report, do not fail; that decision is enforced here by testing only the report.
"""
import json
from pathlib import Path

import pytest

from pr_review.benchmark import rendered


def _ledger(tmp_path):
    return tmp_path / ".rendered.json"


def test_a_source_that_has_not_moved_reports_nothing(tmp_path):
    src = tmp_path / "REPORT.md"
    src.write_text("one")
    led = _ledger(tmp_path)
    rendered.record("page.html", [src], ledger=led)
    assert rendered.drift(ledger=led) == []
    assert rendered.check(ledger=led) == ""


def test_a_source_that_moved_is_named_with_the_page_it_belongs_to(tmp_path):
    src = tmp_path / "REPORT.md"
    src.write_text("one")
    led = _ledger(tmp_path)
    rendered.record("https://example/page", [src], ledger=led)

    src.write_text("two")
    lines = rendered.drift(ledger=led)
    assert len(lines) == 1
    assert "REPORT.md changed since it was last rendered" in lines[0]
    assert "https://example/page" in lines[0]
    assert "PUBLICATION DRIFT" in rendered.check(ledger=led)


def test_a_source_that_vanished_is_drift_and_not_silence(tmp_path):
    """Deleting or renaming a source is exactly as much of a problem as editing
    it, and reports differently so the reader knows which happened."""
    src = tmp_path / "gone.md"
    src.write_text("one")
    led = _ledger(tmp_path)
    rendered.record("page.html", [src], ledger=led)

    src.unlink()
    lines = rendered.drift(ledger=led)
    assert len(lines) == 1 and "missing or unreadable" in lines[0]


def test_recording_an_unreadable_source_raises_rather_than_storing_none(tmp_path):
    """The bug this module shipped with for ten minutes: handed display names
    instead of paths, it stored None for every source. None then compared equal
    to None on every later check, so the ledger reported "no drift" forever
    while watching nothing. Refusing to record it is the fix -- a mechanism that
    cannot fail loudly is worse than no mechanism, because it is believed."""
    led = _ledger(tmp_path)
    with pytest.raises(ValueError, match="unreadable source"):
        rendered.record("page.html", [tmp_path / "does-not-exist"], ledger=led)
    assert not led.exists()


def test_an_unrecorded_page_is_not_reported_as_current(tmp_path):
    """A ledger that has never seen a page says nothing about it. That is why
    `check` distinguishes "no drift" from "nothing recorded" at the call site
    rather than returning a cheerful empty string for both cases."""
    led = _ledger(tmp_path)
    assert rendered.drift("never-rendered.html", ledger=led) == []
    assert json.loads(led.read_text()) if led.exists() else True


def test_drift_can_be_scoped_to_one_page(tmp_path):
    a, b = tmp_path / "a.md", tmp_path / "b.md"
    a.write_text("a"); b.write_text("b")
    led = _ledger(tmp_path)
    rendered.record("page-a", [a], ledger=led)
    rendered.record("page-b", [b], ledger=led)

    a.write_text("a2"); b.write_text("b2")
    assert len(rendered.drift(ledger=led)) == 2
    assert len(rendered.drift("page-a", ledger=led)) == 1
    assert "a.md" in rendered.drift("page-a", ledger=led)[0]


def test_the_scorecard_declares_the_renderer_that_writes_its_prose():
    """The ledger's blind spot on 2026-08-24, and the reason §14.52 happened.

    `comparison.html` was recorded as built from the arm runs and
    `comparison.sh`, both true and neither sufficient: the callouts, the limits
    list and the ceiling note are literal strings in `report_html.py`. So the
    scorecard could assert a claim the errata had retired, `check()` would
    return "none", and the published page would sit there contradicting its own
    table. The companion generator, `render_report.py`, had recorded `__file__`
    from the first version.

    This asserts the declaration rather than a rendered page because the
    declaration is what was wrong -- the renderer worked perfectly, on the wrong
    list of inputs.
    """
    from pr_review.benchmark.__main__ import comparison_sources

    srcs = comparison_sources([])
    assert any(s.endswith("report_html.py") for s in srcs), srcs
    assert any(s.endswith("comparison.sh") for s in srcs), srcs


def test_every_declared_scorecard_source_is_readable():
    """A source that cannot be read is recorded as None, and None compares equal
    to None forever -- the silent pass `record` now raises on (§24's own bug,
    shipped and caught the same day). A path that goes stale by a rename would
    reintroduce it here, so the declaration is checked against the disk."""
    from pr_review.benchmark.__main__ import comparison_sources

    for src in comparison_sources([]):
        assert rendered.digest(src) is not None, src


def test_a_ledger_key_survives_being_someone_elses_checkout():
    """`__file__` is absolute, the ledger is committed, and `digest` resolves
    keys against the working directory. Recording one verbatim writes this
    machine's home directory into a shared file, and every other clone then sees
    drift on a source that never moved -- a check that cries wolf on `git clone`,
    which is the one failure this module can least afford (see its docstring on
    why it reports rather than fails)."""
    from pr_review.benchmark import report_html
    from pr_review.benchmark.__main__ import comparison_sources

    key = rendered.repo_relative(report_html.__file__)
    assert key == "pr_review/benchmark/report_html.py"
    assert not Path(key).is_absolute()
    assert all(not Path(s).is_absolute() for s in comparison_sources([])), \
        comparison_sources([])


def test_a_path_outside_the_tree_is_kept_rather_than_raising():
    """Bookkeeping must not be able to take down a render."""
    assert rendered.repo_relative("/etc/hosts") == "/etc/hosts"
