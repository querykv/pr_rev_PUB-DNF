"""`render_report.py` — the report page's title, eyebrow and <h1>.

All three were literals in the renderer until 2026-08-25, duplicating what
`REPORT.md` already said. That is the shape of the defect errata §14.52 is
about: a claim living in a string in a generator, out of reach of a
documentation sweep, free to drift away from the document it was rendered
from. These tests pin the direction of the dependency — the document decides,
the renderer only reads — and the last one refuses to let the literals back.
"""
import importlib.util
from pathlib import Path

import pytest

# `render_report.py` is a build script at the repository root, not part of the
# `pr_review` package, so there is no import path to it. Loading it by location
# is deliberate: putting the root on `sys.path` would change every other test's
# import environment to reach one file.
_SPEC = importlib.util.spec_from_file_location(
    "render_report", Path(__file__).resolve().parents[1] / "render_report.py")
render_report = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(render_report)

DOC = """---
title: A Title Nobody Hardcoded
eyebrow: An eyebrow · 2026-01-01
---
# The heading the document actually carries

**A standfirst.**

---

## 1. A section

Body text.
"""


@pytest.fixture
def build(tmp_path, monkeypatch):
    """Render a document to a page, with the drift ledger held still.

    `main()` records what it rendered into the real `benchmark/results/.rendered.json`.
    A test that let it do so would rewrite the repository's publication ledger as a
    side effect of running the suite, reporting a page as freshly rendered from a
    document that only ever existed in `tmp_path`.
    """
    from pr_review.benchmark import rendered
    monkeypatch.setattr(rendered, "record", lambda *a, **k: None)
    monkeypatch.setattr(rendered, "check", lambda *a, **k: "")

    def _build(md=DOC):
        src, dst = tmp_path / "REPORT.md", tmp_path / "out.html"
        src.write_text(md)
        render_report.main(str(src), str(dst))
        return dst.read_text()
    return _build


def test_the_tab_title_comes_from_the_document(build):
    assert "<title>A Title Nobody Hardcoded</title>" in build()


def test_the_h1_is_the_documents_own_heading(build):
    """Not a copy of it. Editing `REPORT.md`'s first line changes the page."""
    assert "<h1>The heading the document actually carries</h1>" in build()


def test_the_eyebrow_comes_from_the_document(build):
    assert '<p class="eyebrow">An eyebrow · 2026-01-01</p>' in build()


def test_a_title_carrying_markup_characters_is_escaped_into_the_tab(build):
    page = build(DOC.replace("A Title Nobody Hardcoded", "Pipeline & <Prompt>"))
    assert "<title>Pipeline &amp; &lt;Prompt&gt;</title>" in page


def test_a_document_with_no_front_matter_fails_the_build(build):
    """The tempting fallback — keep the previous title when the block is absent —
    is the defect, not the fix. The page would render, with a title nobody chose,
    and nothing would say so."""
    with pytest.raises(SystemExit, match="front-matter block"):
        build(DOC.split("---\n", 2)[2])


def test_an_unclosed_front_matter_block_fails_the_build(build):
    with pytest.raises(SystemExit, match="no closing"):
        build("---\ntitle: x\neyebrow: y\n# heading\n")


def test_front_matter_missing_a_field_names_the_field(build):
    with pytest.raises(SystemExit, match="missing: eyebrow"):
        build(DOC.replace("eyebrow: An eyebrow · 2026-01-01\n", ""))


def test_a_front_matter_line_that_is_not_key_value_fails_the_build(build):
    with pytest.raises(SystemExit, match="one 'key: value' per line"):
        build(DOC.replace("title: A Title", "title\nA Title"))


def test_nothing_a_reader_sees_is_written_in_the_renderer():
    """The guard the other eight exist to support.

    Every string above could pass while `render_report.py` also carried a
    literal copy of the live report's title — which is exactly the state this
    step replaced. So: take what `REPORT.md` publishes today, and require that
    none of it appears in the generator.
    """
    root = Path(__file__).resolve().parents[1]
    src = (root / "render_report.py").read_text()
    lines = (root / "REPORT.md").read_text().split("\n")
    fields, start = render_report.front_matter(lines)
    heading = next(l for l in lines[start:] if l.startswith("# "))[2:].strip()

    for what, text in (("title", fields["title"]),
                       ("eyebrow", fields["eyebrow"]),
                       ("h1", heading)):
        assert text not in src, (
            f"render_report.py contains the live report's {what} as a literal: "
            f"{text!r}. It is REPORT.md's to decide; a copy here can disagree "
            "with the document and nothing would report it (errata §14.52).")
