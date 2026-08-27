"""Dependency-delta extraction (phase-0 §3.4) — the Phase-2 prerequisite.

The tier-1 noise filter drops lockfile churn *because* a `DepDelta` records it.
Before this module existed `manifest.dep_deltas` was always `[]`, so the rule
dropped lockfiles with nothing capturing what changed in them. These tests hold
that link: if the parsers stop producing deltas, `test_change_filter.py`'s
lockfile drop stops firing too.
"""
import pytest

from pr_review.extract.deps import (
    _parse_toml_lock,
    dep_delta_for,
    extract_dep_deltas,
    is_lockfile_format,
)
from pr_review.extract.diff import parse_unified_diff
from pr_review.extract.manifest import build_manifest


def _one(path: str, body: str):
    """Parse a single-file diff whose hunk body is given verbatim."""
    diff = (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n+++ b/{path}\n"
        f"@@ -1,9 +1,9 @@\n{body}"
    )
    return parse_unified_diff(diff)[0]


# --------------------------------------------------------------------------
# The diff algebra
# --------------------------------------------------------------------------

def test_version_bump_is_a_change_not_an_add_and_a_remove():
    delta = dep_delta_for(_one("requirements.txt",
                               " flask==3.0.0\n-requests==2.28.1\n+requests==2.31.0\n"))
    assert delta.changed == {"requests": ("2.28.1", "2.31.0")}
    assert delta.added == {} and delta.removed == []


def test_added_and_removed_packages():
    delta = dep_delta_for(_one("requirements.txt",
                               " flask==3.0.0\n-oldpkg==1.0\n+newpkg==2.0\n"))
    assert delta.added == {"newpkg": "2.0"}
    assert delta.removed == ["oldpkg"]


def test_context_lines_cancel_out():
    """Unchanged dependencies appear on both sides and must not surface."""
    delta = dep_delta_for(_one("requirements.txt",
                               " flask==3.0.0\n pyyaml==6.0\n+newpkg==2.0\n"))
    assert set(delta.added) == {"newpkg"}
    assert "flask" not in delta.added and "flask" not in delta.removed


def test_pypi_names_are_pep503_normalized():
    """`Flask_Login` and `flask-login` are one project; a respelling is not a
    remove plus an add."""
    delta = dep_delta_for(_one("requirements.txt",
                               "-Flask_Login==0.6.0\n+flask-login==0.6.0\n"))
    assert delta is None


def test_a_file_with_no_dependency_change_yields_no_delta():
    assert dep_delta_for(_one("requirements.txt", " flask==3.0.0\n")) is None


def test_non_dependency_files_are_ignored():
    assert dep_delta_for(_one("app.py", "+import os\n")) is None


# --------------------------------------------------------------------------
# Per-ecosystem parsers
# --------------------------------------------------------------------------

def test_poetry_lock_version_bump_uses_the_context_name_line():
    """The commonest lockfile change in the ecosystem: only `version =` moves,
    and the `name =` line that says which package it is arrives as context."""
    delta = dep_delta_for(_one("poetry.lock",
                               " [[package]]\n name = \"requests\"\n"
                               "-version = \"2.28.1\"\n+version = \"2.31.0\"\n"
                               " description = \"HTTP for Humans.\"\n"))
    assert delta.changed == {"requests": ("2.28.1", "2.31.0")}


def test_package_json_skips_values_that_are_not_versions():
    """A line-level view cannot see which object it is in, so the value shape is
    the discriminator — otherwise `"build": "tsc"` reads as a dependency."""
    delta = dep_delta_for(_one("package.json",
                               '-    "build": "tsc",\n'
                               '+    "build": "tsc --strict",\n'
                               '+    "left-pad": "^1.3.0",\n'))
    assert delta.added == {"left-pad": "^1.3.0"}
    assert "build" not in delta.added


def test_package_lock_reads_node_modules_blocks():
    delta = dep_delta_for(_one("package-lock.json",
                               '     "node_modules/lodash": {\n'
                               '-      "version": "4.17.20",\n'
                               '+      "version": "4.17.21",\n'))
    assert delta.changed == {"lodash": ("4.17.20", "4.17.21")}


def test_yarn_lock_strips_the_range_from_the_descriptor():
    delta = dep_delta_for(_one("yarn.lock",
                               '"@babel/core@^7.0.0":\n'
                               '-  version "7.1.0"\n'
                               '+  version "7.24.0"\n'))
    assert delta.changed == {"@babel/core": ("7.1.0", "7.24.0")}


def test_go_mod_require_lines():
    delta = dep_delta_for(_one("go.mod",
                               "-	github.com/gin-gonic/gin v1.7.0\n"
                               "+	github.com/gin-gonic/gin v1.9.1\n"))
    assert delta.ecosystem == "go"
    assert delta.changed == {"github.com/gin-gonic/gin": ("v1.7.0", "v1.9.1")}


def test_go_sum_collapses_the_go_mod_variant():
    delta = dep_delta_for(_one("go.sum",
                               "-github.com/x/y v1.2.3 h1:abc=\n"
                               "-github.com/x/y v1.2.3/go.mod h1:def=\n"
                               "+github.com/x/y v1.3.0 h1:ghi=\n"
                               "+github.com/x/y v1.3.0/go.mod h1:jkl=\n"))
    assert delta.changed == {"github.com/x/y": ("v1.2.3", "v1.3.0")}


# --------------------------------------------------------------------------
# The four `[[package]]` lockfiles, and the three ways they can be misread
# --------------------------------------------------------------------------

def test_uv_lock_version_bump():
    delta = dep_delta_for(_one("uv.lock",
                               " [[package]]\n name = \"requests\"\n"
                               "-version = \"2.28.1\"\n+version = \"2.31.0\"\n"
                               ' source = { registry = "https://pypi.org/simple" }\n'))
    assert delta.ecosystem == "pypi"
    assert delta.changed == {"requests": ("2.28.1", "2.31.0")}


def test_a_uv_inline_dependency_entry_does_not_become_the_package_name():
    """uv writes a package's own dependencies as inline tables, `{ name = "x" }`.

    Asserted on the parser rather than through `dep_delta_for`, deliberately.
    The end-to-end version of this test passes with the guard removed — uv puts
    `dependencies` *after* `version`, so a stale name is overwritten by the next
    package's `name =` line before it can be claimed — and a test that cannot
    fail is not evidence (errata §14.29). What the guard actually holds is the
    state invariant, so that is what is checked.
    """
    state = {"name": "requests"}
    assert _parse_toml_lock('    { name = "urllib3", specifier = ">=2.0" },',
                            state) is None
    assert state["name"] == "requests", "an inline entry captured the package name"


def test_a_lockfile_schema_version_is_not_a_package_version():
    """`version = 1` heads a uv.lock and `version = 3` a Cargo.lock. Unquoted is
    the whole of what keeps them out.

    At the parser again, and for the same reason: both headers sit above the
    first `[[package]]`, so end-to-end there is never a name in state for them
    to attach to and the assertion would hold either way.
    """
    for header in ("version = 1", "version = 3"):
        state = {"name": "requests"}
        assert _parse_toml_lock(header, state) is None
        assert state["name"] == "requests"


def test_pdm_lock_metadata_is_not_a_package():
    delta = dep_delta_for(_one("pdm.lock",
                               " [metadata]\n"
                               '-lock_version = "4.4.1"\n+lock_version = "4.5.0"\n'
                               '-content_hash = "sha256:aaa"\n'
                               '+content_hash = "sha256:bbb"\n'))
    assert delta is None


def test_cargo_lock_is_a_crates_io_delta_whatever_its_case():
    """The file ships capitalized and the matcher is lowercase."""
    delta = dep_delta_for(_one("Cargo.lock",
                               " [[package]]\n name = \"time\"\n"
                               "-version = \"0.1.44\"\n+version = \"0.3.36\"\n"
                               ' source = "registry+https://github.com/rust-lang/'
                               'crates.io-index"\n'))
    assert delta.ecosystem == "crates.io"
    assert delta.changed == {"time": ("0.1.44", "0.3.36")}


def test_pep503_normalization_stays_inside_pypi():
    """`serde_json` and `serde-json` are two different crates. The Python rule
    that makes `Flask_Login` and `flask-login` one project is a Python rule."""
    delta = dep_delta_for(_one("Cargo.lock",
                               " [[package]]\n name = \"serde_json\"\n"
                               "-version = \"1.0.1\"\n+version = \"1.0.2\"\n"))
    assert delta.changed == {"serde_json": ("1.0.1", "1.0.2")}


# --------------------------------------------------------------------------
# composer.lock and Gemfile.lock — neither shape is shared with anything else
# --------------------------------------------------------------------------

def test_composer_lock_version_bump():
    delta = dep_delta_for(_one("composer.lock",
                               '             "name": "monolog/monolog",\n'
                               '-            "version": "1.25.0",\n'
                               '+            "version": "2.9.1",\n'))
    assert delta.ecosystem == "packagist"
    assert delta.changed == {"monolog/monolog": ("1.25.0", "2.9.1")}


def test_composer_author_names_are_not_package_names():
    """Every package entry carries an `authors` array whose entries also have a
    `"name"`. In the whole file the ordering saves you — authors come after the
    version key — but a diff shows hunks, and a hunk can start anywhere. The
    value shape is what actually decides it."""
    delta = dep_delta_for(_one("composer.lock",
                               '             "authors": [\n'
                               "                 {\n"
                               '                     "name": "Jordi Boggiano",\n'
                               '                     "email": "j@seld.be"\n'
                               "                 }\n"
                               "             ],\n"
                               '-            "version": "1.25.0",\n'
                               '+            "version": "2.9.1",\n'))
    assert delta is None


def test_gemfile_lock_reads_resolved_gems_not_their_requirements():
    """Three indents mean three different things, and only the middle one is a
    package: `DEPENDENCIES` at two, resolved gems at four, each gem's own
    requirements at six."""
    delta = dep_delta_for(_one("Gemfile.lock",
                               "   specs:\n"
                               "-    rack (2.0.6)\n"
                               "+    rack (2.2.8)\n"
                               "     actionpack (5.2.0)\n"
                               "       rack (~> 2.0)\n"))
    assert delta.ecosystem == "rubygems"
    assert delta.changed == {"rack": ("2.0.6", "2.2.8")}
    assert delta.added == {} and delta.removed == []


def test_gemfile_lock_dependencies_section_is_not_the_resolved_set():
    """`DEPENDENCIES` restates what the Gemfile asked for. Reading it would
    report a requirement — `(~> 7.0.4)` — as though it were a version."""
    delta = dep_delta_for(_one("Gemfile.lock",
                               " DEPENDENCIES\n"
                               "-  rails (~> 5.2.0)\n"
                               "+  rails (~> 7.0.4)\n"))
    assert delta is None


def test_a_relaxed_gem_requirement_is_not_a_resolved_version():
    """The case that isolates the operator test. Widening a gem's own
    requirement moves no resolved version, and a lockfile whose only change is
    this one has no dependency delta at all — it is exactly the churn the
    tier-1 filter is entitled to drop.
    """
    delta = dep_delta_for(_one("Gemfile.lock",
                               "     actionpack (5.2.0)\n"
                               "-      rack (~> 2.0)\n"
                               "+      rack (~> 2.2)\n"))
    assert delta is None


def test_pyproject_pep621_array_entries():
    delta = dep_delta_for(_one("pyproject.toml",
                               " dependencies = [\n"
                               '-    "requests>=2.28",\n'
                               '+    "requests>=2.31",\n'
                               " ]\n"))
    assert "requests" in delta.changed


def test_pyproject_metadata_is_not_a_dependency():
    """`version = "0.0.2"` under `[project]` is the project's own version."""
    delta = dep_delta_for(_one("pyproject.toml",
                               " [project]\n name = \"pr-review\"\n"
                               '-version = "0.0.1"\n+version = "0.0.2"\n'))
    assert delta is None


# --------------------------------------------------------------------------
# The lockfile / manifest distinction the filter depends on
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path,lock", [
    ("poetry.lock", True), ("package-lock.json", True), ("yarn.lock", True),
    ("go.sum", True), ("Pipfile.lock", True),
    ("uv.lock", True), ("pdm.lock", True), ("Cargo.lock", True),
    ("composer.lock", True), ("Gemfile.lock", True),
    ("requirements.txt", False), ("pyproject.toml", False),
    ("package.json", False), ("go.mod", False), ("app.py", False),
    # Rust, PHP and Ruby are lockfile-only here, so their manifests are not
    # dependency files to this module at all — which reads as False by a
    # different route than `pyproject.toml` does, and lands in the same
    # never-dropped place.
    ("Cargo.toml", False), ("composer.json", False), ("Gemfile", False),
])
def test_only_lockfiles_are_summarizable(path, lock):
    """§3 permits dropping *lockfile* churn. A manifest is where a human writes
    a dependency and is a profile anchor, so it is never droppable."""
    assert is_lockfile_format(path) is lock


# --------------------------------------------------------------------------
# One source of truth for "is this a lockfile" (OPEN_ITEMS.md §5)
# --------------------------------------------------------------------------

def test_classify_derives_its_lockfile_names_from_this_module():
    """§5. `classify` used to keep its own five names and catch the rest with an
    `.endswith(".lock")` rule. The two lists agreed by accident, and the accident
    had a known expiry: a format ending in `.json` -- `package-lock.json` already
    does -- would be parsed here and unrecognised there."""
    from pr_review.extract import classify, deps

    assert classify._LOCKFILES == deps.lockfile_names()
    assert classify._DEP_MANIFESTS == deps.manifest_names()
    assert not (deps.lockfile_names() & deps.manifest_names())


def test_a_new_json_suffixed_lockfile_is_recognised_without_a_second_edit():
    """The failure §5 predicted, made concrete. Adding a format to `_FORMATS`
    must be enough; if this test needs a second edit somewhere else to pass,
    the two sources of truth are back.

    `filter._lockfile_captured` is the consumer that would silently stop firing
    -- a `DepDelta` with no drop -- which is why this is worth a test rather
    than a comment."""
    from pr_review.extract import classify, deps

    fake = ("bun-lock.json", "npm", "npm_lock")
    assert not classify.is_lockfile(fake[0]), "precondition: not known yet"
    deps._FORMATS.append(fake)
    try:
        # Re-derive exactly as import time does.
        assert fake[0] in deps.lockfile_names()
        assert deps.lockfile_names() != classify._LOCKFILES, (
            "module-level derivation is a snapshot; the point of this test is "
            "that the SOURCE moved, and re-importing classify would pick it up")
        import importlib
        importlib.reload(classify)
        assert classify.is_lockfile(fake[0]), (
            "a format added to deps._FORMATS is still not a lockfile to "
            "classify -- the second source of truth is back")
    finally:
        deps._FORMATS.remove(fake)
        import importlib
        importlib.reload(classify)
    assert not classify.is_lockfile(fake[0])


# --------------------------------------------------------------------------
# Wiring
# --------------------------------------------------------------------------

def test_manifest_populates_dep_deltas():
    manifest, _ = build_manifest(
        repo="o/r", pr_number=1,
        diff_text=open("tests/fixtures/phase2_pr.diff").read(),
    )
    by_manifest = {d.manifest: d for d in manifest.dep_deltas}
    assert set(by_manifest) == {"poetry.lock", "requirements.txt"}
    assert by_manifest["poetry.lock"].changed == {"requests": ("2.28.1", "2.31.0")}


def test_deltas_are_ordered_by_path():
    parsed = parse_unified_diff(open("tests/fixtures/phase2_pr.diff").read())
    paths = [d.manifest for d in extract_dep_deltas(parsed)]
    assert paths == sorted(paths)


def test_removed_line_text_is_retained_by_the_parser():
    """The whole module rests on this: M0 kept only removed line *numbers*."""
    pf = _one("requirements.txt", "-oldpkg==1.0\n+newpkg==2.0\n")
    assert [r.text for r in pf.hunks[0].removed] == ["oldpkg==1.0"]
    assert pf.hunks[0].removed_linenos == [1]


def test_hunk_sides_reconstruct_both_versions():
    pf = _one("requirements.txt", " keep==1\n-old==1\n+new==2\n")
    assert pf.hunks[0].side("old") == ["keep==1", "old==1"]
    assert pf.hunks[0].side("new") == ["keep==1", "new==2"]
