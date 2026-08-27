"""Dependency deltas from a diff (phase-0-extraction.md §3.4).

Turns manifest and lockfile hunks into `DepDelta` records: what was added,
removed, or version-bumped, per ecosystem.

WHY THIS LANDS WITH PHASE 2
The tier-1 noise filter drops "lockfile churn already captured as a `DepDelta`"
(phase-2 §3). Until now `manifest.dep_deltas` was always empty, so that rule
would have dropped lockfiles with *nothing* recording what changed in them — a
silent recall leak in the stage the plan names the pipeline's #1 false-negative
risk. `filter.py` therefore only honours the drop when this module actually
produced a delta for that path.

PARSING APPROACH AND ITS LIMITS
Everything here is line-oriented, reading the diff rather than the file. That is
deliberate: it needs no checkout and no ecosystem toolchain, and it works on a
PR from a fork. The cost is that structure invisible in a single line is
invisible here — a `pyproject.toml` dependency moved between `[project]` and
`[tool.poetry.group.dev]` reads as a plain add/remove, and a `package.json`
value that is not semver-shaped is skipped rather than guessed at.

That inaccuracy is bounded to *which bucket* a package lands in, never to
whether the file was examined at all. Manifests (`pyproject.toml`,
`package.json`, `requirements.txt`) are never dropped by the filter regardless
of what this produces — they are profile anchors and the place a human actually
edits a dependency. Only lockfiles, whose churn is machine-generated and fully
described by name+version, are droppable.

WHAT IS COVERED, AND WHERE IT STOPS
Python, npm and Go have both their manifests and their lockfiles here. Rust,
PHP and Ruby have **only** their lockfiles — no `Cargo.toml`, `composer.json`
or `Gemfile`. That is deliberate rather than unfinished: SCA is the consumer,
osv-scanner matches advisories against resolved versions and rejects manifests
outright (`detect/sca.py:_OSV_LOCKFILES`), and a manifest this module does not
recognize is simply reviewed as an ordinary file — the safe direction. Adding
one buys nothing until something reads declared ranges.

Version *resolution* (is the new version vulnerable?) is Phase 3a's SCA job.
This module reports the delta; it does not judge it.
"""
from __future__ import annotations

import re
from posixpath import basename

from pr_review.extract.diff import ParsedFile
from pr_review.extract.schema import DepDelta

# ---------------------------------------------------------------------------
# Which file is which ecosystem
# ---------------------------------------------------------------------------

# (matcher, ecosystem, format) — format selects the line parser below.
#
# Ecosystem strings are OSV's own, lowercased, so a reader can take one to
# https://osv.dev and get the right index. Four of the lockfiles below share
# `toml_lock`: poetry, uv, pdm and Cargo all write `[[package]]` blocks whose
# first two keys are `name` and `version`, which is the whole of what this
# module reads. They are one parser because they are one format, not because
# one was made to stand in for the others.
_FORMATS: list[tuple[str, str, str]] = [
    ("poetry.lock", "pypi", "toml_lock"),
    ("uv.lock", "pypi", "toml_lock"),
    ("pdm.lock", "pypi", "toml_lock"),
    ("pipfile.lock", "pypi", "pipfile_lock"),
    ("pipfile", "pypi", "toml_pairs"),
    ("pyproject.toml", "pypi", "pyproject"),
    ("setup.py", "pypi", "requirements"),
    ("setup.cfg", "pypi", "requirements"),
    ("package-lock.json", "npm", "npm_lock"),
    ("yarn.lock", "npm", "yarn_lock"),
    ("package.json", "npm", "package_json"),
    ("go.mod", "go", "go_mod"),
    ("go.sum", "go", "go_sum"),
    ("cargo.lock", "crates.io", "toml_lock"),
    ("composer.lock", "packagist", "composer_lock"),
    ("gemfile.lock", "rubygems", "gemfile_lock"),
]

_REQUIREMENTS_RE = re.compile(r"requirements.*\.txt$|constraints.*\.txt$")

# A lockfile is fully described by name+version, so its churn is safely
# summarizable. A manifest is not — see the module docstring.
LOCKFILE_FORMATS = {"toml_lock", "pipfile_lock", "npm_lock", "yarn_lock", "go_sum",
                    "composer_lock", "gemfile_lock"}


def lockfile_names() -> frozenset[str]:
    """Every filename this module parses as a LOCKFILE, lowercase.

    Exported so `extract/classify.py` can derive `is_lockfile` from here instead
    of keeping a second list (`OPEN_ITEMS.md` §5). The two lists agreed only by
    accident: `classify` named five and caught the rest with an `.endswith(
    ".lock")` rule that happens to cover `uv.lock`, `pdm.lock`, `Cargo.lock`,
    `composer.lock` and `Gemfile.lock`. The next format ending in `.json` --
    `package-lock.json` already does -- would be parsed here and unrecognised
    there, and `filter._lockfile_captured` would never fire for it: a `DepDelta`
    with no drop, silently.
    """
    return frozenset(name for name, _eco, fmt in _FORMATS
                     if fmt in LOCKFILE_FORMATS)


def manifest_names() -> frozenset[str]:
    """The mirror of `lockfile_names` for dependency manifests."""
    return frozenset(name for name, _eco, fmt in _FORMATS
                     if fmt not in LOCKFILE_FORMATS)


def _format_of(path: str) -> tuple[str, str] | None:
    """(ecosystem, format) for a dependency file, else None."""
    name = basename(path).lower()
    for match, ecosystem, fmt in _FORMATS:
        if name == match:
            return ecosystem, fmt
    if _REQUIREMENTS_RE.match(name):
        return "pypi", "requirements"
    return None


def is_lockfile_format(path: str) -> bool:
    fmt = _format_of(path)
    return bool(fmt and fmt[1] in LOCKFILE_FORMATS)


# ---------------------------------------------------------------------------
# Name normalization
# ---------------------------------------------------------------------------

def _normalize(name: str, ecosystem: str) -> str:
    name = name.strip().strip("\"',")
    if ecosystem == "pypi":
        # PEP 503: `Flask_Login` and `flask-login` are the same project, and a
        # diff that rewrites the spelling would otherwise read as remove+add.
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


# ---------------------------------------------------------------------------
# Single-line parsers -> (name, version) | None
# ---------------------------------------------------------------------------

_PEP508_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*"      # name
    r"(?:\[[^\]]*\])?\s*"                        # optional extras
    r"(?:([=<>!~^]{1,2}=?)\s*([^\s;,#\]\"']+))?"  # optional first specifier
)
_SKIP_REQ_PREFIXES = ("-", "#", "git+", "http://", "https://", "./", "/", "file:")

# Keys that are metadata, not dependencies, in TOML `key = "value"` form.
_TOML_NON_DEPS = {
    "name", "version", "description", "readme", "license", "authors",
    "requires-python", "python", "homepage", "repository", "documentation",
    "build-backend", "package-mode", "content-hash", "lock-version",
}

_TOML_PAIR_RE = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*[\{"]?([^",\}]*)')
_JSON_PAIR_RE = re.compile(r'^\s*"([^"]+)"\s*:\s*"([^"]*)"')
_SEMVERISH_RE = re.compile(r'^(?:[\^~><=v]*\d|\*$|latest$|next$|'
                           r'(?:npm|git|github|file|link|workspace|portal):)')
_GO_REQUIRE_RE = re.compile(r"^\s*(?:require\s+)?([\w.\-]+(?:\.[\w.\-]+)*/[\w.\-/~]+)"
                            r"\s+(v[\w.\-+]+)")


def _parse_requirements(line: str, _state: dict) -> tuple[str, str] | None:
    text = line.split("#", 1)[0].strip()
    if not text or text.startswith(_SKIP_REQ_PREFIXES):
        return None
    m = _PEP508_RE.match(text)
    if not m:
        return None
    return m.group(1), (m.group(3) or "")


def _parse_pyproject(line: str, state: dict) -> tuple[str, str] | None:
    text = line.strip()
    if text.startswith("["):                       # a table header: remember it
        state["table"] = text.strip("[]").lower()
        return None
    if text.startswith('"') or text.startswith("'"):
        # PEP 621 array entry: `"flask>=2.0",`
        inner = text.strip().strip(",").strip("\"'")
        return _parse_requirements(inner, state)
    if "dependencies" in state.get("table", ""):
        return _parse_toml_pair(line, state)
    return None


def _parse_toml_pair(line: str, _state: dict) -> tuple[str, str] | None:
    """Poetry/Pipfile style: `flask = "^2.0"` or `flask = {version = "^2.0"}`."""
    m = _TOML_PAIR_RE.match(line)
    if not m or m.group(1).lower() in _TOML_NON_DEPS:
        return None
    return m.group(1), m.group(2).strip()


def _parse_package_json(line: str, _state: dict) -> tuple[str, str] | None:
    """`"flask": "^2.0.1"`, but not `"build": "tsc"`.

    A line-level view cannot see which object it is inside, so the value shape
    is the discriminator: dependency values are semver ranges or a scheme-
    prefixed locator. Scripts, `"name"` and `"license"` fail that test.
    """
    m = _JSON_PAIR_RE.match(line)
    if not m:
        return None
    name, value = m.group(1), m.group(2)
    if name.lower() in _TOML_NON_DEPS or not _SEMVERISH_RE.match(value):
        return None
    return name, value


def _parse_go_mod(line: str, _state: dict) -> tuple[str, str] | None:
    text = line.split("//", 1)[0]
    m = _GO_REQUIRE_RE.match(text)
    return (m.group(1), m.group(2)) if m else None


def _parse_go_sum(line: str, _state: dict) -> tuple[str, str] | None:
    parts = line.split()
    if len(parts) < 2 or not parts[1].startswith("v"):
        return None
    # `x v1.2.3` and `x v1.2.3/go.mod` are the same package at the same version.
    return parts[0], parts[1].removesuffix("/go.mod")


# ---------------------------------------------------------------------------
# Block-scanning parsers — the entry spans several lines
# ---------------------------------------------------------------------------

def _parse_toml_lock(line: str, state: dict) -> tuple[str, str] | None:
    """`name = "x"` then `version = "y"`, a few lines apart.

    poetry.lock, uv.lock, pdm.lock and Cargo.lock, which agree on this much.

    Two things keep the match narrow enough to share. Both keys are anchored at
    the start of the line, which is what excludes uv's inline dependency
    entries — `{ name = "x", marker = ... }` inside a `dependencies = [...]`
    array — and pdm's `lock_version`, a different key that ends in the one we
    want. And both require a *quoted* value, which is what excludes the
    file-format header every one of these files opens with: `version = 1` in
    uv.lock, `version = 3` in Cargo.lock.
    """
    m = re.match(r'^\s*name\s*=\s*"([^"]+)"', line)
    if m:
        state["name"] = m.group(1)
        return None
    m = re.match(r'^\s*version\s*=\s*"([^"]+)"', line)
    if m and state.get("name"):
        return state.pop("name"), m.group(1)
    return None


def _parse_pipfile_lock(line: str, state: dict) -> tuple[str, str] | None:
    """`"flask": {` then `"version": "==2.0.1"`."""
    m = re.match(r'^\s*"([^"]+)"\s*:\s*\{\s*$', line)
    if m:
        state["name"] = m.group(1)
        return None
    m = re.match(r'^\s*"version"\s*:\s*"([^"]*)"', line)
    if m and state.get("name"):
        return state.pop("name"), m.group(1).lstrip("=")
    return None


def _parse_npm_lock(line: str, state: dict) -> tuple[str, str] | None:
    """v2/v3 `"node_modules/x": {`, or v1 `"x": {`, then `"version": "y"`."""
    m = re.match(r'^\s*"([^"]+)"\s*:\s*\{', line)
    if m:
        key = m.group(1)
        if key in ("dependencies", "packages", "devDependencies", "peerDependencies"):
            return None
        state["name"] = key.rsplit("node_modules/", 1)[-1]
        return None
    m = re.match(r'^\s*"version"\s*:\s*"([^"]*)"', line)
    if m and state.get("name"):
        return state.pop("name"), m.group(1)
    return None


def _parse_yarn_lock(line: str, state: dict) -> tuple[str, str] | None:
    """`"@babel/core@^7.0.0":` then `  version "7.1.0"`."""
    if line and not line[0].isspace() and line.rstrip().endswith(":"):
        descriptor = line.rstrip().rstrip(":").split(",")[0].strip().strip("\"'")
        # Strip the range, keeping a leading @ for scoped packages.
        at = descriptor.rfind("@")
        state["name"] = descriptor[:at] if at > 0 else descriptor
        return None
    m = re.match(r'^\s*version\s*[:"]?\s*"?([^"\s]+)"?', line)
    if m and state.get("name"):
        return state.pop("name"), m.group(1)
    return None


_COMPOSER_NAME_RE = re.compile(
    r'^\s*"name"\s*:\s*"([A-Za-z0-9][\w.-]*/[A-Za-z0-9][\w.-]*)"')


def _parse_composer_lock(line: str, state: dict) -> tuple[str, str] | None:
    """`"name": "vendor/package"` then `"version": "1.25.0"`.

    `"name"` is not unique in this file — every entry in a package's
    `authors` array has one too. The discriminator is the value: a Packagist
    name is always `vendor/package` with no whitespace, which "Jordi Boggiano"
    is not. Ordering alone would nearly do it (authors come after the version
    key, so the next real `"name"` overwrites the stale one before any
    `"version"` arrives) but a diff shows hunks, not files, and a hunk can
    start anywhere.
    """
    m = _COMPOSER_NAME_RE.match(line)
    if m:
        state["name"] = m.group(1)
        return None
    m = re.match(r'^\s*"version"\s*:\s*"([^"]*)"', line)
    if m and state.get("name"):
        return state.pop("name"), m.group(1)
    return None


_GEMFILE_SPEC_RE = re.compile(r"^ {4,}([A-Za-z0-9][\w.-]*) \(([^)]+)\)\s*$")


def _parse_gemfile_lock(line: str, _state: dict) -> tuple[str, str] | None:
    """`    rack (2.0.6)` — a resolved gem under `specs:`.

    The only single-line parser here, because Bundler puts the version on the
    same line as the name. What it must *not* read is the other two places a
    `name (something)` line appears, and both are excluded by the same test:

        GEM
          specs:
            actionpack (5.2.0)          <- 4 spaces, a bare version: a package
              activesupport (= 5.2.0)   <- 6 spaces, a requirement
        DEPENDENCIES
          actionpack (~> 5.2.0)         <- 2 spaces, a requirement

    Requirements always carry an operator, and that is the test doing the work
    — a nested requirement is *more* indented than a package, so indent alone
    would not separate them. The four-space floor is the format's structure
    rather than a second discriminator, and on Bundler's real output it rejects
    nothing the digit test does not already reject. It is kept because it is
    the shape of the file, and stated here because a guard no test can falsify
    should not be left looking load-bearing (errata §14.29).
    """
    m = _GEMFILE_SPEC_RE.match(line)
    if not m or not m.group(2)[:1].isdigit():
        return None
    return m.group(1), m.group(2)


_PARSERS = {
    "requirements": _parse_requirements,
    "pyproject": _parse_pyproject,
    "toml_pairs": _parse_toml_pair,
    "package_json": _parse_package_json,
    "go_mod": _parse_go_mod,
    "go_sum": _parse_go_sum,
    "toml_lock": _parse_toml_lock,
    "pipfile_lock": _parse_pipfile_lock,
    "npm_lock": _parse_npm_lock,
    "yarn_lock": _parse_yarn_lock,
    "composer_lock": _parse_composer_lock,
    "gemfile_lock": _parse_gemfile_lock,
}


# ---------------------------------------------------------------------------
# The delta
# ---------------------------------------------------------------------------

def _side(hunks: list[list[str]], fmt: str, ecosystem: str) -> dict[str, str]:
    """Parse one side of the diff into {name: version}.

    Takes one list of lines per hunk, in file order. Order matters because the
    block scanners carry state across lines — and the state is reset at each
    hunk boundary, since two hunks are not adjacent in the file and a `name =`
    left dangling by the first would otherwise capture the second hunk's
    `version =`.
    """
    parser = _PARSERS[fmt]
    out: dict[str, str] = {}
    for lines in hunks:
        state: dict = {}
        for line in lines:
            try:
                hit = parser(line, state)
            except Exception:                  # noqa: BLE001 — a malformed line is not fatal
                continue
            if hit is None:
                continue
            name, version = hit
            name = _normalize(name, ecosystem)
            if name:
                out.setdefault(name, version.strip())
    return out


def dep_delta_for(parsed: ParsedFile) -> DepDelta | None:
    """One file's dependency delta, or None if it is not a dependency file."""
    fmt = _format_of(parsed.path)
    if fmt is None:
        return None
    ecosystem, form = fmt

    # Both sides include context lines, so the block scanners see the `name =`
    # line that a version-bump hunk leaves unchanged. Packages that appear
    # identically on both sides cancel out in the algebra below.
    after = _side([h.side("new") for h in parsed.hunks], form, ecosystem)
    before = _side([h.side("old") for h in parsed.hunks], form, ecosystem)

    changed = {
        name: (before[name], after[name])
        for name in sorted(before.keys() & after.keys())
        if before[name] != after[name]
    }
    delta = DepDelta(
        ecosystem=ecosystem,
        manifest=parsed.path,
        added={n: after[n] for n in sorted(after.keys() - before.keys())},
        removed=sorted(before.keys() - after.keys()),
        changed=changed,
    )
    if not (delta.added or delta.removed or delta.changed):
        return None
    return delta


def extract_dep_deltas(parsed: list[ParsedFile]) -> list[DepDelta]:
    """Every dependency delta in a PR, in path order."""
    deltas = []
    for pf in sorted(parsed, key=lambda p: p.path):
        delta = dep_delta_for(pf)
        if delta is not None:
            deltas.append(delta)
    return deltas
