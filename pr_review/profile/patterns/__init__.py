"""Loader for the language security catalogs (`<language>.yaml`).

The catalogs are data (phase-1 §9) — adding a framework must never require
touching Python. This module only finds and parses them.

WHY THE LOADER IS NOT `yaml.safe_load`

PyYAML keeps the **last** of two identical mapping keys and says nothing. A
catalog block written with a stray second `calls:` therefore loses every pattern
in the first one — no error, no warning, and no test failure unless something
asserts that exact pattern.

This is not hypothetical. It happened during a falsification pass
(`OPEN_ITEMS.md` §12): the mutation added a second `calls:` key meaning to
loosen a pattern, silently deleted it instead, the pinning test passed, and a
live guard reported as **INERT** — a wrong conclusion drawn from a file that had
quietly lost half its content.

`cpg._call_patterns` already raises on the related case, a pattern appearing in
both `calls` and `exact_calls`. It cannot see this one: by the time it runs,
PyYAML has thrown the duplicate away. So the check has to happen at parse time,
which is what `_StrictLoader` does.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_DIR = Path(__file__).parent


class CatalogNotFound(FileNotFoundError):
    pass


class CatalogError(ValueError):
    """The catalog parsed as YAML but is not a catalog we will trust."""


class _StrictLoader(yaml.SafeLoader):
    """`SafeLoader` that refuses a mapping with a repeated key.

    Subclassed rather than configured because PyYAML offers no switch for this:
    `construct_mapping` builds a dict, and a dict cannot represent the problem
    it is being asked to detect. The keys are therefore checked before the dict
    exists.
    """


def _no_duplicate_keys(loader: yaml.SafeLoader, node: yaml.MappingNode,
                       deep: bool = False) -> dict:
    seen: set = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            mark = key_node.start_mark
            raise CatalogError(
                f"duplicate key {key!r} at line {mark.line + 1}, column "
                f"{mark.column + 1} of {mark.name}. PyYAML would keep the last "
                f"one and discard the first silently, which is how a catalog "
                f"loses a whole pattern list without failing anything "
                f"(OPEN_ITEMS.md §12)."
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys)


def parse_catalog(text: str, *, name: str = "<catalog>") -> dict:
    """Parse catalog YAML, refusing duplicate keys. Exposed for tests and for
    any caller reading a catalog that is not on disk here."""
    try:
        return yaml.load(text, Loader=_StrictLoader)
    except yaml.YAMLError as exc:                    # pragma: no cover - passthrough
        raise CatalogError(f"{name} is not valid YAML: {exc}") from exc


@lru_cache(maxsize=None)
def load_catalog(language: str = "python") -> dict:
    """Parse `<language>.yaml`. Cached — catalogs are read once per process."""
    path = _DIR / f"{language}.yaml"
    if not path.exists():
        raise CatalogNotFound(
            f"no security catalog for {language!r} "
            f"(have: {', '.join(sorted(p.stem for p in _DIR.glob('*.yaml'))) or 'none'})"
        )
    return parse_catalog(path.read_text(), name=str(path))


def available() -> list[str]:
    return sorted(p.stem for p in _DIR.glob("*.yaml"))
