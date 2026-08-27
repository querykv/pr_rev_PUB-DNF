"""Small shared helpers: ids, path normalization, finding fingerprints."""
from __future__ import annotations

import hashlib
import re
import uuid


def new_id() -> str:
    return str(uuid.uuid4())


def normalize_path(p: str) -> str:
    """Normalize a repo-relative path for stable joins/fingerprints."""
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def _norm_snippet(snippet: str | None) -> str:
    return re.sub(r"\s+", " ", (snippet or "")).strip().lower()


def fingerprint(path: str, internal: str, symbol: str | None, snippet: str | None) -> str:
    """Stable, line-number-independent finding identity (cross-cutting §6).

    Deliberately excludes line numbers so a finding survives reformatting and
    line shifts. M0 uses the normalized matched snippet as the structural-context
    proxy; M1+ swaps in an AST-context hash.
    """
    basis = f"{normalize_path(path)}|{internal}|{symbol or ''}|{_norm_snippet(snippet)}"
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]
