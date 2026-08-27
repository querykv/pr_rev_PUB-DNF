"""DeltaManifest schema (phase-0-extraction.md §2).

The precise, untrusted-tagged record of a PR that every later phase joins against.
M0 populates files/hunks/stats. `dep_deltas` landed 2026-08-08 (`extract/deps.py`,
eleven manifest and lockfile formats). **`tickets` is still modeled and always
empty**: `extract/tickets.py` (phase-0 §4) was never built, and that is a
decision rather than a backlog item — nothing reads this field, and its consumer
is M3 prompt context. `OPEN_ITEMS.md` §15 has the reasoning and the revisit
trigger.
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Ticket(BaseModel):
    source: str  # github_issue | jira | commit_ref
    id: str
    title: str = ""
    body: str = ""  # UNTRUSTED — wrapped before any prompt use
    labels: list[str] = []
    url: str | None = None


class Hunk(BaseModel):
    id: str  # "<file_id>:h<n>"
    old_range: str | None = None
    new_range: str | None = None
    header: str = ""
    added_lines: list[int] = []
    removed_lines: list[int] = []


class FileChange(BaseModel):
    file_id: str
    path: str
    previous_path: str | None = None
    change: str  # added | modified | deleted | renamed | copied
    lang: str | None = None
    is_test: bool = False
    is_generated: bool = False
    is_binary: bool = False
    is_lockfile: bool = False
    is_dep_manifest: bool = False
    is_iac: bool = False
    hunks: list[Hunk] = []
    size_delta: int = 0


class DepDelta(BaseModel):
    ecosystem: str
    manifest: str
    added: dict[str, str] = {}
    removed: list[str] = []
    changed: dict[str, tuple[str, str]] = {}


class DeltaManifest(BaseModel):
    repo: str
    pr_number: int
    title: str = ""
    # UNTRUSTED, and stored verbatim rather than interpreted (phase-0 §4). This
    # is the surface a fork PR actually uses to address a review agent, so
    # `safety/sentinel.py` scans it; it is never placed in an instruction
    # position (`safety/wrap.py`).
    body: str = ""
    author: str = ""
    labels: list[str] = []
    base_sha: str = ""
    head_sha: str = ""
    base_ref: str = ""
    head_ref: str = ""
    from_fork: bool = False
    files: list[FileChange] = []
    dep_deltas: list[DepDelta] = []
    tickets: list[Ticket] = []
    stats: dict = {}
    oversize: bool = False
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
