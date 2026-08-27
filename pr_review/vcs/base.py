"""VCS adapter interface (overview §7.1). GitHub is the only v1 impl; the
interface keeps GitLab/Bitbucket addable later without touching Phase 0 logic.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class PRRef:
    repo: str          # "owner/repo"
    number: int
    title: str = ""
    body: str = ""     # UNTRUSTED — the PR description, scanned by safety/sentinel.py
    author: str = ""
    base_sha: str = ""
    head_sha: str = ""
    base_ref: str = ""
    head_ref: str = ""
    from_fork: bool = False
    labels: list[str] = field(default_factory=list)


class VCSAdapter(ABC):
    @abstractmethod
    def parse_url(self, url: str) -> tuple[str, int]:
        """Return (repo='owner/repo', pr_number)."""

    @abstractmethod
    def get_pr(self, repo: str, number: int) -> PRRef: ...

    @abstractmethod
    def get_diff(self, repo: str, number: int) -> str:
        """Unified diff for base...head."""

    # M1+ surface (not needed by the M0 skeleton)
    def get_linked_issues(self, repo: str, number: int):  # pragma: no cover
        raise NotImplementedError

    def post_comments(self, repo: str, number: int, findings):  # pragma: no cover
        raise NotImplementedError

    def upload_sarif(self, repo: str, sarif_path: str):  # pragma: no cover
        raise NotImplementedError
