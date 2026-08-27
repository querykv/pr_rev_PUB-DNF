"""GitHub adapter (phase-0 §5). Prefers the `gh` CLI (auth reuse). When `gh` is
absent the caller can supply a local diff via --diff-file (offline mode), which
is also how M0 is tested without network access.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess

from pr_review.vcs.base import PRRef, VCSAdapter

_URL_RE = re.compile(r"github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/pull/(\d+)")
_SHORT_RE = re.compile(r"^([^/\s]+)/([^/#\s]+)#(\d+)$")


class GhNotAvailable(RuntimeError):
    pass


def gh_available() -> bool:
    return shutil.which("gh") is not None


class GitHubAdapter(VCSAdapter):
    def __init__(self, token_env: str = "GH_TOKEN") -> None:
        self.token_env = token_env

    def parse_url(self, url: str) -> tuple[str, int]:
        m = _URL_RE.search(url)
        if m:
            return f"{m.group(1)}/{m.group(2)}", int(m.group(3))
        m = _SHORT_RE.match(url.strip())
        if m:
            return f"{m.group(1)}/{m.group(2)}", int(m.group(3))
        raise ValueError(f"unrecognized PR reference: {url!r} (expected a GitHub PR URL or owner/repo#N)")

    def _gh(self, args: list[str]) -> str:
        if not gh_available():
            raise GhNotAvailable(
                "`gh` CLI not found. Install GitHub CLI, or run offline with "
                "--diff-file <path> (and --repo owner/repo --pr N)."
            )
        out = subprocess.run(["gh", *args], capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(f"gh {' '.join(args)} failed: {out.stderr.strip()}")
        return out.stdout

    def get_pr(self, repo: str, number: int) -> PRRef:
        raw = self._gh([
            "api", f"repos/{repo}/pulls/{number}",
        ])
        d = json.loads(raw)
        return PRRef(
            repo=repo,
            number=number,
            title=d.get("title", ""),
            # The REST response already carries it; a null body decodes as None.
            body=d.get("body") or "",
            author=(d.get("user") or {}).get("login", ""),
            base_sha=(d.get("base") or {}).get("sha", ""),
            head_sha=(d.get("head") or {}).get("sha", ""),
            base_ref=(d.get("base") or {}).get("ref", ""),
            head_ref=(d.get("head") or {}).get("ref", ""),
            from_fork=((d.get("head") or {}).get("repo") or {}).get("fork", False),
            labels=[l.get("name", "") for l in d.get("labels", [])],
        )

    def get_diff(self, repo: str, number: int) -> str:
        return self._gh(["pr", "diff", str(number), "--repo", repo])
