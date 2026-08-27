# Plan — Phase 0: Data Extraction

> **Pure I/O. No AI, no LLM tokens.** Deterministic, fast, fully testable. Its job is to turn a
> PR URL into a precise, untrusted-tagged `DeltaManifest` that every later phase joins against.
> Package: `pr_review/extract/` + `pr_review/vcs/`.

## 1. Contract

- **Input:** PR URL (or `owner/repo#number`), `Config`.
- **Output:** `DeltaManifest` (`00_manifest.json`) + a `blame_map` for contributor provenance.
- **Side effects:** none beyond fetching + writing the run dir. Idempotent for a given head SHA.

## 2. DeltaManifest schema (`extract/manifest.py`)

```python
class Ticket(BaseModel):
    source: Literal["github_issue","jira","commit_ref"]; id: str; title: str
    body: str                       # UNTRUSTED — wrapped before any prompt use
    labels: list[str] = []; url: str | None = None

class Hunk(BaseModel):
    id: str                         # "<file_id>:h<n>" — stable within a manifest
    old_range: str | None           # "120-134" (None for added files)
    new_range: str | None           # "120-140" (None for deleted)
    header: str                     # the @@ line
    added_lines: list[int] = []; removed_lines: list[int] = []

class FileChange(BaseModel):
    file_id: str                    # stable hash of normalized path
    path: str; previous_path: str | None = None     # set on rename
    change: Literal["added","modified","deleted","renamed","copied"]
    lang: str | None                # "python" | None
    is_test: bool; is_generated: bool; is_binary: bool
    is_lockfile: bool; is_dep_manifest: bool; is_iac: bool
    hunks: list[Hunk] = []
    size_delta: int                 # +/- lines

class DepDelta(BaseModel):
    ecosystem: Literal["pip","poetry","pipenv","uv"]; manifest: str
    added: dict[str,str] = {}; removed: list[str] = []; changed: dict[str,tuple[str,str]] = {}

class DeltaManifest(BaseModel):
    repo: str; pr_number: int; title: str; author: str; labels: list[str]
    base_sha: str; head_sha: str; base_ref: str; head_ref: str
    from_fork: bool
    files: list[FileChange]
    dep_deltas: list[DepDelta] = []
    tickets: list[Ticket] = []
    stats: dict                     # totals: files, additions, deletions, hunks
    oversize: bool = False          # large-diff guard tripped → chunked downstream
    extracted_at: datetime
```

## 3. Steps

1. **Resolve PR** (`vcs/github.py: get_pr`): metadata, base/head SHAs + refs, author, labels,
   fork flag. (REST `pulls/{n}`; GraphQL for linked issues.)
2. **Fetch & parse diff** (`vcs/github.py: get_diff` → `extract/diff.py`): unified diff for
   base...head; parse into `FileChange`/`Hunk`. Assign **stable `file_id`** = hash(normalized
   path) and `hunk.id` = `<file_id>:h<index>` so all later phases share join keys. Capture
   added/removed line numbers (drives delta scoping, §cross-cutting 5).
3. **Classify files** (`extract/classify.py`, deterministic, no AI):
   - `lang` via extension + shebang (Python focus; non-Python flagged `lang=None`, analyzed only
     by language-agnostic detectors like secrets/iac).
   - `is_test` (path globs: `tests/`, `test_*.py`, `*_test.py`, `conftest.py`), `is_generated`
     (header markers, `*_pb2.py`, `migrations/`, vendored dirs), `is_binary`, `is_lockfile`
     (`poetry.lock`, `Pipfile.lock`, `*.lock`), `is_dep_manifest` (`requirements*.txt`,
     `pyproject.toml`, `Pipfile`, `setup.py/cfg`), `is_iac` (`*.tf`, `Dockerfile`, `*.yaml` under
     k8s/helm, `docker-compose*`).
   - Rename/copy detection from git similarity (`previous_path`).
4. **Extract tickets** (`extract/tickets.py`): GitHub closing/reference keywords + linked issues
   (GraphQL `closingIssuesReferences`); Jira keys (`[A-Z]+-\d+`) from branch/title/commit msgs →
   fetch bodies if a Jira adapter is configured (optional in v1). **All ticket text marked
   untrusted** and stored verbatim for wrapping later.
5. **Dependency deltas** (`extract/deps.py`): for each `is_dep_manifest`/`is_lockfile` file,
   diff parsed dependency sets → `DepDelta` (added/removed/changed with versions). Feeds the SCA
   detector (3a) without re-reading files.
6. **Large-diff guard** (`extract/guard.py`): if files > N or total hunks > M or additions > K
   (config; defaults e.g. 300 files / 2000 hunks), set `oversize=True` and emit a chunk plan so
   Phase 2/3 process in batches instead of failing. Never silently truncate.
7. **Blame map** (`extract/blame.py`): `git blame` the introducing lines of each hunk →
   `contributor_id` per line range (provenance, Principle #5). Cached per head SHA.

## 4. Trust handling

PR title/body, commit messages, and ticket bodies are **untrusted input**. Phase 0 only
*stores* them (verbatim, flagged); it never interprets them. Wrapping with the
data-not-instructions banner happens at prompt-construction time (cross-cutting §9). The
injection sentinel (cross-cutting §9.3) also runs over the diff here as a cheap pre-pass and may
seed an `LLM-PROMPT-INJ` candidate.

## 5. VCS adapter (`vcs/base.py`, v1 `github.py`)

Interface (overview §7.1): `get_pr`, `get_diff`, `get_linked_issues`, `get_blame`,
`post_comments`, `upload_sarif`. GitHub impl prefers `gh` CLI when available (auth reuse), falls
back to PyGithub/REST. **Modular by design** so GitLab/Bitbucket slot in later without touching
Phase 0 logic — only the adapter changes.

## 6. Edge cases (must handle in v1)

Force-pushed PRs (re-extract on new head SHA; runs keyed by head SHA) · merge commits in the
range (diff base...head, not per-commit) · PRs from forks (read-only token; no comment post if
unauthorized → degrade to SARIF only) · binary/deleted files (skip content, keep record) ·
submodules (record pointer change, no recursion in v1) · empty diff (short-circuit to "approved,
nothing to review") · generated/vendored code (flagged, excluded by default in Phase 2).

## 7. Tests & acceptance

- Unit: diff parser (hunk ranges, renames), classifier globs, dep-delta parser, Jira key regex.
- Integration: run against a fixture GitHub PR (recorded HTTP cassettes) → assert manifest
  fields, file classification, dep deltas, blame map.
- **Acceptance (M0):** `pr-review extract <pr-url>` writes a valid `DeltaManifest` for a real
  Python PR with correct base/head, file classes, hunks, tickets, and dep deltas; oversize guard
  trips on a synthetic huge diff.
