"""Three-tier noise filter (phase-2-change-analysis.md §3).

Drops security-irrelevant changes so agents are not wasted — **without dropping
anything a vuln could hide in.** This is the pipeline's #1 false-negative risk:
everything downstream is bounded by what survives here, and a file dropped at
this stage is invisible to every later phase, including the verifier. So the
whole module is written to fail toward *keeping*.

  Tier 1  deterministic drop, zero cost — generated files, docs, binaries,
          lockfile churn already captured as a `DepDelta`, and changes that are
          formatting-only (AST-equal before/after).
  Tier 2  allow-by-default guardrail, which **overrides** tier 1 — never drop a
          file the CPG or profile marks as touching a source, sink, endpoint,
          auth check or sensitive field. Security-relevant beats "looks boring".
  Tier 3  cheap-model triage for the ambiguous remainder only. `maybe` is kept.

FOUR RULES THAT KEEP THIS HONEST

1. **Every drop is recorded**, with a reason and with `guardrail_considered`
   set — the difference between "the CPG said this file is inert" and "nobody
   asked". `benchmark.md` measures recall *after* this stage, and that ablation
   is meaningless if a drop cannot be attributed.
2. **Tests are never dropped for being tests.** A PR that deletes an authz
   assertion has removed a control; phase-2 §3 makes that a change group, not a
   silent omission. `classify.weakened_security_test()` force-keeps it.
3. **"Could not check" is never "safe to drop".** Formatting-only needs both
   file versions; with only one, or none, the check declines and the file stays.
4. **Lockfiles are droppable, manifests are not.** §3 permits dropping lockfile
   churn *because a `DepDelta` already records it*. So the drop is conditional
   on `extract/deps.py` having actually produced one for that path, and a
   `pyproject.toml` or `package.json` — where a human writes the dependency, and
   which is a profile anchor — is never dropped at all.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from posixpath import splitext
from typing import Callable

from pr_review.change import astdiff
from pr_review.change.classify import SecurityIndex, weakened_security_test
from pr_review.change.schema import DropRecord
from pr_review.config import Config
from pr_review.extract.diff import ParsedFile
from pr_review.extract.schema import DeltaManifest, FileChange
from pr_review.profile.schema import ProjectProfile
from pr_review.safety import wrap

# (path, side) -> source text, where side is "before" or "after". Returns None
# when that version is unavailable, which is the normal case offline.
SourceReader = Callable[[str, str], "str | None"]

_DOC_EXTENSIONS = {".md", ".rst", ".adoc", ".txt", ".text"}

# Tier-3 cost ceiling. Past this the remainder is kept unexamined rather than
# paying to triage a PR that is already too big to reason about cheaply.
MAX_TRIAGE_HUNKS = 60
MAX_TRIAGE_CHARS_PER_HUNK = 1200


@dataclass
class GuardrailSave:
    """A tier-1 drop that tier 2 overrode."""
    path: str
    would_have_been: str
    why: str


@dataclass
class FilterResult:
    kept: dict[str, list[str]] = field(default_factory=dict)   # path -> hunk ids
    dropped: list[DropRecord] = field(default_factory=list)
    saves: list[GuardrailSave] = field(default_factory=list)
    triage_labels: dict[str, str] = field(default_factory=dict)   # hunk id -> label
    notes: list[str] = field(default_factory=list)

    @property
    def kept_paths(self) -> list[str]:
        return sorted(self.kept)

    @property
    def dropped_paths(self) -> list[str]:
        return sorted({d.path for d in self.dropped})

    def stats(self) -> dict:
        return {
            "kept_files": len(self.kept),
            "kept_hunks": sum(len(v) for v in self.kept.values()),
            "dropped_files": len(self.dropped),
            "guardrail_saves": len(self.saves),
            "triaged_hunks": len(self.triage_labels),
        }


# ---------------------------------------------------------------------------
# Tier 1 — deterministic
# ---------------------------------------------------------------------------

def _is_docs(fc: FileChange) -> bool:
    if fc.is_dep_manifest or fc.is_lockfile or fc.is_iac:
        return False
    return splitext(fc.path)[1].lower() in _DOC_EXTENSIONS


def _lockfile_captured(fc: FileChange, manifest: DeltaManifest) -> bool:
    """Only true when a `DepDelta` actually records this lockfile's churn.

    The plan's wording — "lockfile churn *already captured as* a `DepDelta`" —
    is a precondition, not a description. Before `extract/deps.py` existed this
    rule dropped lockfiles with nothing recording them.
    """
    if not fc.is_lockfile:
        return False
    return any(d.manifest == fc.path for d in manifest.dep_deltas)


def _formatting_only(fc: FileChange, pf: ParsedFile | None,
                     sources: SourceReader | None) -> tuple[bool, str]:
    """(verdict, how it was decided). Declines rather than guesses."""
    if pf is None or not fc.lang:
        return False, ""
    if not astdiff.parses(fc.lang):
        return False, ""

    before = sources(fc.path, "before") if sources else None
    after = sources(fc.path, "after") if sources else None

    if before is not None and after is not None:
        if astdiff.ast_equal(before, after, fc.lang):
            return True, "AST-equal before/after"
        return False, ""

    # No base version: fall back to the diff-only check, using the after-version
    # if we have it to rule out `#` lines that are really inside a string.
    if astdiff.inert_hunks(pf, fc.lang, after_source=after):
        how = "all changed lines are blank or comments"
        return True, how + ("" if after is not None else " (no base version to AST-compare)")
    return False, ""


def _tier1(fc: FileChange, pf: ParsedFile | None, manifest: DeltaManifest,
           sources: SourceReader | None) -> tuple[str, str] | None:
    """(reason, detail) if this file is a drop candidate, else None."""
    if fc.is_binary:
        return "binary", "binary file — no textual analysis possible"
    if fc.is_generated:
        return "generated", "path matches a generated-code pattern"
    if _is_docs(fc):
        return "docs_only", "documentation file with no code"
    if _lockfile_captured(fc, manifest):
        return "lockfile_captured", "churn recorded as a DepDelta; SCA reads that in 3a"
    verdict, how = _formatting_only(fc, pf, sources)
    if verdict:
        return "formatting_only", how
    return None


# ---------------------------------------------------------------------------
# Tier 3 — cheap-model triage
# ---------------------------------------------------------------------------

_TRIAGE_SYSTEM = (
    "You are a security triage classifier for code review. For each labelled "
    "change below, decide whether it could plausibly bear on the security of "
    "the application.\n"
    "Answer `yes` if it could, `no` only if you are confident it could not, and "
    "`maybe` whenever you are unsure. `maybe` is kept for analysis, so an "
    "honest `maybe` costs nothing and a wrong `no` hides a vulnerability.\n"
    "Each change is introduced by a marker of the form "
    "`origin='<path> [<change id>]'`. The change id is the text inside the "
    "square brackets. Use exactly that string as the JSON key -- not the path, "
    "and not the whole marker.\n"
    "Reply with a single JSON object mapping each change id to one of "
    '"yes", "no", "maybe". No prose.'
)


def _triage_payload(items: list[tuple[str, str, str]]) -> str:
    """items: (hunk_id, path, diff text) -> one wrapped untrusted block."""
    blocks = [
        (f"{path} [{hid}]", text[:MAX_TRIAGE_CHARS_PER_HUNK])
        for hid, path, text in items
    ]
    return wrap.wrap_many(blocks, kind="diff")


def _hunk_text(pf: ParsedFile, hunk_id: str, file_id: str) -> str:
    for n, hunk in enumerate(pf.hunks, start=1):
        if f"{file_id}:h{n}" != hunk_id:
            continue
        lines = [f"@@ {hunk.header}"]
        lines += [f"-{r.text}" for r in hunk.removed]
        lines += [f"+{a.text}" for a in hunk.added]
        return "\n".join(lines)
    return ""


def _parse_labels(response: str, ids: list[str]) -> dict[str, str]:
    """Lenient parse. Anything unparseable leaves the hunk unlabelled, and an
    unlabelled hunk is kept.

    Keys arrive in two shapes and both are accepted. The bare change id is what
    the prompt asks for; the origin-wrapped form -- `app/auth.py [f1:h1]` -- is
    what a real model actually returned the first time one ran through here, in
    2026-08-21's smoke gate. It had classified both hunks *correctly* and the
    labels were still discarded, because the payload shows the id only inside
    the `origin=` marker and nothing had ever told the model which part was the
    key. The fake provider returned bare ids, so the suite never saw it.

    Matching on the bracketed form specifically, rather than on substring
    containment, is what keeps `f1:h1` from also matching `f1:h11`.
    """
    text = (response or "").strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        raw = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return {}
    if not isinstance(raw, dict):
        return {}
    lookup: dict[str, object] = {}
    for key, value in raw.items():
        k = str(key).strip()
        lookup.setdefault(k, value)
        if k.endswith("]") and "[" in k:
            lookup.setdefault(k[k.rindex("[") + 1:-1].strip(), value)
    out = {}
    for hid in ids:
        value = str(lookup.get(hid, "")).strip().lower()
        if value in ("yes", "no", "maybe"):
            out[hid] = value
    return out


def _triage(items: list[tuple[str, str, str]], provider, config: Config
            ) -> tuple[dict[str, str], list[str]]:
    if not items:
        return {}, []
    if len(items) > MAX_TRIAGE_HUNKS:
        return {}, [
            f"triage skipped: {len(items)} ambiguous hunks exceeds the "
            f"{MAX_TRIAGE_HUNKS}-hunk ceiling; all kept unexamined"
        ]
    role = config.models.role("triage")
    ids = [hid for hid, _p, _t in items]
    messages = [
        {"role": "system", "content": _TRIAGE_SYSTEM},
        {"role": "user", "content": _triage_payload(items)},
    ]
    try:
        response = provider.complete(messages, model_id=role.model_id, effort=role.effort)
    except Exception as exc:                         # noqa: BLE001 — degrade to keeping
        return {}, [f"triage unavailable ({type(exc).__name__}: {exc}); all ambiguous kept"]
    labels = _parse_labels(response if isinstance(response, str) else str(response), ids)
    notes = []
    if len(labels) < len(ids):
        notes.append(
            f"triage labelled {len(labels)}/{len(ids)} hunks; the rest were kept")
    return labels, notes


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def filter_changes(
    manifest: DeltaManifest,
    parsed: list[ParsedFile] | None = None,
    *,
    cpg=None,
    profile: ProjectProfile | None = None,
    config: Config | None = None,
    index: SecurityIndex | None = None,
    sources: SourceReader | None = None,
    provider=None,
    force_keep: set[str] | None = None,
) -> FilterResult:
    """Run the three tiers. `index`, `sources` and `provider` are all optional;
    each absence degrades a tier toward keeping, never toward dropping.

    `force_keep` is the injection sentinel's output: paths whose changed content
    carried text addressed to the agents. They survive tier 1 regardless of how
    boring they look, because someone who plants an injection is plausibly
    pointing attention away from something in the same PR — and the classic
    carrier, a comment-only hunk, is precisely what tier 1 deletes.

    This is not the errata §14.9 mistake in a new place. That rule says a signal
    a stage *acts on* must not also veto that stage, and it is about
    `TOUCH_KINDS` vetoing the tier-1 rules that exist to act on them. The
    sentinel is a different stage, run before this one, whose verdict this stage
    consumes but never produces.
    """
    config = config or Config()
    language = config.languages[0] if config.languages else "python"
    index = index or SecurityIndex(cpg, profile, manifest, config, language)
    by_path = {pf.path: pf for pf in (parsed or [])}
    force_keep = force_keep or set()

    result = FilterResult()
    if not index.has_cpg:
        result.notes.append(
            "GUARDRAIL DEGRADED: no CPG available — the allow-by-default check "
            "ran against profile rows and path shape only, so a security-"
            "relevant file with no matching path could be dropped by tier 1."
        )
    if sources is None:
        result.notes.append(
            "formatting-only detection ran without a base checkout: comment-and-"
            "blank-line hunks only, no AST comparison."
        )

    ambiguous: list[tuple[str, str, str]] = []
    for fc in sorted(manifest.files, key=lambda f: f.path):
        pf = by_path.get(fc.path)
        hunk_ids = [h.id for h in fc.hunks]

        # -- pre-emption: the injection sentinel flagged this file ----------
        if fc.path in force_keep:
            result.kept[fc.path] = hunk_ids
            result.saves.append(GuardrailSave(
                fc.path, "n/a",
                "the injection sentinel found text addressed to the agents in "
                "this file's changed content"))
            continue

        # -- tier 2 pre-emption: a weakened security test is always kept -----
        if fc.is_test and pf is not None:
            weakened, _fams = weakened_security_test(pf)
            if weakened:
                result.kept[fc.path] = hunk_ids
                result.saves.append(GuardrailSave(
                    fc.path, "n/a", "a security assertion was removed from a test"))
                continue

        candidate = _tier1(fc, pf, manifest, sources)
        if candidate is not None:
            reason, detail = candidate
            # -- tier 2: the guardrail overrides tier 1 ---------------------
            considered = reason != "binary"
            if considered and index.security_relevant(fc.path):
                result.kept[fc.path] = hunk_ids
                result.saves.append(GuardrailSave(
                    fc.path, reason,
                    f"CPG/profile marks this file security-relevant: {index.why(fc.path)}"))
                continue
            result.dropped.append(DropRecord(
                path=fc.path, hunk_ids=hunk_ids, reason=reason, detail=detail,
                guardrail_considered=considered,
            ))
            continue

        result.kept[fc.path] = hunk_ids

        # -- tier 3 candidates: survived tier 1, and we know nothing about it -
        # "Ambiguous" means *no signal at all*, not merely "no security
        # surface". A lockfile or a settings file already has a touch kind and a
        # family; paying a model to relabel it is spend with no decision
        # attached to it.
        if not index.touches(fc.path) and pf is not None:
            for hid in hunk_ids:
                text = _hunk_text(pf, hid, fc.file_id)
                if text:
                    ambiguous.append((hid, fc.path, text))

    if ambiguous and provider is not None:
        labels, notes = _triage(ambiguous, provider, config)
        result.triage_labels.update(labels)
        result.notes.extend(notes)
        _apply_triage(result, manifest, labels)
    elif ambiguous:
        result.notes.append(
            f"tier-3 triage not run (no model provider): {len(ambiguous)} "
            f"ambiguous hunk(s) kept unexamined."
        )
    return result


def _apply_triage(result: FilterResult, manifest: DeltaManifest,
                  labels: dict[str, str]) -> None:
    """Drop only the hunks explicitly labelled `no`; `maybe` and unlabelled stay."""
    dropped_by_path: dict[str, list[str]] = {}
    for hid, label in labels.items():
        if label != "no":
            continue
        for path, ids in result.kept.items():
            if hid in ids:
                dropped_by_path.setdefault(path, []).append(hid)
                break

    for path, ids in dropped_by_path.items():
        remaining = [h for h in result.kept[path] if h not in ids]
        result.dropped.append(DropRecord(
            path=path, hunk_ids=sorted(ids), reason="triage_not_relevant",
            detail="cheap-model triage labelled these hunks not security-relevant",
            guardrail_considered=True,
        ))
        if remaining:
            result.kept[path] = remaining
        else:
            del result.kept[path]


def recall_report(result: FilterResult, expected_paths: list[str]) -> dict:
    """Which of a labelled vuln-bearing set survived the filter.

    The recall-after-filter metric `benchmark.md` treats as first-class, kept
    here so the ablation runs against the filter's own output rather than a
    reimplementation of it.
    """
    kept = set(result.kept)
    missed = sorted(p for p in expected_paths if p not in kept)
    total = len(expected_paths)
    return {
        "expected": total,
        "kept": total - len(missed),
        "missed": missed,
        "recall": (total - len(missed)) / total if total else 1.0,
        "drop_reasons": {d.path: d.reason for d in result.dropped if d.path in set(expected_paths)},
    }
