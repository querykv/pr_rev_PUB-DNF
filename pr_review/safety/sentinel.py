"""Injection sentinel (cross-cutting §9.3) — the `LLM-PROMPT-INJ` detector.

`wrap.py` controls *placement*: untrusted text never lands in an instruction
position. This module answers the other half — **was an instruction attempted?**
Both are needed. Wrapping means an injection should not work; the sentinel means
an injection that was tried is reported rather than silently absorbed, because
someone who plants one is telling you something about the rest of their diff.

WHERE THIS RUNS, AND WHY IT IS NOT NEGOTIABLE
Against the **manifest**, before the noise filter. An injection lives in a
comment or a docstring, and a comment-only hunk is precisely what `filter.py`'s
tier 1 drops as `formatting_only` (and a README as `docs_only`). A sentinel
placed after the filter would be structurally incapable of seeing its own
primary target — it would scan whatever survived a stage designed to delete
exactly this. The constraint is recorded at `change/astdiff.py:26` too, from the
other side.

WHAT IT SCANS
Added lines of every parsed file — including the ones tier 1 would drop, and
including files with no comment syntax at all (Markdown, YAML). It is
deliberately *not* restricted to comments and string literals: a README has no
comment concept, and a payload in a YAML value is a payload. Precision comes
from the phrases, not from the position. Plus the manifest's own untrusted
prose: PR title, PR body, ticket titles and bodies.

Added lines only. A *removed* injection is not a threat this PR introduces, and
`introduced_by_pr` would be a lie.

WHAT IT DOES NOT SEE, STATED SO IT IS NOT DISCOVERED LATER
- **Anything outside the diff.** A pre-existing injection sitting in a file that
  a `full_file` context bundle later ships to an agent is invisible here.
  `scan_text()` is exported as the primitive precisely so Phase 3's bundle
  assembly can close that; until it does, the gap is real.
- **Multi-line payloads.** Rules match per line, so an instruction split across
  two comment lines evades the phrase rules. Raising this to a sliding window is
  cheap but has never been measured against a corpus, and an unmeasured window
  is how a filter starts flagging prose.
- **Homoglyphs and confusables.** `hidden-text` catches zero-width and bidi
  characters; it does not catch Cyrillic `а` for Latin `a`.
- **Non-English payloads.** Every phrase rule is English.
- **A zero-width space directly behind a visible `@`.** That is the platform's
  own mention-escaping convention, exempted at `_MENTION_ESCAPE` below with the
  reasoning; nothing else invisible is exempt.

TWO RULE TIERS, AND WHY THE LINE IS WHERE IT IS
`policy.gate()` triggers only on `status=validated`, so the status assigned here
decides whether an injection attempt can fail CI. Three rules earn it: their
patterns have no innocent reading — text does not accidentally say "ignore all
previous instructions", forge our fence markers, or address an AI reviewer while
telling it to stay quiet. The other two are heuristics with plausible innocent
matches, so they report and never gate. A repo whose own data is prompt text
(an LLM application, an injection corpus — this repository included) is handled
by `is_test` capping and `detectors.sentinel.allowlist_paths`, not by weakening
the rules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatch

from pr_review.config import Config
from pr_review.extract.diff import ParsedFile
from pr_review.extract.schema import DeltaManifest
from pr_review.safety import wrap
from pr_review.schema import (
    DetectorKind,
    Evidence,
    Finding,
    Location,
    Provenance,
    Remediation,
    Severity,
    Status,
)
from pr_review.taxonomy import lookup
from pr_review.util import fingerprint, new_id

TOOL = "injection-sentinel"

# A single line longer than this is scanned for invisible characters (a cheap
# translate) but not for phrases: a minified bundle is one 5MB line, and running
# six regexes across it per hunk is how a review times out.
MAX_LINE_CHARS = 4000
MAX_SNIPPET_CHARS = 200

# Trust penalty applied to an agent finding sourced from a flagged file.
TRUST_PENALTY = 2


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Rule:
    rule_id: str
    internal: str
    title: str
    severity: Severity
    confidence: int
    status: Status
    pattern: re.Pattern
    why: str
    # Second pattern that must ALSO match the same line. Used by
    # `addressed-to-agent`, where neither half is suspicious alone.
    requires: re.Pattern | None = None

    def search(self, line: str) -> str | None:
        m = self.pattern.search(line)
        if not m:
            return None
        if self.requires is not None and not self.requires.search(line):
            return None
        return m.group(0)


# Our own fence markers, taken from `wrap` rather than respelled, plus the
# special tokens that delimit turns in a chat template. Both are unforgeable by
# accident: no ordinary source line contains `<|im_start|>`.
_FENCE_ALTERNATIVES = "|".join(
    re.escape(m) for m in (*wrap.MARKERS, "<|im_start|>", "<|im_end|>",
                           "<|endoftext|>", "[/INST]", "<<SYS>>", "<</SYS>>")
)

# NB: a bare `Human:` / `Assistant:` line start is deliberately NOT here. It is
# the obvious next pattern and it is too common in legitimate prompt-handling
# code to carry a gating verdict — an LLM application would flag its own every
# PR. The tier exists to be defensible, not exhaustive.

_AI_READER = re.compile(
    r"\b(?:you\s+are\s+an?|as\s+an?|dear|attention[,:]?)\s+"
    r"(?:ai|a\.i\.|llm|language\s+model|assistant|agent|bot|"
    r"(?:security\s+|code\s+)?(?:review(?:er)?|scanner|analy[sz]er|auditor))"
    r"|\b(?:ai|llm|claude|gpt|copilot|code\s*review)[\s-]*(?:reviewer|assistant|bot|agent)\b",
    re.I,
)

_IMPERATIVE = re.compile(
    r"\b(?:ignore|disregard|skip|omit|suppress|approve|overlook|"
    r"do\s+not\s+(?:report|flag|mention|analy[sz]e|review)|"
    r"don'?t\s+(?:report|flag|mention)|"
    r"mark\s+(?:it|this)?\s*(?:as\s+)?(?:safe|secure|reviewed|approved))\b",
    re.I,
)

_RULES: tuple[_Rule, ...] = (
    _Rule(
        rule_id="override-instruction",
        internal="LLM-PROMPT-INJ",
        title="Prompt injection: instruction override in changed content",
        severity=Severity.HIGH, confidence=8, status=Status.VALIDATED,
        pattern=re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?"
            r"(?:the\s+)?(?:previous|prior|above|earlier|preceding|your)\s+"
            r"(?:instructions?|prompts?|rules?|directions?)"
            r"|\bnew\s+instructions?\s*:"
            r"|\b(?:system|developer)\s+prompt\s*:"
            r"|\byou\s+are\s+now\s+(?:a|an|in)\b",
            re.I,
        ),
        why=("Changed content contains an instruction-override phrase. This text "
             "is data under review and is never obeyed, but its presence is "
             "itself the finding."),
    ),
    _Rule(
        rule_id="fence-forgery",
        internal="LLM-PROMPT-INJ",
        title="Prompt injection: forged prompt-delimiter or chat control token",
        severity=Severity.HIGH, confidence=8, status=Status.VALIDATED,
        pattern=re.compile(_FENCE_ALTERNATIVES),
        why=("Changed content contains a prompt-boundary marker — either this "
             "tool's own untrusted-data delimiter or a chat-template control "
             "token. Source code has no innocent reason to carry one; the "
             "purpose is to end the data block and resume as instructions."),
    ),
    _Rule(
        rule_id="addressed-to-agent",
        internal="LLM-PROMPT-INJ",
        title="Prompt injection: content addressed to an automated reviewer",
        severity=Severity.HIGH, confidence=7, status=Status.VALIDATED,
        pattern=_AI_READER, requires=_IMPERATIVE,
        why=("Changed content addresses an AI reviewer by name and issues an "
             "instruction to it. Neither half is suspicious alone; together "
             "they have no innocent reading."),
    ),
    _Rule(
        rule_id="suppress-finding",
        internal="LLM-PROMPT-INJ",
        title="Suppression language in changed content",
        severity=Severity.MEDIUM, confidence=5, status=Status.CANDIDATE,
        pattern=re.compile(
            r"\b(?:do\s+not|don'?t)\s+(?:report|flag|analy[sz]e|review)\b"
            r"|\bmark\s+(?:this|it)\s+(?:as\s+)?(?:safe|secure|reviewed|approved)\b"
            r"|\bno\s+(?:vulnerabilit|security\s+issue|finding)"
            r"|\b(?:skip|exclude)\s+(?:this\s+)?(?:file|check|review|scan)\b",
            re.I,
        ),
        why=("Changed content asks for analysis to be skipped or a result to be "
             "assumed. Reported, never gating: a maintainer writing a genuine "
             "'do not report' note to a colleague matches this too."),
    ),
    _Rule(
        rule_id="hidden-text",
        internal="INTEG-HIDDEN-TEXT",
        title="Invisible characters in changed content",
        severity=Severity.MEDIUM, confidence=6, status=Status.CANDIDATE,
        # Matched by `_invisible()`, not by this pattern — kept as a marker so
        # the rule carries the same metadata shape as the others.
        pattern=re.compile(r"(?!)"),
        why=("Changed content contains zero-width or bidirectional-control "
             "characters, so what a human reviewer reads and what a parser or a "
             "model reads are not the same text (Trojan Source, CWE-1007)."),
    ),
)

_BY_ID = {r.rule_id: r for r in _RULES}

# Zero-width and bidi-override characters. A BOM at position 0 is legitimate and
# is excluded at the call site.
_INVISIBLE = {
    "​": "ZWSP", "‌": "ZWNJ", "‍": "ZWJ", "﻿": "BOM",
    "⁠": "WJ", "᠎": "MVS",
    "‪": "LRE", "‫": "RLE", "‬": "PDF", "‭": "LRO",
    "‮": "RLO", "⁦": "LRI", "⁧": "RLI", "⁨": "FSI",
    "⁩": "PDI",
}

# GitHub's release-note generator (and Renovate, and dependabot) spells a
# credited contributor as `@<ZWSP>handle`, inserting a zero-width space so that
# publishing a changelog does not notify everyone it thanks. It is a convention
# of the platform whose PR bodies this tool reads, and it turned up in generated
# CHANGELOG files as readily as in `pr:body`.
#
# It was **100% of the invisible characters** found across 50 real merged PRs
# (`benchmark/results/2026-08-07/analysis.md` §1: 106 of 106 occurrences, 85 of
# the corpus's 98 false positives). Errata §14.18's lesson again — a hand-written
# fixture cannot show you this, only real input can.
#
# The exemption is deliberately the narrowest shape that covers it: ZWSP only,
# only immediately after an `@`, only before a word character. Nothing can hide
# behind it, because every character it excuses must be announced by an `@` the
# reader can see — and the bidi overrides that make Trojan Source (CVE-2021-42574)
# work are untouched.
_MENTION_ESCAPE = re.compile(r"@​(?=\w)")

# The three rules whose verdict can fail the gate. A line that matches one of
# these does not also get reported as `suppress-finding` — same
# specific-suppresses-generic dedup the secrets detector uses.
_GATING_IDS = frozenset({"override-instruction", "fence-forgery", "addressed-to-agent"})


# ---------------------------------------------------------------------------
# The primitive
# ---------------------------------------------------------------------------

@dataclass
class InjectionHit:
    origin: str        # "app.py" | "pr:title" | "pr:body" | "ticket:<id>"
    line: int          # 1-based; 0 where the surface has no lines
    rule_id: str
    text: str          # what to show a reviewer, truncated


def _invisible(line: str, at_line_start_ok: bool = True) -> str | None:
    """A rendering of `line` with invisible characters made visible, or None.

    The rendering is the point. `evidence.snippet` is verbatim everywhere else
    (cross-cutting §1), but a verbatim snippet of this finding displays as
    ordinary text and shows the reviewer nothing — the defect is that the
    characters are unreadable. So this one substitutes `<ZWSP>` and says so in
    the evidence `why`.

    Exempt characters stay verbatim rather than rendered, so a line reported for
    a genuine payload does not also point at one we have decided is benign.
    """
    found = False
    out: list[str] = []
    exempt = {m.start() + 1 for m in _MENTION_ESCAPE.finditer(line)}
    for i, ch in enumerate(line):
        name = _INVISIBLE.get(ch)
        if name is None:
            out.append(ch)
            continue
        if ch == "﻿" and i == 0 and at_line_start_ok:
            out.append(ch)      # a leading BOM is a file encoding, not an attack
            continue
        if i in exempt:
            out.append(ch)      # `@<ZWSP>handle` — the platform's mention escape
            continue
        found = True
        out.append(f"<{name}>")
    return "".join(out) if found else None


def scan_lines(lines: list[tuple[int, str]], origin: str) -> list[InjectionHit]:
    """Scan `(lineno, text)` pairs. The primitive every other entry point uses."""
    hits: list[InjectionHit] = []
    for lineno, raw in lines:
        rendered = _invisible(raw, at_line_start_ok=lineno == 1)
        if rendered is not None:
            hits.append(InjectionHit(origin, lineno, "hidden-text",
                                     rendered[:MAX_SNIPPET_CHARS]))
        if len(raw) > MAX_LINE_CHARS:
            continue
        gated = False
        for rule in _RULES:
            if rule.rule_id == "hidden-text":
                continue
            if rule.rule_id == "suppress-finding" and gated:
                continue        # a stronger rule already reported this line
            if rule.search(raw) is None:
                continue
            if rule.rule_id in _GATING_IDS:
                gated = True
            hits.append(InjectionHit(origin, lineno, rule.rule_id,
                                     raw.strip()[:MAX_SNIPPET_CHARS]))
    return hits


def scan_text(text: str, origin: str) -> list[InjectionHit]:
    """Scan a blob of untrusted text.

    Exported for Phase 3: a `full_file` context bundle carries source this
    module never saw, because it was not in the diff. Calling this on bundle
    content before it reaches an agent closes the gap named in the module
    docstring.
    """
    if not text:
        return []
    return scan_lines(list(enumerate(text.splitlines(), start=1)), origin)


# ---------------------------------------------------------------------------
# The pipeline entry point
# ---------------------------------------------------------------------------

@dataclass
class SentinelResult:
    findings: list[Finding] = field(default_factory=list)
    # path -> rule_ids. The provenance trust-flag of cross-cutting §9.3.
    flagged: dict[str, list[str]] = field(default_factory=dict)
    # Non-file surfaces (PR body, a ticket). These taint the whole run rather
    # than one file, because nothing downstream can attribute them to a path.
    run_flagged: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    scanned: dict = field(default_factory=dict)

    def stats(self) -> dict:
        return {
            **self.scanned,
            "findings": len(self.findings),
            "flagged_paths": sorted(self.flagged),
            "run_flagged": list(self.run_flagged),
        }


def _snippet_for(hit: InjectionHit) -> str:
    return hit.text


def _finding(hit: InjectionHit, *, is_test: bool, allowlisted: bool) -> Finding:
    rule = _BY_ID[hit.rule_id]
    severity, status = rule.severity, rule.status
    why = rule.why

    if is_test:
        # Same move as `secrets.py`: a payload in a test is usually a fixture
        # for the very thing being tested. Capping at MEDIUM keeps it visible
        # and out of the HIGH gate.
        if severity.rank > Severity.MEDIUM.rank:
            severity = Severity.MEDIUM
        why += " (in test code — a payload here is usually a fixture.)"
    if allowlisted:
        # Scanned, reported, never gating: `gate()` requires VALIDATED.
        status = Status.CANDIDATE
        why += " (path is sentinel-allowlisted, so this never gates.)"

    return Finding(
        id=new_id(),
        fingerprint=fingerprint(hit.origin, rule.internal, None, hit.text),
        title=rule.title,
        taxonomy=lookup(rule.internal),
        severity=severity,
        confidence=rule.confidence,
        status=status,
        introduced_by_pr=True,       # added lines only, by construction
        location=Location(file=hit.origin, start_line=hit.line, end_line=hit.line),
        evidence=[Evidence(file=hit.origin, lines=str(hit.line),
                           snippet=_snippet_for(hit), why=why)],
        remediation=Remediation(
            summary=(
                "Remove the instruction-like text from the change. If it is "
                "legitimate content (prompt-handling code, a test fixture, "
                "documentation about prompt injection), add its path to "
                "`detectors.sentinel.allowlist_paths`. Treat the rest of this "
                "PR as suspect until a human has read it: an injection attempt "
                "is usually pointing away from something."
            ),
            effort="low",
        ),
        provenance=Provenance(
            detector=DetectorKind.STRUCTURAL, tool=TOOL, rule_id=rule.rule_id
        ),
    )


def scan_manifest(manifest: DeltaManifest, parsed: list[ParsedFile] | None = None,
                  *, config: Config | None = None) -> SentinelResult:
    """Scan a PR's untrusted surfaces. Runs before the noise filter."""
    config = config or Config()
    result = SentinelResult()
    if not config.detectors.sentinel.enabled:
        result.notes.append("injection sentinel disabled by config")
        result.scanned = {"files": 0, "lines": 0}
        return result

    allowlist = config.detectors.sentinel.allowlist_paths
    by_path = {fc.path: fc for fc in manifest.files}

    hits: list[InjectionHit] = []
    files_scanned = lines_scanned = 0

    for pf in parsed or []:
        fc = by_path.get(pf.path)
        if pf.binary or (fc is not None and fc.is_binary):
            continue
        added = [(a.lineno, a.text) for h in pf.hunks for a in h.added]
        if not added:
            continue
        files_scanned += 1
        lines_scanned += len(added)
        hits.extend(scan_lines(added, pf.path))

    # The manifest's own prose. `body` is the surface a fork PR actually uses,
    # and until this milestone it was never captured at all (errata §14.13).
    for origin, text in (("pr:title", manifest.title), ("pr:body", manifest.body)):
        if text:
            lines_scanned += len(text.splitlines())
            hits.extend(scan_text(text, origin))
    for ticket in manifest.tickets:
        for suffix, text in (("title", ticket.title), ("body", ticket.body)):
            if text:
                lines_scanned += len(text.splitlines())
                hits.extend(scan_text(text, f"ticket:{ticket.id}:{suffix}"))

    for hit in hits:
        fc = by_path.get(hit.origin)
        is_file = fc is not None
        allowlisted = any(fnmatch(hit.origin, g) for g in allowlist)
        result.findings.append(_finding(
            hit,
            is_test=bool(fc is not None and fc.is_test),
            allowlisted=allowlisted,
        ))
        if is_file:
            result.flagged.setdefault(hit.origin, [])
            if hit.rule_id not in result.flagged[hit.origin]:
                result.flagged[hit.origin].append(hit.rule_id)
        elif hit.origin not in result.run_flagged:
            result.run_flagged.append(hit.origin)

    result.scanned = {"files": files_scanned, "lines": lines_scanned, "hits": len(hits)}
    if result.flagged:
        result.notes.append(
            "injection sentinel flagged " + ", ".join(sorted(result.flagged))
            + " — these files are force-kept through the noise filter and any "
              "agent finding sourced from them is trust-penalized."
        )
    if result.run_flagged:
        result.notes.append(
            "injection sentinel flagged run-level input (" +
            ", ".join(result.run_flagged) + ") — it cannot be attributed to a "
            "file, so every agent finding in this run is trust-penalized."
        )
    return result


def apply_trust(findings: list[Finding], result: SentinelResult) -> list[Finding]:
    """Lower confidence on agent findings sourced from flagged input (§9.3).

    A no-op today and deliberately built anyway: there are no `DetectorKind.AGENT`
    findings until M3, so the alternative is to discover at M3 that the trust
    flag was only ever a field in a JSON file. Deterministic detectors are
    untouched — a regex does not read comments and cannot be talked out of a
    match, which is the property that makes the deterministic floor worth having.
    """
    if not result.flagged and not result.run_flagged:
        return findings
    for f in findings:
        if f.provenance.detector != DetectorKind.AGENT:
            continue
        if not (result.run_flagged or f.location.file in result.flagged):
            continue
        before = f.confidence
        f.confidence = max(0, f.confidence - TRUST_PENALTY)
        f.verification.confidence_adjustment = f.confidence - before
        f.verification.refutation_attempts.append(
            f"injection sentinel: untrusted input for this finding carried an "
            f"instruction-like payload; confidence lowered by {TRUST_PENALTY}"
        )
    return findings
