"""Secrets detector (tooling.md #5, phase-3 §3a).

Prefers `gitleaks` when available; falls back to a built-in regex scanner so the
skeleton works with no external binary (degrade, don't crash). M0 implements the
built-in engine; the gitleaks adapter is a drop-in swap behind the same Detector
interface. Secret values are redacted in evidence — the report must never leak the
secret it found.
"""
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass

from pr_review.detect.base import Detector, ScanTarget
from pr_review.detect.normalize import MAX_SNIPPET_CHARS
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


@dataclass
class _Rule:
    rule_id: str
    internal: str
    title: str
    severity: Severity
    confidence: int
    pattern: re.Pattern
    secret_group: int  # which capture group holds the secret value (0 = whole match)


_RULES: list[_Rule] = [
    _Rule("private-key", "SEC-PRIVATE-KEY", "Hardcoded private key", Severity.CRITICAL, 9,
          re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), 0),
    _Rule("aws-access-key-id", "SEC-AWS-KEY", "Hardcoded AWS access key id", Severity.HIGH, 9,
          re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0),
    _Rule("github-pat", "SEC-TOKEN", "Hardcoded GitHub personal access token", Severity.HIGH, 9,
          re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), 0),
    _Rule("slack-token", "SEC-TOKEN", "Hardcoded Slack token", Severity.HIGH, 8,
          re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), 0),
    # NB: keyword may be embedded in an identifier (DB_PASSWORD, AWS_ACCESS_KEY_ID),
    # so we match the whole surrounding identifier rather than relying on \b, which
    # fails across underscores.
    _Rule("generic-assignment", "SEC-PASSWORD", "Hardcoded credential in assignment", Severity.HIGH, 7,
          re.compile(r"""(?i)\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|token|auth[_-]?token)[A-Za-z0-9_]*)\s*[:=]\s*['"]([^'"]{6,})['"]"""), 2),
]

# Specific high-signal rules run first; the broad generic-assignment rule fires
# only when no specific rule matched the line (avoids double-reporting one secret).
_SPECIFIC = [r for r in _RULES if r.rule_id != "generic-assignment"]
_GENERIC = next(r for r in _RULES if r.rule_id == "generic-assignment")

# values that look like placeholders rather than real secrets → suppress
_PLACEHOLDERS = {
    "changeme", "change_me", "password", "passwd", "secret", "token", "example",
    "your_api_key", "your-api-key", "xxx", "xxxxxx", "none", "null", "todo",
    "placeholder", "redacted", "dummy", "test", "fake", "sample", "<your-key>",
}
# `$(...)` joins `${...}` here for the same reason and was added 2026-08-09 after
# the IaC corpus: `NSS_WRAPPER_PASSWD="$(mktemp)"` in postgres's
# `docker-entrypoint.sh:76` is a temp *file path*, and it was reported HIGH and
# **failed the gate** — secrets still carry the M0 `status=validated`
# simplification, so they are the one finding class that can. A command
# substitution is a value computed at run time; it is definitionally not a
# hardcoded one, exactly like a variable expansion.
#
# Backticks are deliberately absent. Legacy `` `cmd` `` is the same construct,
# but it was not observed in either corpus, and `is_generated`'s docstring
# records the standing trade: stay close to what has actually been seen rather
# than trading unmeasured coverage for a hypothetical.
_PLACEHOLDER_RE = re.compile(
    r"(?i)(\$\{.*\}|\$\(.*\)|<[^>]+>|example|placeholder|changeme|xxxx)")


def _looks_placeholder(value: str) -> bool:
    v = value.strip()
    if v.lower() in _PLACEHOLDERS:
        return True
    if _PLACEHOLDER_RE.search(v):
        return True
    if len(set(v)) <= 2:  # "aaaaaa", "------"
        return True
    return False


def _redact(secret: str) -> str:
    secret = secret.strip()
    if len(secret) <= 6:
        return "***"
    return f"{secret[:3]}***{secret[-2:]}"


class SecretsDetector(Detector):
    kind = DetectorKind.SECRETS
    name = "secrets"

    def __init__(self) -> None:
        # gitleaks adapter is a future swap; M0 uses the builtin engine regardless.
        self.engine = "gitleaks" if shutil.which("gitleaks") else "builtin"
        self.tool = "builtin-secrets"  # honest provenance for M0

    def applicable(self, targets: list[ScanTarget]) -> bool:
        return any(not t.is_binary for t in targets)

    def run(self, targets: list[ScanTarget]) -> list[Finding]:
        findings: list[Finding] = []
        for t in targets:
            if t.is_binary or t.is_generated:
                continue
            for lineno, text in t.added_lines:
                findings.extend(self._scan_line(t, lineno, text))
        return findings

    def _scan_line(self, t: ScanTarget, lineno: int, text: str) -> list[Finding]:
        out: list[Finding] = []
        matched_specific = False
        for rule in _SPECIFIC:
            m = rule.pattern.search(text)
            if m:
                out.append(self._make(rule, m, t, lineno, text))
                matched_specific = True
        if not matched_specific:
            m = _GENERIC.pattern.search(text)
            if m and not _looks_placeholder(m.group(_GENERIC.secret_group)):
                out.append(self._make(_GENERIC, m, t, lineno, text))
        return out

    def _make(self, rule: _Rule, m: "re.Match", t: ScanTarget, lineno: int, text: str) -> Finding:
        secret = m.group(rule.secret_group) if rule.secret_group else m.group(0)
        severity = rule.severity
        why = "Secret literal committed to source."
        if t.is_test:
            # in-test secrets are lower impact; keep them out of the HIGH gate
            severity = Severity.MEDIUM if severity.rank > Severity.MEDIUM.rank else severity
            why = "Secret literal in test code (lower impact, still flagged)."
        # Bounded for the same reason `normalize.make_finding` bounds its own:
        # a match on a minified or generated file captures the whole line, and
        # "the whole line" there is the whole file. Measured on the benchmark
        # corpus — a `SEC-PASSWORD` hit on `netbox.js.map` carried a **1.25 MB**
        # evidence snippet into the finding, the run artifact, and (had it been
        # introduced rather than pre-existing) a code fence in `report.md`.
        #
        # This cannot move a fingerprint: `fingerprint()` below is given the
        # *secret*, not this line, so truncation changes what a reader sees and
        # nothing that `findings/delta.py` compares.
        redacted_line = text.replace(secret, _redact(secret)).strip()[:MAX_SNIPPET_CHARS]
        return Finding(
            id=new_id(),
            fingerprint=fingerprint(t.path, rule.internal, None, secret),
            title=rule.title,
            taxonomy=lookup(rule.internal),
            severity=severity,
            confidence=rule.confidence,
            status=Status.VALIDATED,  # deterministic + direct evidence (no verifier until M4)
            introduced_by_pr=True,    # no baseline yet (delta scoping arrives at M2)
            location=Location(file=t.path, start_line=lineno, end_line=lineno),
            evidence=[Evidence(file=t.path, lines=str(lineno), snippet=redacted_line, why=why)],
            remediation=Remediation(
                summary=(
                    "Remove the secret from source control, rotate the exposed "
                    "credential, and load it at runtime from a secret manager or "
                    "environment variable."
                ),
                effort="low",
            ),
            provenance=Provenance(
                detector=DetectorKind.SECRETS, tool=self.tool, rule_id=rule.rule_id
            ),
        )
