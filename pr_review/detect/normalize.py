"""Detector output normalization (phase-3 §3a) — the shared spine of `detect/`.

Every adapter turns something foreign (SARIF, a scanner's JSON, our own CPG)
into the same `Finding`. Doing that per adapter would put four copies of the
taxonomy decision, the severity decision and the test-file rule in four files
that drift apart, so all of it lives here and the adapters supply only what is
genuinely tool-specific.

THREE DECISIONS THIS MODULE OWNS

1. **Rule id -> our taxonomy.** External rulesets are large and moving targets:
   `p/python` alone is hundreds of rules. So mapping is three-stage — an exact
   table for rules we have read, a token heuristic over the rule id for the
   rest, and `TOOL-UNMAPPED` when neither fires. An unmapped rule still
   *reports* (recall is the whole point of 3a) but is capped and left
   `candidate`, so an unclassified rule can never reach the gate. Its id goes
   to telemetry, which is how the exact table earns its next entry.

2. **Severity.** Prefer SARIF's `security-severity` (a CVSS-ish number that
   Semgrep and Checkov both emit) over `level`, because `level` collapses
   everything interesting into "error". A rule we mapped explicitly overrides
   both — we have read that rule and the tool has not read our threat model.

3. **The test-file cap.** A finding in test code is capped at MEDIUM. The rule
   was already written twice (`detect/secrets.py`, `safety/sentinel.py`) before
   this module existed; `cap_for_test()` is now the one copy, and the fact that
   it needed to exist three times is why it is exported rather than inlined.

WHAT THIS MODULE DOES NOT DO: decide `introduced_by_pr`. Adapters report what
they see; `findings/delta.py` decides what the PR is responsible for. A
detector that guessed would be guessing without a baseline in front of it.
"""
from __future__ import annotations

import hashlib

import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from pr_review.schema import (
    DetectorKind,
    Evidence,
    Finding,
    FlowNode,
    Location,
    Provenance,
    Reachability,
    Remediation,
    Severity,
    Status,
)
from pr_review.taxonomy import lookup
from pr_review.util import fingerprint, new_id

MAX_SNIPPET_CHARS = 400


# ---------------------------------------------------------------------------
# Rule mapping
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleMapping:
    """How one external rule id lands in our taxonomy."""
    internal: str
    severity: Severity | None = None   # None -> take the tool's own severity
    confidence: int = 5                # per-rule precision prior (cross-cutting §4)
    title: str | None = None
    origin: str = "exact"              # exact | heuristic | unmapped

    @property
    def classified(self) -> bool:
        return self.internal != "TOOL-UNMAPPED"


UNMAPPED = RuleMapping("TOOL-UNMAPPED", Severity.MEDIUM, 3, origin="unmapped")

# Rules we have actually read, keyed by tool. Small on purpose: an entry here is
# a claim that someone checked what the rule does, so it is added from evidence
# (a telemetry line naming an unmapped rule) rather than from a ruleset dump.
_EXACT: dict[str, dict[str, RuleMapping]] = {
    # Verified against `p/python` 1.172.0 by listing the rule ids the installed
    # ruleset actually loads. Five earlier entries here were plausible-looking
    # ids that do not exist in it, and a table of ids that never fire is worse
    # than no table: it reads as coverage. Add an entry only after seeing the id
    # in a real run's `unmapped_rules`.
    "semgrep": {
        "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true":
            RuleMapping("INJ-CMD", Severity.HIGH, 7),
        "python.flask.security.audit.debug-enabled.debug-enabled":
            RuleMapping("CFG-DEBUG", Severity.MEDIUM, 8),
    },
    # All six were verified present in `checkov --list` (506 checks) on 3.3.0.
    # Checkov's ids are stable and well-known, which is why an exact table is
    # worth keeping here and was a poor bet for Semgrep.
    "checkov": {
        "CKV_AWS_18": RuleMapping("CFG-IAC", Severity.LOW, 7, "S3 bucket access logging disabled"),
        "CKV_AWS_24": RuleMapping("CFG-IAC", Severity.HIGH, 8,
                                  "Security group allows ingress from 0.0.0.0/0 to port 22"),
        "CKV_AWS_20": RuleMapping("CFG-IAC", Severity.HIGH, 8, "S3 bucket is publicly readable"),
        "CKV_AWS_23": RuleMapping("CFG-IAC", Severity.LOW, 7, "Security group rule has no description"),
        "CKV_DOCKER_1": RuleMapping("CFG-IAC", Severity.MEDIUM, 7, "Container exposes SSH"),
        # `OPEN_ITEMS.md` §18, closed 2026-08-22. This was `CFG-DEFAULT-CREDS`
        # for three weeks — a visible wrong label, kept deliberately, because
        # the obvious correction destroyed data.
        #
        # Retargeting to `CFG-IAC` was tried and reverted: the fingerprint is
        # `(path, internal, symbol, snippet)` and CKV_DOCKER_2 reports on the
        # same Dockerfile at the same line, so sharing an id collapsed the pair
        # in dedup and **silently deleted 16 findings**. The fix is therefore a
        # *new* taxonomy id, which cannot collide with `CFG-IAC` by
        # construction. `test_two_rules_on_one_line_collapse_if_they_share_a_
        # taxonomy_id` still pins the mechanism that made the first attempt fail.
        "CKV_DOCKER_3": RuleMapping("CFG-CONTAINER-PRIVILEGE", Severity.MEDIUM, 7,
                                    "Container runs as root"),
        "CKV_K8S_20": RuleMapping("CFG-IAC", Severity.HIGH, 8, "Container allows privilege escalation"),
    },
}


def mapping_digest() -> str:
    """A stable hash of every table that decides a finding's `internal` id.

    WHY A CACHE NEEDS THIS. `Finding.fingerprint` is
    `fingerprint(path, internal, symbol, snippet)`, so `internal` is an *input*
    to the identity that `findings/delta.py` matches head findings against
    cached baseline ones. Change a mapping and every affected finding's
    fingerprint changes on the head side while the cached baseline still holds
    the old hashes — no match, so a pre-existing finding is reported as
    introduced, silently.

    Measured 2026-08-22 on the IaC corpus when `CKV_DOCKER_3` was remapped:
    **32 reported findings became 112**, and the same run against a freshly
    built baseline came back to 32 exactly. Errata §14.49.

    `ProfileCache` has carried `ANALYZER_VERSION` for this class of problem
    since M1; the baseline cache was keyed on `base_sha` alone. This is the
    automatic half of the answer — a human forgetting to bump a constant is the
    failure mode a constant has, and a remap is precisely the edit somebody
    makes without thinking about caches.
    """
    parts: list[str] = []
    for tool in sorted(_EXACT):
        for rule in sorted(_EXACT[tool]):
            parts.append(f"e|{tool}|{rule}|{_EXACT[tool][rule].internal}")
    for pattern, m in _TOKENS:
        parts.append(f"t|{pattern}|{m.internal}")
    for tool in sorted(_FALLBACK):
        parts.append(f"f|{tool}|{_FALLBACK[tool].internal}")
    # Not `util.fingerprint` — that takes a finding's four fields and means
    # "these are the same defect". This means "these tables are the same
    # tables", and borrowing the other function's shape would make one of them
    # lie about what it identifies.
    return hashlib.sha1("\n".join(parts).encode("utf-8")).hexdigest()[:16]

# Token heuristics over the rule id, tried in order. These are what actually
# classify most of a ruleset, and they are ordered most-specific-first because
# "sql-injection" also contains "injection" and `insecure-deserialization` also
# contains "insecure".
#
# A heuristic match is one confidence point below the same rule mapped exactly.
# That is not false modesty: the exact table means someone read the rule, and
# a substring of an id is weaker evidence than that.
_TOKENS: tuple[tuple[str, RuleMapping], ...] = (
    (r"sql[-_.]?injection|sqli\b|sql[-_.]?string|sqlalchemy[-_.]?text",
     RuleMapping("INJ-SQLI", Severity.HIGH, 6)),
    (r"command[-_.]?injection|subprocess|os[-_.]system|shell[-_.]?(true|injection)"
     r"|system[-_.]?call|spawn[-_.]?process|asyncio[-_.]?shell",
     RuleMapping("INJ-CMD", Severity.HIGH, 6)),
    (r"code[-_.]?(exec|injection|run)|\beval\b|\bexec\b|dynamic[-_.]?import|subinterp",
     RuleMapping("INJ-CODE-EXEC", Severity.HIGH, 6)),
    (r"deserial|\bpickle\b|marshal|unsafe[-_.]?yaml|yaml[-_.]?load",
     RuleMapping("INJ-DESERIALIZE", Severity.HIGH, 6)),
    (r"\bssti\b|template[-_.]?injection|autoescape",
     RuleMapping("INJ-SSTI", Severity.HIGH, 6)),
    (r"\bxss\b|cross[-_.]?site[-_.]?scripting|mark[-_.]?safe|raw[-_.]?html"
     r"|html[-_.]?(format|string|response)",
     RuleMapping("INJ-XSS", Severity.MEDIUM, 6)),
    (r"path[-_.]?traversal|zip[-_.]?slip|directory[-_.]?traversal",
     RuleMapping("BAC-PATH-TRAVERSAL", Severity.HIGH, 6)),
    (r"\bssrf\b|server[-_.]?side[-_.]?request|tainted[-_.]?url[-_.]?host",
     RuleMapping("BAC-SSRF", Severity.HIGH, 6)),
    (r"missing[-_.]?authz|authorization[-_.]?(missing|bypass)|permission[-_.]?classes",
     RuleMapping("BAC-MISSING-AUTHZ", Severity.HIGH, 6)),
    (r"\bcors\b|allow[-_.]?origin", RuleMapping("CFG-CORS", Severity.MEDIUM, 6)),
    (r"debug[-_.]?(enabled|true|mode)", RuleMapping("CFG-DEBUG", Severity.MEDIUM, 6)),
    (r"secure[-_.]?cookie|httponly|samesite|security[-_.]?header|hsts",
     RuleMapping("CFG-HEADERS", Severity.MEDIUM, 6)),
    (r"default[-_.]?cred|run[-_.]?as[-_.]?root|privileg",
     RuleMapping("CFG-DEFAULT-CREDS", Severity.MEDIUM, 6)),
    (r"weak[-_.]?(hash|cipher|crypto|random|ssl|tls)|\bmd5\b|\bsha1\b|\bsha224\b|\bdes\b"
     r"|insecure[-_.]?(hash|cipher)|cipher[-_.]?(algorithm|mode)|insufficient[-_.]?\w+[-_.]?key[-_.]?size"
     r"|empty[-_.]?aes[-_.]?key|mode[-_.]?without[-_.]?authentication|insecure[-_.]?uuid",
     RuleMapping("CRY-WEAK-ALGO", Severity.MEDIUM, 6)),
    (r"verify[-_.]?false|insecure[-_.]?transport|http[-_.]?url|disable[-_.]?tls|ssl[-_.]?verify"
     r"|cert[-_.]?validation|not[-_.]?https|unverified[-_.]?ssl|require[-_.]?encryption"
     r"|ssl[-_.]?wrap[-_.]?socket",
     RuleMapping("CRY-NO-TLS", Severity.MEDIUM, 6)),
    # `jwt-none-alg`, `unverified-jwt-decode`: a token accepted without its
    # signature being checked is an authentication failure, not a crypto one.
    (r"\bjwt\b", RuleMapping("AUTH-WEAK-TOKEN", Severity.HIGH, 6)),
    (r"hardcoded|hard[-_.]?coded|secret|credential|api[-_.]?key",
     RuleMapping("SEC-PASSWORD", Severity.HIGH, 6)),
    (r"log(ging)?[-_.]?(sensitive|pii|secret)|sensitive[-_.]?data[-_.]?log",
     RuleMapping("LOG-SENSITIVE", Severity.MEDIUM, 6)),
    (r"vulnerable[-_.]?(dependency|package)|known[-_.]?vuln",
     RuleMapping("SC-VULN-DEP", Severity.HIGH, 6)),
)

_COMPILED = tuple((re.compile(pat, re.I), m) for pat, m in _TOKENS)


# Per-tool last resort, for tools whose *whole output* belongs to one family
# even when the individual check is unread. Every Checkov check is a
# misconfiguration by construction, so `CFG-IAC` is a fact about the tool rather
# than a guess about the rule — which is exactly what `TOOL-UNMAPPED` is not.
# Semgrep deliberately has no entry: its rules span the entire taxonomy, so
# there is nothing true to say about an unread one.
_FALLBACK: dict[str, RuleMapping] = {
    "checkov": RuleMapping("CFG-IAC", None, 5, origin="fallback"),
}


def map_rule(tool: str, rule_id: str) -> RuleMapping:
    """`(tool, rule_id)` -> taxonomy. Never raises, never returns None."""
    exact = _EXACT.get(tool, {}).get(rule_id)
    if exact is not None:
        return exact
    for pattern, mapping in _COMPILED:
        if pattern.search(rule_id or ""):
            # One point below the exact table (see `_TOKENS`).
            return RuleMapping(mapping.internal, mapping.severity,
                               max(1, mapping.confidence - 1), mapping.title,
                               origin="heuristic")
    return _FALLBACK.get(tool, UNMAPPED)


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------

@dataclass
class SarifResult:
    rule_id: str
    message: str
    path: str
    start_line: int
    end_line: int
    level: str = "warning"
    security_severity: float | None = None
    snippet: str = ""
    properties: dict = field(default_factory=dict)


def _rel(uri: str, root: str | None) -> str:
    """SARIF artifact URI -> repo-relative path.

    Tools disagree here: Semgrep emits repo-relative, Checkov emits paths with
    a leading `/`, and both can emit `file://` absolutes when run with an
    absolute target. A finding whose path does not join against the manifest is
    invisible to delta scoping and to the report, so this is not cosmetic.
    """
    uri = (uri or "").strip()
    for prefix in ("file://",):
        if uri.startswith(prefix):
            uri = uri[len(prefix):]
    if root:
        root_p = str(PurePosixPath(root))
        if uri.startswith(root_p):
            uri = uri[len(root_p):]
    return uri.lstrip("/")


def read_sarif(doc: str | dict, root: str | None = None) -> list[SarifResult]:
    """Parse SARIF 2.1.0 into flat results. Tolerant by design.

    SARIF is the stable interface between us and tools we do not control
    (phase-3 §3a), which only holds if a missing optional field degrades one
    result instead of the run. Every field below except `ruleId` is optional in
    the spec and absent in at least one real tool's output.
    """
    if isinstance(doc, str):
        # Tools print things before their report. Checkov emits an ASCII-art
        # banner and a version-update notice ahead of any JSON, and `--quiet`
        # does not suppress either, so the document is taken from the first
        # brace rather than from the first byte.
        start = doc.find("{")
        doc = json.loads(doc[start:] if start > 0 else doc)
    out: list[SarifResult] = []
    for run in doc.get("runs", []) or []:
        # Rule metadata lives once per run; results reference it by id or index.
        rules = (run.get("tool", {}).get("driver", {}) or {}).get("rules", []) or []
        by_id = {r.get("id"): r for r in rules if r.get("id")}
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or ""
            if not rule_id and isinstance(res.get("ruleIndex"), int):
                idx = res["ruleIndex"]
                if 0 <= idx < len(rules):
                    rule_id = rules[idx].get("id", "")
            rule = by_id.get(rule_id, {})
            locs = res.get("locations") or []
            phys = (locs[0].get("physicalLocation") if locs else {}) or {}
            region = phys.get("region") or {}
            start = int(region.get("startLine") or 0)
            props = {**(rule.get("properties") or {}), **(res.get("properties") or {})}
            sec = props.get("security-severity")
            try:
                sec_f = float(sec) if sec is not None else None
            except (TypeError, ValueError):
                sec_f = None
            out.append(SarifResult(
                rule_id=rule_id,
                message=((res.get("message") or {}).get("text") or "").strip(),
                path=_rel((phys.get("artifactLocation") or {}).get("uri", ""), root),
                start_line=start,
                end_line=int(region.get("endLine") or start or 0),
                level=(res.get("level")
                       or (rule.get("defaultConfiguration") or {}).get("level")
                       or "warning"),
                security_severity=sec_f,
                snippet=((region.get("snippet") or {}).get("text") or "").strip(),
                properties=props,
            ))
    return out


_LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def severity_from_sarif(level: str, security_severity: float | None) -> Severity:
    """SARIF severity -> ours, preferring the numeric score.

    `level` has four values and tools put almost everything in `error`, so it
    cannot separate an RCE from a missing security header. `security-severity`
    is a CVSS-style 0-10 that both Semgrep and Checkov emit, and the bands below
    are the GitHub code-scanning convention.
    """
    if security_severity is not None:
        if security_severity >= 9.0:
            return Severity.CRITICAL
        if security_severity >= 7.0:
            return Severity.HIGH
        if security_severity >= 4.0:
            return Severity.MEDIUM
        if security_severity > 0:
            return Severity.LOW
        return Severity.INFO
    return _LEVEL_SEVERITY.get((level or "").lower(), Severity.MEDIUM)


# ---------------------------------------------------------------------------
# The finding factory
# ---------------------------------------------------------------------------

def cap(severity: Severity, ceiling: Severity) -> Severity:
    """`severity`, or `ceiling` if it exceeds it."""
    return ceiling if severity.rank > ceiling.rank else severity


def cap_for_test(severity: Severity) -> Severity:
    """Test-code severity ceiling. The one copy of a rule written three times."""
    return cap(severity, Severity.MEDIUM)


_REMEDIATION: dict[str, str] = {
    "INJ-SQLI": "Use parameter binding; never build SQL by string interpolation.",
    "INJ-CMD": "Pass an argument list instead of a shell string, or quote with shlex.quote().",
    "INJ-CODE-EXEC": "Replace dynamic evaluation with an explicit dispatch table.",
    "INJ-DESERIALIZE": "Deserialize untrusted data with a safe format (json, yaml.safe_load).",
    "INJ-SSTI": "Render with autoescaping on and pass data as template variables, not as template text.",
    "INJ-XSS": "Escape on output; do not mark untrusted values as safe.",
    "BAC-PATH-TRAVERSAL": "Resolve the path and verify it stays inside the intended root.",
    "BAC-SSRF": "Validate the destination against an allowlist before making the request.",
    "BAC-MISSING-AUTHZ": "Apply the project's authorization check to this endpoint.",
    "SC-VULN-DEP": "Upgrade to a fixed version, or pin away from the affected range.",
    "CRY-WEAK-ALGO": "Use a current algorithm (SHA-256+/AES-GCM) for security purposes.",
    "CRY-NO-TLS": "Use TLS and leave certificate verification enabled.",
    "CFG-IAC": "Apply the hardened setting this check describes.",
}
_GENERIC_REMEDIATION = ("Review the flagged construct and apply the tool's guidance for "
                        "this rule.")


def make_finding(
    *,
    internal: str,
    title: str,
    severity: Severity,
    confidence: int,
    detector: DetectorKind,
    tool: str,
    rule_id: str | None,
    path: str,
    start_line: int,
    end_line: int | None = None,
    snippet: str = "",
    why: str,
    symbol: str | None = None,
    is_test: bool = False,
    status: Status = Status.CANDIDATE,
    remediation: str | None = None,
    data_flow: list[FlowNode] | None = None,
    reachability: Reachability | None = None,
    cvss_vector: str | None = None,
) -> Finding:
    """Build one `Finding` with the invariants every adapter shares.

    `status` defaults to `candidate` because that is what phase-3 §3a says a
    deterministic detector produces: 3a buys recall and 3c buys precision. The
    consequence is worth stating plainly — until the verifier lands at M4, a
    detector added here raises what the report *sees*, not what the gate
    *blocks*, since `policy.gate()` triggers only on `validated`.
    """
    if is_test:
        severity = cap_for_test(severity)
    snippet = (snippet or "").strip()[:MAX_SNIPPET_CHARS]
    end_line = end_line or start_line
    return Finding(
        id=new_id(),
        # Line numbers are deliberately not in the fingerprint (cross-cutting
        # §6) — it has to survive the line shifts a PR causes, or every finding
        # in a file with an insertion above it would look newly introduced to
        # `findings/delta.py`.
        fingerprint=fingerprint(path, internal, symbol, snippet or f"{rule_id}"),
        title=title,
        taxonomy=lookup(internal),
        severity=severity,
        cvss_vector=cvss_vector,
        confidence=max(0, min(10, confidence)),
        status=status,
        # Not the adapter's call — see the module docstring.
        introduced_by_pr=True,
        location=Location(file=path, start_line=start_line, end_line=end_line,
                          symbol=symbol),
        data_flow=data_flow or [],
        evidence=[Evidence(file=path, lines=(str(start_line) if end_line == start_line
                                             else f"{start_line}-{end_line}"),
                           snippet=snippet, why=why)],
        reachability=reachability or Reachability(),
        remediation=Remediation(
            summary=remediation or _REMEDIATION.get(internal, _GENERIC_REMEDIATION),
        ),
        provenance=Provenance(detector=detector, tool=tool, rule_id=rule_id),
    )


def from_sarif(
    results: list[SarifResult],
    *,
    tool: str,
    detector: DetectorKind,
    is_test: dict[str, bool] | None = None,
) -> tuple[list[Finding], dict]:
    """SARIF results -> findings, plus the mapping report for telemetry.

    The report is not decoration. An unmapped rule is silent by nature: the
    finding still appears, correctly located, with a plausible title, and
    nothing in the output says "we do not know what this rule means". The
    counts and the rule-id list are the only place that shows.
    """
    is_test = is_test or {}
    findings: list[Finding] = []
    unmapped: set[str] = set()
    heuristic: set[str] = set()
    origins: dict[str, int] = {"exact": 0, "heuristic": 0, "fallback": 0, "unmapped": 0}
    for res in results:
        mapping = map_rule(tool, res.rule_id)
        origins[mapping.origin] = origins.get(mapping.origin, 0) + 1
        if mapping.origin == "unmapped":
            unmapped.add(res.rule_id)
        elif mapping.origin == "heuristic":
            heuristic.add(res.rule_id)
        severity = mapping.severity or severity_from_sarif(res.level, res.security_severity)
        if not mapping.classified:
            # An unclassified rule may not out-shout a classified one, however
            # loudly the tool scored it.
            severity = cap(severity, Severity.MEDIUM)
        findings.append(make_finding(
            internal=mapping.internal,
            title=mapping.title or (res.message.split("\n")[0][:120] or res.rule_id),
            severity=severity,
            confidence=mapping.confidence,
            detector=detector,
            tool=tool,
            rule_id=res.rule_id,
            path=res.path,
            start_line=res.start_line,
            end_line=res.end_line,
            snippet=res.snippet,
            why=res.message or f"{tool} rule {res.rule_id} matched.",
            is_test=is_test.get(res.path, False),
        ))
    report = {
        "results": len(results),
        "mapped_exact": origins["exact"],
        "mapped_heuristic": origins["heuristic"],
        "mapped_fallback": origins["fallback"],
        "unmapped": origins["unmapped"],
        "heuristic_rules": sorted(heuristic),
        "unmapped_rules": sorted(unmapped),
    }
    return findings, report
