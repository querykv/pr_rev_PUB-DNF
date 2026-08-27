"""Canonical taxonomy registry (cross-cutting §2).

M0 shipped only the entries the secrets detector needs. M1 adds the **family**
vocabulary, because Phase-2 routing (`change/classify.py`) has to name the
Phase-3b families a change group should be analyzed by, and a routing table that
invents its own strings is a contract that silently fails to bind.

The full OWASP-2025 / CWE / ASVS mapping tables still arrive as data files
(taxonomy/*.yaml) in later milestones; `lookup()`'s contract is unchanged.
"""
from __future__ import annotations

from pr_review.schema import Taxonomy

# The operational detector families (cross-cutting §2, "Family" column). This is
# the vocabulary Phase 2 routes into and Phase 3b's runner dispatches on, so the
# spelling is the contract — `families()` is the only sanctioned source, and
# `validate_families()` fails loudly rather than letting a typo route a change
# group to a family that will never run.
FAMILIES: tuple[str, ...] = (
    "Broken Access Control",
    "Security Misconfiguration",
    "Software Supply Chain",
    "Cryptographic Failures",
    "Injection",
    "Insecure Design",
    "Authentication Failures",
    "Software/Data Integrity",
    "Logging & Alerting",
    "Exceptional Conditions",
    "Hardcoded Secrets",
    "LLM Safety",
    "Privacy / PII",
)

# Families with no agent in Phase 3b — routed, but handled deterministically in
# 3a. Phase 2 records them so the coverage denominator stays honest (a change
# that is only a dependency bump is *covered*, not *skipped*).
DETERMINISTIC_ONLY: frozenset[str] = frozenset({"Software Supply Chain"})

# The home for a finding from a rule we have not classified (`TOOL-UNMAPPED`).
#
# It is deliberately NOT in `FAMILIES`, and that is the whole design. External
# rulesets are large and move: `p/python` alone carries hundreds of rules and
# gains more with every release, so an unmapped rule id is the normal case, not
# an error. The two obvious responses are both wrong — dropping the finding
# costs recall, which is the one thing 3a exists to provide, and guessing a
# family puts a rule we have not read into an agent's routing table and into
# the coverage denominator, where it reads as analyzed.
#
# So an unmapped rule reports, under a family that no Phase-3b runner claims
# and `validate_families()` rejects. `detect/normalize.py` additionally caps it
# at MEDIUM and leaves it `candidate`, so an unclassified rule cannot reach the
# gate, and records its rule id in telemetry so the map grows from evidence.
UNMAPPED_FAMILY = "Unmapped"

# internal_id -> (family, owasp_2025, cwe[])
_TABLE: dict[str, dict] = {
    "SEC-API-KEY": {"family": "Hardcoded Secrets", "owasp_2025": "A02", "cwe": ["CWE-798"]},
    "SEC-PRIVATE-KEY": {"family": "Hardcoded Secrets", "owasp_2025": "A02", "cwe": ["CWE-798"]},
    "SEC-PASSWORD": {"family": "Hardcoded Secrets", "owasp_2025": "A02", "cwe": ["CWE-798", "CWE-259"]},
    "SEC-AWS-KEY": {"family": "Hardcoded Secrets", "owasp_2025": "A02", "cwe": ["CWE-798"]},
    "SEC-TOKEN": {"family": "Hardcoded Secrets", "owasp_2025": "A02", "cwe": ["CWE-798"]},
    # The injection sentinel (safety/sentinel.py). Prompt injection is both a
    # threat we defend against and a class we report (cross-cutting §9).
    "LLM-PROMPT-INJ": {"family": "LLM Safety", "owasp_2025": "A05",
                       "cwe": ["CWE-77", "CWE-1427"]},
    # Not prompt injection itself — the *delivery mechanism* for one. Text that
    # reads differently to a human than to a parser is an integrity problem
    # first (Trojan Source, CWE-1007), which is why it is its own id rather
    # than a fifth LLM-PROMPT-INJ rule.
    "INTEG-HIDDEN-TEXT": {"family": "Software/Data Integrity", "owasp_2025": "A08",
                          "cwe": ["CWE-1007", "CWE-94"]},

    # -- M2: what the deterministic detectors emit (cross-cutting §2) -------
    # Spellings come from §2's table, not from the detectors. A detector that
    # wants an id not listed there is making a taxonomy decision, and it should
    # be made here, once, rather than inside an adapter.

    # Injection (A05). `INJ-SSTI` covers the CPG's whole `template` sink class:
    # the catalog groups `render_template_string` with `mark_safe`, and taint
    # alone cannot separate server-side template evaluation from unescaped HTML.
    # `INJ-XSS` stays separate because Semgrep *can* tell them apart.
    "INJ-SQLI": {"family": "Injection", "owasp_2025": "A05", "cwe": ["CWE-89"]},
    "INJ-CMD": {"family": "Injection", "owasp_2025": "A05", "cwe": ["CWE-78"]},
    "INJ-CODE-EXEC": {"family": "Injection", "owasp_2025": "A05",
                      "cwe": ["CWE-94", "CWE-95"]},
    "INJ-SSTI": {"family": "Injection", "owasp_2025": "A05",
                 "cwe": ["CWE-1336", "CWE-79"]},
    "INJ-XSS": {"family": "Injection", "owasp_2025": "A05", "cwe": ["CWE-79"]},
    "INJ-DESERIALIZE": {"family": "Injection", "owasp_2025": "A05", "cwe": ["CWE-502"]},

    # Broken Access Control (A01) — which in 2025 absorbs SSRF and path traversal.
    "BAC-MISSING-AUTHZ": {"family": "Broken Access Control", "owasp_2025": "A01",
                          "cwe": ["CWE-862"]},
    "BAC-IDOR": {"family": "Broken Access Control", "owasp_2025": "A01",
                 "cwe": ["CWE-639"]},
    "BAC-PATH-TRAVERSAL": {"family": "Broken Access Control", "owasp_2025": "A01",
                           "cwe": ["CWE-22"]},
    "BAC-SSRF": {"family": "Broken Access Control", "owasp_2025": "A01",
                 "cwe": ["CWE-918"]},

    # Software Supply Chain (A03).
    "SC-VULN-DEP": {"family": "Software Supply Chain", "owasp_2025": "A03",
                    "cwe": ["CWE-1395", "CWE-1035"]},
    "SC-UNPINNED": {"family": "Software Supply Chain", "owasp_2025": "A03",
                    "cwe": ["CWE-1357"]},

    # Security Misconfiguration (A02). `CFG-IAC` is the catch-all for a Checkov
    # check we have not classified individually — it is still a *classified*
    # family, unlike TOOL-UNMAPPED, because every Checkov check is by definition
    # a misconfiguration.
    "CFG-DEBUG": {"family": "Security Misconfiguration", "owasp_2025": "A02",
                  "cwe": ["CWE-489"]},
    "CFG-CORS": {"family": "Security Misconfiguration", "owasp_2025": "A02",
                 "cwe": ["CWE-942"]},
    "CFG-HEADERS": {"family": "Security Misconfiguration", "owasp_2025": "A02",
                    "cwe": ["CWE-614", "CWE-1021"]},
    "CFG-DEFAULT-CREDS": {"family": "Security Misconfiguration", "owasp_2025": "A02",
                          "cwe": ["CWE-1188", "CWE-798"]},
    # Added 2026-08-22 to close `OPEN_ITEMS.md` §18. `CKV_DOCKER_3` ("ensure a
    # user for the container has been created") had been filed under
    # `CFG-DEFAULT-CREDS`, which is a different defect: running as root is a
    # privilege misconfiguration, not a credential left at its default. The IaC
    # corpus produced 16 of them, every one carrying a family that would route
    # it to the wrong agent.
    #
    # It is a NEW id rather than a retarget to `CFG-IAC` because that was tried
    # and reverted: `CKV_DOCKER_2` reports on the same Dockerfile at the same
    # line, and the fingerprint is `(path, internal, symbol, snippet)`, so
    # sharing an id collapsed the pair in dedup and silently deleted 16
    # findings. A distinct id cannot collide with `CFG-IAC` by construction.
    #
    # CWE-250/269 were chosen after checking they cannot move the benchmark's
    # recall ceiling: neither is in `in_scope_cwes()` today, neither matches any
    # of the labelled corpus's 17 ground-truth CWEs under `cwe_match`, and
    # neither appears in any `scoring._CWE_GROUPS` group. `scope.py` reads this
    # table, so that check is the precondition §18 blocked on, and a test now
    # asserts the corpus's in-scope count is unchanged at 9/36.
    "CFG-CONTAINER-PRIVILEGE": {"family": "Security Misconfiguration",
                                "owasp_2025": "A02",
                                "cwe": ["CWE-250", "CWE-269"]},
    "CFG-IAC": {"family": "Security Misconfiguration", "owasp_2025": "A02",
                "cwe": ["CWE-16"]},

    # Authentication Failures (A07). Added when `p/python` turned out to carry
    # `jwt-none-alg` and `unverified-jwt-decode`: a token accepted without its
    # signature checked is an auth failure, not a crypto one.
    "AUTH-WEAK-TOKEN": {"family": "Authentication Failures", "owasp_2025": "A07",
                        "cwe": ["CWE-347", "CWE-287"]},

    # Cryptographic Failures (A04).
    "CRY-WEAK-ALGO": {"family": "Cryptographic Failures", "owasp_2025": "A04",
                      "cwe": ["CWE-327", "CWE-328"]},
    "CRY-NO-TLS": {"family": "Cryptographic Failures", "owasp_2025": "A04",
                   "cwe": ["CWE-319"]},

    # Logging & Alerting (A09). The CPG's `log` sink class is not this — see
    # `detect/structural.py` for why an untrusted-source-to-log path is a
    # different question from a sensitive-value-to-log one.
    "LOG-SENSITIVE": {"family": "Logging & Alerting", "owasp_2025": "A09",
                      "cwe": ["CWE-532"]},

    # A tool fired a rule we have not classified. See `UNMAPPED_FAMILY`.
    "TOOL-UNMAPPED": {"family": UNMAPPED_FAMILY, "owasp_2025": "", "cwe": []},
}


def lookup(internal: str) -> Taxonomy:
    entry = _TABLE.get(internal)
    if entry is None:
        raise KeyError(f"unknown taxonomy id: {internal!r} (not in registry)")
    return Taxonomy(internal=internal, **entry)


def known_ids() -> list[str]:
    return sorted(_TABLE)


def families() -> list[str]:
    return list(FAMILIES)


def validate_families(names: list[str]) -> list[str]:
    """Return `names` unchanged, or raise on anything not in the registry.

    Called by the Phase-2 routing table. A misspelled family would otherwise
    produce a change group that no Phase-3b runner claims — a coverage hole that
    reads as "analyzed" in the report.
    """
    unknown = [n for n in names if n not in FAMILIES]
    if unknown:
        raise KeyError(
            f"unknown detector family/families: {', '.join(sorted(unknown))} "
            f"(registry has: {', '.join(FAMILIES)})"
        )
    return names
