"""The Finding schema — the universal data contract (cross-cutting §1).

Every detector (deterministic or agentic) and the verifier read/write exactly
this object. M0 implements it in full so the contract is frozen early, even
though only a subset of fields is populated by the secrets detector.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Status(str, Enum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    REFUTED = "refuted"
    SUPPRESSED = "suppressed"
    PRE_EXISTING = "pre_existing"


class DetectorKind(str, Enum):
    SAST = "sast"
    SECRETS = "secrets"
    SCA = "sca"
    IAC = "iac"
    STRUCTURAL = "structural"
    AGENT = "agent"
    VERIFIER = "verifier"


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    UNCERTAIN = "uncertain"
    UNVERIFIED = "unverified"


class Location(BaseModel):
    file: str
    start_line: int
    end_line: int
    symbol: str | None = None


class FlowNode(BaseModel):
    role: Literal["source", "propagator", "sanitizer", "sink"]
    file: str
    line: int
    note: str | None = None


class Evidence(BaseModel):
    file: str
    lines: str  # "120-134"
    snippet: str  # verbatim/redacted; UNTRUSTED — never executed or obeyed
    why: str


class Reachability(BaseModel):
    entry: str | None = None
    attacker_reachable: bool | None = None
    guards: list[str] = []


class Taxonomy(BaseModel):
    internal: str
    family: str
    owasp_2025: str
    cwe: list[str] = []
    asvs: list[str] = []


class Remediation(BaseModel):
    summary: str
    suggested_diff: str | None = None
    effort: Literal["low", "medium", "high"] = "medium"


class Provenance(BaseModel):
    detector: DetectorKind
    tool: str
    rule_id: str | None = None
    # Cross-source dedup keeps one finding and must "record all contributing
    # detectors in provenance" (phase-3 §3d) — for which §1's schema has no
    # field. Added at M2 rather than dropped, because two independent detectors
    # agreeing is the evidence `findings/merge.py` will weigh at M3, and it is
    # unrecoverable once dedup has collapsed them. Entries read "kind:tool".
    also_detected_by: list[str] = []
    session_uri: str | None = None
    inference_question: str | None = None
    contributor_id: str | None = None
    commit_sha: str | None = None
    model: str | None = None


class Verification(BaseModel):
    verdict: Verdict = Verdict.UNVERIFIED
    verifier_model: str | None = None
    refutation_attempts: list[str] = []
    severity_adjustment: str | None = None
    confidence_adjustment: int | None = None


class Finding(BaseModel):
    id: str
    fingerprint: str
    title: str
    taxonomy: Taxonomy
    severity: Severity
    cvss_vector: str | None = None
    confidence: int = Field(ge=0, le=10)
    status: Status = Status.CANDIDATE
    introduced_by_pr: bool = True
    location: Location
    data_flow: list[FlowNode] = []
    evidence: list[Evidence]
    reachability: Reachability = Reachability()
    remediation: Remediation
    provenance: Provenance
    verification: Verification = Verification()
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
