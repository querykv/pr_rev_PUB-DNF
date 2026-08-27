"""SARIF 2.1.0 emitter (cross-cutting §7). Enables GitHub/GitLab code-scanning."""
from __future__ import annotations

from pr_review import __version__
from pr_review.findings.schema import NormalizedFindingSet
from pr_review.schema import Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def build_sarif(fset: NormalizedFindingSet) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in fset.findings:
        rid = f.taxonomy.internal
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.taxonomy.family.replace(" ", ""),
                "shortDescription": {"text": f.taxonomy.family},
                "properties": {
                    "owasp-2025": f.taxonomy.owasp_2025,
                    "cwe": f.taxonomy.cwe,
                    "tags": ["security", f.taxonomy.family],
                },
            }
        ev = f.evidence[0] if f.evidence else None
        msg = f.title + (f" — {ev.why}" if ev else "")
        results.append({
            "ruleId": rid,
            "level": _LEVEL[f.severity],
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.file},
                    "region": {"startLine": f.location.start_line, "endLine": f.location.end_line},
                }
            }],
            "partialFingerprints": {"prReviewFingerprint/v1": f.fingerprint},
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence,
                "status": f.status.value,
                "introducedByPr": f.introduced_by_pr,
                "detector": f.provenance.tool,
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pr-review",
                "version": __version__,
                "informationUri": "https://example.invalid/pr-review",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
