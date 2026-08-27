"""Semgrep adapter (phase-3 §3a, tooling.md #6).

Breadth. Semgrep's community rulesets encode a large body of language- and
framework-specific knowledge that we are never going to re-derive, and SARIF
keeps the coupling to a data format rather than to a CLI shape.

SCOPE: the PR's changed files, in the **head** checkout. Not the whole repo —
a repo-wide Semgrep run on every PR reports the same pre-existing findings
forever, which is precisely the noise `findings/delta.py` exists to remove, and
it is cheaper not to generate them.

`--baseline-commit` (config `baseline_aware`) makes Semgrep do its own
diff-scoping and report only results absent at the base commit. It is left on by
default, and it is worth knowing that it changes the meaning of an empty result
set: with it, "no findings" means "nothing new", not "nothing here". Our own
delta scoping runs regardless, so the two are belt and braces rather than
either being load-bearing alone.

VALIDATED against semgrep 1.172.0 / `p/python` (151 rules) on 2026-08-05: the
argv runs, the SARIF parses, and a real `subprocess.run(..., shell=True)` maps
to `INJ-CMD`. Two things that run found and no fixture could:
`--baseline-commit` with an unresolvable sha is a hard exit-2 failure rather
than an empty result (see `_usable_baseline`), and five of the six rule ids
originally in `normalize._EXACT` do not exist in the ruleset at all.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from pr_review.detect.base import AdapterRun, Detector, ExternalTool, ScanTarget
from pr_review.detect.normalize import from_sarif, read_sarif
from pr_review.schema import DetectorKind, Finding

DEFAULT_RULESET = "p/python"


class SemgrepDetector(Detector, ExternalTool):
    kind = DetectorKind.SAST
    name = "semgrep"
    binary = "semgrep"

    def __init__(self, ruleset: str = DEFAULT_RULESET, head_dir: str | Path | None = None,
                 baseline_commit: str | None = None, timeout_s: int = 300,
                 configs: tuple[str, ...] = ()) -> None:
        self.ruleset = ruleset
        self.head_dir = Path(head_dir) if head_dir else None
        self.baseline_commit = baseline_commit
        self.timeout_s = timeout_s
        self.configs = configs

    def applicable(self, targets: list[ScanTarget]) -> bool:
        return bool(self.head_dir) and any(self._scannable(t) for t in targets)

    @staticmethod
    def _scannable(t: ScanTarget) -> bool:
        return not (t.is_binary or t.is_generated)

    def run(self, targets: list[ScanTarget]) -> list[Finding]:
        return self.scan(targets).findings

    def _usable_baseline(self) -> str | None:
        """`baseline_commit` if git can resolve it in the head checkout, else None.

        Found by running it: Semgrep exits 2 — a hard failure, not "no findings"
        — when `--baseline-commit` names a sha it cannot reach, and the fixture
        and offline `--diff-file` runs both carry a `base_sha` that exists in no
        repository. Passing the flag unconditionally therefore turned every such
        run into `status=error` and silently lost SAST coverage for it.
        """
        if not (self.baseline_commit and self.head_dir):
            return None
        try:
            proc = subprocess.run(
                ["git", "-C", str(self.head_dir), "rev-parse", "--verify", "--quiet",
                 f"{self.baseline_commit}^{{commit}}"],
                capture_output=True, text=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return self.baseline_commit if proc.returncode == 0 else None

    def scan(self, targets: list[ScanTarget]) -> AdapterRun:
        if self.head_dir is None:
            return AdapterRun("not_applicable", notes=[
                "semgrep detector skipped: no head checkout to scan (--head-dir)."])
        if not self.available:
            return AdapterRun("missing_tool", notes=[self.unavailable_note()])

        paths = [t.path for t in targets
                 if self._scannable(t) and (self.head_dir / t.path).is_file()]
        if not paths:
            return AdapterRun("not_applicable", notes=[
                "semgrep detector skipped: no changed file exists in the head checkout."])

        argv = [self.binary, "scan", "--sarif", "--quiet", "--metrics=off",
                "--config", self.ruleset]
        for extra in self.configs:
            argv += ["--config", extra]
        notes: list[str] = []
        baseline = self._usable_baseline()
        if self.baseline_commit and baseline is None:
            notes.append(
                f"semgrep ran without --baseline-commit: {self.baseline_commit[:12]} "
                f"does not resolve in {self.head_dir}. Semgrep therefore reports "
                f"pre-existing findings too; findings/delta.py still scopes them.")
        if baseline:
            argv += ["--baseline-commit", baseline]
        argv += paths

        # Semgrep exits 1 when it has findings and 2+ on real failures.
        result = self.invoke(argv, cwd=self.head_dir, ok_returncodes=(0, 1))
        if not result.ok:
            return AdapterRun("error", notes=notes + [f"semgrep failed: {result.error}"],
                              detail={"argv": argv})
        try:
            sarif = read_sarif(result.stdout)
        except (ValueError, KeyError, TypeError) as exc:
            return AdapterRun("error", notes=notes + [
                f"semgrep produced output that is not SARIF ({type(exc).__name__}: {exc})."],
                detail={"argv": argv})

        findings, report = from_sarif(
            sarif, tool=self.name, detector=DetectorKind.SAST,
            is_test={t.path: t.is_test for t in targets},
        )
        if report["unmapped_rules"]:
            notes.append(
                f"{report['unmapped']} semgrep result(s) came from "
                f"{len(report['unmapped_rules'])} rule(s) with no taxonomy mapping; "
                f"they are reported as TOOL-UNMAPPED and cannot gate: "
                f"{', '.join(report['unmapped_rules'][:5])}"
                + ("..." if len(report["unmapped_rules"]) > 5 else ""))
        return AdapterRun("ran", findings=findings, notes=notes,
                          detail={**report, "files": len(paths),
                                  "duration_s": round(result.duration_s, 3),
                                  "baseline_commit": baseline})
