"""Infrastructure-as-code adapter — Checkov (phase-3 §3a, tooling.md #8).

Terraform, Dockerfiles, Kubernetes manifests and the rest of the A02 surface.
Phase 0 already flags these files (`FileChange.is_iac`), so this adapter scans
that set and nothing else: an IaC scanner pointed at a whole repo spends its
time on the same unchanged modules every run.

Checkov's check ids (`CKV_AWS_20`, `CKV_DOCKER_3`) are stable and readable, so
the exact table in `detect/normalize.py` is worth growing here; everything else
falls to `CFG-IAC`. Note that unlike a Semgrep miss, an unmapped Checkov check
is *still correctly classified as a misconfiguration* — every Checkov check is
one by construction — which is why it lands on a real family rather than on
`TOOL-UNMAPPED`.

VALIDATED against checkov 3.3.0 on 2026-08-05, which corrected two assumptions
no fixture could have caught. Checkov writes its SARIF to a **file** and prints
a human summary to stdout, so there is nothing to parse from the pipe; and
`--output-file-path console` is not a way to say "stdout" — it is read as a
directory name, and the first real run left a stray `console/` directory inside
the checkout being scanned.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from pr_review.detect.base import AdapterRun, Detector, ExternalTool, ScanTarget
from pr_review.detect.normalize import from_sarif, read_sarif
from pr_review.schema import DetectorKind, Finding


class IaCDetector(Detector, ExternalTool):
    kind = DetectorKind.IAC
    name = "iac"
    binary = "checkov"

    def __init__(self, head_dir: str | Path | None = None, iac_paths: set[str] | None = None,
                 timeout_s: int = 300) -> None:
        self.head_dir = Path(head_dir) if head_dir else None
        # Which paths are IaC is Phase 0's judgement (`extract/classify.py`),
        # not a second opinion formed here.
        self.iac_paths = iac_paths or set()
        self.timeout_s = timeout_s

    def applicable(self, targets: list[ScanTarget]) -> bool:
        return bool(self.head_dir) and any(t.path in self.iac_paths for t in targets)

    def run(self, targets: list[ScanTarget]) -> list[Finding]:
        return self.scan(targets).findings

    def scan(self, targets: list[ScanTarget]) -> AdapterRun:
        paths = [t.path for t in targets if t.path in self.iac_paths]
        if not paths:
            return AdapterRun("not_applicable", notes=[
                "iac detector skipped: this PR changes no infrastructure-as-code file."])
        if self.head_dir is None:
            return AdapterRun("not_applicable", notes=[
                "iac detector skipped: no head checkout to scan (--head-dir)."])
        if not self.available:
            return AdapterRun("missing_tool", notes=[self.unavailable_note()])

        present = [p for p in paths if (self.head_dir / p).is_file()]
        if not present:
            return AdapterRun("not_applicable", notes=[
                "iac detector skipped: no changed IaC file exists in the head checkout."])

        # Checkov writes its SARIF to a *file* and prints a human summary to
        # stdout, so the report is collected from a temporary directory rather
        # than from the pipe. `--output-file-path console` is not a way to ask
        # for stdout: it is read as a directory name and creates one, which on
        # the first real run left a stray `console/` inside the checkout being
        # scanned.
        with tempfile.TemporaryDirectory(prefix="pr-review-checkov-") as tmp:
            argv = [self.binary, "--quiet", "--compact", "--output", "sarif",
                    "--output-file-path", tmp]
            for p in present:
                argv += ["-f", p]

            # Checkov exits 1 when a check fails, which is its working state.
            result = self.invoke(argv, cwd=self.head_dir, ok_returncodes=(0, 1))
            if not result.ok:
                return AdapterRun("error", notes=[f"checkov failed: {result.error}"],
                                  detail={"argv": argv})
            report_text = self._collect(Path(tmp), result.stdout)

        if report_text is None:
            return AdapterRun("error", notes=[
                "checkov ran but produced no SARIF file and no JSON on stdout; "
                "its output conventions may have changed."], detail={"argv": argv})
        try:
            sarif = read_sarif(report_text, root=str(self.head_dir))
        except (ValueError, KeyError, TypeError) as exc:
            return AdapterRun("error", notes=[
                f"checkov produced output that is not SARIF ({type(exc).__name__}: {exc})."],
                detail={"argv": argv})

        findings, report = from_sarif(
            sarif, tool="checkov", detector=DetectorKind.IAC,
            is_test={t.path: t.is_test for t in targets},
        )
        return AdapterRun("ran", findings=findings,
                          detail={**report, "files": len(present),
                                  "duration_s": round(result.duration_s, 3)})

    @staticmethod
    def _collect(tmp: Path, stdout: str) -> str | None:
        """The SARIF text, from the output directory or (failing that) stdout.

        The filename is not stable across versions — 3.3.0 writes
        `results_sarif.sarif` here and `results.sarif` when no output path is
        given — so the directory is globbed rather than a name assumed. Stdout
        is kept as a fallback in case a later version prints the report again.
        """
        for candidate in sorted(tmp.glob("*.sarif")):
            try:
                return candidate.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        return stdout if "{" in (stdout or "") else None
