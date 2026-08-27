"""Detector adapter interface (overview §7.3, phase-3 §3a).

Every deterministic detector normalizes its native output to Finding objects with
status=candidate. M0 shipped only the secrets detector; M2 adds the
semgrep/sca/iac/structural adapters behind the same interface.

THE RESILIENCE CONTRACT (phase-3 §3a: "missing tool -> adapter disabled with a
telemetry warning; degrade, don't crash"). `ExternalTool` below is that contract
in code. It matters more than it looks: a security tool that silently reports
nothing because its scanner is not installed is indistinguishable, in its
output, from one that looked and found nothing. So absence is a recorded state
with a reason string, not an empty list.
"""
from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from pr_review.schema import DetectorKind, Finding


@dataclass
class ScanTarget:
    """A changed file with the content of its added lines (what detectors scan)."""
    path: str
    is_test: bool = False
    is_generated: bool = False
    is_binary: bool = False
    added_lines: list[tuple[int, str]] = field(default_factory=list)  # (lineno, text)


class Detector(ABC):
    kind: DetectorKind
    name: str

    @abstractmethod
    def applicable(self, targets: list[ScanTarget]) -> bool: ...

    @abstractmethod
    def run(self, targets: list[ScanTarget]) -> list[Finding]: ...


@dataclass
class AdapterRun:
    """What one adapter did, for telemetry. `status` is the field that matters.

    `ran` with zero findings and `missing_tool` with zero findings look
    identical in the finding stream and mean opposite things, which is the
    whole reason this type exists rather than a bare list.
    """
    status: str = "ran"          # ran | disabled | missing_tool | error | not_applicable
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


@dataclass
class ToolRun:
    """One subprocess invocation, including the ways it can fail."""
    ok: bool
    stdout: str = ""
    stderr: str = ""
    error: str = ""          # why we got nothing, in reportable English
    duration_s: float = 0.0
    argv: list[str] = field(default_factory=list)


class ExternalTool:
    """Mixin for adapters that shell out. Keeps "absent" and "found nothing" apart.

    Subclasses set `binary` and get `available`; `invoke()` returns a `ToolRun`
    and never raises, because a scanner that segfaults on one PR must not take
    the review down with it.
    """

    binary: str = ""
    timeout_s: int = 300

    @property
    def path(self) -> str | None:
        return shutil.which(self.binary) if self.binary else None

    @property
    def available(self) -> bool:
        return self.path is not None

    def unavailable_note(self) -> str:
        return (f"{self.name} detector disabled: `{self.binary}` is not on PATH, "
                f"so nothing was scanned for this class. This is an absence of "
                f"evidence, not evidence of absence.")

    def invoke(self, argv: list[str], cwd: str | Path | None = None,
               ok_returncodes: tuple[int, ...] = (0,)) -> ToolRun:
        import time

        started = time.perf_counter()
        try:
            proc = subprocess.run(
                argv, cwd=str(cwd) if cwd else None, capture_output=True,
                text=True, timeout=self.timeout_s, check=False,
            )
        except subprocess.TimeoutExpired:
            return ToolRun(False, error=f"{self.binary} timed out after {self.timeout_s}s",
                           duration_s=time.perf_counter() - started, argv=argv)
        except OSError as exc:
            return ToolRun(False, error=f"{self.binary} could not be run: {exc}",
                           duration_s=time.perf_counter() - started, argv=argv)
        elapsed = time.perf_counter() - started
        if proc.returncode not in ok_returncodes:
            return ToolRun(
                False, stdout=proc.stdout, stderr=proc.stderr,
                error=(f"{self.binary} exited {proc.returncode}: "
                       f"{(proc.stderr or '').strip().splitlines()[-1][:200] if proc.stderr else 'no stderr'}"),
                duration_s=elapsed, argv=argv,
            )
        return ToolRun(True, stdout=proc.stdout, stderr=proc.stderr,
                       duration_s=elapsed, argv=argv)
