"""Software-composition analysis — osv-scanner over the PR's dependency delta
(phase-3 §3a, tooling.md #7).

DELTA-SCOPED AT THE SOURCE, NOT AFTERWARDS. Phase 0 already computed which
packages this PR adds or changes (`DeltaManifest.dep_deltas`). A lockfile
carries hundreds of transitive packages and most repos have known-vulnerable
ones sitting there; reporting them on an unrelated PR is how a security tool
teaches people to ignore it. So the scanner runs over the changed manifests and
the results are then filtered to the packages the PR actually moved, with the
count of what was dropped recorded rather than silently discarded.

WHY THIS ONE DOES NOT USE SARIF. Every other adapter parses SARIF because a
tool's rule ids are a small, stable vocabulary worth mapping. Here the "rule id"
is a CVE or GHSA id — unbounded data, not a rule — so routing it through
`normalize.map_rule` would classify every advisory as unmapped. The native JSON
also carries what the finding is actually made of: the resolved package version,
the fixed version, and a CVSS vector we can pass through to `Finding.cvss_vector`.

VALIDATED against osv-scanner 2.4.0 on 2026-08-05. `--lockfile` still works in
v2, and the JSON shape is unchanged, but three things the recorded fixture had
wrong only appeared on contact with the real tool: `source.path` is **absolute**,
so `head_dir` has to be resolved before it can be stripped; PYSEC advisories
carry neither `summary` nor `database_specific.severity`, so severity has to
fall through to the enclosing group's `max_severity`; and one defect arrives as
several ids (`pyyaml` came back as `PYSEC-2021-142` *and* `GHSA-8q59-q68h-6hv4`),
which is why findings are emitted per package rather than per advisory.

RE-VALIDATED 2026-08-07 against 50 real merged PRs, which found a fourth thing
no fixture could: `--lockfile` rejects dependency *manifests*, and it rejects
them for the whole invocation rather than for the one file. See `_OSV_LOCKFILES`.

AND A FIFTH, 2026-08-08: a lockfile records the project it locks, so osv-scanner
matches a repository against its own advisory. That entry is the *subject* of
"is this dependency vulnerable" rather than an answer to it, and it is dropped —
counted and stated, never silently. See `SCADetector._first_party`, errata
§14.32 (the mechanism) and §14.33 (the decision).
"""
from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

from pr_review.detect.base import AdapterRun, Detector, ExternalTool, ScanTarget
from pr_review.detect.normalize import make_finding
from pr_review.extract.schema import DeltaManifest
from pr_review.schema import DetectorKind, Finding, Severity

# osv-scanner reports an OSV `database_specific.severity` string for most
# ecosystems; when it is absent we fall back to the group's CVSS score.
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


# What `osv-scanner --lockfile` will actually extract, narrowed to the files
# Phase 0 can hand us (`extract/deps.py:_FORMATS`). Verified against
# osv-scanner 2.4.0 / osv-scalibr 0.4.5 on 2026-08-07 by feeding it one of each:
# everything absent here exits **127** with "could not determine extractor
# suitable to this file".
#
# The distinction is lockfile vs manifest. osv-scanner matches advisories against
# *resolved* versions; `pyproject.toml`, `package.json`, `Pipfile`, `setup.py`
# and `setup.cfg` state ranges, and a range is not a version an advisory can be
# checked against. (`go.sum` and `constraints*.txt` are unsupported too, for the
# scanner's own reasons — measured, not reasoned.)
#
# Filtering here rather than letting the scanner reject them is not cosmetic:
# the failure is **per invocation, not per file**. One unsupported path aborts
# the whole run and discards the packages already extracted from the good ones,
# so before this filter a PR touching `poetry.lock` *and* `pyproject.toml` got
# no SCA coverage for either (`benchmark/results/2026-08-07/analysis.md` §5).
#
# Re-measured 2026-08-08 when `extract/deps.py` gained five more lockfiles. All
# five extract cleanly, in the same multi-`--lockfile` invocation this adapter
# builds — `uv.lock` and `pdm.lock` as PyPI, `Cargo.lock` as crates.io,
# `Gemfile.lock` as RubyGems, `composer.lock` as Packagist. Listed here only
# because that was run, not because osv-scanner's documentation says so; the
# entry above it is a standing reminder of what the documentation was worth.
_OSV_LOCKFILES = frozenset({
    "poetry.lock", "pipfile.lock", "package-lock.json", "yarn.lock", "go.mod",
    "uv.lock", "pdm.lock", "cargo.lock", "composer.lock", "gemfile.lock",
})
_OSV_REQUIREMENTS_RE = re.compile(r"requirements.*\.txt$")

# Lockfiles built from `[[package]]` blocks, which is where a first-party entry
# is distinguishable — see `SCADetector._first_party`.
#
# `poetry.lock` is here to be *read*, not because it has a root entry: poetry does
# not record the locked project at all, and it writes provenance as a
# `[package.source]` sub-table rather than an inline `source =` line, so neither
# rule below can fire on it. Confirmed against a real poetry.lock rather than
# assumed, and asserted by a test — the same file contents yield a first-party
# name under Cargo's rule and none under poetry's, decided by the filename.
_TOML_LOCKS = frozenset({"uv.lock", "pdm.lock", "poetry.lock", "cargo.lock"})
_LOCK_NAME_RE = re.compile(r'^\s*name\s*=\s*"([^"]+)"', re.M)
_LOCK_SOURCE_RE = re.compile(r"^\s*source\s*=\s*(.+)$", re.M)
# uv writes `source = { editable = "." }` for the project and `{ virtual = "." }`
# for a root it does not install; a workspace member carries a relative path
# (`{ editable = "pydantic-core" }`) and is first-party too. Only these two words:
# poetry's `directory` and `path` markers live in a sub-table this regex cannot
# reach, so listing them would be a clause no fixture could falsify (§14.29).
_LOCAL_SOURCE_RE = re.compile(r"\b(?:editable|virtual)\b")


def _osv_supports(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return name in _OSV_LOCKFILES or bool(_OSV_REQUIREMENTS_RE.match(name))


def _from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _worst(vulns: list[dict], groups: list[dict]) -> tuple[Severity, str | None]:
    """The worst severity across a package's advisories, plus a CVSS vector.

    Real output made the fallback order matter. PYSEC entries carry neither
    `database_specific.severity` nor a `severity[]` array — only the enclosing
    group's `max_severity` score — so a parser that trusted the OSV fields
    alone rated every one of them MEDIUM-by-default.
    """
    vector = None
    worst: Severity | None = None
    for vuln in vulns:
        for entry in vuln.get("severity") or []:
            score = str(entry.get("score") or "")
            if score.startswith("CVSS:") and vector is None:
                vector = score
        label = ((vuln.get("database_specific") or {}).get("severity") or "").upper()
        if label in _SEVERITY:
            sev = _SEVERITY[label]
            worst = sev if worst is None or sev.rank > worst.rank else worst
    for group in groups:
        try:
            sev = _from_score(float(group.get("max_severity")))
        except (TypeError, ValueError):
            continue
        worst = sev if worst is None or sev.rank > worst.rank else worst
    # An advisory with no severity anywhere is still an advisory. Calling it LOW
    # would be a claim; MEDIUM, with the confidence prior doing the talking, is
    # the honest default.
    return (worst or Severity.MEDIUM), vector


def _best_fix(vulns: list[dict], package: str) -> str | None:
    """The highest fixed version across the package's advisories.

    Upgrading past one advisory's fix but not another's leaves the package
    vulnerable, so the useful number is the largest, not the first.
    """
    fixes: list[str] = []
    for vuln in vulns:
        for affected in vuln.get("affected") or []:
            name = ((affected.get("package") or {}).get("name") or "").lower()
            if name and package and name != package.lower():
                continue
            for rng in affected.get("ranges") or []:
                for event in rng.get("events") or []:
                    if event.get("fixed"):
                        fixes.append(str(event["fixed"]))
    if not fixes:
        return None
    return max(fixes, key=_version_key)


def _version_key(version: str) -> tuple:
    """Numeric-segment ordering, so 5.10 sorts above 5.4 rather than below it."""
    parts: list[tuple[int, object]] = []
    for chunk in str(version).replace("-", ".").split("."):
        if chunk.isdigit():
            parts.append((1, int(chunk)))
        else:
            parts.append((0, chunk))
    return tuple(parts)


def _headline(vulns: list[dict]) -> str:
    """One line of description. v2 output uses `details`; `summary` is optional."""
    for vuln in vulns:
        text = (vuln.get("summary") or vuln.get("details") or "").strip()
        if text:
            first = text.splitlines()[0].strip()
            return first if len(first) <= 200 else first[:197] + "..."
    return ""


class SCADetector(Detector, ExternalTool):
    kind = DetectorKind.SCA
    name = "sca"
    binary = "osv-scanner"

    def __init__(self, manifest: DeltaManifest | None = None,
                 head_dir: str | Path | None = None, timeout_s: int = 300) -> None:
        self.manifest = manifest
        self.head_dir = Path(head_dir) if head_dir else None
        self.timeout_s = timeout_s
        # `parse()` asks per package and a lockfile has hundreds of them.
        self._first_party_cache: dict[str, set[str]] = {}

    # -- what the PR moved -------------------------------------------------

    def changed_packages(self) -> dict[str, str]:
        """`{lowercased name: version}` for packages this PR adds or changes."""
        out: dict[str, str] = {}
        for delta in (self.manifest.dep_deltas if self.manifest else []):
            for name, version in (delta.added or {}).items():
                out[name.lower()] = version
            for name, pair in (delta.changed or {}).items():
                # `changed` is (old, new); only the new version is ours to answer for.
                out[name.lower()] = pair[1] if isinstance(pair, (list, tuple)) else str(pair)
        return out

    def applicable(self, targets: list[ScanTarget]) -> bool:
        return bool(self.changed_packages())

    def run(self, targets: list[ScanTarget]) -> list[Finding]:
        return self.scan(targets).findings

    def scan(self, targets: list[ScanTarget]) -> AdapterRun:
        wanted = self.changed_packages()
        if not wanted:
            return AdapterRun("not_applicable", notes=[
                "sca detector skipped: this PR adds or changes no dependency."])
        if self.head_dir is None:
            return AdapterRun("not_applicable", notes=[
                "sca detector skipped: no head checkout to resolve manifests against."])
        if not self.available:
            return AdapterRun("missing_tool", notes=[self.unavailable_note()])

        present = sorted({d.manifest for d in self.manifest.dep_deltas
                          if (self.head_dir / d.manifest).is_file()})
        if not present:
            return AdapterRun("not_applicable", notes=[
                "sca detector skipped: no changed dependency manifest exists in the "
                "head checkout."])

        manifests = [m for m in present if _osv_supports(m)]
        unsupported = [m for m in present if not _osv_supports(m)]
        # Stated, never silent. A dropped manifest is uncovered dependencies, and
        # the one thing worse than not scanning them is not scanning them quietly.
        skipped: list[str] = []
        if unsupported:
            skipped.append(
                f"osv-scanner cannot extract from {', '.join(unsupported)} — it "
                f"matches advisories against resolved lockfile versions, not "
                f"against the version ranges a dependency manifest declares. "
                f"Packages declared only there are unscanned by SCA."
            )
        if not manifests:
            return AdapterRun("not_applicable", detail={"unsupported": unsupported},
                              notes=[*skipped, "sca detector skipped: this PR "
                                     "changed no dependency file osv-scanner can read."])

        argv = [self.binary, "--format", "json"]
        for m in manifests:
            argv += ["--lockfile", m]
        # osv-scanner exits 1 when it finds vulnerabilities.
        result = self.invoke(argv, cwd=self.head_dir, ok_returncodes=(0, 1))
        if not result.ok:
            return AdapterRun("error", notes=[*skipped, f"osv-scanner failed: {result.error}"],
                              detail={"argv": argv, "unsupported": unsupported})
        try:
            doc = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            return AdapterRun("error", notes=[*skipped, f"osv-scanner output was not JSON: {exc}"],
                              detail={"argv": argv, "unsupported": unsupported})

        findings, detail = self.parse(doc, wanted)
        if detail.get("first_party"):
            skipped.append(
                f"{', '.join(detail['first_party'])} is this repository's own "
                f"source rather than a fetched dependency, so advisories against "
                f"it are not an upgrade this PR's reviewer can make. Not reported "
                f"as a vulnerable dependency; see the project's own release "
                f"process if its declared version sits inside its advisory range."
            )
        return AdapterRun("ran", findings=findings, notes=skipped,
                          detail={**detail, "manifests": manifests,
                                  "unsupported": unsupported,
                                  "duration_s": round(result.duration_s, 3)})

    # -- parsing (separated so it is testable without the binary) ----------

    def parse(self, doc: dict, wanted: dict[str, str]) -> tuple[list[Finding], dict]:
        """OSV JSON -> one finding per vulnerable **package**.

        Per package, not per advisory, and real output is what settled it.
        `pyyaml 5.3.1` comes back as two vulnerabilities — `PYSEC-2021-142` and
        `GHSA-8q59-q68h-6hv4` — which osv-scanner itself groups as aliases of
        one defect; `requests` came back with six under three groups. Reporting
        each id would put the same defect in the report twice and give a
        reviewer three rows whose remediation is one identical upgrade. The
        package at its resolved version is the unit the action applies to, so
        it is the unit reported, with every advisory id kept in the evidence.
        """
        findings: list[Finding] = []
        out_of_delta = 0
        advisories = 0
        first_party: list[str] = []

        for source in doc.get("results", []) or []:
            path = self._relative(((source.get("source") or {}).get("path") or "").strip())
            local = self._first_party(path)
            for pkg in source.get("packages", []) or []:
                info = pkg.get("package") or {}
                name = (info.get("name") or "").strip()
                version = (info.get("version") or "").strip()
                vulns = pkg.get("vulnerabilities", []) or []
                advisories += len(vulns)
                if not vulns:
                    continue
                # Before the delta check, so a first-party entry is reported as
                # what it is rather than as a package that happened to miss the
                # delta — those are different facts and one of them is a defect.
                if name.lower() in local:
                    first_party.append(f"{name} ({path})")
                    continue
                if name.lower() not in wanted:
                    out_of_delta += len(vulns)
                    continue

                severity, vector = _worst(vulns, pkg.get("groups") or [])
                fixed = _best_fix(vulns, name)
                ids = [v.get("id") for v in vulns if v.get("id")]
                cves = sorted({a for v in vulns for a in (v.get("aliases") or [])
                               if a.startswith("CVE-")})
                headline = _headline(vulns)

                findings.append(make_finding(
                    internal="SC-VULN-DEP",
                    title=(f"{name} {version} is affected by "
                           f"{len(cves) or len(ids)} known "
                           f"{'advisory' if (len(cves) or len(ids)) == 1 else 'advisories'}"
                           + (f" ({cves[0]})" if cves else "")),
                    severity=severity,
                    # A published advisory against a resolved version is about
                    # as direct as deterministic evidence gets; what it does not
                    # know is whether the vulnerable code path is used, which is
                    # a reachability question for 3c.
                    confidence=8,
                    detector=DetectorKind.SCA,
                    tool=self.name,
                    rule_id=(cves[0] if cves else ids[0]),
                    path=path or "dependencies",
                    start_line=self._line_of(path, name),
                    snippet=f"{name}=={version}",
                    why=(f"{', '.join(ids)}"
                         + (f" ({', '.join(cves)})" if cves else "")
                         + f" affect {name} {version}."
                         + (f" {headline}" if headline else "")
                         + (f" Fixed in {fixed}." if fixed else
                            " No fixed version is published.")),
                    symbol=name,
                    remediation=(f"Upgrade {name} to {fixed} or later."
                                 if fixed else
                                 f"No fix is published; assess whether {name} can be "
                                 f"removed, pinned away from the affected range, or "
                                 f"mitigated."),
                    cvss_vector=vector,
                ))

        detail = {
            "advisories": advisories,
            "in_delta": len(findings),
            "outside_delta_dropped": out_of_delta,
            "packages_in_delta": len(wanted),
        }
        if first_party:
            detail["first_party_skipped"] = len(first_party)
            detail["first_party"] = sorted(set(first_party))
        return findings, detail

    def _relative(self, path: str) -> str:
        """osv-scanner v2 reports absolute source paths, so `head_dir` has to be
        resolved before it can be a prefix of one."""
        if self.head_dir:
            root = str(self.head_dir.resolve())
            if path.startswith(root):
                return path[len(root):].lstrip("/")
        return path.lstrip("/")

    def _first_party(self, path: str) -> set[str]:
        """Lowercased names the lockfile marks as **this repository's own source**.

        A lockfile records the project it locks, and osv-scanner cannot tell that
        entry from a fetched dependency — it has a name and a resolved version, so
        it gets matched against the advisory database like anything else. On
        `GHSA-29w2-fq35-v728` that made the tool report a project as affected by
        the very advisory the fix in front of it was closing, because the version
        bump announcing the fix landed in a later commit (errata §14.32).

        Skipping is not about the noise. osv-scanner is being asked "is this
        *dependency* vulnerable", and a first-party entry is the subject of the
        question rather than an answer to it: the remediation this adapter
        generates — "Upgrade <name> to <version> or later" — is addressed to the
        people who publish <name>, who are the people reading the review. The
        drop is counted and stated (`first_party_skipped`) so the case this hides
        (a repo shipping a version of itself its own advisory covers) is still
        visible to anyone who looks at the adapter's detail.

        Covers what the corpus exercises, and says so:
          uv / pdm / poetry  `[[package]]` with `source = { editable|virtual }`
          Cargo              `[[package]]` with **no** `source` key, which is
                             Cargo's own convention for a local crate and
                             correctly also catches workspace members
        `composer.lock` has no root entry to confuse, and Bundler's equivalent is
        the `PATH` section's `specs:` — unimplemented because no case in either
        corpus reaches it, and a parser nothing exercises is a parser nobody knows
        is wrong. Listed in `OPEN_ITEMS.md`.
        """
        if path in self._first_party_cache:
            return self._first_party_cache[path]

        names: set[str] = set()
        name = PurePosixPath(path).name.lower()
        if self.head_dir and name in _TOML_LOCKS:
            try:
                text = (self.head_dir / path).read_text(encoding="utf-8",
                                                        errors="replace")
            except OSError:
                text = ""
            cargo = name == "cargo.lock"
            for block in text.split("[[package]]")[1:]:
                # Stop at the next top-level table so a later section cannot
                # donate its keys to this block.
                block = re.split(r"^\[(?!\[)", block, maxsplit=1, flags=re.M)[0]
                m = _LOCK_NAME_RE.search(block)
                if not m:
                    continue
                source = _LOCK_SOURCE_RE.search(block)
                if (cargo and source is None) or (
                        source is not None and _LOCAL_SOURCE_RE.search(source.group(1))):
                    names.add(m.group(1).lower())

        self._first_party_cache[path] = names
        return names

    def _line_of(self, path: str, package: str) -> int:
        """Where the package is named in the manifest, so evidence points at a line.

        Falls back to line 1: a finding about a dependency is about the file as
        a whole, and a wrong line is worse than an unsurprising one.
        """
        if not (self.head_dir and path and package):
            return 1
        target = self.head_dir / path
        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return 1
        needle = package.lower()
        for i, line in enumerate(text.splitlines(), start=1):
            if needle in line.lower():
                return i
        return 1
