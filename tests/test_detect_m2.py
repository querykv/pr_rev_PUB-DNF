"""M2 — the deterministic detector suite and the 3d stages it feeds.

The tests are grouped by the thing they protect rather than by module, because
several of the properties that matter are relationships *between* modules: that
the base and head passes fingerprint the same defect identically, that a missing
binary is distinguishable from a clean scan, that an unclassified rule cannot
reach the gate.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from pr_review import pipeline
from pr_review.config import Config
from pr_review.detect import normalize as norm
from pr_review.detect import sca as sca_mod
from pr_review.detect.base import ScanTarget, ToolRun
from pr_review.detect.iac import IaCDetector
from pr_review.detect.sast_semgrep import SemgrepDetector
from pr_review.detect.sca import SCADetector
from pr_review.detect.structural import StructuralDetector, head_subgraph
from pr_review.extract.manifest import build_manifest
from pr_review.extract.schema import DepDelta
from pr_review.findings import delta as delta_mod
from pr_review.findings.dedup import dedup
from pr_review.findings.validate import validate
from pr_review.policy import gate
from pr_review.schema import (
    DetectorKind,
    Evidence,
    Finding,
    Location,
    Provenance,
    Remediation,
    Severity,
    Status,
    Taxonomy,
)
from pr_review.taxonomy import registry

FIXTURES = Path(__file__).parent / "fixtures"
M2_BASE = FIXTURES / "m2_base"
M2_HEAD = FIXTURES / "m2_head"
M2_DIFF = (FIXTURES / "m2_pr.diff").read_text()


def _manifest(diff_text: str = M2_DIFF, pr: int = 9):
    return build_manifest(repo="o/r", pr_number=pr, diff_text=diff_text,
                          base_sha="b" * 40, head_sha="h" * 40)


def _reader(root: Path):
    def read(path: str, side: str = "after"):
        try:
            return (root / path).read_text()
        except OSError:
            return None
    return read


def _acceptance_config(cache_root) -> Config:
    """The end-to-end case, with the external scanners switched off.

    Not a convenience. Whether `semgrep` and `osv-scanner` are installed is a
    property of the machine, so leaving them on would make the acceptance
    assertions pass here and fail on a developer's laptop that happens to have
    them — and the thing under test is delta scoping, which is ours. The
    adapters have their own tests, and the ones that need a real binary skip
    when it is absent.
    """
    config = Config()
    config.profile.cache_root = str(cache_root)
    config.detectors.semgrep.enabled = False
    config.detectors.sca.enabled = False
    config.detectors.iac.enabled = False
    return config


# ---------------------------------------------------------------------------
# normalize.py — rule mapping and SARIF
# ---------------------------------------------------------------------------

def test_a_rule_we_have_read_maps_exactly():
    """A real id, confirmed present in p/python 1.172.0. Five ids that looked
    exactly this plausible were in the table first and existed in no ruleset."""
    m = norm.map_rule(
        "semgrep",
        "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true")
    assert (m.internal, m.origin) == ("INJ-CMD", "exact")


def test_an_unread_rule_falls_to_the_token_heuristic_one_point_lower():
    m = norm.map_rule("semgrep", "python.aws-lambda.security.mysql-sqli.mysql-sqli")
    assert (m.internal, m.origin) == ("INJ-SQLI", "heuristic")
    assert m.confidence < 6, "a substring of an id is weaker evidence than a read rule"


def test_checkov_falls_back_to_a_real_family_but_semgrep_does_not():
    """The asymmetry is the point: every Checkov check is a misconfiguration,
    while Semgrep's rules span the whole taxonomy, so there is nothing true to
    say about an unread one."""
    assert norm.map_rule("checkov", "CKV_GCP_999").internal == "CFG-IAC"
    assert norm.map_rule("semgrep", "python.lang.best-practice.zzz").internal == "TOOL-UNMAPPED"


def test_two_rules_on_one_line_collapse_if_they_share_a_taxonomy_id():
    """Why `CKV_DOCKER_3`'s wrong family cannot just be corrected in place.

    The fingerprint is `(path, internal, symbol, snippet)` — `rule_id` is a
    *fallback* used only when there is no snippet (`normalize.py`). Checkov
    reports both `CKV_DOCKER_2` (no HEALTHCHECK) and `CKV_DOCKER_3` (runs as
    root) at line 1 of the same Dockerfile, so today only the differing
    taxonomy id keeps them apart.

    Retargeting `CKV_DOCKER_3` to `CFG-IAC` was tried on the IaC corpus and
    **silently deleted 16 findings** (`BENCHMARK_STATUS.md` §4h). This pins the
    mechanism so the next person to fix that mapping finds out here rather than
    in a corpus run — and so that adding `rule_id` to the fingerprint, which
    looks like the obvious fix, is a deliberate decision: it would also stop
    semgrep and structural findings for one defect from deduping, which is what
    the fingerprint exists to do (cross-cutting §6).
    """
    common = dict(path="Dockerfile", symbol=None, snippet="FROM alpine:3.20",
                  start_line=1, detector=DetectorKind.IAC, tool="checkov",
                  severity=Severity.MEDIUM, confidence=7, title="t", why="w")
    same = [norm.make_finding(internal="CFG-IAC", rule_id=r, **common)
            for r in ("CKV_DOCKER_2", "CKV_DOCKER_3")]
    assert same[0].fingerprint == same[1].fingerprint, (
        "two different checks became one finding — this is the collapse")

    apart = [norm.make_finding(internal=i, rule_id=r, **common)
             for i, r in (("CFG-IAC", "CKV_DOCKER_2"),
                          ("CFG-DEFAULT-CREDS", "CKV_DOCKER_3"))]
    assert apart[0].fingerprint != apart[1].fingerprint, (
        "the differing taxonomy id is the only thing keeping them apart today")


def test_an_unmapped_rule_reports_but_cannot_gate():
    sarif = json.loads((FIXTURES / "semgrep.sarif").read_text())
    findings, report = norm.from_sarif(norm.read_sarif(sarif), tool="semgrep",
                                       detector=DetectorKind.SAST)
    unmapped = [f for f in findings if f.taxonomy.internal == "TOOL-UNMAPPED"]
    assert len(unmapped) == 1, "recall first: the finding is still reported"
    assert unmapped[0].severity.rank <= Severity.MEDIUM.rank
    assert unmapped[0].status is Status.CANDIDATE
    assert gate(unmapped, Config().gate).triggers == []
    assert report["unmapped_rules"] == [
        "python.django.security.injection.open-redirect.open-redirect"], (
        "open redirect is real, and our taxonomy genuinely has no id for it — "
        "inventing one is what TOOL-UNMAPPED exists to avoid")


def test_sarif_severity_prefers_the_numeric_score_over_the_level():
    # level=error for both, but 9.3 and 8.5 are different findings.
    results = norm.read_sarif((FIXTURES / "semgrep.sarif").read_text())
    by_rule = {r.rule_id.split(".")[-1]: r for r in results}
    assert norm.severity_from_sarif(
        by_rule["mysql-sqli"].level,
        by_rule["mysql-sqli"].security_severity) is Severity.CRITICAL
    assert norm.severity_from_sarif("error", None) is Severity.HIGH


def test_sarif_paths_are_made_repo_relative():
    results = norm.read_sarif((FIXTURES / "semgrep.sarif").read_text())
    assert {r.path for r in results} == {"api.py", "repo/app.py", "util.py"}
    checkov = norm.read_sarif((FIXTURES / "checkov.sarif").read_text())
    assert {r.path for r in checkov} == {"main.tf"}


def test_read_sarif_survives_a_result_with_almost_nothing_in_it():
    doc = {"runs": [{"tool": {"driver": {"name": "x"}},
                     "results": [{"ruleId": "r1"}]}]}
    (res,) = norm.read_sarif(doc)
    assert (res.path, res.start_line, res.level) == ("", 0, "warning")


# ---------------------------------------------------------------------------
# structural.py
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def head_graph():
    manifest, _ = _manifest()
    return head_subgraph(M2_HEAD, manifest), manifest


@pytest.fixture(scope="module")
def base_graph():
    manifest, _ = _manifest()
    return head_subgraph(M2_BASE, manifest)


def _structural(head, base, manifest, root=M2_HEAD):
    det = StructuralDetector(head_cpg=head, base_cpg=base,
                             changed_paths={f.path for f in manifest.files},
                             sources=_reader(root))
    return det.scan([ScanTarget(path=f.path) for f in manifest.files])


def test_a_removed_guard_is_only_visible_with_both_graphs(head_graph, base_graph):
    """The finding that justifies building a head-side subgraph at all."""
    head, manifest = head_graph
    with_base = _structural(head, base_graph, manifest)
    rules = {f.provenance.rule_id for f in with_base.findings}
    assert "guard-removed" in rules

    without_base = _structural(head, None, manifest)
    assert "guard-removed" not in {f.provenance.rule_id for f in without_base.findings}
    assert any("removed authorization check cannot be distinguished" in n
               for n in without_base.notes)


def test_an_unauthenticated_taint_path_outranks_a_guarded_one(head_graph, base_graph):
    head, manifest = head_graph
    result = _structural(head, base_graph, manifest)
    (sqli,) = [f for f in result.findings if f.taxonomy.internal == "INJ-SQLI"]
    assert sqli.severity is Severity.CRITICAL
    assert sqli.reachability.attacker_reachable is True
    assert sqli.reachability.guards == []
    assert [n.role for n in sqli.data_flow] == ["source", "sink"]


def test_without_a_head_checkout_the_detector_refuses_rather_than_using_the_base(base_graph):
    manifest, _ = _manifest()
    result = _structural(None, base_graph, manifest)
    assert result.status == "not_applicable"
    assert result.findings == []
    assert any("STRUCTURAL DETECTOR SKIPPED" in n for n in result.notes)


def test_an_explicit_public_optout_is_not_reported_as_missing_authz():
    """`AllowAny` is a decision on the record, not an omission — judging it
    needs to know what the endpoint returns, which is a Phase-3b question."""
    sample = FIXTURES / "sample_app"
    diff = ("diff --git a/views.py b/views.py\nindex 1..2 100644\n"
            "--- a/views.py\n+++ b/views.py\n@@ -1,1 +1,2 @@\n context\n+added\n")
    manifest, _ = build_manifest(repo="o/r", pr_number=1, diff_text=diff)
    cpg = head_subgraph(sample, manifest)
    result = _structural(cpg, None, manifest, root=sample)
    symbols = {f.location.symbol for f in result.findings}
    assert "PublicView" not in symbols
    assert "LegacyView" in symbols


class _StubCPG:
    """Just enough graph to drive the taint branch with a chosen sink class."""

    def __init__(self, paths):
        self.taint_paths = paths

    def nodes_of_kind(self, kind):
        return []

    def edges(self, relation=None):
        return iter(())


def _taint_path(sink_class: str):
    from pr_review.profile.cpg import CPGNode, TaintPath
    return TaintPath(
        source=CPGNode(id="s", kind="source", file="api.py", name="request.args", line=1),
        sink=CPGNode(id="k", kind="sink", file="api.py", name="logger.info", line=5,
                     attrs={"sink_class": sink_class}),
        symbols=["api.handler"],
    )


@pytest.mark.parametrize("sink_class,expected", [("log", 0), ("response", 0), ("sql", 1)])
def test_log_and_response_sinks_are_skipped_with_the_reason_recorded(sink_class, expected):
    """Not an omission: for those two sinks the question runs the other way —
    whether a *sensitive value* reaches them — which needs the sensitive-field
    overlay and belongs to Privacy/PII in Phase 3b."""
    det = StructuralDetector(head_cpg=_StubCPG([_taint_path(sink_class)]),
                             changed_paths={"api.py"})
    result = det.scan([ScanTarget(path="api.py")])
    assert len(result.findings) == expected
    if expected == 0:
        assert any("not reported" in n for n in result.notes)


# ---------------------------------------------------------------------------
# The subprocess adapters — absent binaries are a recorded state
# ---------------------------------------------------------------------------

def test_a_missing_binary_is_reported_as_missing_not_as_clean():
    """The invariant, asserted without depending on what this machine has.

    Pointing a real adapter at a binary that cannot exist is the only way to
    test this on every machine — an earlier version skipped when semgrep was
    installed, which meant it stopped testing anything the moment the tool it
    guards was present.
    """
    semgrep = SemgrepDetector(head_dir=M2_HEAD)
    semgrep.binary = "semgrep-that-is-not-installed"
    run = semgrep.scan([ScanTarget(path="api.py")])
    assert run.status == "missing_tool"
    assert run.findings == []
    assert "absence of evidence" in run.notes[0]


def test_semgrep_sarif_becomes_findings_with_our_taxonomy():
    findings, report = norm.from_sarif(
        norm.read_sarif((FIXTURES / "semgrep.sarif").read_text()),
        tool="semgrep", detector=DetectorKind.SAST)
    internals = {f.taxonomy.internal for f in findings}
    assert internals == {"INJ-CMD", "INJ-SQLI", "TOOL-UNMAPPED"}
    assert (report["mapped_exact"], report["mapped_heuristic"], report["unmapped"]) == (1, 1, 1)
    assert all(f.provenance.detector is DetectorKind.SAST for f in findings)


def test_checkov_sarif_maps_its_checks_to_misconfiguration():
    """The fixture is real checkov 3.3.0 output, captured from `iac_sample/`."""
    findings, _report = norm.from_sarif(
        norm.read_sarif((FIXTURES / "checkov.sarif").read_text()),
        tool="checkov", detector=DetectorKind.IAC)
    by_rule = {f.provenance.rule_id: f for f in findings}
    assert set(by_rule) == {"CKV_AWS_23", "CKV_AWS_24"}
    assert by_rule["CKV_AWS_24"].severity is Severity.HIGH
    assert all(f.taxonomy.family in registry.FAMILIES for f in findings)


def test_a_banner_before_the_json_does_not_break_the_sarif_reader():
    """Checkov prints ASCII art and an update notice ahead of any report, and
    `--quiet` suppresses neither."""
    noisy = "  _ __ \n | '_ \\  checkov\nBy Prisma Cloud | version: 3.3.0\n" + (
        FIXTURES / "checkov.sarif").read_text()
    assert len(norm.read_sarif(noisy)) == 2


def test_iac_skips_a_pr_with_no_infrastructure_files():
    manifest, _ = _manifest()
    det = IaCDetector(head_dir=M2_HEAD, iac_paths=set())
    run = det.scan([ScanTarget(path=f.path) for f in manifest.files])
    assert run.status == "not_applicable"
    assert "no infrastructure-as-code file" in run.notes[0]


def test_sca_reports_only_the_packages_this_pr_moved():
    """`osv.json` is real osv-scanner 2.4.0 output for the head fixture."""
    manifest, _ = _manifest()
    det = SCADetector(manifest=manifest, head_dir=M2_HEAD)
    doc = json.loads((FIXTURES / "osv.json").read_text())
    findings, detail = det.parse(doc, det.changed_packages())

    assert det.changed_packages() == {"pyyaml": "5.3.1"}
    assert len(findings) == 1, "one finding per vulnerable package, not per advisory id"
    assert detail["outside_delta_dropped"] > 0, (
        "requests is vulnerable at the base commit too and is not this PR's business")
    (f,) = findings
    assert f.taxonomy.internal == "SC-VULN-DEP"
    assert f.severity is Severity.CRITICAL, "severity comes from the group's max_severity"
    assert f.cvss_vector.startswith("CVSS:3.1/")
    assert "5.4" in f.remediation.summary
    assert f.location.file == "requirements.txt" and f.location.start_line == 3
    # Both alias ids of the one defect are kept even though one finding is made.
    assert "PYSEC-2021-142" in f.evidence[0].why
    assert "GHSA-8q59-q68h-6hv4" in f.evidence[0].why


def test_sca_does_not_hand_osv_scanner_a_file_it_cannot_read(tmp_path):
    """osv-scanner matches advisories against resolved lockfile versions, so it
    rejects `pyproject.toml` — and it rejects it for the **whole invocation**,
    discarding the packages it already extracted from the good manifests
    (`benchmark/results/2026-08-07/analysis.md` §5).

    So the unsupported file has to be filtered out before the call, not tolerated
    after it, or one manifest takes SCA coverage down for every other.
    """
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    (tmp_path / "poetry.lock").write_text("# lock\n")
    manifest, _ = _manifest()
    manifest.dep_deltas = [
        DepDelta(ecosystem="pypi", manifest="pyproject.toml", added={"widget": "1.0"}),
        DepDelta(ecosystem="pypi", manifest="poetry.lock", added={"widget": "1.0"}),
    ]
    det = SCADetector(manifest=manifest, head_dir=tmp_path)

    sent = []
    det.invoke = lambda argv, **kw: sent.append(argv) or ToolRun(  # type: ignore[method-assign]
        ok=True, stdout='{"results": []}', argv=argv)
    run = det.scan([])

    assert run.status == "ran"
    assert "poetry.lock" in sent[0] and "pyproject.toml" not in sent[0]
    # Dropped, never silently: those packages are genuinely unscanned.
    assert run.detail["unsupported"] == ["pyproject.toml"]
    assert any("pyproject.toml" in n for n in run.notes)


def test_sca_with_only_an_unreadable_manifest_is_not_applicable_not_an_error(tmp_path):
    """`error` means the tool broke. Being handed input it was never able to read
    is a coverage gap, and `AdapterRun.status` is the field that has to tell them
    apart — that distinction is the whole reason the type exists."""
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    manifest, _ = _manifest()
    manifest.dep_deltas = [
        DepDelta(ecosystem="pypi", manifest="pyproject.toml", added={"widget": "1.0"})]
    det = SCADetector(manifest=manifest, head_dir=tmp_path)
    det.invoke = lambda *a, **k: pytest.fail(  # type: ignore[method-assign]
        "osv-scanner must not be invoked with nothing it can read")

    run = det.scan([])
    assert run.status == "not_applicable"
    assert any("pyproject.toml" in n for n in run.notes)


@pytest.mark.parametrize("path,supported", [
    ("poetry.lock", True),
    ("backend/requirements.txt", True),
    ("requirements-dev.txt", True),
    ("package-lock.json", True),
    ("go.mod", True),
    # Added 2026-08-08 with `extract/deps.py`'s five new formats, and probed the
    # same way: all five extract, in one multi-`--lockfile` invocation.
    ("uv.lock", True),
    ("pdm.lock", True),
    ("Cargo.lock", True),
    ("composer.lock", True),
    ("Gemfile.lock", True),
    ("pyproject.toml", False),      # a range, not a resolved version
    ("package.json", False),
    ("setup.py", False),
    ("go.sum", False),              # measured, not reasoned: osv-scanner takes go.mod
    ("constraints.txt", False),
])
def test_which_dependency_files_osv_scanner_can_extract(path, supported):
    """Pinned against osv-scanner 2.4.0 / osv-scalibr 0.4.5, probed one file at a
    time. If an upgrade widens support this fails, which is the point."""
    assert sca_mod._osv_supports(path) is supported


def test_sca_picks_the_highest_fix_not_the_first():
    """Upgrading past one advisory's fix but not another's leaves the package
    vulnerable, and 5.10 must sort above 5.4."""
    doc = {"results": [{"source": {"path": "requirements.txt"}, "packages": [{
        "package": {"name": "widget", "version": "1.0"},
        "groups": [{"max_severity": "7.5"}],
        "vulnerabilities": [
            {"id": "A", "affected": [{"ranges": [{"events": [{"fixed": "5.4"}]}]}]},
            {"id": "B", "affected": [{"ranges": [{"events": [{"fixed": "5.10"}]}]}]},
        ]}]}]}
    findings, _ = SCADetector(manifest=None).parse(doc, {"widget": "1.0"})
    assert "5.10" in findings[0].remediation.summary


# ---------------------------------------------------------------------------
# A lockfile records the project it locks, and osv-scanner cannot tell that
# entry from a fetched dependency (errata §14.32).
# ---------------------------------------------------------------------------

# Real shapes, trimmed. uv writes `source` on the line *after* `version`, which
# is why this is read here and not in `extract/deps.py`'s line-oriented parser.
UV_LOCK = '''\
version = 1
requires-python = ">=3.10"

[[package]]
name = "my-project"
version = "1.3.46"
source = { editable = "." }
dependencies = [{ name = "widget" }]

[[package]]
name = "widget"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
'''

CARGO_LOCK = '''\
version = 3

[[package]]
name = "my-crate"
version = "0.1.0"
dependencies = ["widget"]

[[package]]
name = "widget"
version = "1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"
'''


def _osv_doc(path, *names):
    return {"results": [{"source": {"path": path}, "packages": [
        {"package": {"name": n, "version": "1.0"},
         "groups": [{"max_severity": "9.8"}],
         "vulnerabilities": [{"id": f"GHSA-{n}"}]} for n in names]}]}


@pytest.mark.parametrize("lockfile,text,project", [
    ("uv.lock", UV_LOCK, "my-project"),
    # Same bytes under a different name. This asserts the TOML-lock family shares
    # one parser — it is *not* a claim about what pdm emits, which no case in
    # either corpus exercises.
    ("pdm.lock", UV_LOCK, "my-project"),
    ("Cargo.lock", CARGO_LOCK, "my-crate"),
])
def test_sca_does_not_report_the_repository_to_itself(tmp_path, lockfile, text,
                                                      project):
    """The project's own entry is the subject of "is this dependency vulnerable",
    not an answer to it — the remediation would tell the reviewer to upgrade the
    thing they are reviewing. Marked `editable`/`virtual` by uv, and by the
    absence of a `source` key in Cargo.

    **The dependency beside it must still be reported.** The guard is pinned by
    what survives it: a rule that silenced the whole file would pass a test that
    only asserted the disappearance.
    """
    (tmp_path / lockfile).write_text(text)
    det = SCADetector(manifest=None, head_dir=tmp_path)
    doc = _osv_doc(str(tmp_path / lockfile), project, "widget")

    findings, detail = det.parse(doc, {project: "1.0", "widget": "1.0"})

    assert [f.location.symbol for f in findings] == ["widget"]
    assert detail["first_party_skipped"] == 1
    assert any(project in entry for entry in detail["first_party"])
    assert detail["outside_delta_dropped"] == 0


def test_a_registry_package_without_a_source_key_is_only_local_for_cargo(tmp_path):
    """poetry.lock omits `source` for every ordinary PyPI package, so "no source
    key means local" is Cargo's convention and must not leak to the others.

    Measured, not assumed: run against the pinned corpus, `poetry.lock` yields no
    first-party names and `uv.lock` yields one. Identical bytes, opposite answers,
    decided by the filename — which is the whole claim, so it is asserted here.
    """
    entry = ('[[package]]\nname = "widget"\nversion = "1.0"\n'
             'description = "a widget"\noptional = false\n')
    (tmp_path / "poetry.lock").write_text(entry)
    (tmp_path / "Cargo.lock").write_text(entry)

    det = SCADetector(manifest=None, head_dir=tmp_path)
    assert det._first_party("poetry.lock") == set()
    assert det._first_party("Cargo.lock") == {"widget"}


def test_first_party_claims_nothing_without_a_checkout_to_read():
    """No head tree means no evidence, and no evidence means no drop."""
    assert SCADetector(manifest=None, head_dir=None)._first_party("uv.lock") == set()


def test_the_first_party_drop_is_stated_not_silent(tmp_path):
    """`sca.py`'s standing rule: a dropped package is uncovered dependencies, and
    the one thing worse than not reporting it is not reporting it quietly."""
    (tmp_path / "uv.lock").write_text(UV_LOCK)
    det = SCADetector(manifest=None, head_dir=tmp_path)
    _, detail = det.parse(_osv_doc(str(tmp_path / "uv.lock"), "my-project"),
                          {"my-project": "1.3.46"})
    assert detail["first_party_skipped"] == 1
    assert detail["in_delta"] == 0


# ---------------------------------------------------------------------------
# Integration — the real binaries, when this machine has them
#
# These skip rather than fail when a scanner is absent, because whether one is
# installed is a property of the machine. They exist because every defect found
# on 2026-08-05's first real run was invisible to a fixture: semgrep exiting 2
# on an unresolvable --baseline-commit, checkov writing SARIF to a file it names
# itself and printing a banner over stdout, and osv-scanner v2 reporting
# absolute paths and grouped aliases.
# ---------------------------------------------------------------------------

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None,
                                   reason="semgrep is not installed")
needs_osv = pytest.mark.skipif(shutil.which("osv-scanner") is None,
                               reason="osv-scanner is not installed")
needs_checkov = pytest.mark.skipif(shutil.which("checkov") is None,
                                   reason="checkov is not installed")


@needs_semgrep
def test_semgrep_runs_and_maps_a_real_finding():
    det = SemgrepDetector(head_dir=FIXTURES / "sample_app", baseline_commit=None,
                          timeout_s=300)
    run = det.scan([ScanTarget(path=p) for p in
                    ("api.py", "app.py", "models.py", "views.py")])
    assert run.status == "ran"
    cmd = [f for f in run.findings if f.taxonomy.internal == "INJ-CMD"]
    assert cmd, "p/python flags subprocess(..., shell=True) in the fixture"
    assert cmd[0].location.file == "api.py"


@needs_semgrep
def test_an_unresolvable_baseline_commit_degrades_instead_of_failing():
    """Semgrep exits 2 — a hard failure, not an empty result — when it cannot
    reach the sha. Offline `--diff-file` runs always carry such a sha."""
    det = SemgrepDetector(head_dir=FIXTURES / "sample_app", baseline_commit="b" * 40,
                          timeout_s=300)
    run = det.scan([ScanTarget(path="api.py")])
    assert run.status == "ran"
    assert run.detail["baseline_commit"] is None
    assert any("does not resolve" in n for n in run.notes)


@needs_osv
def test_osv_scanner_reports_only_the_package_this_pr_added():
    manifest, _ = _manifest()
    det = SCADetector(manifest=manifest, head_dir=M2_HEAD, timeout_s=300)
    run = det.scan([ScanTarget(path=f.path) for f in manifest.files])
    assert run.status == "ran"
    assert [f.symbol for f in [x.location for x in run.findings]] == ["pyyaml"]
    assert run.detail["outside_delta_dropped"] > 0, (
        "requests is vulnerable at the base commit too; that is not this PR's business")
    (f,) = run.findings
    assert f.location.file == "requirements.txt", "absolute source paths are relativized"
    assert f.severity is Severity.CRITICAL


@needs_checkov
def test_checkov_runs_without_littering_the_checkout():
    iac = FIXTURES / "iac_sample"
    before = {p.name for p in iac.iterdir()}
    det = IaCDetector(head_dir=iac, iac_paths={"main.tf"}, timeout_s=300)
    run = det.scan([ScanTarget(path="main.tf")])
    assert run.status == "ran"
    assert run.findings and all(f.taxonomy.internal == "CFG-IAC" for f in run.findings)
    assert {p.name for p in iac.iterdir()} == before, (
        "`--output-file-path console` used to create a stray console/ directory here")


# ---------------------------------------------------------------------------
# findings/ — validate, dedup, delta
# ---------------------------------------------------------------------------

def _finding(**kw) -> Finding:
    base = dict(
        id="i", fingerprint="fp", title="t",
        taxonomy=Taxonomy(internal="INJ-SQLI", family="Injection",
                          owasp_2025="A05", cwe=["CWE-89"]),
        severity=Severity.HIGH, confidence=6, location=Location(
            file="api.py", start_line=10, end_line=10),
        evidence=[Evidence(file="api.py", lines="10", snippet="x", why="y")],
        remediation=Remediation(summary="fix"),
        provenance=Provenance(detector=DetectorKind.SAST, tool="semgrep"),
    )
    base.update(kw)
    return Finding(**base)


def test_validate_rejects_incoherent_findings_with_a_reason():
    good = _finding()
    no_evidence = _finding(evidence=[Evidence(file="a", lines="1", snippet="", why="")])
    off_end = _finding(location=Location(file="api.py", start_line=9999, end_line=9999))
    result = validate([good, no_evidence, off_end], line_counts={"api.py": 50})
    assert result.kept == [good]
    reasons = [why for _f, why in result.rejected]
    assert "evidence is empty" in reasons[0]
    assert "past the end of the file" in reasons[1]


def test_dedup_keeps_one_finding_and_records_who_else_saw_it():
    sast = _finding(confidence=6)
    structural = _finding(confidence=8, provenance=Provenance(
        detector=DetectorKind.STRUCTURAL, tool="cpg-structural"))
    result = dedup([sast, structural])
    assert len(result.findings) == 1
    kept = result.findings[0]
    assert kept.confidence == 8, "the richer finding survives"
    assert kept.provenance.also_detected_by == ["sast:semgrep"]
    assert result.stats()["agreed"] == 1


def test_dedup_does_not_reward_agreement_with_confidence():
    """Deliberate: weighting agreement is `findings/merge.py`'s job at M3, and
    doing it here as well would apply it twice."""
    a = _finding(confidence=6)
    b = _finding(confidence=6, provenance=Provenance(
        detector=DetectorKind.STRUCTURAL, tool="cpg-structural"))
    assert dedup([a, b]).findings[0].confidence == 6


def test_a_finding_on_the_prs_own_text_is_always_introduced():
    manifest, _ = _manifest()
    body = _finding(location=Location(file="pr:body", start_line=1, end_line=1),
                    fingerprint="in-baseline-by-accident")
    baseline = delta_mod.Baseline(base_sha="b" * 40,
                                  fingerprints={"in-baseline-by-accident"},
                                  paths=["api.py"])
    result = delta_mod.scope([body], manifest, baseline)
    assert result.findings[0].introduced_by_pr is True, (
        "the PR description is part of the PR; no checkout can contain it")


def test_without_a_baseline_scoping_falls_back_to_hunks_and_says_so():
    manifest, _ = _manifest()
    inside = _finding(location=Location(file="api.py", start_line=45, end_line=45))
    outside = _finding(location=Location(file="api.py", start_line=1000, end_line=1000),
                       fingerprint="other")
    result = delta_mod.scope([inside, outside], manifest, None)
    assert result.method == "hunks"
    assert result.findings[0].introduced_by_pr is True
    assert result.findings[1].introduced_by_pr is False
    assert any("HUNK-BASED" in n for n in result.notes)


def test_a_pre_existing_finding_is_demoted_so_it_cannot_gate():
    manifest, _ = _manifest()
    f = _finding(status=Status.VALIDATED, severity=Severity.CRITICAL, confidence=9)
    baseline = delta_mod.Baseline(base_sha="b" * 40, fingerprints={f.fingerprint},
                                  paths=[fc.path for fc in manifest.files])
    result = delta_mod.scope([f], manifest, baseline)
    assert result.findings[0].status is Status.PRE_EXISTING
    assert gate(result.findings, Config().gate).triggers == []


def test_added_files_are_not_counted_as_baseline_gaps():
    diff = ("diff --git a/new.py b/new.py\nnew file mode 100644\nindex 0..1\n"
            "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,2 @@\n+import os\n+x = 1\n")
    manifest, _ = build_manifest(repo="o/r", pr_number=2, diff_text=diff)
    assert delta_mod.expected_baseline_paths(manifest) == set()


def test_the_baseline_scans_whole_base_files_not_the_diff():
    manifest, _ = _manifest()
    targets = delta_mod.base_targets(manifest, M2_BASE)
    api = next(t for t in targets if t.path == "api.py")
    assert len(api.added_lines) == len((M2_BASE / "api.py").read_text().splitlines())


# ---------------------------------------------------------------------------
# End to end — M2's acceptance case
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def m2_run(tmp_path_factory):
    out = tmp_path_factory.mktemp("m2")
    config = _acceptance_config(out / "cache")
    result = pipeline.run_review(
        repo="o/r", pr_number=9, diff_text=M2_DIFF, config=config,
        out_root=str(out / "runs"), base_dir=M2_BASE, head_dir=M2_HEAD,
        base_sha="b" * 40, head_sha="h" * 40,
    )
    findings = json.loads((result.out_dir / "03d_findings.normalized.json").read_text())
    telemetry = json.loads((result.out_dir / "telemetry.json").read_text())
    return result, findings, telemetry["meta"]


def test_the_m2_thread_separates_what_the_pr_introduced_from_what_it_inherited(m2_run):
    _result, findings, _tel = m2_run
    got = {(f["taxonomy"]["internal"], f["provenance"]["rule_id"],
            f["introduced_by_pr"]) for f in findings["findings"]}
    assert got == {
        ("INJ-SQLI", "taint-sql", True),            # new unguarded endpoint taints SQL
        ("SEC-TOKEN", "github-pat", True),          # new secret
        ("SEC-TOKEN", "github-pat", False),         # the same secret, moved down the file
        ("BAC-MISSING-AUTHZ", "guard-removed", True),
        ("BAC-MISSING-AUTHZ", "missing-authz", True),    # the new endpoint
        ("BAC-MISSING-AUTHZ", "missing-authz", False),   # /legacy, unguarded all along
    }
    assert findings["counts"]["introduced"] == 4
    assert findings["counts"]["pre_existing"] == 2


def test_only_the_introduced_secret_fails_the_gate(m2_run):
    result, findings, _tel = m2_run
    assert result.verdict == "flagged"
    assert result.triggers == 1
    gating = [f for f in findings["findings"]
              if f["status"] == "validated" and f["introduced_by_pr"]]
    assert [f["provenance"]["rule_id"] for f in gating] == ["github-pat"]


def test_the_run_records_which_detectors_never_ran(m2_run):
    _result, _findings, tel = m2_run
    detect = tel["detect"]
    # Every detector that was built reports a status, and a detector switched
    # off in config is absent entirely rather than present with a zero — the
    # report must never be able to imply a class was scanned when it was not.
    assert set(detect) == {"secrets", "structural", "baseline"}
    assert detect["secrets"]["status"] == "ran"
    assert detect["structural"]["status"] == "ran"
    assert tel["delta"]["method"] == "baseline"


def test_the_candidate_artifact_is_written_before_scoping(m2_run):
    result, findings, _tel = m2_run
    candidates = json.loads((result.out_dir / "03a_candidates.json").read_text())
    assert len(candidates) >= len(findings["findings"])
    assert all(c["status"] != "pre_existing" for c in candidates), (
        "3a reports what it saw; deciding what the PR is answerable for is 3d's job")


def test_the_baseline_is_cached_and_reused(m2_run, tmp_path):
    _result, _findings, tel = m2_run
    assert tel["detect"]["baseline"]["source"] == "built"

    config = _acceptance_config(tmp_path / "cache")
    kwargs = dict(repo="o/r", pr_number=9, diff_text=M2_DIFF, config=config,
                  out_root=str(tmp_path / "runs"), base_dir=M2_BASE,
                  head_dir=M2_HEAD, base_sha="b" * 40, head_sha="h" * 40)
    first = pipeline.run_review(**kwargs)
    second = pipeline.run_review(**kwargs)
    tel2 = json.loads((second.out_dir / "telemetry.json").read_text())["meta"]
    assert tel2["detect"]["baseline"]["source"] == "cache"
    assert first.findings == second.findings


def test_container_privilege_has_its_own_taxonomy_id():
    """`OPEN_ITEMS.md` §18, closed. `CKV_DOCKER_3` is "ensure a user for the
    container has been created" — the container runs as root, which is a
    privilege misconfiguration and not a default credential. It sat under
    `CFG-DEFAULT-CREDS` for three weeks because the obvious correction destroyed
    data (see the collapse test above)."""
    from pr_review.taxonomy.registry import lookup

    m = norm._EXACT["checkov"]["CKV_DOCKER_3"]
    assert m.internal == "CFG-CONTAINER-PRIVILEGE"
    row = lookup("CFG-CONTAINER-PRIVILEGE")
    assert row.family == "Security Misconfiguration"
    assert "CWE-250" in row.cwe


def test_the_new_id_still_deduplicates_apart_from_ckv_docker_2():
    """The whole reason this is a NEW id rather than a retarget to `CFG-IAC`.
    Both checks land on the same Dockerfile line with the same snippet, so the
    taxonomy id is the only thing keeping their fingerprints apart."""
    common = dict(path="Dockerfile", symbol=None, snippet="FROM alpine:3.20",
                  start_line=1, detector=DetectorKind.IAC, tool="checkov",
                  severity=Severity.MEDIUM, confidence=7, title="t", why="w")
    apart = [norm.make_finding(internal=i, rule_id=r, **common)
             for i, r in (("CFG-IAC", "CKV_DOCKER_2"),
                          ("CFG-CONTAINER-PRIVILEGE", "CKV_DOCKER_3"))]
    assert apart[0].fingerprint != apart[1].fingerprint


def test_the_new_id_does_not_move_the_benchmark_recall_ceiling():
    """The precondition §18 blocked on: *"any new id has to be checked against
    `scoring._CWE_GROUPS` and `benchmark/scope.py`, which read the same table
    and must not be widened casually."*

    CWE-250/269 correctly enter `in_scope_cwes()` — a detector can now emit them
    — but they match none of the labelled corpus's 17 ground-truth CWEs, so the
    corpus's in-scope row count is unchanged. That is the difference between
    widening the vocabulary because a detector grew and widening it to make a
    number look better (§14.42, `OPEN_ITEMS.md` §19).
    """
    from pathlib import Path

    import pytest

    from pr_review.benchmark.schema import Corpus
    from pr_review.benchmark.scope import in_scope_cwes, is_in_scope

    corpus_path = Path("benchmark/corpus/labelled.json")
    if not corpus_path.exists():                       # pragma: no cover
        pytest.skip("pinned corpus not present")

    scope = in_scope_cwes()
    assert {"CWE-250", "CWE-269"} <= scope             # the detector reaches them
    corpus = Corpus.model_validate_json(corpus_path.read_text())
    rows = [gt for c in corpus.cases if c.labelled for gt in c.ground_truth]
    assert len(rows) == 36
    assert sum(1 for r in rows if is_in_scope(r.cwe, scope)) == 9


# -- the baseline cache refuses what it can no longer match against ---------

def test_a_cached_baseline_is_refused_when_the_mapping_changed(tmp_path):
    """§14.49. `Finding.fingerprint` hashes the taxonomy `internal` id, so
    remapping a rule changes every affected fingerprint on the head side while a
    cached baseline still holds the old ones. Nothing matches and a pre-existing
    finding is reported as **introduced** — silently, and in the direction that
    invents false positives.

    Measured on the IaC corpus when `CKV_DOCKER_3` was remapped: 32 reported
    findings became 112, and a freshly built baseline came back to 32 exactly.
    """
    from unittest import mock

    from pr_review.findings.delta import Baseline, BaselineCache

    cache = BaselineCache("o/r", tmp_path)
    cache.save(Baseline(base_sha="a" * 40, fingerprints={"deadbeef"},
                        paths=["Dockerfile"], tools=["checkov"]))

    assert cache.load("a" * 40) is not None            # same tables, still good

    with mock.patch("pr_review.findings.delta.mapping_digest",
                    return_value="0000000000000000"):
        assert cache.load("a" * 40) is None, (
            "a baseline whose fingerprints were produced by a different "
            "mapping must be rebuilt, not reused")


def test_a_cached_baseline_is_refused_on_a_version_bump(tmp_path):
    """The manual half. `mapping_digest` covers taxonomy edits; `version` covers
    everything else that moves a fingerprint — the fields `util.fingerprint`
    hashes, or how a detector produces its snippet."""
    import json
    from unittest import mock

    from pr_review.findings.delta import Baseline, BaselineCache

    cache = BaselineCache("o/r", tmp_path)
    path = cache.save(Baseline(base_sha="b" * 40, fingerprints={"cafe"}))
    with mock.patch("pr_review.findings.delta.BASELINE_VERSION", 99):
        assert cache.load("b" * 40) is None

    # And a dump written before either guard existed carries neither field.
    stale = json.loads(path.read_text())
    del stale["version"], stale["mapping"]
    path.write_text(json.dumps(stale))
    assert cache.load("b" * 40) is None


def test_the_mapping_digest_moves_when_a_rule_is_remapped():
    """It has to be derived from the tables, not maintained beside them: a human
    forgetting to bump a constant is exactly the failure mode a constant has,
    and a remap is the edit somebody makes without thinking about caches."""
    from unittest import mock

    from pr_review.detect import normalize as n

    before = n.mapping_digest()
    patched = dict(n._EXACT)
    patched["checkov"] = dict(patched["checkov"])
    patched["checkov"]["CKV_DOCKER_3"] = n.RuleMapping(
        "CFG-DEFAULT-CREDS", Severity.MEDIUM, 7, "Container runs as root")
    with mock.patch.object(n, "_EXACT", patched):
        assert n.mapping_digest() != before
    assert n.mapping_digest() == before                 # stable, and restored
