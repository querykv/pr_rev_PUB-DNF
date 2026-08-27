"""M0 walking-skeleton tests: contracts + the underscore-identifier regression."""
from pathlib import Path

from pr_review.config import Config
from pr_review.detect.base import ScanTarget
from pr_review.detect.secrets import SecretsDetector
from pr_review.extract import classify
from pr_review.extract.diff import parse_unified_diff
from pr_review.extract.manifest import build_manifest
from pr_review.findings.normalize import normalize
from pr_review.policy import gate
from pr_review.report.sarif import build_sarif
from pr_review.schema import Severity

FIX = Path(__file__).parent / "fixtures" / "sample.diff"
GHP = "ghp_" + "A" * 36


def _diff() -> str:
    return FIX.read_text()


def test_diff_parser():
    paths = {f.path: f for f in parse_unified_diff(_diff())}
    assert set(paths) == {"app/config.py", "app/util.py", "tests/test_config.py"}
    assert paths["app/config.py"].change == "added"
    assert paths["app/util.py"].change == "modified"
    added = [a.text for h in paths["app/config.py"].hunks for a in h.added]
    assert any("AKIA" in t for t in added)


def test_classify():
    assert classify.detect_lang("a/b.py") == "python"
    assert classify.is_test("tests/test_x.py")
    assert not classify.is_test("app/config.py")
    assert classify.is_dep_manifest("requirements.txt")
    assert classify.is_iac("Dockerfile")


def test_build_output_is_classified_generated():
    """Regression, benchmark 2026-08-07: a minified sourcemap under `dist/`
    produced a HIGH `SEC-PASSWORD` finding with a 1.25 MB evidence snippet.
    `secrets.py` and `sast_semgrep.py` both skip generated files, so this is
    what stops them scanning a bundle."""
    for path in ("netbox/project-static/dist/netbox.js.map",
                 "static/dist/app.css.map",
                 "web/dist/bundle.js",
                 "assets/site.min.css"):
        assert classify.is_generated(path), path


def test_hand_written_code_is_not_classified_generated():
    """The dangerous direction: a generated file is never scanned, so a false
    positive here is silent lost coverage rather than noise. `build/` is
    excluded from the rule for exactly this reason."""
    for path in ("app/views.py",
                 "build/scripts/release.py",     # `build/` is deliberately not a marker
                 "app/distributed/tasks.py",     # substring of "dist", not a dist/ dir
                 "src/mapper.py"):               # substring of ".map", not a sourcemap
        assert not classify.is_generated(path), path


# --------------------------------------------------------------------------
# Header markers (OPEN_ITEMS.md §17) -- content, when there is any
# --------------------------------------------------------------------------

DOCKER_LIBRARY_HEADER = """\
#
# NOTE: THIS DOCKERFILE IS GENERATED VIA "apply-templates.sh"
#
# PLEASE DO NOT EDIT IT DIRECTLY.
#
FROM alpine:3.20
RUN adduser -D app
"""


def test_a_generated_header_is_read_when_content_is_available():
    """`plan/phase-0-extraction.md` §3 asked for header markers and only the
    path half existed. This is the exact text on the IaC corpus's
    docker-library Dockerfiles."""
    assert classify.is_generated("Dockerfile", DOCKER_LIBRARY_HEADER)
    assert not classify.is_generated("Dockerfile"), "path alone must not decide"


def test_the_script_that_writes_the_header_is_not_itself_generated():
    """The measured false positive, and the reason for the two-signal rule.
    `apply-templates.sh` CONTAINS the header it emits. A single-marker rule
    suppresses it -- and it is hand-written shell that a security tool should
    read. Measured: single-marker newly suppresses 11,073 files, two-signal 803
    (`BENCHMARK_STATUS.md` §4n)."""
    # The real file, whose first lines are setup -- the heredoc that emits the
    # header is far below. This is the shape the corpus measurement saw.
    generator = (
        "#!/usr/bin/env bash\n"
        "set -Eeuo pipefail\n"
        "\n"
        '[ -f versions.json ] # run "versions.sh" first\n'
        "\n"
        "jqt='.jq-template.awk'\n"
        "if [ -n \"${BASHBREW_SCRIPTS:-}\" ]; then\n"
        "\tjqt=\"$BASHBREW_SCRIPTS/jq-template.awk\"\n"
        "fi\n"
        "\n"
        "for version; do\n"
        '\techo "# NOTE: THIS DOCKERFILE IS GENERATED VIA apply-templates.sh"\n'
        '\techo "# PLEASE DO NOT EDIT IT DIRECTLY."\n'
        "done\n"
    )
    assert not classify.is_generated("apply-templates.sh", generator)


def test_a_generator_that_emits_its_header_in_its_first_ten_lines_is_a_known_blind_spot():
    """Pinned because it is WRONG and known, not because it is right.

    A `#`-prefixed line inside a heredoc is indistinguishable from a header
    comment by any rule that does not parse the language. If a generator emits
    its template within its own first ten lines, this suppresses it -- a false
    positive, the expensive direction.

    It is left because it was measured and does not occur: zero of 305,861 files
    in the corpus trees (`BENCHMARK_STATUS.md` §4n). The line-10 window is what
    keeps the real generators out, and this test says so out loud so nobody
    reads the measurement as proof the rule is sound in general."""
    pathological = (
        "#!/bin/sh\n"
        'cat <<EOF\n'
        "# this file is generated\n"
        "# do not edit\n"
        "EOF\n"
    )
    assert classify.is_generated("gen.sh", pathological), (
        "if this now returns False the rule got stronger -- update the entry "
        "in OPEN_ITEMS.md §17 rather than deleting this test")


def test_one_signal_alone_is_never_enough():
    """The two-signal rule itself, which nothing else here exercises.

    Caught by falsification: relaxing `gen and edit` to `gen or edit` left the
    whole file green, because every other fixture matches either both markers
    or neither. A guard no test can break is not a guard.

    Measured stakes: one signal newly suppresses 11,073 files, two suppresses
    803 (`BENCHMARK_STATUS.md` §4n)."""
    gen_only = "# this file is generated from schema.json\nFROM alpine\n"
    edit_only = "# do not edit -- ask the platform team first\nFROM alpine\n"

    assert not classify.is_generated("Dockerfile", gen_only)
    assert not classify.is_generated("Dockerfile", edit_only)
    # And both together, on separate lines, is the real docker-library shape.
    assert classify.is_generated("Dockerfile", gen_only + edit_only)


def test_prose_about_generation_is_not_a_generated_file():
    """`dependency-submission.yml` says "automatically generated" while
    DESCRIBING GitHub's dependency graph, and is not suppressed. Note this one
    passes at the *marker* stage, not the two-signal stage: "automatically
    generated" is deliberately not in `_GEN_MARKERS`, because the measured
    variant that included it caught workflow files. Workflows are an attack
    surface, so suppressing them is the expensive direction."""
    workflow = (
        "name: Dependency submission\n"
        "\n"
        "# GitHub's automatically generated dependency graph only covers\n"
        "# dependencies declared in recognised package manifests.\n"
        "on: [push]\n"
    )
    assert not classify.is_generated(".github/workflows/dependency-submission.yml",
                                     workflow)


def test_the_marker_must_be_in_a_comment_and_near_the_top():
    """Two more clauses, each with its own failure. A string literal deep in a
    file is not a header, and neither is one 200 lines down."""
    literal = 'MSG = "this file is generated, do not edit"\nimport os\n'
    assert not classify.is_generated("app/tool.py", literal)

    buried = "\n".join(["import os"] * 40 + [
        "# this file is generated", "# do not edit"])
    assert not classify.is_generated("app/tool.py", buried)


def test_path_rules_still_decide_on_their_own_with_no_content():
    """The content half is strictly additive. An offline run has a diff and no
    checkout (arm 2c), so the path answer must stand alone -- unchanged."""
    assert classify.is_generated("app/migrations/0001_initial.py")
    assert classify.is_generated("api/service_pb2.py", "hand written, honest")
    assert not classify.is_generated("app/views.py", "import os\n")


def test_secrets_catches_underscore_identifiers():
    """Regression: keywords embedded in identifiers (DB_PASSWORD) must be caught."""
    t = ScanTarget(path="app/config.py", added_lines=[
        (3, 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"'),
        (4, 'DB_PASSWORD = "s3cr3tP@ssw0rd!"'),
    ])
    fs = SecretsDetector().run([t])
    internals = {f.taxonomy.internal for f in fs}
    assert "SEC-AWS-KEY" in internals
    assert "SEC-PASSWORD" in internals
    # secrets redacted in evidence
    assert all("AKIA1234567890ABCDEF" not in f.evidence[0].snippet for f in fs)
    assert all("s3cr3tP@ssw0rd!" not in f.evidence[0].snippet for f in fs)


def test_placeholder_suppressed():
    t = ScanTarget(path="x.py", added_lines=[
        (1, 'password = "changeme"'),
        (2, 'api_key = "${API_KEY}"'),
    ])
    assert SecretsDetector().run([t]) == []


def test_a_command_substitution_is_not_a_hardcoded_credential():
    """The exact line that failed a gate on the IaC corpus, 2026-08-09.

    `docker-library/postgres`'s `docker-entrypoint.sh:76` assigns a temp *file
    path*; it was reported HIGH and flagged the build, because secrets still
    carry the M0 `status=validated` simplification and are the only class that
    can reach the gate. `${...}` was already suppressed and `$(...)` was not,
    though a value computed at run time is not a hardcoded one either way.
    """
    t = ScanTarget(path="docker-entrypoint.sh", added_lines=[
        (76, '\t\t\tNSS_WRAPPER_PASSWD="$(mktemp)"'),
        (77, 'DB_PASSWORD="$(cat /run/secrets/db_password)"'),
    ])
    assert SecretsDetector().run([t]) == []


def test_a_real_credential_on_the_same_shape_still_fires():
    """The anti-vacuity half: the fix must not silence the whole rule."""
    t = ScanTarget(path="docker-entrypoint.sh",
                   added_lines=[(1, 'DB_PASSWORD="s3cr3tP@ssw0rd!"')])
    fs = SecretsDetector().run([t])
    assert [f.taxonomy.internal for f in fs] == ["SEC-PASSWORD"]


def test_test_file_capped_to_medium():
    t = ScanTarget(path="tests/t.py", is_test=True, added_lines=[(1, f'token = "{GHP}"')])
    fs = SecretsDetector().run([t])
    assert fs and all(f.severity == Severity.MEDIUM for f in fs)


def test_specific_suppresses_generic_same_line():
    t = ScanTarget(path="app/x.py", added_lines=[(1, f'token = "{GHP}"')])
    fs = SecretsDetector().run([t])
    assert len(fs) == 1 and fs[0].taxonomy.internal == "SEC-TOKEN"


def test_normalize_sorts_and_counts():
    t = ScanTarget(path="app/config.py", added_lines=[
        (3, 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"'),
        (4, 'DB_PASSWORD = "s3cr3tP@ssw0rd!"'),
    ])
    fs = normalize(SecretsDetector().run([t]))
    ranks = [f.severity.rank for f in fs.findings]
    assert ranks == sorted(ranks, reverse=True)
    assert fs.counts["total"] == 2


def test_gate_flags_high_and_ignores_test_medium():
    targets = [
        ScanTarget(path="app/config.py", added_lines=[(4, 'DB_PASSWORD = "s3cr3tP@ssw0rd!"')]),
        ScanTarget(path="tests/t.py", is_test=True, added_lines=[(1, f'token = "{GHP}"')]),
    ]
    findings = []
    for t in targets:
        findings += SecretsDetector().run([t])
    fs = normalize(findings)
    g = gate(fs.findings, Config().gate)
    assert g.verdict == "flagged"
    assert len(g.triggers) == 1  # only the HIGH app-code secret, not the MEDIUM test token


def test_sarif_shape():
    t = ScanTarget(path="app/config.py", added_lines=[(4, 'DB_PASSWORD = "s3cr3tP@ssw0rd!"')])
    s = build_sarif(normalize(SecretsDetector().run([t])))
    assert s["version"] == "2.1.0"
    assert s["runs"][0]["tool"]["driver"]["name"] == "pr-review"
    assert s["runs"][0]["results"][0]["level"] == "error"


def test_build_manifest_classification():
    m, _ = build_manifest(repo="o/r", pr_number=1, diff_text=_diff())
    assert m.stats["files"] == 3
    assert {f.path for f in m.files if f.is_test} == {"tests/test_config.py"}
