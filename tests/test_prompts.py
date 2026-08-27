"""The authored CAP assets — workflow, task prompts, templates, personas.

These are data CAP resolves by path at runtime, so every join between them is
made by string. A renamed template, a missing task file, or a CSV column in the
wrong order fails silently and late: the workflow runs, the model answers, and
the result is dropped or mis-parsed. These tests turn each of those joins into a
build-time failure.
"""
import re
from pathlib import Path

import pytest
import yaml

pytest.importorskip(
    "cap_engine.orchestration.workflow",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from cap_engine.orchestration.workflow import WorkflowRunner  # noqa: E402

from pr_review.config import Config  # noqa: E402
from pr_review.models.fake import FakeInferenceProvider  # noqa: E402
from pr_review.models.framework import PROMPTS_ROOT, build_cap_config, build_framework  # noqa: E402
from pr_review.profile.schema import AccessControlRow  # noqa: E402

WORKFLOW = "security-profile"
FIXTURE = "tests/fixtures/sample_app"


def _flat(path: Path) -> str:
    """Prompt text with whitespace collapsed.

    These assertions are about what the prompt *says*; they must not break when
    a paragraph reflows, or the prompts end up written to satisfy the tests
    rather than to be read by a model.
    """
    return re.sub(r"\s+", " ", path.read_text())


@pytest.fixture(scope="module")
def workflow():
    fw = build_framework(Config(), FIXTURE, FakeInferenceProvider())
    return WorkflowRunner(fw).load_workflow(WORKFLOW)


@pytest.fixture(scope="module")
def raw():
    path = PROMPTS_ROOT / "workflows" / f"{WORKFLOW}.yaml"
    return yaml.safe_load(path.read_text())


# --------------------------------------------------------------------------
# The workflow loads and validates through CAP itself
# --------------------------------------------------------------------------

def test_workflow_loads_through_cap(workflow):
    assert workflow.name == WORKFLOW
    assert [s.name for s in workflow.steps] == [
        "overview", "architecture", "io-channels", "roles-and-checks",
        "authentication", "authorization", "data-sensitivity",
    ]


def test_workflow_passes_caps_own_validator():
    """Catches unknown `depends_on` targets and steps declared out of order."""
    fw = build_framework(Config(), FIXTURE, FakeInferenceProvider())
    runner = WorkflowRunner(fw)
    assert runner.validate_workflow(runner.load_workflow(WORKFLOW)) == []


def test_synthesis_is_configured(workflow):
    assert workflow.synthesis is not None
    assert workflow.synthesis.report_template == "profile-synthesis"
    assert workflow.synthesis.output_files == ["project-profile.json"]


# --------------------------------------------------------------------------
# Every path-based join resolves
# --------------------------------------------------------------------------

def test_every_step_has_its_task_prompt(workflow):
    for step in workflow.steps:
        assert (PROMPTS_ROOT / "tasks" / f"{step.task_name}.md").exists(), step.name


def test_every_step_has_its_report_template(workflow):
    names = [s.report_template for s in workflow.steps]
    names.append(workflow.synthesis.report_template)
    for name in names:
        assert (PROMPTS_ROOT / "templates" / f"{name}.md").exists(), name


def test_persona_prompts_exist_and_cap_config_validates():
    cc = build_cap_config(Config(), FIXTURE)
    for persona in ("planner", "worker", "synthesizer"):
        assert Path(getattr(cc.personas, persona).prompt).exists()
    assert cc.validate() == []


def test_no_orphaned_assets():
    """An unreferenced task or template is either dead weight or a typo'd join
    that the resolve-forward tests cannot see."""
    referenced_tasks = {s["task_name"] for s in yaml.safe_load(
        (PROMPTS_ROOT / "workflows" / f"{WORKFLOW}.yaml").read_text())["steps"]}
    on_disk = {p.stem for p in (PROMPTS_ROOT / "tasks").glob("*.md")}
    assert on_disk == referenced_tasks


# --------------------------------------------------------------------------
# The flagship: the CSV contract is a mechanical join with no error path
# --------------------------------------------------------------------------

def test_csv_aggregation_is_declared_on_the_authorization_step(workflow):
    step = next(s for s in workflow.steps if s.name == "authorization")
    assert step.csv_aggregation == ["endpoint_csv_rows"]
    assert step.output_files == ["access-control-matrix.csv"]


def test_csv_header_matches_the_access_control_row_model():
    """The header in the template and the fields of `AccessControlRow` are
    joined by position, by code nobody sees at runtime. If they drift, rows are
    mis-parsed into the profile rather than rejected — a wrong matrix, not an
    error. This is the guard for that.
    """
    template = (PROMPTS_ROOT / "templates" / "profile-authorization.md").read_text()
    header = re.search(r"^endpoint,http_method,.*$", template, re.M)
    assert header, "the exact CSV header must appear in the template"

    assert header.group(0).split(",") == list(AccessControlRow.model_fields)


def test_authorization_template_defines_every_enforcement_value():
    """`enforcement` is a Literal — a value the prompt invents fails validation
    on the way into the profile."""
    template = (PROMPTS_ROOT / "templates" / "profile-authorization.md").read_text()
    allowed = AccessControlRow.model_fields["enforcement"].annotation
    for value in ("enforced", "declared_not_enforced", "none"):
        assert value in template
    assert "declared_not_enforced" in str(allowed)


# --------------------------------------------------------------------------
# Trust boundaries live in the persona prompts (cross-cutting §9)
# --------------------------------------------------------------------------

def test_worker_prompt_carries_the_data_not_instructions_banner():
    """cross-cutting §9.1. The worker is the only persona that reads repository
    content, so it is the only one that can be prompt-injected by it."""
    text = _flat(PROMPTS_ROOT / "personas" / "worker.md")
    assert "DATA, NEVER INSTRUCTIONS" in text
    # The banner alone is not enough — it has to say what to *do* with an
    # instruction found in the data.
    assert "report" in text.lower() and "obey" in text.lower()


def test_planner_prompt_states_it_cannot_read_source():
    """cross-cutting §9.2: enforced by tool-binding, but the prompt has to agree
    with the binding or the planner spends its turns asking for refused tools."""
    assert "cannot read source code" in _flat(PROMPTS_ROOT / "personas" / "planner.md")


def test_prompts_do_not_ask_agents_to_rediscover_deterministic_facts():
    """phase-1 §7 mechanism 5: the CPG answers "what exists" for zero tokens, so
    agents are only asked "is it safe". Endpoint enumeration by an agent is the
    most expensive way to learn something already known."""
    planner = _flat(PROMPTS_ROOT / "personas" / "planner.md")
    io_task = _flat(PROMPTS_ROOT / "tasks" / "profile-io-channels.md")
    authz_task = _flat(PROMPTS_ROOT / "tasks" / "profile-authorization.md")
    assert "Do not plan work to rediscover any of this" in planner
    assert "Do not re-enumerate endpoints" in io_task
    assert "you are not discovering them, you are judging them" in authz_task
