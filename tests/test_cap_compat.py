"""Compat shims for defects in the vendored CAP engine.

Each test states the defect and how to tell when the shim can be deleted.
"""
import pytest

pytest.importorskip(
    "cap_engine.orchestration.loop",
    reason="cap_engine not installed — run: pip install -e cap_engine/'[tree-sitter]'",
)

from pr_review import cap_compat  # noqa: E402


def test_apply_is_idempotent_and_reports_what_it_did():
    first = cap_compat.apply()
    second = cap_compat.apply()
    assert first == second == cap_compat.applied()
    assert "unique_session_ids" in first


def test_session_ids_are_unique_within_one_second():
    """The defect: `CAPOrchestrationLoop.__init__` builds
    `session-{_timestamp()}` at second resolution and `CGPServer.session_create`
    raises on a duplicate, so two workflow steps starting in the same second
    abort the run with `CGPError [-32012] Session already exists`.

    Reproducing it needs steps to be *fast*, which is why static analysis and
    the single-call smoke test both missed it — but a fake provider, a small
    repo, or a quick model all hit it, and it blocks every multi-step workflow.
    """
    cap_compat.apply()
    from cap_engine.orchestration.loop import loop as loop_mod

    ids = {loop_mod._timestamp() for _ in range(200)}
    assert len(ids) == 200


def test_the_defect_is_still_present_upstream():
    """When CAP fixes this, `SHIMS` should lose the entry and this test with it.

    CAP's own `SubAgentDispatcher._make_agent_id` already uses microseconds plus
    an atomic counter — the loop simply never got the same treatment, so the
    upstream fix is small and may well land.
    """
    import inspect

    from cap_engine.orchestration.loop import loop as loop_mod

    # The patched module global is ours; the defect is in the source text.
    source = inspect.getsource(loop_mod.CAPOrchestrationLoop.__init__)
    assert 'f"session-{_timestamp()}"' in source, (
        "session id no longer derives from _timestamp — re-check whether the "
        "unique_session_ids shim is still needed"
    )


def test_multi_step_workflow_runs_with_the_shim(tmp_path):
    """End-to-end proof: the 7-step security-profile workflow completes."""
    from cap_engine.orchestration.workflow import WorkflowRunner

    from pr_review.config import Config
    from pr_review.models.fake import FakeInferenceProvider, plan_response
    from pr_review.models.framework import build_framework

    cap_compat.apply()
    provider = FakeInferenceProvider(responses={"planner": plan_response()})
    fw = build_framework(Config(), "tests/fixtures/sample_app", provider,
                         output_dir=tmp_path / "out", log_dir=tmp_path / "logs")
    report = WorkflowRunner(fw).run(
        "security-profile", output=str(tmp_path / "out" / "report.md")
    )

    assert report
    # Every step dispatched a planner; without the shim the run dies on step 2.
    assert len(provider.calls_for("planner")) >= 7
    assert len(provider.calls_for("synthesizer")) >= 1
