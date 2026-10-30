"""Regression checks for active repository CI workflow contracts."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


def load_workflow(filename: str) -> dict[str, object]:
    """Load one checked-in workflow as a YAML mapping."""
    path = WORKFLOWS_DIR / filename
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{filename}: expected a YAML mapping"
    return document


def workflow_triggers(workflow: dict[str, object]) -> dict[str, object]:
    """Return triggers while supporting PyYAML's YAML 1.1 'on' parsing."""
    triggers = (
        workflow["on"]
        if "on" in workflow
        else next((value for key, value in workflow.items() if key is True), None)
    )
    assert isinstance(triggers, dict), "Expected event triggers to be a mapping"
    return triggers


def event_paths(workflow: dict[str, object], event: str) -> list[str]:
    """Return configured path filters for one workflow event."""
    config = workflow_triggers(workflow).get(event, {})
    assert isinstance(config, dict), f"{event}: expected a configuration mapping"
    paths = config.get("paths", [])
    assert isinstance(paths, list), f"{event}: expected a paths list"
    return paths


def test_python_ci_checks_critical_rules_and_lints_actual_pr_changes() -> None:
    """CI must keep critical repository-wide checks and scope strict lint correctly."""
    workflow = load_workflow("ci.yml")
    permissions = workflow.get("permissions")
    assert isinstance(permissions, dict)
    assert permissions.get("contents") == "read"

    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict)
    job = jobs["build"]
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)

    all_commands = "\n".join(
        str(step.get("run", "")) for step in steps if isinstance(step, dict)
    )
    assert "--select=E9,F63,F7,F82" in all_commands
    assert "PR_HEAD_SHA" in all_commands or any(
        isinstance(step, dict) and "PR_HEAD_SHA" in step.get("env", {})
        for step in steps
    )
    assert (
        'git diff --name-only --diff-filter=ACMR "$base_sha" "$target_sha"'
        in all_commands
    )
    assert "python -m pytest" in all_commands


def test_governance_docs_workflow_uses_read_only_permissions() -> None:
    """The docs workflow must run the repository's documented lint target."""
    workflow = load_workflow("governance-docs-lint.yml")
    permissions = workflow.get("permissions")
    assert isinstance(permissions, dict)
    assert permissions.get("contents") == "read"

    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict)
    job = jobs["lint-governance-docs"]
    assert isinstance(job, dict)
    assert job.get("runs-on") == "ubuntu-latest"
    steps = job["steps"]
    assert isinstance(steps, list)
    assert any(
        isinstance(step, dict) and step.get("run") == "make governance-docs-check"
        for step in steps
    )


def test_governance_artifacts_ci_keeps_both_validation_tracks() -> None:
    """Both governance artifact tracks must remain separately represented."""
    workflow = load_workflow("governance-artifacts-ci.yml")
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict)
    assert "validate-existing-governance-stack" in jobs
    assert "validate-gstack-artifacts" in jobs

    for event in ("pull_request", "push"):
        paths = event_paths(workflow, event)
        assert ".github/workflows/governance-artifacts-ci.yml" in paths
        assert "gstack_artifacts/**" in paths


def test_governance_artifacts_validate_checks_json_output_and_unit_tests() -> None:
    """The artifact validator must verify output contracts and execute unit tests."""
    workflow = load_workflow("governance-artifacts-validate.yml")
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict)
    job = jobs["validate"]
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)

    step_names = {str(step.get("name", "")) for step in steps if isinstance(step, dict)}
    assert "Validate governance artifacts JSON output file" in step_names
    assert "Run validator unit tests" in step_names

    commands = "\n".join(
        str(step.get("run", "")) for step in steps if isinstance(step, dict)
    )
    assert "python3 -m unittest discover" in commands
