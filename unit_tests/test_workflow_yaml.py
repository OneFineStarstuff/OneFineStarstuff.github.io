"""Structural validation for every workflow currently in the repository."""

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
WORKFLOW_PATHS = tuple(
    sorted(WORKFLOWS_DIR.glob("*.yml"))
    + sorted(WORKFLOWS_DIR.glob("*.yaml"))
)


def load_workflow(path: Path) -> dict:
    """Parse a workflow and require a mapping at the YAML document root."""
    with path.open(encoding="utf-8") as workflow_file:
        document = yaml.safe_load(workflow_file)
    assert isinstance(document, dict), (
        f"{path.name} must parse to a YAML mapping"
    )
    return document


def workflow_triggers(document: dict) -> dict:
    """Handle PyYAML's YAML 1.1 interpretation of the unquoted 'on' key."""
    return document.get("on") or document.get(True) or {}


def test_workflow_inventory_is_not_empty():
    """The parametrized workflow inventory must discover active files."""
    assert WORKFLOW_PATHS, "No .yml or .yaml files found under .github/workflows"


@pytest.mark.parametrize(
    "workflow_path",
    WORKFLOW_PATHS,
    ids=lambda path: path.name,
)
def test_workflow_is_valid_yaml_mapping(workflow_path: Path):
    """Every active workflow file must contain valid YAML mapping data."""
    load_workflow(workflow_path)


@pytest.mark.parametrize(
    "workflow_path",
    WORKFLOW_PATHS,
    ids=lambda path: path.name,
)
def test_workflow_has_nonempty_name(workflow_path: Path):
    """Every workflow must declare a nonempty name."""
    document = load_workflow(workflow_path)
    name = document.get("name")
    assert isinstance(name, str) and name.strip(), (
        f"{workflow_path.name} must declare a nonempty string name"
    )


@pytest.mark.parametrize(
    "workflow_path",
    WORKFLOW_PATHS,
    ids=lambda path: path.name,
)
def test_workflow_has_trigger_configuration(workflow_path: Path):
    """Every workflow must declare at least one event trigger."""
    document = load_workflow(workflow_path)
    triggers = workflow_triggers(document)
    assert isinstance(triggers, (dict, list)) and triggers, (
        f"{workflow_path.name} must declare a nonempty 'on' trigger"
    )


@pytest.mark.parametrize(
    "workflow_path",
    WORKFLOW_PATHS,
    ids=lambda path: path.name,
)
def test_workflow_has_nonempty_jobs_mapping(workflow_path: Path):
    """Every workflow must define at least one job."""
    document = load_workflow(workflow_path)
    jobs = document.get("jobs")
    assert isinstance(jobs, dict) and jobs, (
        f"{workflow_path.name} must define a nonempty jobs mapping"
    )


@pytest.mark.parametrize(
    "workflow_path",
    WORKFLOW_PATHS,
    ids=lambda path: path.name,
)
def test_workflow_jobs_are_runnable_or_reusable(workflow_path: Path):
    """Each job must be runnable on a runner or call a reusable workflow."""
    document = load_workflow(workflow_path)
    for job_name, job in document["jobs"].items():
        assert isinstance(job, dict), (
            f"{workflow_path.name}: job {job_name!r} must be a mapping"
        )
        if "uses" in job:
            assert isinstance(job["uses"], str) and job["uses"].strip(), (
                f"{workflow_path.name}: reusable job {job_name!r} needs a uses target"
            )
            continue

        assert job.get("runs-on"), (
            f"{workflow_path.name}: job {job_name!r} needs runs-on or uses"
        )
        steps = job.get("steps")
        assert isinstance(steps, list) and steps, (
            f"{workflow_path.name}: job {job_name!r} needs a nonempty steps list"
        )
        for index, step in enumerate(steps):
            assert isinstance(step, dict), (
                f"{workflow_path.name}: job {job_name!r} step {index} must be a mapping"
            )
            assert step.get("uses") or step.get("run"), (
                f"{workflow_path.name}: job {job_name!r} step {index} needs uses or run"
            )
