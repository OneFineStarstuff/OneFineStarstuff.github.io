"""Current-state validation for the repository's GitHub Actions workflows.

These checks inspect workflows present in this checkout instead of asserting
that obsolete templates from an earlier repository state must exist.
"""
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
WORKFLOW_FILES = sorted(
    path.name
    for pattern in ("*.yml", "*.yaml")
    for path in WORKFLOWS_DIR.glob(pattern)
    if path.is_file()
)


def workflow_on(document: dict) -> dict:
    """Return triggers regardless of PyYAML's YAML 1.1 handling of 'on'."""
    return document.get("on", document.get(True, {})) or {}


def load_workflow(filename: str) -> dict:
    """Load an existing workflow as a YAML mapping."""
    path = WORKFLOWS_DIR / filename
    if not path.is_file():
        pytest.skip(f"Workflow is not present in this checkout: {filename}")
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{filename}: expected a YAML mapping"
    return document


def test_workflow_directory_contains_yaml_files():
    assert WORKFLOW_FILES, "No GitHub Actions workflow YAML files were found"


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_workflow_is_nonempty_yaml_mapping(filename: str):
    path = WORKFLOWS_DIR / filename
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict) and document, f"{filename}: invalid or empty YAML"


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_workflow_has_nonempty_name(filename: str):
    document = load_workflow(filename)
    assert isinstance(document.get("name"), str) and document["name"].strip(), (
        f"{filename}: expected a nonempty workflow name"
    )


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_workflow_has_triggers(filename: str):
    document = load_workflow(filename)
    assert workflow_on(document), f"{filename}: no trigger configuration found"


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_workflow_has_jobs(filename: str):
    document = load_workflow(filename)
    jobs = document.get("jobs")
    assert isinstance(jobs, dict) and jobs, f"{filename}: expected at least one job"


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_jobs_have_runner_or_reusable_workflow(filename: str):
    document = load_workflow(filename)
    for name, job in document["jobs"].items():
        assert isinstance(job, dict), f"{filename}: job {name!r} must be a mapping"
        assert job.get("uses") or job.get("runs-on"), (
            f"{filename}: job {name!r} must declare runs-on or use a reusable workflow"
        )


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_nonreusable_jobs_have_nonempty_steps(filename: str):
    document = load_workflow(filename)
    for name, job in document["jobs"].items():
        if job.get("uses"):
            continue
        steps = job.get("steps")
        assert isinstance(steps, list) and steps, (
            f"{filename}: job {name!r} must contain a nonempty steps list"
        )
        for index, step in enumerate(steps):
            assert isinstance(step, dict) and any(
                key in step for key in ("uses", "run", "name")
            ), f"{filename}: job {name!r} step {index} lacks uses, run, and name"


def test_governance_artifacts_workflow_keeps_both_validation_jobs():
    document = load_workflow("governance-artifacts-ci.yml")
    jobs = document["jobs"]
    assert "validate-existing-governance-stack" in jobs
    assert "validate-gstack-artifacts" in jobs


def test_governance_artifacts_workflow_runs_validator_tests():
    document = load_workflow("governance-artifacts-ci.yml")
    steps = document["jobs"]["validate-existing-governance-stack"]["steps"]
    assert any("make governance-validator-test" in step.get("run", "") for step in steps), (
        "The governance artifact workflow must run its validator regression tests"
    )


def test_blueprint_manifest_workflow_exists_and_runs_checks():
    document = load_workflow("governance-blueprint-manifest-ci.yml")
    steps = document["jobs"]["manifest-check"]["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)
    assert "generate_artifact_manifest.py --check" in commands
    assert "selftest_generate_artifact_manifest.py" in commands


def test_labeler_configuration_is_valid_yaml():
    path = REPO_ROOT / ".github" / "labeler.yml"
    assert path.is_file(), "The configured workflow labeler requires .github/labeler.yml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict) and document, ".github/labeler.yml must be a nonempty YAML mapping"
