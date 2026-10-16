"""Current-state validation for the repository's GitHub Actions workflows.

These checks inspect workflows present in this checkout instead of assuming
obsolete workflow templates from an earlier repository state still exist.
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


def require(condition: object, message: str) -> None:
    """Fail a test without relying on assert statements removed by python -O."""
    if not condition:
        pytest.fail(message, pytrace=False)


def workflow_on(document: dict) -> dict:
    """Return triggers regardless of PyYAML's YAML 1.1 handling of 'on'."""
    return document.get("on", document.get(True, {})) or {}


def load_workflow(filename: str) -> dict:
    """Load an existing workflow as a YAML mapping."""
    path = WORKFLOWS_DIR / filename
    if not path.is_file():
        pytest.skip(f"Workflow is not present in this checkout: {filename}")
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(isinstance(document, dict), f"{filename}: expected a YAML mapping")
    return document


def test_workflow_directory_contains_yaml_files():
    """Require at least one discoverable workflow file."""
    require(bool(WORKFLOW_FILES), "No GitHub Actions workflow YAML files were found")


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_workflow_is_nonempty_yaml_mapping(filename: str):
    """Check that each discovered workflow parses to a nonempty mapping."""
    path = WORKFLOWS_DIR / filename
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(
        isinstance(document, dict) and bool(document),
        f"{filename}: invalid or empty YAML",
    )


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_workflow_has_nonempty_name(filename: str):
    """Require each workflow to declare a meaningful name."""
    document = load_workflow(filename)
    require(
        isinstance(document.get("name"), str) and document["name"].strip(),
        f"{filename}: expected a nonempty workflow name",
    )


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_workflow_has_triggers(filename: str):
    """Require each workflow to declare one or more event triggers."""
    document = load_workflow(filename)
    require(bool(workflow_on(document)), f"{filename}: no trigger configuration found")


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_workflow_has_jobs(filename: str):
    """Require each workflow to contain a nonempty jobs mapping."""
    document = load_workflow(filename)
    jobs = document.get("jobs")
    require(
        isinstance(jobs, dict) and bool(jobs),
        f"{filename}: expected at least one job",
    )


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_jobs_have_runner_or_reusable_workflow(filename: str):
    """Require jobs to specify a runner or a reusable workflow."""
    document = load_workflow(filename)
    for name, job in document["jobs"].items():
        require(isinstance(job, dict), f"{filename}: job {name!r} must be a mapping")
        require(
            bool(job.get("uses") or job.get("runs-on")),
            f"{filename}: job {name!r} must declare runs-on or use a reusable workflow",
        )


def _validate_nonreusable_job_steps(filename: str, name: str, job: dict) -> None:
    """Validate step entries for one non-reusable workflow job."""
    if job.get("uses"):
        return
    steps = job.get("steps")
    if not isinstance(steps, list) or not steps:
        pytest.fail(
            f"{filename}: job {name!r} must contain a nonempty steps list",
            pytrace=False,
        )
    for index, step in enumerate(steps):
        valid_step = isinstance(step, dict) and any(
            key in step for key in ("uses", "run", "name")
        )
        require(
            valid_step,
            f"{filename}: job {name!r} step {index} lacks uses, run, and name",
        )


@pytest.mark.parametrize("filename", WORKFLOW_FILES)
def test_nonreusable_jobs_have_nonempty_steps(filename: str):
    """Require regular jobs to contain meaningful step definitions."""
    document = load_workflow(filename)
    for name, job in document["jobs"].items():
        require(isinstance(job, dict), f"{filename}: job {name!r} must be a mapping")
        _validate_nonreusable_job_steps(filename, name, job)


def test_governance_artifacts_workflow_keeps_both_validation_jobs():
    """Keep both governance artifact validation jobs configured."""
    document = load_workflow("governance-artifacts-ci.yml")
    jobs = document["jobs"]
    require("validate-existing-governance-stack" in jobs, "Existing validator job is missing")
    require("validate-gstack-artifacts" in jobs, "G-Stack validator job is missing")


def test_governance_artifacts_workflow_runs_validator_tests():
    """Ensure the governance workflow invokes validator regression tests."""
    document = load_workflow("governance-artifacts-ci.yml")
    steps = document["jobs"]["validate-existing-governance-stack"]["steps"]
    require(
        any("make governance-validator-test" in step.get("run", "") for step in steps),
        "The governance artifact workflow must run its validator regression tests",
    )


def test_blueprint_manifest_workflow_exists_and_runs_checks():
    """Ensure manifest CI checks integrity and runs regression tests."""
    document = load_workflow("governance-blueprint-manifest-ci.yml")
    steps = document["jobs"]["manifest-check"]["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)
    require(
        "generate_artifact_manifest.py --check" in commands,
        "Manifest consistency check is missing",
    )
    require(
        "selftest_generate_artifact_manifest.py" in commands,
        "Manifest regression tests are missing",
    )


def test_labeler_configuration_is_valid_yaml():
    """Validate the label configuration used by the label workflow."""
    path = REPO_ROOT / ".github" / "labeler.yml"
    require(path.is_file(), "The configured workflow labeler requires .github/labeler.yml")
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    require(
        isinstance(document, dict) and bool(document),
        ".github/labeler.yml must be a nonempty YAML mapping",
    )
