"""Validate the workflow files that actually exist in this repository."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
WORKFLOW_FILES = sorted(
    path
    for path in WORKFLOWS_DIR.iterdir()
    if path.is_file() and path.suffix in {".yml", ".yaml"}
)


@pytest.mark.parametrize("workflow_path", WORKFLOW_FILES, ids=lambda path: path.name)
def test_workflow_has_valid_structure(workflow_path: Path) -> None:
    """Every checked-in workflow must parse and define runnable work."""
    document = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

    assert isinstance(document, dict), f"{workflow_path.name}: expected a YAML mapping"
    assert (
        isinstance(document.get("name"), str) and document["name"].strip()
    ), f"{workflow_path.name}: missing a non-empty workflow name"

    # PyYAML's YAML 1.1 parser can interpret the unquoted key "on" as True.
    triggers = document.get("on", document.get(True))
    assert (
        isinstance(triggers, (dict, list)) and triggers
    ), f"{workflow_path.name}: missing workflow triggers"

    jobs = document.get("jobs")
    assert (
        isinstance(jobs, dict) and jobs
    ), f"{workflow_path.name}: expected at least one job"

    for job_name, job_config in jobs.items():
        assert isinstance(
            job_config, dict
        ), f"{workflow_path.name}: job {job_name!r} must be a mapping"
        if "uses" in job_config:
            # Reusable-workflow jobs declare their own runner and steps.
            continue
        assert job_config.get(
            "runs-on"
        ), f"{workflow_path.name}: job {job_name!r} is missing runs-on"
        steps = job_config.get("steps")
        assert (
            isinstance(steps, list) and steps
        ), f"{workflow_path.name}: job {job_name!r} needs at least one step"


def test_labeler_configuration_is_valid_yaml() -> None:
    """Keep the repository's current GitHub labeler configuration parseable."""
    labeler_path = REPO_ROOT / ".github" / "labeler.yml"
    assert labeler_path.is_file(), "Expected .github/labeler.yml to exist"

    labeler = yaml.safe_load(labeler_path.read_text(encoding="utf-8"))
    assert isinstance(labeler, dict) and labeler
