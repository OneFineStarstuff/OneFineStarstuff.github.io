"""Repository-level checks for the active GitHub Actions workflow set."""

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

CORE_WORKFLOWS = (
    "ci.yml",
    "gien-evidence-api-ci.yml",
    "gien-platform-ci.yml",
    "governance-artifacts-ci.yml",
    "governance-docs-lint.yml",
    "sentinel-governance-gates.yml",
)


def load_workflow(filename: str) -> dict:
    """Load a workflow document from the repository."""
    path = WORKFLOWS_DIR / filename
    with path.open(encoding="utf-8") as workflow_file:
        document = yaml.safe_load(workflow_file)
    assert isinstance(document, dict), f"{filename} must be a YAML mapping"
    return document


def workflow_triggers(document: dict) -> dict:
    """Read GitHub's 'on' key across PyYAML YAML 1.1 and string-key modes."""
    return document.get("on") or document.get(True) or {}


def step_commands(document: dict) -> str:
    """Return all shell commands declared by workflow steps."""
    commands = []
    for job in document.get("jobs", {}).values():
        for step in job.get("steps", []):
            command = step.get("run")
            if isinstance(command, str):
                commands.append(command)
    return "\n".join(commands)


def test_workflow_directory_contains_yaml_files():
    """The repository must retain at least one GitHub Actions workflow."""
    workflow_files = list(WORKFLOWS_DIR.glob("*.yml")) + list(
        WORKFLOWS_DIR.glob("*.yaml")
    )
    assert workflow_files, "No workflow YAML files found"


def test_core_workflows_exist():
    """The platform's core validation workflows must remain present."""
    missing = [
        filename
        for filename in CORE_WORKFLOWS
        if not (WORKFLOWS_DIR / filename).is_file()
    ]
    assert not missing, f"Missing required workflow files: {', '.join(missing)}"


def test_python_ci_keeps_lint_and_test_gates():
    """Python CI must retain Ruff checks and the pytest suite."""
    document = load_workflow("ci.yml")
    commands = step_commands(document)
    assert "ruff check" in commands
    assert "pytest" in commands


def test_gien_platform_ci_runs_frontend_contract_build_and_smoke_checks():
    """The GIEN platform workflow must exercise its frontend release checks."""
    document = load_workflow("gien-platform-ci.yml")
    jobs = document["jobs"]
    assert "build" in jobs
    commands = step_commands(document)
    assert "npm run test:evidence" in commands
    assert "npm run build" in commands
    assert "npm run dev" in commands
    assert "evidence-api" in jobs


def test_gien_evidence_api_ci_runs_syntax_and_contract_checks():
    """The evidence API workflow must run both syntax and contract tests."""
    document = load_workflow("gien-evidence-api-ci.yml")
    commands = step_commands(document)
    assert "npm run check" in commands
    assert "npm test" in commands


def test_gien_ci_workflows_have_pull_request_triggers():
    """The focused GIEN CI workflows must validate pull requests."""
    for filename in ("gien-platform-ci.yml", "gien-evidence-api-ci.yml"):
        triggers = workflow_triggers(load_workflow(filename))
        assert (
            "pull_request" in triggers
        ), f"{filename} is missing a pull_request trigger"
