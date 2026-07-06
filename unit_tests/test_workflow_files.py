"""
Tests for GitHub Actions workflow file changes introduced in this PR.

Covers:
  - Deleted files are no longer present
  - New workflow files exist and parse as valid YAML
  - New workflow files have required structural properties
  - artifact-validation.yml specifics (concurrency, paths, Python version)
  - blueprint-artifacts-validation.yml specifics (job, paths, script references)
  - governance-artifacts-ci.yml modifications (job rename, timeout, permissions, env,
    step renames, trigger path changes)
"""

from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
GITHUB_DIR = REPO_ROOT / ".github"


def load_workflow(filename: str) -> dict:
    """Load and YAML-parse a workflow file from .github/workflows/."""
    path = WORKFLOWS_DIR / filename
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def workflow_on(data: dict) -> dict:
    """
    Return the trigger block of a workflow.

    PyYAML maps the 'on:' key to Python's boolean True,
    so we check both representations for robustness.
    """
    return data.get(True, data.get("on", {})) or {}


# ---------------------------------------------------------------------------
# Deleted-file assertions
# ---------------------------------------------------------------------------


def test_labeler_yml_was_deleted():
    """labeler.yml must have been removed in this PR."""
    assert not (GITHUB_DIR / "labeler.yml").exists()


def test_daily_gsifi_governance_validation_workflow_was_deleted():
    """daily-gsifi-governance-validation.yml must have been removed."""
    assert not (WORKFLOWS_DIR / "daily-gsifi-governance-validation.yml").exists()


def test_federated_zk_docs_validation_workflow_was_deleted():
    """federated-zk-docs-validation.yml must have been removed."""
    assert not (WORKFLOWS_DIR / "federated-zk-docs-validation.yml").exists()


# ---------------------------------------------------------------------------
# All new workflow files exist and are parseable
# ---------------------------------------------------------------------------

NEW_WORKFLOW_FILES = [
    "ada.yml",
    "alibabacloud.yml",
    "anchore-syft.yml",
    "anchore.yml",
    "android.yml",
    "artifact-validation.yml",
    "astro.yml",
    "aws-new.yml",
    "aws.yml",
    "azure-container-webapp-new.yml",
    "azure-container-webapp.yml",
    "azure-webapps-node.yml",
    "blueprint-artifacts-validation.yml",
    "c-cpp.yml",
    "clojure.yml",
    "cmake-multi-platform.yml",
    "cmake-single-platform.yml",
    "codacy.yml",
    "crystal.yml",
    "d.yml",
    "dart.yml",
    "datadog-synthetics.yml",
    "defender-for-devops.yml",
]


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_new_workflow_file_exists(filename: str):
    assert (WORKFLOWS_DIR / filename).exists(), f"{filename} not found in .github/workflows/"


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_new_workflow_file_is_valid_yaml(filename: str):
    data = load_workflow(filename)
    assert isinstance(data, dict), f"{filename} did not parse as a YAML mapping"


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_new_workflow_file_has_name(filename: str):
    data = load_workflow(filename)
    assert "name" in data, f"{filename} is missing a 'name' key"
    assert data["name"], f"{filename} has an empty 'name'"


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_new_workflow_file_has_jobs(filename: str):
    data = load_workflow(filename)
    assert "jobs" in data, f"{filename} is missing a 'jobs' key"
    assert data["jobs"], f"{filename} has no jobs defined"


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_new_workflow_file_has_triggers(filename: str):
    data = load_workflow(filename)
    on = workflow_on(data)
    assert on, f"{filename} has no trigger ('on:') configuration"


# ---------------------------------------------------------------------------
# Expected workflow names for selected new files
# ---------------------------------------------------------------------------

EXPECTED_NAMES = {
    "ada.yml": "Ada (GNAT)",
    "android.yml": "Android CI",
    "artifact-validation.yml": "Artifact Validation",
    "blueprint-artifacts-validation.yml": "Blueprint Artifact Validation",
    "c-cpp.yml": "C/C++ CI",
    "clojure.yml": "Clojure CI",
    "cmake-multi-platform.yml": "CMake on multiple platforms",
    "cmake-single-platform.yml": "CMake on a single platform",
    "codacy.yml": "Codacy Security Scan",
    "crystal.yml": "Crystal CI",
    "d.yml": "D",
    "dart.yml": "Dart",
    "datadog-synthetics.yml": "Run Datadog Synthetic tests",
    "defender-for-devops.yml": "Microsoft Defender For Devops",
    "alibabacloud.yml": "Build and Deploy to ACK",
    "anchore-syft.yml": "Anchore Syft SBOM scan",
    "anchore.yml": "Anchore Grype vulnerability scan",
    "aws-new.yml": "Deploy to Amazon ECS",
    "aws.yml": "Deploy to Amazon ECS",
}


@pytest.mark.parametrize("filename,expected_name", EXPECTED_NAMES.items())
def test_workflow_name_matches_expected(filename: str, expected_name: str):
    data = load_workflow(filename)
    assert data["name"] == expected_name


# ---------------------------------------------------------------------------
# Workflows that trigger on both push and pull_request to "main"
# ---------------------------------------------------------------------------

PUSH_AND_PR_WORKFLOWS = [
    "ada.yml",
    "android.yml",
    "c-cpp.yml",
    "clojure.yml",
    "cmake-multi-platform.yml",
    "cmake-single-platform.yml",
    "codacy.yml",
    "crystal.yml",
    "d.yml",
    "dart.yml",
    "datadog-synthetics.yml",
    "defender-for-devops.yml",
    "anchore.yml",
]


@pytest.mark.parametrize("filename", PUSH_AND_PR_WORKFLOWS)
def test_workflow_triggers_on_push_and_pull_request(filename: str):
    data = load_workflow(filename)
    on = workflow_on(data)
    assert "push" in on, f"{filename} missing push trigger"
    assert "pull_request" in on, f"{filename} missing pull_request trigger"


# ---------------------------------------------------------------------------
# artifact-validation.yml – detailed tests
# ---------------------------------------------------------------------------


def test_artifact_validation_has_workflow_dispatch_trigger():
    data = load_workflow("artifact-validation.yml")
    on = workflow_on(data)
    assert "workflow_dispatch" in on


def test_artifact_validation_concurrency_cancel_in_progress():
    data = load_workflow("artifact-validation.yml")
    concurrency = data.get("concurrency", {})
    assert concurrency.get("cancel-in-progress") is True


def test_artifact_validation_concurrency_group_uses_workflow_and_ref():
    data = load_workflow("artifact-validation.yml")
    group = data.get("concurrency", {}).get("group", "")
    assert "github.workflow" in group
    assert "github.ref" in group


def test_artifact_validation_push_paths_include_artifacts():
    data = load_workflow("artifact-validation.yml")
    on = workflow_on(data)
    assert "artifacts/**" in on["push"]["paths"]


def test_artifact_validation_push_paths_include_unit_tests():
    data = load_workflow("artifact-validation.yml")
    on = workflow_on(data)
    assert "unit_tests/**" in on["push"]["paths"]


def test_artifact_validation_push_paths_include_pytest_ini():
    data = load_workflow("artifact-validation.yml")
    on = workflow_on(data)
    assert "pytest.ini" in on["push"]["paths"]


def test_artifact_validation_push_paths_include_workflow_file():
    data = load_workflow("artifact-validation.yml")
    on = workflow_on(data)
    assert ".github/workflows/artifact-validation.yml" in on["push"]["paths"]


def test_artifact_validation_pr_paths_match_push_paths():
    data = load_workflow("artifact-validation.yml")
    on = workflow_on(data)
    assert set(on["push"]["paths"]) == set(on["pull_request"]["paths"])


def test_artifact_validation_job_is_named_validate():
    data = load_workflow("artifact-validation.yml")
    assert "validate" in data["jobs"]


def test_artifact_validation_runs_on_ubuntu():
    data = load_workflow("artifact-validation.yml")
    assert data["jobs"]["validate"]["runs-on"] == "ubuntu-latest"


def test_artifact_validation_uses_python_312():
    data = load_workflow("artifact-validation.yml")
    steps = data["jobs"]["validate"]["steps"]
    python_steps = [s for s in steps if isinstance(s.get("uses"), str) and s["uses"].startswith("actions/setup-python")]
    assert python_steps, "No actions/setup-python step found"
    assert python_steps[0]["with"]["python-version"] == "3.12"


def test_artifact_validation_runs_make_deps():
    data = load_workflow("artifact-validation.yml")
    steps = data["jobs"]["validate"]["steps"]
    run_commands = [s.get("run", "") for s in steps]
    assert any("make -C artifacts deps" in cmd for cmd in run_commands)


def test_artifact_validation_runs_make_all():
    data = load_workflow("artifact-validation.yml")
    steps = data["jobs"]["validate"]["steps"]
    run_commands = [s.get("run", "") for s in steps]
    assert any("make -C artifacts all" in cmd for cmd in run_commands)


def test_artifact_validation_uses_checkout_v4():
    data = load_workflow("artifact-validation.yml")
    steps = data["jobs"]["validate"]["steps"]
    checkout_steps = [s for s in steps if "actions/checkout" in s.get("uses", "")]
    assert checkout_steps, "No actions/checkout step found"
    assert checkout_steps[0]["uses"] == "actions/checkout@v4"


# ---------------------------------------------------------------------------
# blueprint-artifacts-validation.yml – detailed tests
# ---------------------------------------------------------------------------


def test_blueprint_artifacts_validation_has_workflow_dispatch_trigger():
    data = load_workflow("blueprint-artifacts-validation.yml")
    on = workflow_on(data)
    assert "workflow_dispatch" in on


def test_blueprint_artifacts_validation_push_trigger_includes_scripts():
    data = load_workflow("blueprint-artifacts-validation.yml")
    on = workflow_on(data)
    push_paths = on["push"]["paths"]
    assert "scripts/validate_blueprint_artifacts.py" in push_paths
    assert "scripts/run_blueprint_artifact_checks.sh" in push_paths


def test_blueprint_artifacts_validation_push_trigger_includes_tests():
    data = load_workflow("blueprint-artifacts-validation.yml")
    on = workflow_on(data)
    push_paths = on["push"]["paths"]
    assert "tests/test_validate_blueprint_artifacts.py" in push_paths
    assert "tests/test_run_blueprint_artifact_checks.py" in push_paths


def test_blueprint_artifacts_validation_push_trigger_includes_blueprint_doc():
    data = load_workflow("blueprint-artifacts-validation.yml")
    on = workflow_on(data)
    push_paths = on["push"]["paths"]
    assert "docs/reports/ENTERPRISE_CIVILIZATIONAL_AGI_ASI_BLUEPRINT_2026_2030.md" in push_paths


def test_blueprint_artifacts_validation_pr_trigger_includes_blueprint_doc():
    data = load_workflow("blueprint-artifacts-validation.yml")
    on = workflow_on(data)
    pr_paths = on["pull_request"]["paths"]
    assert "docs/reports/ENTERPRISE_CIVILIZATIONAL_AGI_ASI_BLUEPRINT_2026_2030.md" in pr_paths


def test_blueprint_artifacts_validation_job_is_named_validate_artifacts():
    data = load_workflow("blueprint-artifacts-validation.yml")
    assert "validate-artifacts" in data["jobs"]


def test_blueprint_artifacts_validation_uses_python_312():
    data = load_workflow("blueprint-artifacts-validation.yml")
    steps = data["jobs"]["validate-artifacts"]["steps"]
    python_steps = [s for s in steps if isinstance(s.get("uses"), str) and s["uses"].startswith("actions/setup-python")]
    assert python_steps, "No actions/setup-python step found"
    assert python_steps[0]["with"]["python-version"] == "3.12"


def test_blueprint_artifacts_validation_pip_cache_uses_requirements_file():
    data = load_workflow("blueprint-artifacts-validation.yml")
    steps = data["jobs"]["validate-artifacts"]["steps"]
    python_steps = [s for s in steps if isinstance(s.get("uses"), str) and s["uses"].startswith("actions/setup-python")]
    assert python_steps[0]["with"]["cache-dependency-path"] == "scripts/requirements-blueprint-validator.txt"


def test_blueprint_artifacts_validation_runs_list_checks():
    data = load_workflow("blueprint-artifacts-validation.yml")
    steps = data["jobs"]["validate-artifacts"]["steps"]
    run_commands = [s.get("run", "") for s in steps]
    assert any(
        "scripts/run_blueprint_artifact_checks.sh --list-checks" in cmd for cmd in run_commands
    )


def test_blueprint_artifacts_validation_smoke_checks_output_json():
    data = load_workflow("blueprint-artifacts-validation.yml")
    steps = data["jobs"]["validate-artifacts"]["steps"]
    run_commands = [s.get("run", "") for s in steps]
    combined = " ".join(run_commands)
    assert "--output-json" in combined
    assert "python -m json.tool" in combined


def test_blueprint_artifacts_validation_smoke_checks_help_flag():
    data = load_workflow("blueprint-artifacts-validation.yml")
    steps = data["jobs"]["validate-artifacts"]["steps"]
    run_commands = [s.get("run", "") for s in steps]
    combined = " ".join(run_commands)
    assert "--help" in combined


# ---------------------------------------------------------------------------
# governance-artifacts-ci.yml – modification tests
# ---------------------------------------------------------------------------


def test_governance_artifacts_ci_job_renamed_to_validate_governance_artifacts():
    """Job was renamed from validate-existing-governance-stack to validate-governance-artifacts."""
    data = load_workflow("governance-artifacts-ci.yml")
    assert "validate-governance-artifacts" in data["jobs"]


def test_governance_artifacts_ci_old_job_name_absent():
    data = load_workflow("governance-artifacts-ci.yml")
    assert "validate-existing-governance-stack" not in data["jobs"]


def test_governance_artifacts_ci_timeout_is_ten_minutes():
    """timeout-minutes changed from 12 to 10."""
    data = load_workflow("governance-artifacts-ci.yml")
    job = data["jobs"]["validate-governance-artifacts"]
    assert job["timeout-minutes"] == 10


def test_governance_artifacts_ci_permissions_contents_read():
    """permissions: contents: read was added to the job."""
    data = load_workflow("governance-artifacts-ci.yml")
    job = data["jobs"]["validate-governance-artifacts"]
    assert job.get("permissions", {}).get("contents") == "read"


def test_governance_artifacts_ci_env_pythonunbuffered():
    """PYTHONUNBUFFERED: '1' was added to job env."""
    data = load_workflow("governance-artifacts-ci.yml")
    job = data["jobs"]["validate-governance-artifacts"]
    assert job.get("env", {}).get("PYTHONUNBUFFERED") == "1"


def test_governance_artifacts_ci_install_step_renamed_to_pinned():
    """Install step was renamed to 'Install Python deps (pinned)'."""
    data = load_workflow("governance-artifacts-ci.yml")
    steps = data["jobs"]["validate-governance-artifacts"]["steps"]
    step_names = [s.get("name", "") for s in steps]
    assert "Install Python deps (pinned)" in step_names


def test_governance_artifacts_ci_opa_step_renamed_to_pinned():
    """OPA setup step was renamed to 'Setup OPA (pinned)'."""
    data = load_workflow("governance-artifacts-ci.yml")
    steps = data["jobs"]["validate-governance-artifacts"]["steps"]
    step_names = [s.get("name", "") for s in steps]
    assert "Setup OPA (pinned)" in step_names


def test_governance_artifacts_ci_old_install_step_name_absent():
    """Old step name 'Install governance schema dependencies' should be gone."""
    data = load_workflow("governance-artifacts-ci.yml")
    steps = data["jobs"]["validate-governance-artifacts"]["steps"]
    step_names = [s.get("name", "") for s in steps]
    assert "Install governance schema dependencies" not in step_names


def test_governance_artifacts_ci_old_opa_step_name_absent():
    """Old step name 'Setup OPA' (without 'pinned') should not exist standalone."""
    data = load_workflow("governance-artifacts-ci.yml")
    steps = data["jobs"]["validate-governance-artifacts"]["steps"]
    step_names = [s.get("name", "") for s in steps]
    # Only "Setup OPA (pinned)" should appear; bare "Setup OPA" should not
    assert "Setup OPA" not in step_names


def test_governance_artifacts_ci_push_trigger_includes_governance_blueprint():
    """Push trigger paths now include governance_blueprint/**."""
    data = load_workflow("governance-artifacts-ci.yml")
    on = workflow_on(data)
    push_paths = on.get("push", {}).get("paths", [])
    assert "governance_blueprint/**" in push_paths


def test_governance_artifacts_ci_push_trigger_includes_enterprise_blueprint_doc():
    data = load_workflow("governance-artifacts-ci.yml")
    on = workflow_on(data)
    push_paths = on.get("push", {}).get("paths", [])
    assert "ENTERPRISE_AGI_ASI_GOVERNANCE_BLUEPRINT_2026_2030.md" in push_paths


def test_governance_artifacts_ci_push_trigger_does_not_include_gstack_artifacts():
    """gstack_artifacts/** was removed from trigger paths."""
    data = load_workflow("governance-artifacts-ci.yml")
    on = workflow_on(data)
    push_paths = on.get("push", {}).get("paths", [])
    assert "gstack_artifacts/**" not in push_paths


def test_governance_artifacts_ci_push_trigger_does_not_include_old_gstack_blueprint():
    """G_STACK_GOVERNANCE_BLUEPRINT_2026_2030.md was removed from trigger paths."""
    data = load_workflow("governance-artifacts-ci.yml")
    on = workflow_on(data)
    push_paths = on.get("push", {}).get("paths", [])
    assert "G_STACK_GOVERNANCE_BLUEPRINT_2026_2030.md" not in push_paths
    assert "docs/reports/G_STACK_GOVERNANCE_BLUEPRINT_2026_2030.md" not in push_paths


def test_governance_artifacts_ci_push_trigger_branches_include_main():
    data = load_workflow("governance-artifacts-ci.yml")
    on = workflow_on(data)
    branches = on.get("push", {}).get("branches", [])
    assert "main" in branches


def test_governance_artifacts_ci_push_trigger_branches_include_master():
    data = load_workflow("governance-artifacts-ci.yml")
    on = workflow_on(data)
    branches = on.get("push", {}).get("branches", [])
    assert "master" in branches


def test_governance_artifacts_ci_pr_trigger_includes_governance_blueprint():
    data = load_workflow("governance-artifacts-ci.yml")
    on = workflow_on(data)
    pr_paths = on.get("pull_request", {}).get("paths", [])
    assert "governance_blueprint/**" in pr_paths


def test_governance_artifacts_ci_pr_trigger_does_not_include_gstack_artifacts():
    data = load_workflow("governance-artifacts-ci.yml")
    on = workflow_on(data)
    pr_paths = on.get("pull_request", {}).get("paths", [])
    assert "gstack_artifacts/**" not in pr_paths


def test_governance_artifacts_ci_steps_include_checkout():
    data = load_workflow("governance-artifacts-ci.yml")
    steps = data["jobs"]["validate-governance-artifacts"]["steps"]
    uses = [s.get("uses", "") for s in steps]
    assert any("actions/checkout" in u for u in uses)


def test_governance_artifacts_ci_steps_include_make_governance_validate():
    data = load_workflow("governance-artifacts-ci.yml")
    steps = data["jobs"]["validate-governance-artifacts"]["steps"]
    run_commands = [s.get("run", "") for s in steps]
    assert any("make governance-validate" in cmd for cmd in run_commands)


def test_governance_artifacts_ci_upload_artifact_uses_v4():
    """Upload artifact step uses actions/upload-artifact@v4."""
    data = load_workflow("governance-artifacts-ci.yml")
    steps = data["jobs"]["validate-governance-artifacts"]["steps"]
    upload_steps = [s for s in steps if "actions/upload-artifact" in s.get("uses", "")]
    assert upload_steps, "No upload-artifact step found"
    assert upload_steps[-1]["uses"] == "actions/upload-artifact@v4"


# ---------------------------------------------------------------------------
# anchore-syft.yml – specific checks
# ---------------------------------------------------------------------------


def test_anchore_syft_permissions_contents_write():
    """anchore-syft.yml needs contents: write for Dependency submission API."""
    data = load_workflow("anchore-syft.yml")
    assert data.get("permissions", {}).get("contents") == "write"


def test_anchore_syft_job_has_dependency_snapshot_true():
    data = load_workflow("anchore-syft.yml")
    steps = data["jobs"]["Anchore-Build-Scan"]["steps"]
    sbom_steps = [s for s in steps if "anchore/sbom-action" in s.get("uses", "")]
    assert sbom_steps, "No anchore/sbom-action step found"
    assert sbom_steps[0]["with"].get("dependency-snapshot") is True


# ---------------------------------------------------------------------------
# anchore.yml – specific checks
# ---------------------------------------------------------------------------


def test_anchore_grype_job_has_fail_build_true():
    data = load_workflow("anchore.yml")
    steps = data["jobs"]["Anchore-Build-Scan"]["steps"]
    scan_steps = [s for s in steps if "anchore/scan-action" in s.get("uses", "")]
    assert scan_steps, "No anchore/scan-action step found"
    assert scan_steps[0]["with"].get("fail-build") is True


def test_anchore_grype_severity_cutoff_is_critical():
    data = load_workflow("anchore.yml")
    steps = data["jobs"]["Anchore-Build-Scan"]["steps"]
    scan_steps = [s for s in steps if "anchore/scan-action" in s.get("uses", "")]
    assert scan_steps[0]["with"].get("severity-cutoff") == "critical"


# ---------------------------------------------------------------------------
# cmake-multi-platform.yml – matrix strategy checks
# ---------------------------------------------------------------------------


def test_cmake_multi_platform_has_matrix_strategy():
    data = load_workflow("cmake-multi-platform.yml")
    job = data["jobs"]["build"]
    assert "strategy" in job
    assert "matrix" in job["strategy"]


def test_cmake_multi_platform_fail_fast_is_false():
    data = load_workflow("cmake-multi-platform.yml")
    assert data["jobs"]["build"]["strategy"].get("fail-fast") is False


def test_cmake_multi_platform_matrix_includes_ubuntu_and_windows():
    data = load_workflow("cmake-multi-platform.yml")
    os_list = data["jobs"]["build"]["strategy"]["matrix"]["os"]
    assert "ubuntu-latest" in os_list
    assert "windows-latest" in os_list


# ---------------------------------------------------------------------------
# defender-for-devops.yml – platform checks
# ---------------------------------------------------------------------------


def test_defender_for_devops_runs_on_windows_latest():
    """MSDO currently requires windows-latest."""
    data = load_workflow("defender-for-devops.yml")
    assert data["jobs"]["MSDO"]["runs-on"] == "windows-latest"


def test_defender_for_devops_has_schedule_trigger():
    data = load_workflow("defender-for-devops.yml")
    on = workflow_on(data)
    assert "schedule" in on


# ---------------------------------------------------------------------------
# android.yml – Java setup check
# ---------------------------------------------------------------------------


def test_android_sets_up_jdk_11():
    data = load_workflow("android.yml")
    steps = data["jobs"]["build"]["steps"]
    java_steps = [s for s in steps if isinstance(s.get("uses"), str) and "setup-java" in s["uses"]]
    assert java_steps, "No actions/setup-java step found"
    assert java_steps[0]["with"]["java-version"] == "11"


# ---------------------------------------------------------------------------
# aws.yml and aws-new.yml are identical – regression check
# ---------------------------------------------------------------------------


def test_aws_and_aws_new_have_identical_content():
    """aws.yml and aws-new.yml were added with identical content."""
    aws_path = WORKFLOWS_DIR / "aws.yml"
    aws_new_path = WORKFLOWS_DIR / "aws-new.yml"
    assert aws_path.read_text(encoding="utf-8") == aws_new_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# azure-container-webapp.yml and azure-container-webapp-new.yml are identical
# ---------------------------------------------------------------------------


def test_azure_container_webapp_and_new_have_identical_content():
    path_old = WORKFLOWS_DIR / "azure-container-webapp.yml"
    path_new = WORKFLOWS_DIR / "azure-container-webapp-new.yml"
    assert path_old.read_text(encoding="utf-8") == path_new.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Boundary / negative cases
# ---------------------------------------------------------------------------


def test_no_new_workflow_file_contains_empty_jobs():
    """Each new workflow must define at least one job."""
    for filename in NEW_WORKFLOW_FILES:
        data = load_workflow(filename)
        assert data.get("jobs"), f"{filename} has an empty jobs block"


def test_no_new_workflow_file_has_empty_name():
    for filename in NEW_WORKFLOW_FILES:
        data = load_workflow(filename)
        assert data.get("name", "").strip(), f"{filename} has a blank workflow name"


def test_governance_artifacts_ci_duplicate_keys_resolve_to_second_name():
    """
    governance-artifacts-ci.yml contains duplicate top-level 'name:' keys.
    PyYAML resolves duplicates by keeping the last value, which should be
    'Governance Artifacts CI'.
    """
    data = load_workflow("governance-artifacts-ci.yml")
    assert data["name"] == "Governance Artifacts CI"
