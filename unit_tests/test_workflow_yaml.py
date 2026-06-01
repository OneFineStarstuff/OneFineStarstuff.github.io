"""Tests for GitHub Actions workflow YAML files added/modified in this PR.

Covers:
- YAML syntax validity for all new workflow files
- Required top-level keys (name, on, jobs)
- Trigger branch configuration
- Runner types
- Permissions blocks
- Deletion of .github/labeler.yml
- Per-workflow structural and content assertions
"""

import os
from pathlib import Path

import pytest
import yaml

# Root of the repository
REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# All workflow files added/changed in the PR (only these are in scope)
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
    "deno.yml",
]


def load_workflow(filename: str) -> dict:
    """Parse a workflow YAML file and return the document as a dict."""
    path = WORKFLOWS_DIR / filename
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Parametrized structural checks for all new workflow files
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_workflow_file_exists(filename):
    """Each new workflow file must exist on disk."""
    assert (WORKFLOWS_DIR / filename).is_file(), (
        f"Expected workflow file not found: {filename}"
    )


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_workflow_is_valid_yaml(filename):
    """Each workflow file must contain valid YAML."""
    path = WORKFLOWS_DIR / filename
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    # yaml.safe_load raises yaml.YAMLError on invalid YAML
    doc = yaml.safe_load(content)
    assert doc is not None, f"{filename} parsed to None (empty file?)"


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_workflow_has_name_key(filename):
    """Each workflow must have a top-level 'name' key."""
    doc = load_workflow(filename)
    assert "name" in doc, f"{filename}: missing top-level 'name' key"
    assert isinstance(doc["name"], str), f"{filename}: 'name' must be a string"
    assert doc["name"].strip(), f"{filename}: 'name' must not be blank"


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_workflow_has_on_key(filename):
    """Each workflow must have a top-level 'on' (trigger) key."""
    doc = load_workflow(filename)
    # PyYAML parses 'on' as True due to YAML 1.1 booleans; it also appears as
    # the string 'on' with safe_load in recent PyYAML. Either True or 'on'.
    assert ("on" in doc or True in doc), (
        f"{filename}: missing top-level 'on' trigger key"
    )


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_workflow_has_jobs_key(filename):
    """Each workflow must define at least one job."""
    doc = load_workflow(filename)
    assert "jobs" in doc, f"{filename}: missing top-level 'jobs' key"
    assert isinstance(doc["jobs"], dict), f"{filename}: 'jobs' must be a mapping"
    assert len(doc["jobs"]) >= 1, f"{filename}: 'jobs' must have at least one job"


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_workflow_jobs_have_runs_on(filename):
    """Every job in each workflow must declare a 'runs-on' runner."""
    doc = load_workflow(filename)
    for job_name, job_def in doc["jobs"].items():
        assert "runs-on" in job_def, (
            f"{filename}: job '{job_name}' is missing 'runs-on'"
        )


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_workflow_jobs_have_steps(filename):
    """Every job must have at least one step."""
    doc = load_workflow(filename)
    for job_name, job_def in doc["jobs"].items():
        # jobs that use 'uses' (reusable workflow calls) may not have steps
        if "uses" in job_def:
            continue
        assert "steps" in job_def, (
            f"{filename}: job '{job_name}' has no 'steps'"
        )
        assert len(job_def["steps"]) >= 1, (
            f"{filename}: job '{job_name}' steps list is empty"
        )


# ---------------------------------------------------------------------------
# labeler.yml deletion
# ---------------------------------------------------------------------------

def test_labeler_yml_was_deleted():
    """The labeler.yml file should have been removed from .github/."""
    labeler = REPO_ROOT / ".github" / "labeler.yml"
    assert not labeler.exists(), (
        ".github/labeler.yml should have been deleted in this PR but still exists"
    )


# ---------------------------------------------------------------------------
# Per-workflow specific checks
# ---------------------------------------------------------------------------

class TestAdaWorkflow:
    def setup_method(self):
        self.doc = load_workflow("ada.yml")

    def test_name(self):
        assert self.doc["name"] == "Ada (GNAT)"

    def test_triggers_push_and_pr_on_main(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on
        assert "main" in on["push"]["branches"]
        assert "main" in on["pull_request"]["branches"]

    def test_job_runs_on_ubuntu(self):
        assert self.doc["jobs"]["build"]["runs-on"] == "ubuntu-latest"

    def test_steps_include_checkout(self):
        steps = self.doc["jobs"]["build"]["steps"]
        uses_values = [s.get("uses", "") for s in steps]
        assert any("actions/checkout" in u for u in uses_values)

    def test_steps_include_gnat_install(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = " ".join(s.get("run", "") for s in steps)
        assert "gnat" in run_values.lower()

    def test_build_step_uses_gprbuild(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = " ".join(s.get("run", "") for s in steps)
        assert "gprbuild" in run_values


class TestAlibabaCloudWorkflow:
    def setup_method(self):
        self.doc = load_workflow("alibabacloud.yml")

    def test_name(self):
        assert "ACK" in self.doc["name"] or "alibaba" in self.doc["name"].lower() or "Deploy" in self.doc["name"]

    def test_trigger_push_main(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "main" in on["push"]["branches"]

    def test_env_region_id_set(self):
        env = self.doc.get("env", {})
        assert "REGION_ID" in env
        assert env["REGION_ID"] == "cn-hangzhou"

    def test_env_registry_set(self):
        env = self.doc.get("env", {})
        assert "REGISTRY" in env
        assert "aliyuncs.com" in env["REGISTRY"]

    def test_permissions_contents_read(self):
        perms = self.doc.get("permissions", {})
        assert perms.get("contents") == "read"

    def test_build_job_environment_production(self):
        build_job = self.doc["jobs"]["build"]
        assert build_job.get("environment") == "production"

    def test_build_job_runner(self):
        assert self.doc["jobs"]["build"]["runs-on"] == "ubuntu-latest"


class TestAnchoreSyftWorkflow:
    def setup_method(self):
        self.doc = load_workflow("anchore-syft.yml")

    def test_name(self):
        assert "Syft" in self.doc["name"] or "SBOM" in self.doc["name"]

    def test_trigger_push_main(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "main" in on["push"]["branches"]

    def test_permissions_contents_write(self):
        perms = self.doc.get("permissions", {})
        assert perms.get("contents") == "write"

    def test_job_permissions_contents_write(self):
        job = list(self.doc["jobs"].values())[0]
        job_perms = job.get("permissions", {})
        assert job_perms.get("contents") == "write"

    def test_step_uses_sbom_action(self):
        job = list(self.doc["jobs"].values())[0]
        uses_values = [s.get("uses", "") for s in job["steps"]]
        assert any("anchore/sbom-action" in u for u in uses_values)

    def test_sbom_action_dependency_snapshot_true(self):
        job = list(self.doc["jobs"].values())[0]
        for step in job["steps"]:
            if "anchore/sbom-action" in step.get("uses", ""):
                assert step["with"]["dependency-snapshot"] is True
                break
        else:
            pytest.fail("sbom-action step not found")


class TestAnchoreWorkflow:
    def setup_method(self):
        self.doc = load_workflow("anchore.yml")

    def test_name(self):
        assert "Grype" in self.doc["name"] or "Anchore" in self.doc["name"]

    def test_triggers_push_pr_schedule(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on
        assert "schedule" in on

    def test_schedule_cron_present(self):
        on = self.doc.get("on") or self.doc.get(True)
        crons = [entry["cron"] for entry in on["schedule"]]
        assert len(crons) == 1
        assert crons[0] == "19 13 * * 5"

    def test_job_permissions_security_events_write(self):
        job = list(self.doc["jobs"].values())[0]
        assert job["permissions"]["security-events"] == "write"

    def test_grype_scan_fail_build_true(self):
        job = list(self.doc["jobs"].values())[0]
        for step in job["steps"]:
            if "anchore/scan-action" in step.get("uses", ""):
                assert step["with"]["fail-build"] is True
                assert step["with"]["severity-cutoff"] == "critical"
                break
        else:
            pytest.fail("scan-action step not found")

    def test_upload_sarif_step_present(self):
        job = list(self.doc["jobs"].values())[0]
        uses_values = [s.get("uses", "") for s in job["steps"]]
        assert any("codeql-action/upload-sarif" in u for u in uses_values)


class TestAndroidWorkflow:
    def setup_method(self):
        self.doc = load_workflow("android.yml")

    def test_name(self):
        assert "Android" in self.doc["name"]

    def test_triggers_push_and_pr(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on

    def test_java_setup_version(self):
        steps = self.doc["jobs"]["build"]["steps"]
        for step in steps:
            if "actions/setup-java" in step.get("uses", ""):
                assert step["with"]["java-version"] == "11"
                assert step["with"]["distribution"] == "temurin"
                break
        else:
            pytest.fail("setup-java step not found")

    def test_gradle_build_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = " ".join(s.get("run", "") for s in steps)
        assert "gradlew build" in run_values


class TestArtifactValidationWorkflow:
    def setup_method(self):
        self.doc = load_workflow("artifact-validation.yml")

    def test_name(self):
        assert "Artifact" in self.doc["name"]

    def test_triggers_workflow_dispatch(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "workflow_dispatch" in on

    def test_triggers_paths_include_artifacts(self):
        on = self.doc.get("on") or self.doc.get(True)
        push_paths = on.get("push", {}).get("paths", [])
        pr_paths = on.get("pull_request", {}).get("paths", [])
        all_paths = push_paths + pr_paths
        assert any("artifacts" in p for p in all_paths)

    def test_concurrency_cancel_in_progress(self):
        concurrency = self.doc.get("concurrency", {})
        assert concurrency.get("cancel-in-progress") is True

    def test_python_312(self):
        steps = self.doc["jobs"]["validate"]["steps"]
        for step in steps:
            if "actions/setup-python" in step.get("uses", ""):
                assert step["with"]["python-version"] == "3.12"
                break
        else:
            pytest.fail("setup-python step not found")

    def test_make_deps_and_all_steps(self):
        steps = self.doc["jobs"]["validate"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert any("make -C artifacts deps" in r for r in run_values)
        assert any("make -C artifacts all" in r for r in run_values)


class TestAstroWorkflow:
    def setup_method(self):
        self.doc = load_workflow("astro.yml")

    def test_name(self):
        assert "Astro" in self.doc["name"] or "Pages" in self.doc["name"]

    def test_permissions_pages_write(self):
        perms = self.doc.get("permissions", {})
        assert perms.get("pages") == "write"
        assert perms.get("id-token") == "write"

    def test_concurrency_not_cancel_in_progress(self):
        concurrency = self.doc.get("concurrency", {})
        assert concurrency.get("cancel-in-progress") is False

    def test_deploy_job_needs_build(self):
        deploy_job = self.doc["jobs"].get("deploy")
        assert deploy_job is not None
        assert "build" in deploy_job.get("needs", [])

    def test_build_path_env(self):
        env = self.doc.get("env", {})
        assert "BUILD_PATH" in env

    def test_upload_pages_artifact_step(self):
        build_steps = self.doc["jobs"]["build"]["steps"]
        uses_values = [s.get("uses", "") for s in build_steps]
        assert any("upload-pages-artifact" in u for u in uses_values)

    def test_deploy_pages_step(self):
        deploy_steps = self.doc["jobs"]["deploy"]["steps"]
        uses_values = [s.get("uses", "") for s in deploy_steps]
        assert any("deploy-pages" in u for u in uses_values)


class TestAwsWorkflows:
    """Both aws.yml and aws-new.yml are identical — test both."""

    @pytest.mark.parametrize("filename", ["aws.yml", "aws-new.yml"])
    def test_name(self, filename):
        doc = load_workflow(filename)
        assert "ECS" in doc["name"] or "Amazon" in doc["name"]

    @pytest.mark.parametrize("filename", ["aws.yml", "aws-new.yml"])
    def test_trigger_push_main(self, filename):
        doc = load_workflow(filename)
        on = doc.get("on") or doc.get(True)
        assert "push" in on
        assert "main" in on["push"]["branches"]

    @pytest.mark.parametrize("filename", ["aws.yml", "aws-new.yml"])
    def test_env_variables_present(self, filename):
        doc = load_workflow(filename)
        env = doc.get("env", {})
        for key in ("AWS_REGION", "ECR_REPOSITORY", "ECS_SERVICE", "ECS_CLUSTER",
                    "ECS_TASK_DEFINITION", "CONTAINER_NAME"):
            assert key in env, f"{filename}: missing env var '{key}'"

    @pytest.mark.parametrize("filename", ["aws.yml", "aws-new.yml"])
    def test_permissions_contents_read(self, filename):
        doc = load_workflow(filename)
        perms = doc.get("permissions", {})
        assert perms.get("contents") == "read"

    @pytest.mark.parametrize("filename", ["aws.yml", "aws-new.yml"])
    def test_deploy_job_environment_production(self, filename):
        doc = load_workflow(filename)
        deploy_job = doc["jobs"].get("deploy")
        assert deploy_job is not None
        assert deploy_job.get("environment") == "production"

    @pytest.mark.parametrize("filename", ["aws.yml", "aws-new.yml"])
    def test_ecr_login_step(self, filename):
        doc = load_workflow(filename)
        deploy_job = doc["jobs"]["deploy"]
        uses_values = [s.get("uses", "") for s in deploy_job["steps"]]
        assert any("amazon-ecr-login" in u for u in uses_values)

    @pytest.mark.parametrize("filename", ["aws.yml", "aws-new.yml"])
    def test_ecs_deploy_step(self, filename):
        doc = load_workflow(filename)
        deploy_job = doc["jobs"]["deploy"]
        uses_values = [s.get("uses", "") for s in deploy_job["steps"]]
        assert any("amazon-ecs-deploy-task-definition" in u for u in uses_values)

    @pytest.mark.parametrize("filename", ["aws.yml", "aws-new.yml"])
    def test_aws_files_are_identical(self, filename):
        """aws.yml and aws-new.yml have the same content per the diff."""
        aws_content = (WORKFLOWS_DIR / "aws.yml").read_text(encoding="utf-8")
        aws_new_content = (WORKFLOWS_DIR / "aws-new.yml").read_text(encoding="utf-8")
        assert aws_content == aws_new_content, (
            "aws.yml and aws-new.yml should be identical per the PR diff"
        )


class TestAzureContainerWebappWorkflows:
    """Both azure-container-webapp.yml and azure-container-webapp-new.yml are identical."""

    @pytest.mark.parametrize("filename", ["azure-container-webapp.yml", "azure-container-webapp-new.yml"])
    def test_name(self, filename):
        doc = load_workflow(filename)
        assert "Azure" in doc["name"] or "container" in doc["name"].lower()

    @pytest.mark.parametrize("filename", ["azure-container-webapp.yml", "azure-container-webapp-new.yml"])
    def test_azure_webapp_name_env(self, filename):
        doc = load_workflow(filename)
        env = doc.get("env", {})
        assert "AZURE_WEBAPP_NAME" in env

    @pytest.mark.parametrize("filename", ["azure-container-webapp.yml", "azure-container-webapp-new.yml"])
    def test_trigger_push_and_workflow_dispatch(self, filename):
        doc = load_workflow(filename)
        on = doc.get("on") or doc.get(True)
        assert "push" in on
        assert "workflow_dispatch" in on

    @pytest.mark.parametrize("filename", ["azure-container-webapp.yml", "azure-container-webapp-new.yml"])
    def test_build_job_docker_login(self, filename):
        doc = load_workflow(filename)
        build_steps = doc["jobs"]["build"]["steps"]
        uses_values = [s.get("uses", "") for s in build_steps]
        assert any("docker/login-action" in u for u in uses_values)

    @pytest.mark.parametrize("filename", ["azure-container-webapp.yml", "azure-container-webapp-new.yml"])
    def test_deploy_job_needs_build(self, filename):
        doc = load_workflow(filename)
        deploy_job = doc["jobs"].get("deploy")
        assert deploy_job is not None
        assert "build" in (deploy_job.get("needs") or [])

    @pytest.mark.parametrize("filename", ["azure-container-webapp.yml", "azure-container-webapp-new.yml"])
    def test_deploy_uses_azure_webapps_deploy(self, filename):
        doc = load_workflow(filename)
        deploy_steps = doc["jobs"]["deploy"]["steps"]
        uses_values = [s.get("uses", "") for s in deploy_steps]
        assert any("azure/webapps-deploy" in u for u in uses_values)

    def test_azure_container_webapp_files_are_identical(self):
        c1 = (WORKFLOWS_DIR / "azure-container-webapp.yml").read_text(encoding="utf-8")
        c2 = (WORKFLOWS_DIR / "azure-container-webapp-new.yml").read_text(encoding="utf-8")
        assert c1 == c2, (
            "azure-container-webapp.yml and azure-container-webapp-new.yml "
            "should be identical per the PR diff"
        )


class TestAzureWebappsNodeWorkflow:
    def setup_method(self):
        # NOTE: azure-webapps-node.yml is a concatenation of two workflow
        # definitions. PyYAML parses only one merged document — the latter
        # Azure Node.js webapp workflow dominates (its keys overwrite the
        # first Docker workflow's keys).  Tests below verify the resulting
        # parsed structure.
        self.doc = load_workflow("azure-webapps-node.yml")

    def test_has_jobs(self):
        assert "jobs" in self.doc
        assert len(self.doc["jobs"]) >= 1

    def test_build_job_runs_on_ubuntu(self):
        build_job = self.doc["jobs"].get("build")
        assert build_job is not None
        assert build_job["runs-on"] == "ubuntu-latest"

    def test_build_job_has_node_setup_or_npm(self):
        # The parsed document contains the Azure Node.js workflow section;
        # its build job installs Node and runs npm.
        build_steps = self.doc["jobs"]["build"]["steps"]
        uses_values = [s.get("uses", "") for s in build_steps]
        run_values = " ".join(s.get("run", "") for s in build_steps)
        has_node_setup = any("actions/setup-node" in u for u in uses_values)
        has_npm = "npm" in run_values
        assert has_node_setup or has_npm, (
            "Expected Node.js setup or npm command in azure-webapps-node.yml build steps"
        )

    def test_deploy_job_uses_azure_webapps_deploy(self):
        deploy_steps = self.doc["jobs"]["deploy"]["steps"]
        uses_values = [s.get("uses", "") for s in deploy_steps]
        assert any("azure/webapps-deploy" in u for u in uses_values)


class TestBlueprintArtifactsValidationWorkflow:
    def setup_method(self):
        self.doc = load_workflow("blueprint-artifacts-validation.yml")

    def test_name(self):
        assert "Blueprint" in self.doc["name"] or "Artifact" in self.doc["name"]

    def test_triggers_include_workflow_dispatch(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "workflow_dispatch" in on

    def test_triggers_push_paths(self):
        on = self.doc.get("on") or self.doc.get(True)
        push_paths = on.get("push", {}).get("paths", [])
        assert any("artifacts" in p for p in push_paths)

    def test_python_version_312(self):
        job = self.doc["jobs"]["validate-artifacts"]
        for step in job["steps"]:
            if "actions/setup-python" in step.get("uses", ""):
                assert step["with"]["python-version"] == "3.12"
                break
        else:
            pytest.fail("setup-python step not found")

    def test_run_blueprint_artifact_checks_step(self):
        job = self.doc["jobs"]["validate-artifacts"]
        run_values = " ".join(s.get("run", "") for s in job["steps"])
        assert "run_blueprint_artifact_checks.sh" in run_values

    def test_list_checks_flag(self):
        job = self.doc["jobs"]["validate-artifacts"]
        run_values = " ".join(s.get("run", "") for s in job["steps"])
        assert "--list-checks" in run_values


class TestCCppWorkflow:
    def setup_method(self):
        self.doc = load_workflow("c-cpp.yml")

    def test_name(self):
        assert "C" in self.doc["name"]

    def test_triggers(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on
        assert "main" in on["push"]["branches"]

    def test_configure_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "./configure" in run_values

    def test_make_steps(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "make" in run_values
        assert "make check" in run_values
        assert "make distcheck" in run_values


class TestClojureWorkflow:
    def setup_method(self):
        self.doc = load_workflow("clojure.yml")

    def test_name(self):
        assert "Clojure" in self.doc["name"]

    def test_triggers(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on

    def test_lein_deps_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "lein deps" in run_values

    def test_lein_test_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "lein test" in run_values


class TestCmakeMultiPlatformWorkflow:
    def setup_method(self):
        self.doc = load_workflow("cmake-multi-platform.yml")

    def test_name(self):
        assert "CMake" in self.doc["name"] or "cmake" in self.doc["name"].lower()

    def test_strategy_fail_fast_false(self):
        strategy = self.doc["jobs"]["build"].get("strategy", {})
        assert strategy.get("fail-fast") is False

    def test_matrix_os_includes_ubuntu_and_windows(self):
        matrix = self.doc["jobs"]["build"]["strategy"]["matrix"]
        assert "ubuntu-latest" in matrix["os"]
        assert "windows-latest" in matrix["os"]

    def test_matrix_c_compiler_options(self):
        matrix = self.doc["jobs"]["build"]["strategy"]["matrix"]
        compilers = matrix["c_compiler"]
        assert "gcc" in compilers
        assert "clang" in compilers
        assert "cl" in compilers

    def test_matrix_excludes_windows_gcc_clang(self):
        excludes = self.doc["jobs"]["build"]["strategy"]["matrix"].get("exclude", [])
        excluded_combos = [(e["os"], e["c_compiler"]) for e in excludes]
        assert ("windows-latest", "gcc") in excluded_combos
        assert ("windows-latest", "clang") in excluded_combos

    def test_cmake_build_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = " ".join(s.get("run", "") for s in steps)
        assert "cmake" in run_values.lower()

    def test_ctest_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = " ".join(s.get("run", "") for s in steps)
        assert "ctest" in run_values


class TestCmakeSinglePlatformWorkflow:
    def setup_method(self):
        self.doc = load_workflow("cmake-single-platform.yml")

    def test_name(self):
        assert "CMake" in self.doc["name"] or "cmake" in self.doc["name"].lower()

    def test_build_type_env_release(self):
        env = self.doc.get("env", {})
        assert env.get("BUILD_TYPE") == "Release"

    def test_runner_ubuntu(self):
        assert self.doc["jobs"]["build"]["runs-on"] == "ubuntu-latest"

    def test_cmake_configure_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = " ".join(s.get("run", "") for s in steps)
        assert "cmake" in run_values.lower()
        assert "BUILD_TYPE" in run_values or "build_type" in run_values.lower()

    def test_ctest_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = " ".join(s.get("run", "") for s in steps)
        assert "ctest" in run_values


class TestCodacyWorkflow:
    def setup_method(self):
        self.doc = load_workflow("codacy.yml")

    def test_name(self):
        assert "Codacy" in self.doc["name"]

    def test_triggers_push_pr_schedule(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on
        assert "schedule" in on

    def test_schedule_cron(self):
        on = self.doc.get("on") or self.doc.get(True)
        crons = [entry["cron"] for entry in on["schedule"]]
        assert crons[0] == "40 17 * * 2"

    def test_job_permissions(self):
        job = list(self.doc["jobs"].values())[0]
        perms = job.get("permissions", {})
        assert perms.get("security-events") == "write"

    def test_codacy_analysis_cli_action_step(self):
        job = list(self.doc["jobs"].values())[0]
        uses_values = [s.get("uses", "") for s in job["steps"]]
        assert any("codacy/codacy-analysis-cli-action" in u for u in uses_values)

    def test_upload_sarif_step(self):
        job = list(self.doc["jobs"].values())[0]
        uses_values = [s.get("uses", "") for s in job["steps"]]
        assert any("codeql-action/upload-sarif" in u for u in uses_values)


class TestCrystalWorkflow:
    def setup_method(self):
        self.doc = load_workflow("crystal.yml")

    def test_name(self):
        assert "Crystal" in self.doc["name"]

    def test_triggers(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on

    def test_container_image(self):
        job = self.doc["jobs"]["build"]
        container = job.get("container", {})
        assert "crystallang/crystal" in container.get("image", "")

    def test_shards_install_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "shards install" in run_values

    def test_crystal_spec_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "crystal spec" in run_values


class TestDWorkflow:
    def setup_method(self):
        self.doc = load_workflow("d.yml")

    def test_name(self):
        assert self.doc["name"] == "D"

    def test_permissions_contents_read(self):
        perms = self.doc.get("permissions", {})
        assert perms.get("contents") == "read"

    def test_triggers(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on

    def test_setup_dlang_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        uses_values = [s.get("uses", "") for s in steps]
        assert any("dlang-community/setup-dlang" in u for u in uses_values)

    def test_dub_build_and_test(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = " ".join(s.get("run", "") for s in steps)
        assert "dub build" in run_values
        assert "dub test" in run_values


class TestDartWorkflow:
    def setup_method(self):
        self.doc = load_workflow("dart.yml")

    def test_name(self):
        assert self.doc["name"] == "Dart"

    def test_triggers(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on

    def test_setup_dart_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        uses_values = [s.get("uses", "") for s in steps]
        assert any("dart-lang/setup-dart" in u for u in uses_values)

    def test_dart_pub_get_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "dart pub get" in run_values

    def test_dart_analyze_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "dart analyze" in run_values

    def test_dart_test_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "dart test" in run_values


class TestDatadogSyntheticsWorkflow:
    def setup_method(self):
        self.doc = load_workflow("datadog-synthetics.yml")

    def test_name(self):
        assert "Datadog" in self.doc["name"] or "Synthetic" in self.doc["name"]

    def test_triggers(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on

    def test_datadog_action_step(self):
        steps = self.doc["jobs"]["build"]["steps"]
        uses_values = [s.get("uses", "") for s in steps]
        assert any("DataDog/synthetics-ci-github-action" in u for u in uses_values)

    def test_api_key_references_secret(self):
        steps = self.doc["jobs"]["build"]["steps"]
        for step in steps:
            if "DataDog/synthetics-ci-github-action" in step.get("uses", ""):
                assert "DD_API_KEY" in step["with"]["api_key"]
                assert "DD_APP_KEY" in step["with"]["app_key"]
                break
        else:
            pytest.fail("Datadog synthetics step not found")

    def test_test_search_query_set(self):
        steps = self.doc["jobs"]["build"]["steps"]
        for step in steps:
            if "DataDog/synthetics-ci-github-action" in step.get("uses", ""):
                assert step["with"]["test_search_query"]
                break


class TestDefenderForDevopsWorkflow:
    def setup_method(self):
        self.doc = load_workflow("defender-for-devops.yml")

    def test_name(self):
        assert "Defender" in self.doc["name"] or "Microsoft" in self.doc["name"]

    def test_triggers_push_pr_schedule(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on
        assert "schedule" in on

    def test_schedule_cron(self):
        on = self.doc.get("on") or self.doc.get(True)
        crons = [entry["cron"] for entry in on["schedule"]]
        assert crons[0] == "24 5 * * 3"

    def test_runs_on_windows_latest(self):
        job = self.doc["jobs"]["MSDO"]
        assert job["runs-on"] == "windows-latest"

    def test_setup_dotnet_step(self):
        steps = self.doc["jobs"]["MSDO"]["steps"]
        uses_values = [s.get("uses", "") for s in steps]
        assert any("actions/setup-dotnet" in u for u in uses_values)

    def test_dotnet_versions(self):
        steps = self.doc["jobs"]["MSDO"]["steps"]
        for step in steps:
            if "actions/setup-dotnet" in step.get("uses", ""):
                dotnet_version = step["with"]["dotnet-version"]
                assert "5.0.x" in dotnet_version
                assert "6.0.x" in dotnet_version
                break
        else:
            pytest.fail("setup-dotnet step not found")

    def test_msdo_action_step(self):
        steps = self.doc["jobs"]["MSDO"]["steps"]
        uses_values = [s.get("uses", "") for s in steps]
        assert any("microsoft/security-devops-action" in u for u in uses_values)

    def test_upload_sarif_step(self):
        steps = self.doc["jobs"]["MSDO"]["steps"]
        uses_values = [s.get("uses", "") for s in steps]
        assert any("codeql-action/upload-sarif" in u for u in uses_values)


class TestDenoWorkflow:
    def setup_method(self):
        self.doc = load_workflow("deno.yml")

    def test_name(self):
        assert self.doc["name"] == "Deno"

    def test_permissions_contents_read(self):
        perms = self.doc.get("permissions", {})
        assert perms.get("contents") == "read"

    def test_triggers(self):
        on = self.doc.get("on") or self.doc.get(True)
        assert "push" in on
        assert "pull_request" in on

    def test_setup_deno_step(self):
        steps = self.doc["jobs"]["test"]["steps"]
        uses_values = [s.get("uses", "") for s in steps]
        assert any("denoland/setup-deno" in u for u in uses_values)

    def test_deno_version_v1x(self):
        steps = self.doc["jobs"]["test"]["steps"]
        for step in steps:
            if "denoland/setup-deno" in step.get("uses", ""):
                assert step["with"]["deno-version"] == "v1.x"
                break
        else:
            pytest.fail("setup-deno step not found")

    def test_deno_lint_step(self):
        steps = self.doc["jobs"]["test"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "deno lint" in run_values

    def test_deno_test_step(self):
        steps = self.doc["jobs"]["test"]["steps"]
        run_values = [s.get("run", "") for s in steps]
        assert "deno test -A" in run_values


# ---------------------------------------------------------------------------
# Edge-case / regression tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_workflow_checkout_action_present(filename):
    """Every workflow must include at least one checkout step."""
    doc = load_workflow(filename)
    found_checkout = False
    for job_def in doc["jobs"].values():
        if "uses" in job_def:
            continue
        for step in job_def.get("steps", []):
            if "actions/checkout" in step.get("uses", ""):
                found_checkout = True
                break
        if found_checkout:
            break
    assert found_checkout, (
        f"{filename}: no 'actions/checkout' step found in any job"
    )


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_workflow_name_is_nonempty_string(filename):
    """Workflow 'name' field must be a non-empty string (regression guard)."""
    doc = load_workflow(filename)
    name = doc.get("name")
    assert isinstance(name, str) and name.strip(), (
        f"{filename}: 'name' must be a non-empty string, got {name!r}"
    )


def test_no_duplicate_workflow_filenames_in_scope():
    """The list of new workflow files should not contain duplicates."""
    assert len(NEW_WORKFLOW_FILES) == len(set(NEW_WORKFLOW_FILES)), (
        "NEW_WORKFLOW_FILES contains duplicate entries"
    )


@pytest.mark.parametrize("filename", ["aws.yml", "aws-new.yml",
                                       "azure-container-webapp.yml",
                                       "azure-container-webapp-new.yml"])
def test_duplicate_workflows_have_matching_job_names(filename):
    """Files intended to be duplicates should share the same job names."""
    pairs = {
        "aws-new.yml": "aws.yml",
        "azure-container-webapp-new.yml": "azure-container-webapp.yml",
    }
    if filename not in pairs:
        pytest.skip("not a -new variant")
    original = load_workflow(pairs[filename])
    variant = load_workflow(filename)
    assert set(original["jobs"].keys()) == set(variant["jobs"].keys()), (
        f"Job names differ between {pairs[filename]} and {filename}"
    )


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_workflow_file_is_not_empty(filename):
    """Each workflow file must not be empty."""
    path = WORKFLOWS_DIR / filename
    content = path.read_text(encoding="utf-8").strip()
    assert content, f"{filename}: file is empty"


@pytest.mark.parametrize("filename", NEW_WORKFLOW_FILES)
def test_all_steps_have_either_uses_or_run_or_name(filename):
    """Each step should have at least 'uses', 'run', or 'name'."""
    doc = load_workflow(filename)
    for job_name, job_def in doc["jobs"].items():
        if "uses" in job_def:
            continue
        for i, step in enumerate(job_def.get("steps", [])):
            has_uses = "uses" in step
            has_run = "run" in step
            has_name = "name" in step
            assert has_uses or has_run or has_name, (
                f"{filename}: job '{job_name}' step index {i} "
                f"has neither 'uses', 'run', nor 'name'"
            )
