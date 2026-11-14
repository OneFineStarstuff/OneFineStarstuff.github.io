"""Regression tests for keeping hosted pre-commit checks environment-portable."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / ".pre-commit-config.yaml"

# Local hooks invoke repository Make targets, OPA, or full governance suites.
# Dedicated GitHub Actions workflows enforce these controls with the required
# repository toolchain.
ENVIRONMENT_DEPENDENT_LOCAL_HOOKS = {
    "governance-report-pack-validate",
    "governance-report-pack-check",
    "governance-validate",
    "governance-policy-test",
    "governance-validator-test",
    "governance-evidence-checks",
    "governance-validation-suite",
}

# These hooks mutate the full repository when run by pre-commit.ci, which
# supplies the entire tracked file set. GitHub Actions runs them on changed
# files instead, so legacy/generated-file backlog does not block unrelated PRs.
REPOSITORY_WIDE_SKIP_HOOKS = {
    "end-of-file-fixer",
    "trailing-whitespace",
    "yamllint",
}


def _all_hooks(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index all configured hooks by their unique hook identifier."""
    return {
        hook["id"]: hook
        for repository in config.get("repos", [])
        for hook in repository.get("hooks", [])
    }


def _local_hooks(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return only hooks defined in the local repository section."""
    local_repositories = [
        repository
        for repository in config.get("repos", [])
        if repository.get("repo") == "local"
    ]
    return {
        hook["id"]: hook
        for repository in local_repositories
        for hook in repository.get("hooks", [])
    }


def test_environment_dependent_local_hooks_are_skipped_only_by_precommit_ci() -> None:
    """Keep local system hooks enabled while excluding them from hosted CI."""
    config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    local_hooks = _local_hooks(config)
    configured_skip = set(config.get("ci", {}).get("skip", []))

    assert ENVIRONMENT_DEPENDENT_LOCAL_HOOKS <= local_hooks.keys()
    assert ENVIRONMENT_DEPENDENT_LOCAL_HOOKS <= configured_skip

    # Keep each hook configured for local use; only pre-commit.ci skips them.
    for hook_id in ENVIRONMENT_DEPENDENT_LOCAL_HOOKS:
        assert local_hooks[hook_id]["language"] == "system"


def test_repository_wide_mutating_hooks_are_preserved_but_skipped_by_precommit_ci() -> None:
    """Ensure full-repository formatters remain configured but hosted-skipped."""
    config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    hooks = _all_hooks(config)
    configured_skip = set(config.get("ci", {}).get("skip", []))

    assert REPOSITORY_WIDE_SKIP_HOOKS <= hooks.keys()
    assert REPOSITORY_WIDE_SKIP_HOOKS <= configured_skip


def test_yamllint_receives_only_changed_yaml_files() -> None:
    """Ensure yamllint uses the filenames supplied by the changed-file runner."""
    config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    yamllint_hooks = [
        hook
        for repository in config.get("repos", [])
        if repository.get("repo") == "https://github.com/adrienverge/yamllint"
        for hook in repository.get("hooks", [])
        if hook.get("id") == "yamllint"
    ]

    assert len(yamllint_hooks) == 1
    assert yamllint_hooks[0].get("args") == ["-c", ".yamllint"]
    assert yamllint_hooks[0].get("pass_filenames", True) is True


def test_changed_file_precommit_workflow_is_version_pinned() -> None:
    """Keep the portable changed-file workflow pinned and reproducible."""
    workflow = ROOT / ".github" / "workflows" / "pre-commit-changed-files.yml"
    source = workflow.read_text(encoding="utf-8")

    assert "pre-commit==4.7.0" in source
    assert "git diff --name-only --diff-filter=ACMRT -z" in source
    assert "pre-commit run --show-diff-on-failure --files" in source
