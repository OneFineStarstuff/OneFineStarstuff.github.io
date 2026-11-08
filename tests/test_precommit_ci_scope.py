"""Regression tests for keeping hosted pre-commit checks environment-portable."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / ".pre-commit-config.yaml"

# These hooks invoke repository Make targets, OPA, or full governance suites.
# They are already enforced by dedicated GitHub Actions and need host tools
# that pre-commit.ci does not provision for language: system hooks.
ENVIRONMENT_DEPENDENT_LOCAL_HOOKS = {
    "governance-report-pack-validate",
    "governance-validate",
    "governance-policy-test",
    "governance-validator-test",
    "governance-evidence-checks",
    "governance-validation-suite",
    "end-of-file-fixer",
    "trailing-whitespace",
    "yamllint",
}


def _local_hooks(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        hook["id"]: hook
        for repository in config.get("repos", [])
        if repository.get("repo") == "local"
        for hook in repository.get("hooks", [])
    }


def test_environment_dependent_local_hooks_are_skipped_only_by_precommit_ci() -> None:
    config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    local_hooks = _local_hooks(config)
    configured_skip = set(config.get("ci", {}).get("skip", []))

    assert ENVIRONMENT_DEPENDENT_LOCAL_HOOKS <= local_hooks.keys()
    assert ENVIRONMENT_DEPENDENT_LOCAL_HOOKS <= configured_skip

    # Do not disable these checks for developers: CI-specific skips must not
    # rewrite the underlying local hook definitions or their execution stages.
    for hook_id in ENVIRONMENT_DEPENDENT_LOCAL_HOOKS:
        assert local_hooks[hook_id]["language"] == "system"


def test_yamllint_receives_only_changed_yaml_files() -> None:
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
    workflow = ROOT / ".github" / "workflows" / "pre-commit-changed-files.yml"
    source = workflow.read_text(encoding="utf-8")

    assert "pre-commit==4.7.0" in source
    assert "git diff --name-only --diff-filter=ACMRT -z" in source
    assert "pre-commit run --show-diff-on-failure --files" in source
