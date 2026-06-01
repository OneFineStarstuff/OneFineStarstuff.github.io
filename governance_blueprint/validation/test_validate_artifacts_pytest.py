from __future__ import annotations

from governance_blueprint.validation import validate_artifacts as va


def test_run_checks_includes_systemic_artifacts() -> None:
    results = va.run_checks()
    assert "systemic_artifacts/*" in results


def test_run_checks_has_no_errors_for_repo_state() -> None:
    results = va.run_checks()
    non_manifest = {k: v for k, v in results.items() if k != "artifact_manifest.json"}
    assert all(not errors for errors in non_manifest.values()), non_manifest
