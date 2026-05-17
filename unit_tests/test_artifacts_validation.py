import json
import subprocess
import sys
from argparse import Namespace

import pytest

from artifacts import build_manifest
from artifacts import check_all
from artifacts import validate_artifacts
from artifacts.build_manifest import build_manifest_payload, run_cli as run_manifest_cli
from artifacts.validate_artifacts import (
    ValidationError,
    display_artifact_path,
    load_manifest_targets,
    run_cli,
    validate_control_catalog,
    validate_manifest,
    validate_schema_documents,
)


def run_python(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_artifacts_validation_script_runs():
    proc = run_python("artifacts/validate_artifacts.py")
    assert proc.returncode == 0, proc.stderr
    assert "All artifact validations passed." in proc.stdout


def test_validation_json_output_mode():
    proc = run_python("artifacts/validate_artifacts.py", "--json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["status"] == "ok"
    assert payload["checks"]["manifest"] == "pass"


def test_validation_skip_manifest_mode():
    proc = run_python("artifacts/validate_artifacts.py", "--json", "--skip-manifest")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["checks"]["manifest"] == "skipped"


def test_run_cli_json_error_mode(monkeypatch, capsys):
    def fail_validation(include_manifest: bool = True) -> dict:
        raise ValidationError("forced failure")

    monkeypatch.setattr(validate_artifacts, "run_validation", fail_validation)
    rc = run_cli(Namespace(skip_manifest=False, json=True, quiet=False))
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 1
    assert payload["status"] == "error"
    assert "forced failure" in payload["error"]


def test_validation_json_mode_reports_missing_required_artifact(monkeypatch, tmp_path, capsys):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    monkeypatch.setattr(validate_artifacts, "ARTIFACTS_DIR", artifact_dir)

    rc = run_cli(Namespace(skip_manifest=False, json=True, quiet=False))
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["status"] == "error"
    assert "required artifact file missing" in payload["error"]
    assert "annex-iv-dossier-schema-v1.json" in payload["error"]


def test_validate_schema_documents_missing_file(monkeypatch, tmp_path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    monkeypatch.setattr(validate_artifacts, "ARTIFACTS_DIR", artifact_dir)
    with pytest.raises(ValidationError, match=r"required artifact file missing: schemas/manifest-targets-schema-v1.json"):
        validate_schema_documents()


def test_display_artifact_path_is_relative_to_artifacts_dir(monkeypatch, tmp_path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    nested = artifact_dir / "schemas" / "x.json"

    monkeypatch.setattr(validate_artifacts, "ARTIFACTS_DIR", artifact_dir)
    assert display_artifact_path(nested) == "schemas/x.json"


def test_display_artifact_path_preserves_non_artifact_paths(monkeypatch, tmp_path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    external = tmp_path / "outside.json"

    monkeypatch.setattr(validate_artifacts, "ARTIFACTS_DIR", artifact_dir)
    assert display_artifact_path(external) == str(external)


def test_manifest_targets_contains_expected_blueprint_file():
    targets = load_manifest_targets()
    assert "enterprise-civilizational-agi-asi-blueprint-2026-2030.md" in targets


def test_build_manifest_reproducible_timestamp(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")
    payload = build_manifest_payload()
    assert payload["generated_at"] == "2026-01-01T00:00:00+00:00"


def test_build_manifest_check_mode_passes():
    proc = run_python("artifacts/build_manifest.py", "--check")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_manifest_targets_duplicate_entries_fail(monkeypatch, tmp_path):
    bad_targets = {
        "version": "1.0",
        "files": ["a.json", "a.json"],
    }
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "manifest-targets-v1.json").write_text(json.dumps(bad_targets), encoding="utf-8")

    monkeypatch.setattr(validate_artifacts, "ARTIFACTS_DIR", artifact_dir)
    with pytest.raises(ValidationError, match="duplicate"):
        validate_artifacts.load_manifest_targets()

    monkeypatch.setattr(build_manifest, "ARTIFACTS_DIR", artifact_dir)
    with pytest.raises(ValueError, match="duplicate"):
        build_manifest.load_manifest_targets()


def test_manifest_targets_invalid_version_fails(monkeypatch, tmp_path):
    bad_targets = {
        "version": "9.9",
        "files": ["a.json"],
    }
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "manifest-targets-v1.json").write_text(json.dumps(bad_targets), encoding="utf-8")

    monkeypatch.setattr(build_manifest, "ARTIFACTS_DIR", artifact_dir)
    with pytest.raises(ValueError, match="version must be 1.0"):
        build_manifest.load_manifest_targets()


def test_manifest_targets_missing_file_fails(monkeypatch, tmp_path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()

    monkeypatch.setattr(build_manifest, "ARTIFACTS_DIR", artifact_dir)
    with pytest.raises(ValueError, match="is missing"):
        build_manifest.load_manifest_targets()


def test_manifest_targets_invalid_json_fails(monkeypatch, tmp_path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "manifest-targets-v1.json").write_text("{not-json", encoding="utf-8")

    monkeypatch.setattr(build_manifest, "ARTIFACTS_DIR", artifact_dir)
    with pytest.raises(ValueError, match="not valid JSON"):
        build_manifest.load_manifest_targets()


def test_manifest_targets_unsafe_path_fails(monkeypatch, tmp_path):
    bad_targets = {
        "version": "1.0",
        "files": ["../secrets.txt"],
    }
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "manifest-targets-v1.json").write_text(json.dumps(bad_targets), encoding="utf-8")

    monkeypatch.setattr(build_manifest, "ARTIFACTS_DIR", artifact_dir)
    with pytest.raises(ValueError, match="safe relative paths"):
        build_manifest.load_manifest_targets()


def test_manifest_targets_windows_separators_fail(monkeypatch, tmp_path):
    bad_targets = {
        "version": "1.0",
        "files": ["schemas\\manifest-targets-schema-v1.json"],
    }
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "manifest-targets-v1.json").write_text(json.dumps(bad_targets), encoding="utf-8")

    monkeypatch.setattr(build_manifest, "ARTIFACTS_DIR", artifact_dir)
    with pytest.raises(ValueError, match="POSIX-style separators"):
        build_manifest.load_manifest_targets()


def test_manifest_targets_missing_files_key_fails(monkeypatch, tmp_path):
    bad_targets = {
        "version": "1.0",
    }
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "manifest-targets-v1.json").write_text(json.dumps(bad_targets), encoding="utf-8")

    monkeypatch.setattr(build_manifest, "ARTIFACTS_DIR", artifact_dir)
    with pytest.raises(ValueError, match="non-empty files list"):
        build_manifest.load_manifest_targets()


def test_manifest_targets_referenced_file_must_exist(monkeypatch, tmp_path):
    bad_targets = {
        "version": "1.0",
        "files": ["missing.json"],
    }
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "manifest-targets-v1.json").write_text(json.dumps(bad_targets), encoding="utf-8")

    monkeypatch.setattr(build_manifest, "ARTIFACTS_DIR", artifact_dir)
    with pytest.raises(ValueError, match="references missing file"):
        build_manifest.load_manifest_targets()


def test_build_manifest_check_mode_json_output():
    proc = run_python("artifacts/build_manifest.py", "--check", "--json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["status"] == "ok"


def test_build_manifest_check_mode_invalid_existing_manifest_json(monkeypatch, tmp_path, capsys):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "manifest-targets-v1.json").write_text(
        json.dumps({"version": "1.0", "files": ["a.json"]}),
        encoding="utf-8",
    )
    (artifact_dir / "a.json").write_text("{}", encoding="utf-8")
    (artifact_dir / "artifact-manifest-v1.json").write_text("{not-json", encoding="utf-8")
    monkeypatch.setattr(build_manifest, "ARTIFACTS_DIR", artifact_dir)

    rc = run_manifest_cli(Namespace(check=True, json=True))
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["status"] == "error"
    assert "invalid JSON" in payload["message"]


def test_build_manifest_check_mode_invalid_existing_manifest_structure(monkeypatch, tmp_path, capsys):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "manifest-targets-v1.json").write_text(
        json.dumps({"version": "1.0", "files": ["a.json"]}),
        encoding="utf-8",
    )
    (artifact_dir / "a.json").write_text("{}", encoding="utf-8")
    (artifact_dir / "artifact-manifest-v1.json").write_text('["not-an-object"]', encoding="utf-8")
    monkeypatch.setattr(build_manifest, "ARTIFACTS_DIR", artifact_dir)

    rc = run_manifest_cli(Namespace(check=True, json=True))
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["status"] == "error"
    assert "invalid structure" in payload["message"]


def test_build_manifest_error_json_mode(monkeypatch, capsys):
    def fail_targets() -> list[str]:
        raise ValueError("forced manifest failure")

    monkeypatch.setattr(build_manifest, "load_manifest_targets", fail_targets)
    rc = run_manifest_cli(Namespace(check=False, json=True))
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["status"] == "error"
    assert "forced manifest failure" in payload["message"]


def test_build_manifest_error_plain_mode(monkeypatch, capsys):
    def fail_targets() -> list[str]:
        raise ValueError("forced manifest failure plain")

    monkeypatch.setattr(build_manifest, "load_manifest_targets", fail_targets)
    rc = run_manifest_cli(Namespace(check=False, json=False))
    out = capsys.readouterr().out

    assert rc == 1
    assert "forced manifest failure plain" in out


def test_check_all_json_mode():
    proc = run_python("artifacts/check_all.py", "--json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema_version"] == "1.0"
    assert payload["status"] == "ok"
    assert payload["manifest_fresh"] is True
    assert payload["validation_ok"] is True
    assert payload["errors"] == []
    assert payload["checked_at"].endswith("+00:00")


def test_check_all_detects_manifest_staleness(monkeypatch):
    def fake_build_manifest_payload() -> dict:
        return {"version": "1.1", "files": {"x": "y"}}

    monkeypatch.setattr(check_all, "build_manifest_payload", fake_build_manifest_payload)
    result = check_all.run_all()
    assert result["status"] == "error"
    assert "manifest_not_fresh" in result["errors"]


def test_check_all_plain_mode_output():
    proc = run_python("artifacts/check_all.py")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "All checks passed." in proc.stdout


def test_check_all_error_json_mode(monkeypatch, capsys):
    def fail_run_all() -> dict:
        raise ValidationError("forced check_all failure")

    monkeypatch.setattr(check_all, "run_all", fail_run_all)
    rc = check_all.run_cli(Namespace(json=True))
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["status"] == "error"
    assert "forced check_all failure" in payload["error"]


def test_check_all_error_json_mode_for_value_error(monkeypatch, capsys):
    def fail_run_all() -> dict:
        raise ValueError("forced value error")

    monkeypatch.setattr(check_all, "run_all", fail_run_all)
    rc = check_all.run_cli(Namespace(json=True))
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["status"] == "error"
    assert "forced value error" in payload["error"]


def test_check_all_error_json_mode_for_os_error(monkeypatch, capsys):
    def fail_run_all() -> dict:
        raise OSError("forced os error")

    monkeypatch.setattr(check_all, "run_all", fail_run_all)
    rc = check_all.run_cli(Namespace(json=True))
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["status"] == "error"
    assert "forced os error" in payload["error"]


def test_check_all_error_json_mode_for_key_error(monkeypatch, capsys):
    def fail_run_all() -> dict:
        raise KeyError("forced key error")

    monkeypatch.setattr(check_all, "run_all", fail_run_all)
    rc = check_all.run_cli(Namespace(json=True))
    payload = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert payload["status"] == "error"
    assert "forced key error" in payload["error"]


def test_check_all_result_schema_file_exists_and_has_required_keys():
    with open("artifacts/schemas/check-all-result-schema-v1.json", "r", encoding="utf-8") as f:
        schema = json.load(f)

    assert schema["type"] == "object"
    assert "required" in schema
    assert "status" in schema["properties"]


def test_check_all_error_plain_mode(monkeypatch, capsys):
    def fail_run_all() -> dict:
        raise ValidationError("forced check_all plain failure")

    monkeypatch.setattr(check_all, "run_all", fail_run_all)
    rc = check_all.run_cli(Namespace(json=False))
    captured = capsys.readouterr()

    assert rc == 1
    assert "forced check_all plain failure" in captured.err


def test_control_catalog_mapping_references_known_ids():
    with open("artifacts/control-catalog-v1.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    bad = json.loads(json.dumps(data))
    bad["mappings"]["eu_ai_act_annex_iv"].append("unknown.control.id")

    with pytest.raises(ValidationError, match="unknown control id"):
        validate_control_catalog(bad)


def test_manifest_check_detects_missing_file(tmp_path):
    manifest = {
        "version": "1.1",
        "generated_at": "2026-04-25T00:00:00+00:00",
        "files": {"missing.json": "abc"},
    }
    with pytest.raises(ValidationError, match="coverage mismatch"):
        validate_manifest(tmp_path, manifest)


def test_manifest_invalid_timestamp(tmp_path):
    manifest = {
        "version": "1.1",
        "generated_at": "not-a-time",
        "files": {},
    }
    with pytest.raises(ValidationError, match="ISO-8601"):
        validate_manifest(tmp_path, manifest)


def test_manifest_coverage_detects_extra_file(tmp_path):
    manifest = {
        "version": "1.1",
        "generated_at": "2026-04-25T00:00:00+00:00",
        "files": {
            "annex-iv-dossier-schema-v1.json": "abc",
            "control-catalog-v1.json": "abc",
            "roadmap-2026-2030.yaml": "abc",
            "regulator-report-template.xml": "abc",
            "enterprise-civilizational-agi-asi-blueprint-2026-2030.md": "abc",
            "examples/annex-iv-dossier-example.json": "abc",
            "extra.txt": "abc",
        },
    }
    with pytest.raises(ValidationError, match="coverage mismatch"):
        validate_manifest(tmp_path, manifest)
