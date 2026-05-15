import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import validate_blueprint_artifacts as v


def stage_artifacts(tmp_path: Path) -> Path:
    alt = tmp_path / "art"
    alt.mkdir()
    for f in v.REQUIRED_FILES:
        src = v.DEFAULT_ART / f
        dst = alt / f
        shutil.copy2(src, dst)
    return alt


def test_check_sequence_has_unique_ids():
    ids = [name for name, _desc in v.CHECK_SEQUENCE]
    assert len(ids) == len(set(ids))


def test_required_files_unique():
    assert len(v.REQUIRED_FILES) == len(set(v.REQUIRED_FILES))


def test_manifest_top_keys_match_expectation():
    manifest = v.load_manifest(v.DEFAULT_ART)
    assert set(manifest.keys()) == {"manifest_id", "generated_at", "institution", "artifacts"}


def test_validation_results_all_pass():
    results = v.run_validations(v.DEFAULT_ART)
    assert all(r.ok for r in results)


def test_expected_check_names_present():
    names = [r.name for r in v.run_validations(v.DEFAULT_ART)]
    assert names == [name for name, _desc in v.CHECK_SEQUENCE]


def test_safe_run_converts_exception_to_failure():
    result = v.safe_run("boom", lambda _base: 1 / 0, v.DEFAULT_ART)
    assert result.ok is False
    assert result.name == "boom"
    assert "Unhandled exception" in result.detail


def test_non_default_base_dir_supported(tmp_path: Path):
    alt = stage_artifacts(tmp_path)
    results = v.run_validations(alt)
    assert all(r.ok for r in results)


def test_missing_file_reports_presence_failure(tmp_path: Path):
    alt = stage_artifacts(tmp_path)
    (alt / "T5_RedTeam_Closure_Report.md").unlink()
    results = v.run_validations(alt)
    presence = [r for r in results if r.name == "presence"][0]
    assert presence.ok is False
    assert "Missing files" in presence.detail


def test_invalid_timestamp_reports_failure(tmp_path: Path):
    alt = stage_artifacts(tmp_path)
    manifest_path = alt / "T6_Evidence_Manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["generated_at"] = "not-a-timestamp"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    results = v.run_validations(alt)
    ts_result = [r for r in results if r.name == "manifest_timestamp"][0]
    assert ts_result.ok is False
    assert "Invalid generated_at timestamp" in ts_result.detail


def test_invalid_model_risk_csv_date_reports_failure(tmp_path: Path):
    alt = stage_artifacts(tmp_path)
    risk = alt / "T3_Model_Risk_Register.csv"
    lines = risk.read_text().splitlines()
    # Corrupt next_review_date format on first data row.
    parts = lines[1].split(",")
    parts[-1] = "2026/06/30"
    lines[1] = ",".join(parts)
    risk.write_text("\n".join(lines) + "\n")

    results = v.run_validations(alt)
    csv_result = [r for r in results if r.name == "csv_semantics"][0]
    assert csv_result.ok is False
    assert "invalid date format" in csv_result.detail


def test_empty_manifest_signature_reports_schema_constraint_failure(tmp_path: Path):
    alt = stage_artifacts(tmp_path)
    manifest_path = alt / "T6_Evidence_Manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"][0]["signature"] = ""
    manifest_path.write_text(json.dumps(manifest, indent=2))

    results = v.run_validations(alt)
    schema_result = [r for r in results if r.name == "schema_constraints"][0]
    assert schema_result.ok is False
    assert "violates minLength/type" in schema_result.detail


def test_k8s_yaml_missing_egress_reports_failure(tmp_path: Path):
    alt = stage_artifacts(tmp_path)
    k8s = alt / "T9_K8s_NetworkPolicy_Example.yaml"
    text = k8s.read_text().replace("- Egress", "- Ingress")
    k8s.write_text(text)

    results = v.run_validations(alt)
    yaml_result = [r for r in results if r.name == "yaml_examples"][0]
    assert yaml_result.ok is False
    assert "policyTypes must include Egress" in yaml_result.detail


def test_json_mode_output_is_machine_readable():
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_blueprint_artifacts.py"),
            "--json",
            "--base-dir",
            str(v.DEFAULT_ART),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list)
    assert any(item.get("name") == "yaml_examples" for item in payload)


def test_no_unregistered_handler_errors_in_default_run():
    results = v.run_validations(v.DEFAULT_ART)
    assert all("No handler registered" not in r.detail for r in results)


def test_list_checks_mode_outputs_sequence():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate_blueprint_artifacts.py"), "--list-checks"],
        check=True,
        capture_output=True,
        text=True,
    )
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    expected = [f"{name}: {desc}" for name, desc in v.CHECK_SEQUENCE]
    assert lines == expected
