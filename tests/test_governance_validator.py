import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from tools.validate_ai_governance_artifacts import ROOT, main, run_validation


def test_validator_main_passes_for_repo_samples():
    exit_code = main([])
    assert exit_code == 0


def test_validator_emits_json_report(tmp_path: Path):
    report = tmp_path / "validation-report.json"
    exit_code = main(["--report-file", str(report)])
    assert exit_code == 0

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["bbom_files_discovered"] >= 1
    assert payload["arre_files_discovered"] >= 1
    assert payload["bbom_files_checked"] >= 1
    assert payload["arre_files_checked"] >= 1
    assert payload["failed_files"] == []
    assert payload["bbom_failed"] == 0
    assert payload["arre_failed"] == 0
    assert len(payload["passed_files"]) >= 2
    assert payload["validator_version"]
    assert payload["status"] == "passed"
    assert payload["bbom_dir"]
    assert payload["arre_dirs"]
    assert payload["errors"] == []
    assert payload["exit_code"] == 0


def test_validator_supports_custom_arre_dir_args():
    exit_code = main(["--arre-dir", "examples/arre", "--bbom-dir", "artifacts/bbom"])
    assert exit_code == 0


def test_validator_returns_error_when_arre_dir_missing():
    errors, _summary = run_validation("artifacts/bbom", ["does-not-exist/arre"])
    assert any("No ARRE files found" in error for error in errors)
    assert _summary.get("exit_code") == 2


def test_bbom_schema_rejects_missing_required_field():
    schema = json.loads((ROOT / "schemas" / "bbom.schema.json").read_text(encoding="utf-8"))
    sample = json.loads((ROOT / "artifacts" / "bbom" / "sample_tier0_fraud.json").read_text(encoding="utf-8"))
    sample.pop("artifact_id")

    errors = list(Draft202012Validator(schema).iter_errors(sample))
    assert errors, "Expected schema validation errors for missing artifact_id"


def test_arre_schema_rejects_missing_control_id():
    schema = json.loads((ROOT / "schemas" / "arre_record.schema.json").read_text(encoding="utf-8"))
    sample = json.loads((ROOT / "examples" / "arre" / "sample_t0_sanctions_002.json").read_text(encoding="utf-8"))
    sample.pop("control_id")

    errors = list(Draft202012Validator(schema).iter_errors(sample))
    assert errors, "Expected schema validation errors for missing control_id"


def test_arre_schema_rejects_bad_date_format_when_format_checker_enabled():
    schema = json.loads((ROOT / "schemas" / "arre_record.schema.json").read_text(encoding="utf-8"))
    sample = json.loads((ROOT / "examples" / "arre" / "sample_t0_sanctions_002.json").read_text(encoding="utf-8"))
    sample["period"]["start"] = "2026/10/01"

    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(sample))
    assert errors, "Expected schema validation errors for non-ISO date format"


def test_semantic_check_rejects_bbom_threshold_violation(tmp_path: Path):
    bbom_dir = tmp_path / "bbom"
    arre_dir = tmp_path / "arre"
    bbom_dir.mkdir()
    arre_dir.mkdir()

    bbom = json.loads((ROOT / "artifacts" / "bbom" / "sample_tier0_fraud.json").read_text(encoding="utf-8"))
    arre = json.loads((ROOT / "examples" / "arre" / "sample_t0_sanctions_002.json").read_text(encoding="utf-8"))
    bbom["hazard_scores"]["deception"] = 0.9
    bbom["acceptance_thresholds"]["max_deception"] = 0.2

    (bbom_dir / "bad_bbom.json").write_text(json.dumps(bbom), encoding="utf-8")
    (arre_dir / "good_arre.json").write_text(json.dumps(arre), encoding="utf-8")

    errors, _summary = run_validation(str(bbom_dir), [str(arre_dir)])
    assert any("max_deception" in err for err in errors)


def test_semantic_check_rejects_arre_period_inversion(tmp_path: Path):
    bbom_dir = tmp_path / "bbom"
    arre_dir = tmp_path / "arre"
    bbom_dir.mkdir()
    arre_dir.mkdir()

    bbom = json.loads((ROOT / "artifacts" / "bbom" / "sample_tier0_fraud.json").read_text(encoding="utf-8"))
    arre = json.loads((ROOT / "examples" / "arre" / "sample_t0_sanctions_002.json").read_text(encoding="utf-8"))
    arre["period"]["start"] = "2027-01-01"
    arre["period"]["end"] = "2026-01-01"

    (bbom_dir / "good_bbom.json").write_text(json.dumps(bbom), encoding="utf-8")
    (arre_dir / "bad_arre.json").write_text(json.dumps(arre), encoding="utf-8")

    errors, _summary = run_validation(str(bbom_dir), [str(arre_dir)])
    assert any("period.end before period.start" in err for err in errors)


def test_semantic_check_rejects_duplicate_evidence_hashes(tmp_path: Path):
    bbom_dir = tmp_path / "bbom"
    arre_dir = tmp_path / "arre"
    bbom_dir.mkdir()
    arre_dir.mkdir()

    bbom = json.loads((ROOT / "artifacts" / "bbom" / "sample_tier0_fraud.json").read_text(encoding="utf-8"))
    arre = json.loads((ROOT / "examples" / "arre" / "sample_t0_sanctions_002.json").read_text(encoding="utf-8"))
    arre["evidence_hashes"] = ["abc123abc123abc123abc123abc123ab", "abc123abc123abc123abc123abc123ab"]

    (bbom_dir / "good_bbom.json").write_text(json.dumps(bbom), encoding="utf-8")
    (arre_dir / "bad_arre.json").write_text(json.dumps(arre), encoding="utf-8")

    errors, _summary = run_validation(str(bbom_dir), [str(arre_dir)])
    assert any("duplicate evidence_hashes" in err for err in errors)


def test_failure_summary_contains_failed_file_details(tmp_path: Path):
    bbom_dir = tmp_path / "bbom"
    arre_dir = tmp_path / "arre"
    bbom_dir.mkdir()
    arre_dir.mkdir()

    bbom = json.loads((ROOT / "artifacts" / "bbom" / "sample_tier0_fraud.json").read_text(encoding="utf-8"))
    arre = json.loads((ROOT / "examples" / "arre" / "sample_t0_sanctions_002.json").read_text(encoding="utf-8"))
    bbom["hazard_scores"]["deception"] = 0.99
    bbom["acceptance_thresholds"]["max_deception"] = 0.01

    bad_bbom = bbom_dir / "bad_bbom.json"
    good_arre = arre_dir / "good_arre.json"
    bad_bbom.write_text(json.dumps(bbom), encoding="utf-8")
    good_arre.write_text(json.dumps(arre), encoding="utf-8")

    errors, summary = run_validation(str(bbom_dir), [str(arre_dir)])
    assert errors
    assert summary["failed_files"]
    assert summary.get("exit_code") == 2
    assert summary.get("exit_code") == 2
    assert summary["failed_files"][0]["file"].endswith("bad_bbom.json")
    assert summary["bbom_failed"] >= 1


def test_malformed_json_is_reported_without_crash(tmp_path: Path):
    bbom_dir = tmp_path / "bbom"
    arre_dir = tmp_path / "arre"
    bbom_dir.mkdir()
    arre_dir.mkdir()

    # malformed BBOM JSON (missing closing brace)
    (bbom_dir / "broken_bbom.json").write_text('{"artifact_id": "bad"', encoding="utf-8")

    arre = json.loads((ROOT / "examples" / "arre" / "sample_t0_sanctions_002.json").read_text(encoding="utf-8"))
    (arre_dir / "good_arre.json").write_text(json.dumps(arre), encoding="utf-8")

    errors, summary = run_validation(str(bbom_dir), [str(arre_dir)])
    assert errors
    assert any("Failed to parse JSON" in err for err in errors)
    assert summary["failed_files"]
    assert summary["bbom_failed"] >= 1


def test_schema_load_failure_is_reported(monkeypatch):
    from tools import validate_ai_governance_artifacts as mod

    original = mod.load_json

    def fake_load_json(path):
        if str(path).endswith('bbom.schema.json'):
            raise mod.ValidationError('simulated schema load failure')
        return original(path)

    monkeypatch.setattr(mod, 'load_json', fake_load_json)
    errors, summary = mod.run_validation('artifacts/bbom', ['examples/arre'])

    assert errors
    assert 'simulated schema load failure' in errors[0]
    assert summary.get('fatal_error') == 'schema_load_failure'


def test_main_returns_nonzero_for_missing_dirs():
    exit_code = main(["--bbom-dir", "missing/bbom", "--arre-dir", "missing/arre"])
    assert exit_code == 2
