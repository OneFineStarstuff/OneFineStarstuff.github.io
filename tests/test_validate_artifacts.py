from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from gstack_artifacts.validate_artifacts import main


def _write_schema(root: Path) -> None:
    schema_dir = root / "schemas"
    schema_dir.mkdir(parents=True, exist_ok=True)
    (schema_dir / "control_catalog.schema.json").write_text('{"type":"object"}')


class ValidateArtifactsTests(unittest.TestCase):
    def test_repo_artifacts_pass(self):
        out = StringIO()
        err = StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["--root", str(Path("gstack_artifacts").resolve())])
        self.assertEqual(rc, 0)
        self.assertIn("OK: all G-Stack artifacts validated", out.getvalue())
        self.assertEqual("", err.getvalue())

    def test_duplicate_scenario_ids_fail(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "gstack_control_catalog.yaml").write_text(
                "version: 1\nscope: s\ncontrols:\n  - id: GAIRDS-GOV-001\n    layer: L\n    title: t\n    requirement: r\n    mappings: [ISO42001-X]\n    evidence: [e]\nkpis: [{id: KPI-1, threshold: t}]\n"
            )
            (root / "stress_test_matrix.csv").write_text(
                "scenario_id,scenario_name,trigger_class,severity,target_layer,pass_criteria,owner\n"
                "S-01,a,t,T1,x,p,o\nS-01,b,t,T1,x,p,o\nS-03,c,t,T1,x,p,o\nS-04,d,t,T1,x,p,o\nS-05,e,t,T1,x,p,o\n"
            )
            _write_schema(root)
            (root / "lifecycle_integrity_report_template.md").write_text(
                "## 1. Model/System Identification\n## 3. Control Attestations\n## 5. Compliance Crosswalk Status\n## 6. Signatures\n"
            )
            out = StringIO(); err = StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = main(["--root", str(root)])
            self.assertEqual(rc, 1)
            self.assertIn("duplicate scenario_id", err.getvalue())

    def test_invalid_control_id_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "gstack_control_catalog.yaml").write_text(
                "version: 1\nscope: s\ncontrols:\n  - id: BAD\n    layer: L\n    title: t\n    requirement: r\n    mappings: [ISO42001-X]\n    evidence: [e]\nkpis: [{id: KPI-1, threshold: t}]\n"
            )
            (root / "stress_test_matrix.csv").write_text(
                "scenario_id,scenario_name,trigger_class,severity,target_layer,pass_criteria,owner\n"
                "S-01,a,t,T1,x,p,o\nS-02,b,t,T1,x,p,o\nS-03,c,t,T1,x,p,o\nS-04,d,t,T1,x,p,o\nS-05,e,t,T1,x,p,o\n"
            )
            _write_schema(root)
            (root / "lifecycle_integrity_report_template.md").write_text(
                "## 1. Model/System Identification\n## 3. Control Attestations\n## 5. Compliance Crosswalk Status\n## 6. Signatures\n"
            )
            out = StringIO(); err = StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = main(["--root", str(root)])
            self.assertEqual(rc, 1)
            self.assertIn("invalid control id format", err.getvalue())

    def test_missing_schema_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "gstack_control_catalog.yaml").write_text(
                "version: 1\nscope: s\ncontrols:\n  - id: GAIRDS-GOV-001\n    layer: L\n    title: t\n    requirement: r\n    mappings: [ISO42001-X]\n    evidence: [e]\nkpis: [{id: KPI-1, threshold: t}]\n"
            )
            (root / "stress_test_matrix.csv").write_text(
                "scenario_id,scenario_name,trigger_class,severity,target_layer,pass_criteria,owner\n"
                "S-01,a,t,T1,x,p,o\nS-02,b,t,T1,x,p,o\nS-03,c,t,T1,x,p,o\nS-04,d,t,T1,x,p,o\nS-05,e,t,T1,x,p,o\n"
            )
            (root / "lifecycle_integrity_report_template.md").write_text(
                "## 1. Model/System Identification\n## 3. Control Attestations\n## 5. Compliance Crosswalk Status\n## 6. Signatures\n"
            )
            out = StringIO(); err = StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = main(["--root", str(root)])
            self.assertEqual(rc, 1)
            self.assertIn("Missing file", err.getvalue())

    def test_invalid_severity_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "gstack_control_catalog.yaml").write_text(
                "version: 1\nscope: s\ncontrols:\n  - id: GAIRDS-GOV-001\n    layer: L\n    title: t\n    requirement: r\n    mappings: [ISO42001-X]\n    evidence: [e]\nkpis: [{id: KPI-1, threshold: t}]\n"
            )
            (root / "stress_test_matrix.csv").write_text(
                "scenario_id,scenario_name,trigger_class,severity,target_layer,pass_criteria,owner\n"
                "S-01,a,t,BAD,x,p,o\nS-02,b,t,T1,x,p,o\nS-03,c,t,T1,x,p,o\nS-04,d,t,T1,x,p,o\nS-05,e,t,T1,x,p,o\n"
            )
            _write_schema(root)
            (root / "lifecycle_integrity_report_template.md").write_text(
                "## 1. Model/System Identification\n## 3. Control Attestations\n## 5. Compliance Crosswalk Status\n## 6. Signatures\n"
            )
            out = StringIO(); err = StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = main(["--root", str(root)])
            self.assertEqual(rc, 1)
            self.assertIn("invalid severity", err.getvalue())

    def test_strict_schema_flag_requires_jsonschema(self):
        out = StringIO(); err = StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["--root", str(Path("gstack_artifacts").resolve()), "--strict-schema"])
        # In environments without jsonschema installed, strict mode must fail loudly.
        if rc == 1:
            self.assertIn("strict schema mode", err.getvalue())
        else:
            self.assertEqual(rc, 0)

    def test_blueprint_pointer_targets_canonical_path(self):
        pointer = Path("G_STACK_GOVERNANCE_BLUEPRINT_2026_2030.md")
        canonical = Path("docs/reports/G_STACK_GOVERNANCE_BLUEPRINT_2026_2030.md")
        self.assertTrue(pointer.exists())
        self.assertTrue(canonical.exists())
        content = pointer.read_text()
        self.assertIn("docs/reports/G_STACK_GOVERNANCE_BLUEPRINT_2026_2030.md", content)

    def test_json_output_mode(self):
        out = StringIO(); err = StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["--root", str(Path("gstack_artifacts").resolve()), "--json"])
        self.assertEqual(rc, 0)
        payload = __import__("json").loads(out.getvalue())
        self.assertEqual(payload["status"], "passed")
        self.assertIn("validator_version", payload)
        self.assertIn("timestamp", payload)
        self.assertIn("validator_version", payload)
        self.assertEqual("", err.getvalue())

    def test_template_marker_order_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "gstack_control_catalog.yaml").write_text(
                "version: \"1.0\"\nscope: s\ncontrols:\n  - id: GAIRDS-GOV-001\n    layer: L\n    title: t\n    requirement: r\n    mappings: [ISO42001-X]\n    evidence: [e]\nkpis: [{id: KPI-1, threshold: t}]\n"
            )
            (root / "stress_test_matrix.csv").write_text(
                "scenario_id,scenario_name,trigger_class,severity,target_layer,pass_criteria,owner\n"
                "S-01,a,t,T1,x,p,o\nS-02,b,t,T1,x,p,o\nS-03,c,t,T1,x,p,o\nS-04,d,t,T1,x,p,o\nS-05,e,t,T1,x,p,o\n"
            )
            _write_schema(root)
            (root / "lifecycle_integrity_report_template.md").write_text(
                "## 6. Signatures\n## 1. Model/System Identification\n## 3. Control Attestations\n## 5. Compliance Crosswalk Status\n"
            )
            out = StringIO(); err = StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = main(["--root", str(root)])
            self.assertEqual(rc, 1)
            self.assertIn("out of required order", err.getvalue())
    def test_json_report_path_writes_file(self):
        out = StringIO(); err = StringIO()
        report = Path("artifacts/test-results/unit-json-report.json")
        if report.exists():
            report.unlink()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["--root", str(Path("gstack_artifacts").resolve()), "--json", "--report-path", str(report)])
        self.assertEqual(rc, 0)
        self.assertTrue(report.exists())
        payload = __import__("json").loads(report.read_text())
        self.assertEqual(payload["status"], "passed")
import unittest
import subprocess
import json as jsonlib
from unittest.mock import patch
import io
from contextlib import redirect_stdout
from pathlib import Path

from governance_artifacts import validate_artifacts as va


class TestGovernanceArtifactsValidator(unittest.TestCase):
    def test_validator_main_passes(self):
        # Should run without raising and emit PASS.
        va.main([])

    def test_assert_non_empty_list_rejects_empty(self):
        with self.assertRaises(AssertionError):
            va.assert_non_empty_list([], "empty_list")

    def test_assert_type_rejects_wrong_type(self):
        with self.assertRaises(AssertionError):
            va.assert_type("not_a_list", list, "type_check")

    def test_assert_iso_date_accepts_valid_date(self):
        va.assert_iso_date("2026-04-29", "valid_date")

    def test_assert_iso_date_rejects_invalid_date(self):
        with self.assertRaises(AssertionError):
            va.assert_iso_date("29-04-2026", "invalid_date")

    def test_to_date_rejects_invalid_date(self):
        with self.assertRaises(AssertionError):
            va.to_date("invalid", "to_date_invalid")

    def test_run_all_checks_returns_pass_results(self):
        results = va.run_all_checks()
        self.assertTrue(results)
        self.assertTrue(all(v == "PASS" for v in results.values()))

    def test_json_output_mode(self):
        cp = subprocess.run(
            ["python3", "governance_artifacts/validate_artifacts.py", "--json"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = jsonlib.loads(cp.stdout)
        self.assertEqual(payload["status"], "PASS")
        self.assertIn("generated_at_utc", payload)

    def test_main_returns_nonzero_on_assertion_failure(self):
        with patch.object(va, "run_all_checks", side_effect=AssertionError("boom")):
            buf = io.StringIO()
            with self.assertRaises(SystemExit) as ctx:
                with redirect_stdout(buf):
                    va.main(["--json"])
            self.assertEqual(ctx.exception.code, 1)
            payload = jsonlib.loads(buf.getvalue())
            self.assertEqual(payload["status"], "FAIL")
            self.assertEqual(payload["error"], "boom")
            self.assertIn("generated_at_utc", payload)

    def test_quiet_mode_has_no_stdout_on_success(self):
        cp = subprocess.run(
            ["python3", "governance_artifacts/validate_artifacts.py", "--quiet"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(cp.stdout.strip(), "")

    def test_kpi_kri_schema_validation_passes(self):
        va.validate_kpi_kri_schema()

    def test_control_references_validation_passes(self):
        va.validate_control_references()

    def test_json_output_file_written(self):
        out = Path("artifacts/nested/validator-output.json")
        if out.exists():
            out.unlink()
        if out.parent.exists():
            for p in sorted(out.parent.glob("*"), reverse=True):
                if p.is_file():
                    p.unlink()
        subprocess.run(
            ["python3", "governance_artifacts/validate_artifacts.py", "--quiet", "--output", str(out)],
            check=True,
        )
        payload = jsonlib.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "PASS")

    def test_output_file_written_on_failure(self):
        out = Path("artifacts/validator-output-fail.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.exists():
            out.unlink()
        with patch.object(va, "run_all_checks", side_effect=AssertionError("forced-fail")):
            with self.assertRaises(SystemExit):
                va.main(["--quiet", "--output", str(out)])
        payload = jsonlib.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "FAIL")
        self.assertEqual(payload["error"], "forced-fail")

    def test_duplicate_control_id_is_rejected(self):
        duplicate_controls = {
            "version": "1.0.0",
            "last_updated": "2026-04-29",
            "controls": [
                {"id": "CTRL-1", "name": "a", "mapped_regimes": ["x"], "owner": "o", "evidence": ["e"]},
                {"id": "CTRL-1", "name": "b", "mapped_regimes": ["x"], "owner": "o", "evidence": ["e"]},
            ],
        }
        with patch.object(va, "load_yaml", return_value=duplicate_controls):
            with self.assertRaises(AssertionError):
                va.validate_control_library()

    def test_duplicate_model_id_is_rejected(self):
        duplicate_models = {
            "registry_version": "1.0.0",
            "generated_on": "2026-04-29",
            "models": [
                {"model_id": "M-1", "use_case": "u", "risk_tier": "high", "deployment_status": "production", "controls": ["CTRL-1"], "validation": {"last_validation": "2026-01-01", "next_due": "2026-02-01", "independent_validation": True}},
                {"model_id": "M-1", "use_case": "u", "risk_tier": "high", "deployment_status": "production", "controls": ["CTRL-1"], "validation": {"last_validation": "2026-01-01", "next_due": "2026-02-01", "independent_validation": True}},
            ],
        }
        with patch.object(va, "load_json", return_value=duplicate_models):
            with self.assertRaises(AssertionError):
                va.validate_model_registry()

    def test_blank_control_reference_is_rejected(self):
        control_library = {
            "controls": [{"id": "CTRL-1"}]
        }
        model_registry = {
            "models": [{"model_id": "M-1", "controls": ["   "]}]
        }
        with patch.object(va, "load_yaml", return_value=control_library), patch.object(va, "load_json", return_value=model_registry):
            with self.assertRaises(AssertionError):
                va.validate_control_references()

    def test_invalid_mapped_regime_value_is_rejected(self):
        invalid_controls = {
            "version": "1.0.0",
            "last_updated": "2026-04-29",
            "controls": [
                {"id": "CTRL-1", "name": "a", "mapped_regimes": ["EU-AI-ACT"], "owner": "o", "evidence": ["e"]},
            ],
        }
        with patch.object(va, "load_yaml", return_value=invalid_controls):
            with self.assertRaises(AssertionError):
                va.validate_control_library()

    def test_missing_rego_policy_is_rejected(self):
        with patch("pathlib.Path.exists", return_value=False):
            with self.assertRaises(AssertionError):
                va.validate_rego_policy()

    def test_duplicate_runbook_id_is_rejected(self):
        duplicate_runbooks = {
            "runbooks": [
                {"id": "RB-1", "trigger": "x", "steps": ["a"]},
                {"id": "RB-1", "trigger": "y", "steps": ["b"]},
            ]
        }
        with patch.object(va, "load_yaml", return_value=duplicate_runbooks):
            with self.assertRaises(AssertionError):
                va.validate_runbooks()

    def test_blank_runbook_trigger_is_rejected(self):
        invalid_runbooks = {
            "runbooks": [
                {"id": "RB-1", "trigger": "   ", "steps": ["a"]},
            ]
        }
        with patch.object(va, "load_yaml", return_value=invalid_runbooks):
            with self.assertRaises(AssertionError):
                va.validate_runbooks()

    def test_list_checks_json_mode(self):
        cp = subprocess.run(
            ["python3", "governance_artifacts/validate_artifacts.py", "--list-checks", "--json"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = jsonlib.loads(cp.stdout)
        self.assertIn("version", payload)
        self.assertIn("checks", payload)
        self.assertIn("validate_control_library", payload["checks"])

    def test_list_checks_plain_mode(self):
        cp = subprocess.run(
            ["python3", "governance_artifacts/validate_artifacts.py", "--list-checks"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("validate_control_library", cp.stdout)

    def test_check_flag_runs_selected_check(self):
        cp = subprocess.run(
            ["python3", "governance_artifacts/validate_artifacts.py", "--json", "--check", "validate_control_library"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = jsonlib.loads(cp.stdout)
        self.assertEqual(payload["status"], "PASS")
        self.assertEqual(list(payload["checks"].keys()), ["validate_control_library"])

    def test_unknown_check_fails(self):
        cp = subprocess.run(
            ["python3", "governance_artifacts/validate_artifacts.py", "--json", "--check", "not_a_check"],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(cp.returncode, 0)
        payload = jsonlib.loads(cp.stdout)
        self.assertEqual(payload["status"], "FAIL")

    def test_duplicate_check_arguments_are_deduplicated(self):
        cp = subprocess.run(
            [
                "python3",
                "governance_artifacts/validate_artifacts.py",
                "--json",
                "--check",
                "validate_control_library",
                "--check",
                "validate_control_library",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = jsonlib.loads(cp.stdout)
        self.assertEqual(list(payload["checks"].keys()), ["validate_control_library"])

    def test_version_plain_mode(self):
        cp = subprocess.run(
            ["python3", "governance_artifacts/validate_artifacts.py", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertRegex(cp.stdout.strip(), r"^\d+\.\d+\.\d+$")

    def test_version_json_mode(self):
        cp = subprocess.run(
            ["python3", "governance_artifacts/validate_artifacts.py", "--version", "--json"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = jsonlib.loads(cp.stdout)
        self.assertIn("version", payload)


if __name__ == "__main__":
    unittest.main()
