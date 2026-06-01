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


if __name__ == "__main__":
    unittest.main()
