import tempfile
import unittest
from pathlib import Path
import json
import subprocess
import sys

from tools.validate_governance_reports import (
    collect_validation_errors,
    validate_file,
    validate_manifest,
    validate_manifest_schema,
    validate_readme_index,
)


VALID_DOC = """<title>
Sample Title For Validation
</title>
<abstract>
Short abstract text.
</abstract>
<content>
## Required Heading
Some content here.
</content>
"""


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class ValidateGovernanceReportsTests(unittest.TestCase):
    def test_validate_file_accepts_valid_document(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "doc.md"
            path.write_text(VALID_DOC, encoding="utf-8")
            errors = validate_file(path, ["## Required Heading"])
            self.assertEqual(errors, [])

    def test_validate_file_rejects_missing_tag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "doc.md"
            path.write_text("<title>Only title</title>", encoding="utf-8")
            errors = validate_file(path, [])
            self.assertTrue(any("missing tag <abstract>" in e for e in errors))
            self.assertTrue(any("missing tag <content>" in e for e in errors))

    def test_validate_file_rejects_missing_required_heading(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "doc.md"
            path.write_text(VALID_DOC, encoding="utf-8")
            errors = validate_file(path, ["## Heading Not Present"])
            self.assertTrue(any("missing required heading" in e for e in errors))

    def test_validate_file_rejects_duplicate_title_blocks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "doc.md"
            path.write_text(
                VALID_DOC + "\n<title>\nAnother title\n</title>\n",
                encoding="utf-8",
            )
            errors = validate_file(path, ["## Required Heading"])
            self.assertTrue(any("expected exactly one <title> block" in e for e in errors))

    def test_validate_file_rejects_duplicate_abstract_blocks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "doc.md"
            path.write_text(
                VALID_DOC + "\n<abstract>\nAnother abstract\n</abstract>\n",
                encoding="utf-8",
            )
            errors = validate_file(path, ["## Required Heading"])
            self.assertTrue(any("expected exactly one <abstract> block" in e for e in errors))

    def test_validate_file_rejects_duplicate_content_blocks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "doc.md"
            path.write_text(
                VALID_DOC + "\n<content>\n## Required Heading\nMore content\n</content>\n",
                encoding="utf-8",
            )
            errors = validate_file(path, ["## Required Heading"])
            self.assertTrue(any("expected exactly one <content> block" in e for e in errors))

    def test_validate_file_rejects_missing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing.md"
            errors = validate_file(missing, [])
            self.assertEqual(len(errors), 1)
            self.assertIn("missing file", errors[0])

    def test_validate_readme_index_accepts_valid_readme(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "README_GOVERNANCE_REPORTS.md"
            path.write_text(
                "\n".join(
                    [
                        "INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md",
                        "BOARD_BRIEF_AGI_ASI_GOVERNANCE_2026_2030.md",
                        "REGULATOR_EXAM_PACK_AI_GOVERNANCE_2026_2030.md",
                        "ENGINEERING_IMPLEMENTATION_PLAYBOOK_AI_GOVERNANCE_2026_2030.md",
                        "governance_reports_manifest.json",
                        "governance_reports_manifest.schema.json",
                        "python3 -m unittest discover tool_tests",
                        "python3 tools/validate_governance_reports.py",
                        "make governance-check",
                    ]
                ),
                encoding="utf-8",
            )
            reports = [
                "docs/reports/INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md",
                "docs/reports/BOARD_BRIEF_AGI_ASI_GOVERNANCE_2026_2030.md",
                "docs/reports/REGULATOR_EXAM_PACK_AI_GOVERNANCE_2026_2030.md",
                "docs/reports/ENGINEERING_IMPLEMENTATION_PLAYBOOK_AI_GOVERNANCE_2026_2030.md",
            ]
            errors = validate_readme_index(path, reports)
            self.assertEqual(errors, [])

    def test_validate_readme_index_rejects_missing_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "README_GOVERNANCE_REPORTS.md"
            path.write_text("placeholder", encoding="utf-8")
            reports = [
                "docs/reports/INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md",
            ]
            errors = validate_readme_index(path, reports)
            self.assertTrue(any("missing report reference" in e for e in errors))
            self.assertTrue(any("missing manifest reference" in e for e in errors))
            self.assertTrue(any("missing schema reference" in e for e in errors))
            self.assertTrue(any("missing unit test command" in e for e in errors))
            self.assertTrue(any("missing validator command" in e for e in errors))
            self.assertTrue(any("missing make command 'make governance-check'" in e for e in errors))

    def test_validate_manifest_accepts_valid_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "governance_reports_manifest.json"
            _write_json(
                path,
                {
                    "version": "2026.1",
                    "report_pack": "institutional_agi_asi_governance",
                    "reports": [
                        {
                            "path": "docs/reports/INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md",
                            "audience": "enterprise",
                            "required": True,
                        },
                        {
                            "path": "docs/reports/BOARD_BRIEF_AGI_ASI_GOVERNANCE_2026_2030.md",
                            "audience": "board",
                            "required": True,
                        },
                    ],
                },
            )
            report_paths = [
                "docs/reports/INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md",
                "docs/reports/BOARD_BRIEF_AGI_ASI_GOVERNANCE_2026_2030.md",
            ]
            errors = validate_manifest(path, report_paths)
            self.assertEqual(errors, [])

    def test_validate_manifest_rejects_missing_report_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "governance_reports_manifest.json"
            _write_json(
                path,
                {
                    "version": "2026.1",
                    "report_pack": "institutional_agi_asi_governance",
                    "reports": [
                        {
                            "path": "docs/reports/BOARD_BRIEF_AGI_ASI_GOVERNANCE_2026_2030.md",
                            "audience": "board",
                            "required": True,
                        }
                    ],
                },
            )
            report_paths = [
                "docs/reports/INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md",
                "docs/reports/BOARD_BRIEF_AGI_ASI_GOVERNANCE_2026_2030.md",
            ]
            errors = validate_manifest(path, report_paths)
            self.assertTrue(any("missing report entries" in e for e in errors))

    def test_validate_manifest_rejects_unexpected_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "governance_reports_manifest.json"
            _write_json(
                path,
                {
                    "version": "2026.1",
                    "report_pack": "institutional_agi_asi_governance",
                    "reports": [
                        {
                            "path": "docs/reports/INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md",
                            "audience": "enterprise",
                            "required": True,
                        },
                        {"path": "docs/reports/EXTRA.md", "audience": "misc", "required": False},
                    ],
                },
            )
            report_paths = [
                "docs/reports/INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md",
            ]
            errors = validate_manifest(path, report_paths)
            self.assertTrue(any("unexpected report entries" in e for e in errors))

    def test_validate_manifest_rejects_nonexistent_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "governance_reports_manifest.json"
            _write_json(
                path,
                {
                    "version": "2026.1",
                    "report_pack": "institutional_agi_asi_governance",
                    "reports": [
                        {
                            "path": "docs/reports/DOES_NOT_EXIST.md",
                            "audience": "enterprise",
                            "required": True,
                        }
                    ],
                },
            )
            report_paths = [
                "docs/reports/DOES_NOT_EXIST.md",
            ]
            errors = validate_manifest(path, report_paths)
            self.assertTrue(any("path does not exist" in e for e in errors))

    def test_validate_manifest_rejects_missing_metadata_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "governance_reports_manifest.json"
            _write_json(path, {"reports": []})
            errors = validate_manifest(path, [])
            self.assertTrue(any("'version' must be a non-empty string" in e for e in errors))
            self.assertTrue(any("'report_pack' must be a non-empty string" in e for e in errors))

    def test_validate_manifest_schema_accepts_valid_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "schema.json"
            path.write_text(
                """
{
  "required": ["version", "report_pack", "reports"],
  "properties": {
    "reports": {
      "items": {
        "required": ["path", "audience", "required"]
      }
    }
  }
}
""".strip(),
                encoding="utf-8",
            )
            errors = validate_manifest_schema(path)
            self.assertEqual(errors, [])

    def test_validate_manifest_schema_rejects_missing_required_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "schema.json"
            path.write_text(
                """
{
  "required": ["version"],
  "properties": {
    "reports": {
      "items": {
        "required": ["path"]
      }
    }
  }
}
""".strip(),
                encoding="utf-8",
            )
            errors = validate_manifest_schema(path)
            self.assertTrue(any("schema missing root required fields" in e for e in errors))
            self.assertTrue(any("schema missing report item required fields" in e for e in errors))

    def test_validate_manifest_uses_schema_required_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = Path(tmpdir) / "manifest.json"
            schema = Path(tmpdir) / "schema.json"

            _write_json(
                manifest,
                {
                    "version": "2026.1",
                    "report_pack": "pack",
                    "reports": [
                        {
                            "path": "docs/reports/INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md",
                            "audience": "enterprise",
                            "required": True,
                        }
                    ],
                },
            )
            _write_json(
                schema,
                {
                    "required": ["version", "report_pack", "reports", "owner"],
                    "properties": {
                        "reports": {
                            "items": {
                                "required": ["path", "audience", "required"]
                            }
                        }
                    },
                },
            )

            errors = validate_manifest(
                manifest,
                ["docs/reports/INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md"],
                schema,
            )
            self.assertTrue(any("missing required manifest field 'owner'" in e for e in errors))

    def test_collect_validation_errors_returns_tuple(self):
        errors, report_count = collect_validation_errors()
        self.assertIsInstance(errors, list)
        self.assertIsInstance(report_count, int)

    def test_validator_json_output_mode(self):
        result = subprocess.run(
            [sys.executable, "tools/validate_governance_reports.py", "--json"],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(result.stdout.strip())
        self.assertEqual(payload["status"], "passed")
        self.assertIn("validated_report_files", payload)


if __name__ == "__main__":
    unittest.main()
