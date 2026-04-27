import json
import subprocess
import sys
import tempfile
import unittest
from importlib.util import find_spec
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GEN = ROOT / "generate_evidence_bundle.py"
VALIDATE = ROOT / "validate_evidence_manifest.py"
SCHEMA = ROOT / "evidence_bundle_manifest.schema.json"
HAS_JSONSCHEMA = find_spec("jsonschema") is not None


@unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is required for evidence manifest validation tests")
class ValidateEvidenceManifestTests(unittest.TestCase):
    def test_validate_manifest_success(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.json"
            gen = subprocess.run(
                [sys.executable, str(GEN), "--repo-root", str(ROOT.parent.parent), "--output", str(manifest)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(gen.returncode, 0)

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--manifest",
                    str(manifest),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(val.returncode, 0, msg=val.stdout + val.stderr)

    def test_validate_manifest_failure(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "bad_manifest.json"
            with manifest.open("w", encoding="utf-8") as f:
                json.dump({"bundle_version": "1.0.0", "artifacts": [{"path": "x"}]}, f)

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--manifest",
                    str(manifest),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(val.returncode, 0)
            self.assertIn("[FAIL]", val.stdout)

    def test_validate_manifest_missing_file_failure(self):
        val = subprocess.run(
            [
                sys.executable,
                str(VALIDATE),
                "--repo-root",
                str(ROOT.parent.parent),
                "--manifest",
                "docs/schemas/does_not_exist.json",
                "--schema",
                str(SCHEMA),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(val.returncode, 0)
        self.assertIn("Manifest file not found", val.stdout)

    def test_validate_manifest_invalid_json_failure(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "invalid_manifest.json"
            manifest.write_text("{not-json", encoding="utf-8")

            val = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATE),
                    "--repo-root",
                    str(ROOT.parent.parent),
                    "--manifest",
                    str(manifest),
                    "--schema",
                    str(SCHEMA),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(val.returncode, 0)
            self.assertIn("Invalid JSON in manifest file", val.stdout)


if __name__ == "__main__":
    unittest.main()
