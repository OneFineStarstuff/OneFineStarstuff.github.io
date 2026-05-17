import subprocess
import sys
import unittest
from importlib.util import find_spec
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "governance_artifacts_validation.py"
YAML_PATH = ROOT / "agi_asi_governance_profile_2026_2030.yaml"
JSON_PATH = ROOT / "compliance_control_mapping.json"
YAML_SCHEMA_PATH = ROOT / "agi_asi_governance_profile.schema.json"
JSON_SCHEMA_PATH = ROOT / "compliance_control_mapping.schema.json"

TESTDATA = ROOT / "testdata"
INVALID_PROFILE = TESTDATA / "invalid_profile_missing_framework.yaml"
INVALID_CONTROL = TESTDATA / "invalid_control_bad_domain.json"
HAS_JSONSCHEMA = find_spec("jsonschema") is not None


@unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is required for governance validator integration tests")
class GovernanceValidatorCLITests(unittest.TestCase):
    def run_validator(self, yaml_path: Path, json_path: Path):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--yaml",
                str(yaml_path),
                "--json",
                str(json_path),
                "--yaml-schema",
                str(YAML_SCHEMA_PATH),
                "--json-schema",
                str(JSON_SCHEMA_PATH),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_validator_help(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Path to governance profile YAML", result.stdout)

    def test_validator_default_paths_pass(self):
        result = self.run_validator(YAML_PATH, JSON_PATH)
        self.assertEqual(result.returncode, 0)
        self.assertIn("[OK] Governance YAML/JSON artifacts validated", result.stdout)

    def test_validator_fails_on_missing_framework_key(self):
        result = self.run_validator(INVALID_PROFILE, JSON_PATH)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("framework_crosswalk missing keys", result.stdout)

    def test_validator_fails_on_control_domain_mismatch(self):
        result = self.run_validator(YAML_PATH, INVALID_CONTROL)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not present in canonical_domains", result.stdout)


if __name__ == "__main__":
    unittest.main()
