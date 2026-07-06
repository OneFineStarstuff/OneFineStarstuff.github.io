import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from importlib.util import find_spec
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
VALIDATE = ROOT / "validate_daily_devsecops_evidence.py"
SCHEMA = ROOT / "daily_devsecops_evidence.schema.json"
EXAMPLE = ROOT / "examples" / "daily_devsecops_evidence_2026-05-29.json"
HAS_JSONSCHEMA = find_spec("jsonschema") is not None
HASH = "sha256:" + hashlib.sha256(b"test-evidence").hexdigest()


@unittest.skipUnless(HAS_JSONSCHEMA, "jsonschema is required for daily evidence validation tests")
class DailyDevSecOpsEvidenceValidationTests(unittest.TestCase):
    def run_validator(self, bundle: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATE),
                "--repo-root",
                str(REPO),
                "--bundle",
                str(bundle),
                "--schema",
                str(SCHEMA),
                *extra,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def load_example(self) -> dict:
        with EXAMPLE.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def write_bundle(self, data: dict, directory: str) -> Path:
        path = Path(directory) / "bundle.json"
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    def make_passing_bundle(self) -> dict:
        data = self.load_example()
        data["certification_status"] = "passed"
        data["deviations"] = []
        for control in data["controls"].values():
            control["status"] = "pass"
            control["evidence_uris"] = ["s3://omni-sentinel-evidence/test.json"]
            control["evidence_hashes"] = [HASH]
        for endpoint in data["controls"]["internal_endpoints"]["endpoint_results"]:
            endpoint["status"] = "pass"
            endpoint["signature_verified"] = True
            endpoint["latency_ms"] = 25
        data["controls"]["g_sri"].update({"max": 0.41, "p95": 0.35, "black_swan_override": False})
        data["controls"]["worm_audit"].update(
            {
                "expected_batches": 96,
                "committed_batches": 96,
                "object_lock_enabled": True,
                "object_lock_mode": "COMPLIANCE",
                "retention_until": "2033-05-29T23:59:59Z",
                "cloudtrail_event_ids": ["evt-001"],
                "merkle_root": HASH,
            }
        )
        data["controls"]["tee_attestation"].update({"measurement_match": True, "quote_freshness_seconds": 300})
        data["controls"]["tpm_attestation"].update({"pcr_match": True, "quote_freshness_seconds": 300})
        data["controls"]["zk_compliance"].update({"verifier_decision": "ACCEPTED"})
        for sign_off in data["sign_off"]:
            sign_off["decision"] = "approved"
            sign_off["signature_hash"] = HASH
        return data

    def test_example_validates_only_when_evidence_required_is_allowed(self):
        result = self.run_validator(EXAMPLE, "--allow-evidence-required")
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertIn("[OK]", result.stdout)

    def test_example_fails_without_evidence_override(self):
        result = self.run_validator(EXAMPLE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("still requires evidence", result.stdout)

    def test_passing_bundle_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_bundle(self.make_passing_bundle(), directory)
            result = self.run_validator(path)
            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_passing_bundle_allows_closed_deviation_history(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.make_passing_bundle()
            data["deviations"] = [
                {
                    "id": "DEV-CLOSED-001",
                    "severity": "medium",
                    "owner": "Platform SRE",
                    "due": "closed",
                    "status": "closed",
                    "remediation": "Evidence gap remediated and verified.",
                }
            ]
            path = self.write_bundle(data, directory)
            result = self.run_validator(path)
            self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_passing_bundle_fails_when_deviation_remains_open(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.make_passing_bundle()
            data["deviations"] = [
                {
                    "id": "DEV-OPEN-001",
                    "severity": "high",
                    "owner": "Platform SRE",
                    "due": "same business day",
                    "status": "open",
                    "remediation": "Attach signed production evidence.",
                }
            ]
            path = self.write_bundle(data, directory)
            result = self.run_validator(path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Passed certification cannot include open deviations", result.stdout)

    def test_passing_bundle_fails_when_g_sri_reaches_halt_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.make_passing_bundle()
            data["controls"]["g_sri"]["max"] = data["controls"]["g_sri"]["thresholds"]["halt_min"]
            path = self.write_bundle(data, directory)
            result = self.run_validator(path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("below halt threshold", result.stdout)

    def test_passing_bundle_fails_when_tpm_pcr_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.make_passing_bundle()
            data["controls"]["tpm_attestation"]["pcr_match"] = False
            path = self.write_bundle(data, directory)
            result = self.run_validator(path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TPM pass requires pcr_match=true", result.stdout)

    def test_passing_bundle_fails_when_worm_batch_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.make_passing_bundle()
            data["controls"]["worm_audit"]["committed_batches"] = 95
            path = self.write_bundle(data, directory)
            result = self.run_validator(path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expected_batches == committed_batches", result.stdout)

    def test_schema_failure_for_missing_required_control(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.make_passing_bundle()
            del data["controls"]["g_sri"]
            path = self.write_bundle(data, directory)
            result = self.run_validator(path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Schema validation failed", result.stdout)


if __name__ == "__main__":
    unittest.main()
