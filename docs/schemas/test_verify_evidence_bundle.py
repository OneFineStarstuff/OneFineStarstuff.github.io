import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GEN = ROOT / "generate_evidence_bundle.py"
VERIFY = ROOT / "verify_evidence_bundle.py"


class VerifyEvidenceBundleTests(unittest.TestCase):
    def test_verify_manifest_success(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.json"
            gen = subprocess.run(
                [sys.executable, str(GEN), "--repo-root", str(ROOT.parent.parent), "--output", str(manifest)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(gen.returncode, 0, msg=gen.stderr)

            verify = subprocess.run(
                [sys.executable, str(VERIFY), "--repo-root", str(ROOT.parent.parent), "--manifest", str(manifest)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, msg=verify.stdout + verify.stderr)
            self.assertIn("[OK] Evidence bundle manifest verified", verify.stdout)

    def test_verify_manifest_detects_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = Path(td) / "manifest.json"
            gen = subprocess.run(
                [sys.executable, str(GEN), "--repo-root", str(ROOT.parent.parent), "--output", str(manifest)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(gen.returncode, 0, msg=gen.stderr)

            with manifest.open("r", encoding="utf-8") as f:
                data = json.load(f)
            data["artifacts"][0]["sha256"] = "0" * 64
            with manifest.open("w", encoding="utf-8") as f:
                json.dump(data, f)

            verify = subprocess.run(
                [sys.executable, str(VERIFY), "--repo-root", str(ROOT.parent.parent), "--manifest", str(manifest)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(verify.returncode, 0)
            self.assertIn("Hash mismatch", verify.stdout)


if __name__ == "__main__":
    unittest.main()
