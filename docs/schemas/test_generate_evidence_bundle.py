import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "generate_evidence_bundle.py"


class EvidenceBundleTests(unittest.TestCase):
    def run_generator(self, output_path: Path, include_timestamp: bool = False):
        cmd = [sys.executable, str(SCRIPT), "--repo-root", str(ROOT.parent.parent), "--output", str(output_path)]
        if include_timestamp:
            cmd.append("--include-timestamp")
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def test_manifest_generation_deterministic_default(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "manifest.json"
            result = self.run_generator(out)
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(out.exists())

            with out.open("r", encoding="utf-8") as f:
                manifest = json.load(f)

            self.assertNotIn("generated_at_utc", manifest)
            self.assertEqual(manifest["bundle_version"], "1.0.0")
            self.assertGreaterEqual(len(manifest["artifacts"]), 7)
            self.assertTrue(all("sha256" in a for a in manifest["artifacts"]))

    def test_manifest_generation_with_timestamp(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "manifest.json"
            result = self.run_generator(out, include_timestamp=True)
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            with out.open("r", encoding="utf-8") as f:
                manifest = json.load(f)
            self.assertIn("generated_at_utc", manifest)


if __name__ == "__main__":
    unittest.main()
