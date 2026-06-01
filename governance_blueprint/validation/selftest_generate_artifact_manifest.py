#!/usr/bin/env python3
"""Unit tests for generate_artifact_manifest.py behavior."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
import io
from pathlib import Path
from unittest.mock import patch

DUMMY_CONTENT = "x"
DUMMY_HASH = hashlib.sha256(DUMMY_CONTENT.encode("utf-8")).hexdigest()

MODULE_PATH = Path(__file__).with_name("generate_artifact_manifest.py")
spec = importlib.util.spec_from_file_location("generate_artifact_manifest", MODULE_PATH)
gm = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(gm)


class GenerateManifestTests(unittest.TestCase):
    def _run_check_with_manifest(self, manifest_payload: dict) -> int:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            artifacts_dir = tmp_path / "governance_blueprint"
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            dummy = artifacts_dir / "dummy.txt"
            dummy.write_text(DUMMY_CONTENT, encoding="utf-8")
            manifest_path = tmp_path / "artifact_manifest.json"
            manifest_path.write_text(json.dumps(manifest_payload), encoding="utf-8")

            old_artifacts = gm.ARTIFACTS
            old_manifest_path = gm.MANIFEST_PATH
            old_default_files = gm.DEFAULT_FILES
            gm.MANIFEST_PATH = manifest_path
            gm.ARTIFACTS = artifacts_dir
            gm.DEFAULT_FILES = ["dummy.txt"]
            try:
                with patch.object(sys, "argv", ["generate_artifact_manifest.py", "--check"]):
                    with redirect_stdout(io.StringIO()):
                        return gm.main()
            finally:
                gm.ARTIFACTS = old_artifacts
                gm.MANIFEST_PATH = old_manifest_path
                gm.DEFAULT_FILES = old_default_files

    def test_build_manifest_has_expected_metadata(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=True)
        self.assertEqual(manifest["package"], "enterprise_agi_asi_governance_blueprint")
        self.assertEqual(manifest["version"], "1.4.0")
        self.assertIn("artifacts", manifest)

    def test_check_fails_on_version_mismatch(self) -> None:
        rc = self._run_check_with_manifest(
            {
                "package": "enterprise_agi_asi_governance_blueprint",
                "version": "0.0.0",
                "generated_utc": "2026-01-01T00:00:00Z",
                "artifacts": {"dummy.txt": DUMMY_HASH},
            }
        )
        self.assertEqual(rc, 1)

    def test_check_fails_on_package_mismatch(self) -> None:
        rc = self._run_check_with_manifest(
            {
                "package": "wrong_package_name",
                "version": "1.4.0",
                "generated_utc": "2026-01-01T00:00:00Z",
                "artifacts": {"dummy.txt": DUMMY_HASH},
            }
        )
        self.assertEqual(rc, 1)

    def test_check_passes_with_matching_metadata(self) -> None:
        rc = self._run_check_with_manifest(
            {
                "package": "enterprise_agi_asi_governance_blueprint",
                "version": "1.4.0",
                "generated_utc": "2026-01-01T00:00:00Z",
                "artifacts": {"dummy.txt": DUMMY_HASH},
            }
        )
        self.assertEqual(rc, 0)

    def test_stamp_now_writes_fresh_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            artifacts_dir = tmp_path / "governance_blueprint"
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            (artifacts_dir / "dummy.txt").write_text(DUMMY_CONTENT, encoding="utf-8")
            manifest_path = artifacts_dir / "artifact_manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "package": "enterprise_agi_asi_governance_blueprint",
                        "version": "1.4.0",
                        "generated_utc": "2000-01-01T00:00:00Z",
                        "artifacts": {},
                    }
                ),
                encoding="utf-8",
            )

            old_artifacts = gm.ARTIFACTS
            old_manifest_path = gm.MANIFEST_PATH
            old_default_files = gm.DEFAULT_FILES
            gm.ARTIFACTS = artifacts_dir
            gm.MANIFEST_PATH = manifest_path
            gm.DEFAULT_FILES = ["dummy.txt"]
            try:
                with patch.object(sys, "argv", ["generate_artifact_manifest.py", "--stamp-now"]):
                    with redirect_stdout(io.StringIO()):
                        rc = gm.main()
                self.assertEqual(rc, 0)
                generated = json.loads(manifest_path.read_text(encoding="utf-8"))
                self.assertNotEqual(generated["generated_utc"], "2000-01-01T00:00:00Z")
                self.assertRegex(generated["generated_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
            finally:
                gm.ARTIFACTS = old_artifacts
                gm.MANIFEST_PATH = old_manifest_path
                gm.DEFAULT_FILES = old_default_files


if __name__ == "__main__":
    unittest.main()
