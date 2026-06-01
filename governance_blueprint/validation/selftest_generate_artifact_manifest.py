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
"""Unit tests for generate_artifact_manifest.py."""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock
from pathlib import Path

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
class GenerateArtifactManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self.tmp.name)
        self.artifacts = self.tmp_root / "governance_blueprint"
        self.artifacts.mkdir(parents=True, exist_ok=True)

        self.original_root = gm.ROOT
        self.original_artifacts = gm.ARTIFACTS
        self.original_manifest = gm.MANIFEST_PATH
        self.original_base_defaults = gm.BASE_DEFAULT_FILES
        self.original_external = gm.EXTERNAL_FILES

        gm.ROOT = self.tmp_root
        gm.ARTIFACTS = self.artifacts
        gm.MANIFEST_PATH = self.artifacts / "artifact_manifest.json"
        gm.BASE_DEFAULT_FILES = ["control_mapping_matrix.csv"]
        gm.EXTERNAL_FILES = ["REPORT.md"]
        (self.artifacts / "validation").mkdir(parents=True, exist_ok=True)
        (self.artifacts / "validation" / "selftest_tmp.py").write_text("print('ok')\n", encoding="utf-8")

        (self.artifacts / "control_mapping_matrix.csv").write_text("h\n", encoding="utf-8")
        (self.tmp_root / "REPORT.md").write_text("report\n", encoding="utf-8")

    def tearDown(self) -> None:
        gm.ROOT = self.original_root
        gm.ARTIFACTS = self.original_artifacts
        gm.MANIFEST_PATH = self.original_manifest
        gm.BASE_DEFAULT_FILES = self.original_base_defaults
        gm.EXTERNAL_FILES = self.original_external
        self.tmp.cleanup()

    def test_safe_join_rejects_traversal(self) -> None:
        with self.assertRaises(ValueError):
            gm._safe_join(self.artifacts, "../oops.txt")

    def test_build_manifest_hashes_current_files(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=False)
        self.assertEqual(manifest["package"], "enterprise_agi_asi_governance_blueprint")
        self.assertIn("control_mapping_matrix.csv", manifest["artifacts"])
        self.assertIn("validation/selftest_tmp.py", manifest["artifacts"])
        self.assertIn("REPORT.md", manifest["external_artifacts"])

    def test_default_files_are_deduplicated(self) -> None:
        gm.BASE_DEFAULT_FILES = ["control_mapping_matrix.csv", "validation/selftest_tmp.py"]
        files = gm._default_files()
        self.assertEqual(len(files), len(set(files)))

    def test_default_files_prefers_git_tracked_selftests_when_available(self) -> None:
        class _R:
            returncode = 0
            stdout = (
                "governance_blueprint/validation/selftest_run_validation_suite.py\n"
                "../bad.py\n"
            )

        with mock.patch.object(gm.subprocess, "run", return_value=_R()):
            files = gm._default_files()
        self.assertIn("validation/selftest_run_validation_suite.py", files)
        self.assertFalse(any(".." in f for f in files))

    def test_default_files_falls_back_when_git_invocation_fails(self) -> None:
        with mock.patch.object(gm.subprocess, "run", side_effect=gm.subprocess.TimeoutExpired(cmd="git", timeout=10)):
            files = gm._default_files()
        self.assertIn("validation/selftest_tmp.py", files)

    def test_check_fails_when_manifest_payload_differs(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=True)
        manifest["version"] = "0.0.1"
        gm.MANIFEST_PATH.write_text(json.dumps(manifest), encoding="utf-8")

        with mock.patch("sys.argv", ["generate_artifact_manifest.py", "--check"]):
            with redirect_stdout(io.StringIO()):
                rc = gm.main()
        self.assertEqual(rc, 1)

    def test_check_fails_on_invalid_generated_timestamp_shape(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=True)
        manifest["generated_utc"] = "2026/01/01 00:00:00"
        gm.MANIFEST_PATH.write_text(json.dumps(manifest), encoding="utf-8")

        with mock.patch("sys.argv", ["generate_artifact_manifest.py", "--check"]):
            with redirect_stdout(io.StringIO()):
                rc = gm.main()
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
