#!/usr/bin/env python3
"""Tests for the governance artifact manifest generator."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, cast
from unittest import mock

MODULE_PATH = Path(__file__).with_name("generate_artifact_manifest.py")
MODULE_SPEC = importlib.util.spec_from_file_location(
    "generate_artifact_manifest", MODULE_PATH
)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise ImportError(f"Unable to load manifest generator from {MODULE_PATH}")

gm = cast(Any, importlib.util.module_from_spec(MODULE_SPEC))
MODULE_SPEC.loader.exec_module(gm)


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

        validation_dir = self.artifacts / "validation"
        validation_dir.mkdir(parents=True, exist_ok=True)
        (validation_dir / "selftest_tmp.py").write_text(
            "print('ok')\n", encoding="utf-8"
        )
        (self.artifacts / "control_mapping_matrix.csv").write_text(
            "h\n", encoding="utf-8"
        )
        (self.tmp_root / "REPORT.md").write_text("report\n", encoding="utf-8")

    def tearDown(self) -> None:
        gm.ROOT = self.original_root
        gm.ARTIFACTS = self.original_artifacts
        gm.MANIFEST_PATH = self.original_manifest
        gm.BASE_DEFAULT_FILES = self.original_base_defaults
        gm.EXTERNAL_FILES = self.original_external
        self.tmp.cleanup()

    def test_safe_join_rejects_path_traversal(self) -> None:
        with self.assertRaises(ValueError):
            gm._safe_join(self.artifacts, "../outside.txt")

    def test_build_manifest_hashes_current_and_external_files(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=False)

        self.assertEqual(
            manifest["package"], "enterprise_agi_asi_governance_blueprint"
        )
        self.assertIn("control_mapping_matrix.csv", manifest["artifacts"])
        self.assertIn("validation/selftest_tmp.py", manifest["artifacts"])
        self.assertIn("REPORT.md", manifest["external_artifacts"])

    def test_default_files_are_deduplicated(self) -> None:
        gm.BASE_DEFAULT_FILES = [
            "control_mapping_matrix.csv",
            "validation/selftest_tmp.py",
        ]

        files = gm._default_files()

        self.assertEqual(len(files), len(set(files)))

    def test_default_files_prefers_git_tracked_selftests_when_available(self) -> None:
        class MockGitResult:
            returncode = 0
            stdout = (
                "governance_blueprint/validation/"
                "selftest_run_validation_suite.py\n"
                "../bad.py\n"
            )

        with mock.patch.object(
            gm.subprocess, "run", return_value=MockGitResult()
        ):
            files = gm._default_files()

        self.assertIn("validation/selftest_run_validation_suite.py", files)
        self.assertFalse(any(".." in Path(item).parts for item in files))

    def test_default_files_falls_back_when_git_invocation_fails(self) -> None:
        timeout = gm.subprocess.TimeoutExpired(cmd="git", timeout=10)
        with mock.patch.object(gm.subprocess, "run", side_effect=timeout):
            files = gm._default_files()

        self.assertIn("validation/selftest_tmp.py", files)

    def test_check_fails_when_manifest_payload_differs(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=True)
        manifest["version"] = "0.0.1"
        gm.MANIFEST_PATH.write_text(json.dumps(manifest), encoding="utf-8")

        with mock.patch("sys.argv", ["generate_artifact_manifest.py", "--check"]):
            with redirect_stdout(mock.MagicMock()):
                result = gm.main()

        self.assertEqual(result, 1)

    def test_check_fails_on_invalid_generated_timestamp_shape(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=True)
        manifest["generated_utc"] = "2026/01/01 00:00:00"
        gm.MANIFEST_PATH.write_text(
            json.dumps(manifest), encoding="utf-8"
        )

        with mock.patch(
            "sys.argv", ["generate_artifact_manifest.py", "--check"]
        ):
            with redirect_stdout(mock.MagicMock()):
                result = gm.main()

        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
