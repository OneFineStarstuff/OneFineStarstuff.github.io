#!/usr/bin/env python3
"""Unit tests for generate_artifact_manifest.py."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

MODULE_PATH = Path(__file__).with_name("generate_artifact_manifest.py")
SPEC = importlib.util.spec_from_file_location("generate_artifact_manifest", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise ImportError(f"Cannot load manifest generator from {MODULE_PATH}")

gm: Any = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gm)

DUMMY_CONTENT = "fixture\n"
DUMMY_HASH = hashlib.sha256(DUMMY_CONTENT.encode("utf-8")).hexdigest()
PACKAGE_NAME = "enterprise_agi_asi_governance_blueprint"
MANIFEST_VERSION = "1.4.5"


class GenerateArtifactManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_root = Path(self.temp_dir.name)
        self.artifacts = self.temp_root / "governance_blueprint"
        validation_dir = self.artifacts / "validation"
        validation_dir.mkdir(parents=True, exist_ok=True)

        (self.artifacts / "control_mapping_matrix.csv").write_text(
            "header\n", encoding="utf-8"
        )
        (self.artifacts / "validation" / "selftest_fixture.py").write_text(
            "print('fixture')\n", encoding="utf-8"
        )
        (self.temp_root / "REPORT.md").write_text("report\n", encoding="utf-8")

        self.originals = {
            "ROOT": gm.ROOT,
            "ARTIFACTS": gm.ARTIFACTS,
            "MANIFEST_PATH": gm.MANIFEST_PATH,
            "BASE_DEFAULT_FILES": gm.BASE_DEFAULT_FILES,
            "EXTERNAL_FILES": gm.EXTERNAL_FILES,
        }
        gm.ROOT = self.temp_root
        gm.ARTIFACTS = self.artifacts
        gm.MANIFEST_PATH = self.artifacts / "artifact_manifest.json"
        gm.BASE_DEFAULT_FILES = ["control_mapping_matrix.csv"]
        gm.EXTERNAL_FILES = ["REPORT.md"]

    def tearDown(self) -> None:
        for name, value in self.originals.items():
            setattr(gm, name, value)
        self.temp_dir.cleanup()

    def _write_manifest(self, payload: dict | None = None) -> dict:
        manifest = payload if payload is not None else gm.build_manifest(preserve_timestamp=False)
        gm.MANIFEST_PATH.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        return manifest

    def _run_main(self, *args: str) -> int:
        command = ["generate_artifact_manifest.py", *args]
        with mock.patch.object(sys, "argv", command):
            with redirect_stdout(io.StringIO()):
                return gm.main()

    def test_build_manifest_has_correct_metadata_and_hashes(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=False)
        self.assertEqual(manifest["package"], PACKAGE_NAME)
        self.assertEqual(manifest["version"], MANIFEST_VERSION)
        self.assertEqual(
            manifest["artifacts"]["control_mapping_matrix.csv"],
            hashlib.sha256(b"header\n").hexdigest(),
        )
        self.assertEqual(
            manifest["external_artifacts"]["REPORT.md"],
            hashlib.sha256(b"report\n").hexdigest(),
        )
        self.assertIn("validation/selftest_fixture.py", manifest["artifacts"])

    def test_default_files_are_deduplicated(self) -> None:
        gm.BASE_DEFAULT_FILES = [
            "control_mapping_matrix.csv",
            "control_mapping_matrix.csv",
            "validation/selftest_fixture.py",
        ]
        files = gm._default_files()
        self.assertEqual(len(files), len(set(files)))

    def test_default_files_use_tracked_selftests_when_git_succeeds(self) -> None:
        class GitResult:
            returncode = 0
            stdout = (
                "governance_blueprint/validation/selftest_example.py\n"
                "../outside.py\n"
            )

        with mock.patch.object(gm.subprocess, "run", return_value=GitResult()):
            files = gm._default_files()
        self.assertIn("validation/selftest_example.py", files)
        self.assertFalse(any(".." in Path(path).parts for path in files))

    def test_default_files_fall_back_to_filesystem_when_git_fails(self) -> None:
        with mock.patch.object(
            gm.subprocess,
            "run",
            side_effect=gm.subprocess.TimeoutExpired(cmd="git", timeout=10),
        ):
            files = gm._default_files()
        self.assertIn("validation/selftest_fixture.py", files)

    def test_safe_join_rejects_path_traversal(self) -> None:
        with self.assertRaises(ValueError):
            gm._safe_join(self.artifacts, "../outside.txt")

    def test_check_passes_for_matching_manifest(self) -> None:
        self._write_manifest()
        self.assertEqual(self._run_main("--check"), 0)

    def test_check_fails_for_version_mismatch(self) -> None:
        manifest = self._write_manifest()
        manifest["version"] = "0.0.0"
        self._write_manifest(manifest)
        self.assertEqual(self._run_main("--check"), 1)

    def test_check_fails_for_artifact_hash_mismatch(self) -> None:
        manifest = self._write_manifest()
        manifest["artifacts"]["control_mapping_matrix.csv"] = "0" * 64
        self._write_manifest(manifest)
        self.assertEqual(self._run_main("--check"), 1)

    def test_check_fails_for_invalid_timestamp_shape(self) -> None:
        manifest = self._write_manifest()
        manifest["generated_utc"] = "2026/01/01 00:00:00"
        self._write_manifest(manifest)
        self.assertEqual(self._run_main("--check"), 1)

    def test_stamp_now_refreshes_the_generated_timestamp(self) -> None:
        manifest = self._write_manifest()
        manifest["generated_utc"] = "2000-01-01T00:00:00Z"
        self._write_manifest(manifest)
        self.assertEqual(self._run_main("--stamp-now"), 0)
        generated = json.loads(gm.MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertNotEqual(generated["generated_utc"], "2000-01-01T00:00:00Z")
        self.assertRegex(
            generated["generated_utc"],
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
        )


if __name__ == "__main__":
    unittest.main()
