#!/usr/bin/env python3
"""Tests for the governance artifact manifest generator."""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, cast
from unittest import mock

MODULE_PATH = Path(__file__).with_name("generate_artifact_manifest.py")
SPEC = importlib.util.spec_from_file_location("generate_artifact_manifest", MODULE_PATH)
assert SPEC and SPEC.loader
gm = cast(Any, importlib.util.module_from_spec(SPEC))
SPEC.loader.exec_module(gm)


class GenerateArtifactManifestTests(unittest.TestCase):
    """Exercise manifest generation and validation against temporary artifacts."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.artifacts = self.root / "governance_blueprint"
        self.validation = self.artifacts / "validation"
        self.validation.mkdir(parents=True)
        (self.artifacts / "control_mapping_matrix.csv").write_text(
            "id\n", encoding="utf-8"
        )
        (self.validation / "selftest_fixture.py").write_text(
            "print('fixture')\n", encoding="utf-8"
        )
        (self.root / "REPORT.md").write_text("report\n", encoding="utf-8")

        self.original = {
            "ROOT": gm.ROOT,
            "ARTIFACTS": gm.ARTIFACTS,
            "MANIFEST_PATH": gm.MANIFEST_PATH,
            "BASE_DEFAULT_FILES": gm.BASE_DEFAULT_FILES,
            "EXTERNAL_FILES": gm.EXTERNAL_FILES,
        }
        gm.ROOT = self.root
        gm.ARTIFACTS = self.artifacts
        gm.MANIFEST_PATH = self.artifacts / "artifact_manifest.json"
        gm.BASE_DEFAULT_FILES = [
            "control_mapping_matrix.csv",
            "control_mapping_matrix.csv",
        ]
        gm.EXTERNAL_FILES = ["REPORT.md"]

    def tearDown(self) -> None:
        for name, value in self.original.items():
            setattr(gm, name, value)
        self.tmp.cleanup()

    def test_build_manifest_hashes_current_files_and_deduplicates_paths(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=False)
        self.assertEqual(manifest["package"], "enterprise_agi_asi_governance_blueprint")
        self.assertEqual(manifest["version"], "1.4.5")
        self.assertIn("control_mapping_matrix.csv", manifest["artifacts"])
        self.assertIn("validation/selftest_fixture.py", manifest["artifacts"])
        self.assertIn("REPORT.md", manifest["external_artifacts"])
        self.assertEqual(len(manifest["artifacts"]), len(set(manifest["artifacts"])))

    def test_safe_join_rejects_path_traversal(self) -> None:
        with self.assertRaises(ValueError):
            gm._safe_join(self.artifacts, "../outside.txt")

    def test_check_passes_for_matching_manifest(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=False)
        gm.MANIFEST_PATH.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        with mock.patch("sys.argv", ["generate_artifact_manifest.py", "--check"]):
            with redirect_stdout(io.StringIO()):
                result = gm.main()
        self.assertEqual(result, 0)

    def test_check_fails_when_payload_is_modified(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=False)
        manifest["version"] = "0.0.0"
        gm.MANIFEST_PATH.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        with mock.patch("sys.argv", ["generate_artifact_manifest.py", "--check"]):
            with redirect_stdout(io.StringIO()):
                result = gm.main()
        self.assertEqual(result, 1)

    def test_stamp_now_refreshes_timestamp(self) -> None:
        old_timestamp = "2000-01-01T00:00:00Z"
        gm.MANIFEST_PATH.write_text(
            json.dumps(
                {
                    "package": "enterprise_agi_asi_governance_blueprint",
                    "version": "1.4.5",
                    "generated_utc": old_timestamp,
                }
            ),
            encoding="utf-8",
        )
        with mock.patch("sys.argv", ["generate_artifact_manifest.py", "--stamp-now"]):
            with redirect_stdout(io.StringIO()):
                result = gm.main()
        self.assertEqual(result, 0)
        generated = json.loads(gm.MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertNotEqual(generated["generated_utc"], old_timestamp)
        self.assertRegex(
            generated["generated_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
        )


if __name__ == "__main__":
    unittest.main()
