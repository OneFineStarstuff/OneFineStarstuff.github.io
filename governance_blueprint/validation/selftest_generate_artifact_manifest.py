"""Unit tests for generate_artifact_manifest.py."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

MODULE_PATH = Path(__file__).with_name("generate_artifact_manifest.py")
SPEC = importlib.util.spec_from_file_location("generate_artifact_manifest", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gm: Any = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gm)


class GenerateArtifactManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_root = Path(self.tmp.name)
        self.artifacts = self.tmp_root / "governance_blueprint"
        self.validation = self.artifacts / "validation"
        self.validation.mkdir(parents=True, exist_ok=True)
        self.original_root = gm.ROOT
        self.original_artifacts = gm.ARTIFACTS
        self.original_manifest = gm.MANIFEST_PATH
        self.original_defaults = gm.BASE_DEFAULT_FILES
        self.original_external = gm.EXTERNAL_FILES

        gm.ROOT = self.tmp_root
        gm.ARTIFACTS = self.artifacts
        gm.MANIFEST_PATH = self.artifacts / "artifact_manifest.json"
        gm.BASE_DEFAULT_FILES = ["control_mapping_matrix.csv"]
        gm.EXTERNAL_FILES = ["REPORT.md"]

        (self.artifacts / "control_mapping_matrix.csv").write_text(
            "headers\n", encoding="utf-8"
        )
        (self.validation / "selftest_example.py").write_text(
            "print('ok')\n", encoding="utf-8"
        )
        (self.tmp_root / "REPORT.md").write_text("synthetic report\n", encoding="utf-8")

    def tearDown(self) -> None:
        gm.ROOT = self.original_root
        gm.ARTIFACTS = self.original_artifacts
        gm.MANIFEST_PATH = self.original_manifest
        gm.BASE_DEFAULT_FILES = self.original_defaults
        gm.EXTERNAL_FILES = self.original_external
        self.tmp.cleanup()

    def _run_main(self, *args: str) -> int:
        with (
            mock.patch("sys.argv", ["generate_artifact_manifest.py", *args]),
            redirect_stdout(io.StringIO()),
        ):
            return gm.main()

    def test_safe_join_rejects_parent_traversal(self) -> None:
        with self.assertRaises(ValueError):
            gm._safe_join(self.artifacts, "../outside.txt")

    def test_build_manifest_hashes_artifacts_and_external_files(self) -> None:
        manifest = gm.build_manifest(preserve_timestamp=False)
        expected_artifact_hash = hashlib.sha256(
            (self.artifacts / "control_mapping_matrix.csv").read_bytes()
        ).hexdigest()
        expected_external_hash = hashlib.sha256(
            (self.tmp_root / "REPORT.md").read_bytes()
        ).hexdigest()

        self.assertEqual(manifest["package"], gm.PACKAGE)
        self.assertEqual(manifest["version"], "1.4.5")
        self.assertEqual(
            manifest["artifacts"]["control_mapping_matrix.csv"], expected_artifact_hash
        )
        self.assertEqual(
            manifest["artifacts"]["validation/selftest_example.py"],
            hashlib.sha256(
                (self.validation / "selftest_example.py").read_bytes()
            ).hexdigest(),
        )
        self.assertEqual(
            manifest["external_artifacts"]["REPORT.md"], expected_external_hash
        )

    def test_default_files_are_deduplicated(self) -> None:
        gm.BASE_DEFAULT_FILES = ["a.txt", "a.txt"]
        fake_git = mock.Mock(
            returncode=0, stdout="governance_blueprint/validation/selftest_example.py\n"
        )
        with mock.patch.object(gm.subprocess, "run", return_value=fake_git):
            files = gm._default_files()
        self.assertEqual(files.count("a.txt"), 1)
        self.assertEqual(files.count("validation/selftest_example.py"), 1)

    def test_check_passes_for_current_manifest(self) -> None:
        payload = gm.build_manifest(preserve_timestamp=False)
        gm.MANIFEST_PATH.write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
        self.assertEqual(self._run_main("--check"), 0)

    def test_check_fails_on_manifest_drift(self) -> None:
        payload = gm.build_manifest(preserve_timestamp=False)
        payload["version"] = "0.0.0"
        gm.MANIFEST_PATH.write_text(json.dumps(payload), encoding="utf-8")
        self.assertEqual(self._run_main("--check"), 1)

    def test_check_fails_on_duplicate_json_keys(self) -> None:
        gm.MANIFEST_PATH.write_text(
            '{"package":"one","package":"two"}\n',
            encoding="utf-8",
        )
        self.assertEqual(self._run_main("--check"), 1)

    def test_stamp_now_refreshes_generation_timestamp(self) -> None:
        gm.MANIFEST_PATH.write_text(
            json.dumps(
                {
                    "package": gm.PACKAGE,
                    "version": gm.VERSION,
                    "generated_utc": "2000-01-01T00:00:00Z",
                    "artifacts": {},
                    "external_artifacts": {},
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(self._run_main("--stamp-now"), 0)
        generated = json.loads(gm.MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertRegex(
            generated["generated_utc"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
        )
        self.assertNotEqual(generated["generated_utc"], "2000-01-01T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
