import builtins
import json
import tempfile
from pathlib import Path

import pytest

from artifacts.validate_board_ai_roadmap import (
    DEFAULT_DATA_PATH,
    DEFAULT_SCHEMA_PATH,
    validate,
)

try:
    from jsonschema import ValidationError as JsonSchemaValidationError

    EXPECTED_ERRORS = (JsonSchemaValidationError, ValueError)
except Exception:  # pragma: no cover - jsonschema may be absent by design
    EXPECTED_ERRORS = (ValueError,)


def test_default_files_validate() -> None:
    validate(DEFAULT_SCHEMA_PATH, DEFAULT_DATA_PATH)


def test_invalid_data_fails_validation() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        bad_data = tmp / "bad.json"
        payload = json.loads(DEFAULT_DATA_PATH.read_text(encoding="utf-8"))
        payload.pop("schema_version", None)
        bad_data.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(EXPECTED_ERRORS):
            validate(DEFAULT_SCHEMA_PATH, bad_data)


def test_invalid_stage_gate_target_fails_validation() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        bad_data = tmp / "bad-target.json"
        payload = json.loads(DEFAULT_DATA_PATH.read_text(encoding="utf-8"))
        payload["stage_gates"][0]["target"] = "2026-Q9"
        bad_data.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(EXPECTED_ERRORS):
            validate(DEFAULT_SCHEMA_PATH, bad_data)


def test_invalid_program_period_fails_validation() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        bad_data = tmp / "bad-period.json"
        payload = json.loads(DEFAULT_DATA_PATH.read_text(encoding="utf-8"))
        payload["program"]["period"] = "2026/2030"
        bad_data.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(EXPECTED_ERRORS):
            validate(DEFAULT_SCHEMA_PATH, bad_data)



def test_fallback_validation_path_without_jsonschema(monkeypatch) -> None:
    original_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "jsonschema":
            raise ModuleNotFoundError("jsonschema")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        bad_data = tmp / "bad-fallback.json"
        payload = json.loads(DEFAULT_DATA_PATH.read_text(encoding="utf-8"))
        payload["program"]["period"] = "bad-period"
        bad_data.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(ValueError):
            validate(DEFAULT_SCHEMA_PATH, bad_data)
