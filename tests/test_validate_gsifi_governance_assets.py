import json
from pathlib import Path

import pytest
import scripts.validate_gsifi_governance_assets as validator


def test_validate_event_schema_and_sample_passes() -> None:
    validator.validate_event_schema_and_sample()


def test_validate_rego_policy_passes() -> None:
    validator.validate_rego_policy()


def test_validate_sr_dsl_passes() -> None:
    validator.validate_sr_dsl()


def test_validation_error_type() -> None:
    assert issubclass(validator.ValidationError, RuntimeError)


def test_validate_event_schema_and_sample_fails_on_missing_required_key(
    tmp_path: Path,
) -> None:
    schema = {
        "required": ["crs_uuid", "event_type"],
        "properties": {
            "crs_uuid": {"type": "string"},
            "event_type": {"type": "string", "enum": ["ai.decision"]},
        },
    }
    sample = {"crs_uuid": "CRS-UUID-2026-04-24-000001"}

    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps(schema))
    sample_path.write_text(json.dumps(sample))

    with pytest.raises(validator.ValidationError, match="missing required keys"):
        validator.validate_event_schema_and_sample(schema_path, sample_path)


def test_validate_event_schema_and_sample_fails_on_non_utc_datetime(
    tmp_path: Path,
) -> None:
    schema = {
        "required": ["timestamp_utc"],
        "properties": {
            "timestamp_utc": {"type": "string", "format": "date-time"}
        },
    }
    sample = {"timestamp_utc": "2026-04-24T12:00:00+00:00"}

    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps(schema))
    sample_path.write_text(json.dumps(sample))

    with pytest.raises(validator.ValidationError, match="end with 'Z'"):
        validator.validate_event_schema_and_sample(schema_path, sample_path)


def test_validate_sr_dsl_fails_on_invalid_directive(tmp_path: Path) -> None:
    dsl_path = tmp_path / "bad.dsl"
    dsl_path.write_text(
        "\n".join(
            [
                "TEST bad",
                "SCOPE jurisdiction=UK product=retail_credit",
                "ASSERT disparity_ratio <= 1.25",
                "ASSERT evidence_completeness == 1.0",
                "BROKEN something",
                "ON_FAIL severity=high remediation_window_days=14",
            ]
        )
    )

    with pytest.raises(validator.ValidationError, match="Unexpected SR-DSL directive"):
        validator.validate_sr_dsl(dsl_path)


def test_main_returns_1_when_validation_fails() -> None:
    assert validator.main(["--schema", "does/not/exist.json"]) == 1


def test_main_returns_0_and_prints_success(capsys: pytest.CaptureFixture[str]) -> None:
    assert validator.main([]) == 0
    captured = capsys.readouterr()
    assert "All GSIFI governance artifact checks passed." in captured.out


def test_main_quiet_suppresses_success_output(capsys: pytest.CaptureFixture[str]) -> None:
    assert validator.main(["--quiet"]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""


def test_validate_event_schema_allows_additional_properties_when_enabled(
    tmp_path: Path,
) -> None:
    schema = {
        "required": ["foo"],
        "properties": {"foo": {"type": "string"}},
        "additionalProperties": True,
    }
    sample = {"foo": "ok", "bar": "extra"}

    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps(schema))
    sample_path.write_text(json.dumps(sample))

    validator.validate_event_schema_and_sample(schema_path, sample_path)


def test_get_jsonschema_validator_returns_none_when_validator_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _JsonschemaWithoutDraft:
        pass

    validator._get_jsonschema_validator.cache_clear()
    monkeypatch.setattr(validator.importlib.util, "find_spec", lambda _name: object())
    monkeypatch.setattr(
        validator.importlib,
        "import_module",
        lambda _name: _JsonschemaWithoutDraft(),
    )

    assert validator._get_jsonschema_validator() is None
    validator._get_jsonschema_validator.cache_clear()


def test_get_jsonschema_validator_returns_none_on_import_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator._get_jsonschema_validator.cache_clear()
    monkeypatch.setattr(validator.importlib.util, "find_spec", lambda _name: object())

    def _raise_import_error(_name: str) -> None:
        raise ImportError("boom")

    monkeypatch.setattr(validator.importlib, "import_module", _raise_import_error)
    assert validator._get_jsonschema_validator() is None
    validator._get_jsonschema_validator.cache_clear()


def test_validate_event_schema_rejects_boolean_for_integer_field(
    tmp_path: Path,
) -> None:
    schema = {
        "required": ["count"],
        "properties": {"count": {"type": "integer"}},
    }
    sample = {"count": True}

    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps(schema))
    sample_path.write_text(json.dumps(sample))

    with pytest.raises(validator.ValidationError, match="must match JSON Schema type"):
        validator.validate_event_schema_and_sample(schema_path, sample_path)


def test_main_returns_1_when_rego_file_missing() -> None:
    assert validator.main(["--rego", "does/not/exist.rego"]) == 1


def test_main_returns_1_when_srdsl_file_missing() -> None:
    assert validator.main(["--srdsl", "does/not/exist.txt"]) == 1


def test_validate_event_schema_fails_when_schema_root_is_not_object(
    tmp_path: Path,
) -> None:
    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps(["not", "an", "object"]))
    sample_path.write_text(json.dumps({"foo": "bar"}))

    with pytest.raises(validator.ValidationError, match="Schema root must be a JSON object"):
        validator.validate_event_schema_and_sample(schema_path, sample_path)


def test_validate_event_schema_fails_when_sample_root_is_not_object(
    tmp_path: Path,
) -> None:
    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps({"type": "object"}))
    sample_path.write_text(json.dumps(["not", "an", "object"]))

    with pytest.raises(
        validator.ValidationError,
        match="Sample event root must be a JSON object",
    ):
        validator.validate_event_schema_and_sample(schema_path, sample_path)


def test_validate_event_schema_supports_object_and_array_types(tmp_path: Path) -> None:
    schema = {
        "required": ["meta", "tags"],
        "properties": {
            "meta": {"type": "object"},
            "tags": {"type": "array"},
        },
    }
    sample = {"meta": {"owner": "risk"}, "tags": ["tier3", "credit"]}

    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps(schema))
    sample_path.write_text(json.dumps(sample))

    validator.validate_event_schema_and_sample(schema_path, sample_path)


def test_validate_event_schema_supports_union_types(tmp_path: Path) -> None:
    schema = {
        "required": ["score"],
        "properties": {"score": {"type": ["integer", "null"]}},
    }
    sample = {"score": None}

    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps(schema))
    sample_path.write_text(json.dumps(sample))

    validator.validate_event_schema_and_sample(schema_path, sample_path)


def test_validate_event_schema_fails_on_unknown_type_keyword(tmp_path: Path) -> None:
    schema = {
        "required": ["field"],
        "properties": {"field": {"type": "definitely_not_a_jsonschema_type"}},
    }
    sample = {"field": "value"}

    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps(schema))
    sample_path.write_text(json.dumps(sample))

    with pytest.raises(validator.ValidationError, match="must match JSON Schema type"):
        validator.validate_event_schema_and_sample(schema_path, sample_path)


def test_validate_event_schema_fails_when_required_is_not_list(tmp_path: Path) -> None:
    schema = {"required": "not-a-list", "properties": {"foo": {"type": "string"}}}
    sample = {"foo": "value"}
    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps(schema))
    sample_path.write_text(json.dumps(sample))

    with pytest.raises(validator.ValidationError, match="required' must be a list"):
        validator.validate_event_schema_and_sample(schema_path, sample_path)


def test_validate_event_schema_fails_when_properties_is_not_object(
    tmp_path: Path,
) -> None:
    schema = {"required": [], "properties": ["not-an-object"]}
    sample = {}
    schema_path = tmp_path / "schema.json"
    sample_path = tmp_path / "sample.json"
    schema_path.write_text(json.dumps(schema))
    sample_path.write_text(json.dumps(sample))

    with pytest.raises(validator.ValidationError, match="properties' must be an object"):
        validator.validate_event_schema_and_sample(schema_path, sample_path)
