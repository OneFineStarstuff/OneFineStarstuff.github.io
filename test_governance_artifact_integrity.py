from pathlib import Path
import datetime
import json

import jsonschema
import yaml


def normalize(value):
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def test_repo_governance_artifact_yaml_json_parity_and_schema():
    root = Path(__file__).resolve().parent
    yaml_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml"
    json_path = root / "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json"
    schema_path = root / "docs/artifacts/schemas/enterprise_ai_governance_artifact.schema.json"

    yaml_data = yaml.safe_load(yaml_path.read_text())
    json_data = json.loads(json_path.read_text())
    schema = json.loads(schema_path.read_text())

    assert normalize(yaml_data) == json_data
    jsonschema.validate(instance=json_data, schema=schema)

    # sanity checks on key governance fields
    assert "pillars" in json_data and len(json_data["pillars"]) >= 5
    assert "regulatory_alignment" in json_data and len(json_data["regulatory_alignment"]) >= 5
