import json
from datetime import datetime
import re
from pathlib import Path

DOC = Path('DAILY_GSIFI_AGI_ASI_GOVERNANCE_2026_2030.md')
JSON_CANONICAL = Path('artifacts/daily_governance_report.example.json')
REGO_CANONICAL = Path('policies/sentinel_governance.rego')
JSON_SCHEMA = Path('artifacts/daily_governance_report.schema.json')


def _extract_all_fenced_blocks(markdown: str, language: str) -> list[str]:
    pattern = rf"```{language}\n(.*?)\n```"
    return re.findall(pattern, markdown, re.DOTALL)


def _extract_single_fenced_block(markdown: str, language: str) -> str:
    blocks = _extract_all_fenced_blocks(markdown, language)
    assert blocks, f"Missing fenced {language} block"
    assert len(blocks) == 1, f"Expected exactly 1 {language} block, found {len(blocks)}"
    return blocks[0]


def test_json_snippet_parses_and_has_required_shape():
    text = DOC.read_text(encoding='utf-8')
    snippet = _extract_single_fenced_block(text, 'json')
    parsed = json.loads(snippet)

    required_top_level = {
        'report_date',
        'institution',
        'model_inventory_delta',
        'risk_posture',
        'sr_26_2',
        'aucb',
        'containment',
        'attestations',
        'approvals',
    }
    assert required_top_level.issubset(parsed.keys())

    assert parsed['institution'] == 'GSIFI_NAME'
    assert isinstance(parsed['risk_posture']['top_risks'], list)
    assert isinstance(parsed['aucb']['confidence_interval'], list)
    assert len(parsed['aucb']['confidence_interval']) == 2


def test_rego_snippet_has_expected_policy_guards():
    text = DOC.read_text(encoding='utf-8')
    rego = _extract_single_fenced_block(text, 'rego')

    expected_fragments = [
        'package sentinel.governance',
        'deny[msg]',
        'input.environment == "prod"',
        'Annex IV evidence incomplete',
        'Model card hash mismatch',
        'Explainability confidence below minimum',
    ]
    for expected in expected_fragments:
        assert expected in rego

    # Ensure policy structure is stable: exactly three deny rules in this baseline.
    deny_blocks = re.findall(r'deny\[msg\]\s*\{', rego)
    assert len(deny_blocks) == 3


def test_snippets_are_in_implementation_artifacts_section():
    text = DOC.read_text(encoding='utf-8')
    artifacts_index = text.find('## 11) Implementation Artifacts')
    json_index = text.find('```json')
    rego_index = text.find('```rego')

    assert artifacts_index != -1, 'Missing Implementation Artifacts section'
    assert json_index > artifacts_index, 'JSON snippet must appear in artifacts section'
    assert rego_index > artifacts_index, 'Rego snippet must appear in artifacts section'


def test_markdown_snippets_match_canonical_artifact_files():
    text = DOC.read_text(encoding='utf-8')
    json_snippet = _extract_single_fenced_block(text, 'json').strip()
    rego_snippet = _extract_single_fenced_block(text, 'rego').strip()

    canonical_json = JSON_CANONICAL.read_text(encoding='utf-8').strip()
    canonical_rego = REGO_CANONICAL.read_text(encoding='utf-8').strip()

    assert json.loads(json_snippet) == json.loads(canonical_json)
    assert rego_snippet == canonical_rego


def test_json_example_matches_declared_schema_requirements():
    schema = json.loads(JSON_SCHEMA.read_text(encoding='utf-8'))
    example = json.loads(JSON_CANONICAL.read_text(encoding='utf-8'))

    assert schema['type'] == 'object'
    required_top = set(schema['required'])
    assert required_top.issubset(example.keys())

    type_map = {'string': str, 'integer': int, 'boolean': bool, 'array': list, 'object': dict}

    for key, prop in schema['properties'].items():
        assert key in example
        expected_type = prop.get('type')
        if expected_type in type_map:
            assert isinstance(example[key], type_map[expected_type])

        if prop.get('type') == 'object':
            assert isinstance(example[key], dict)
            nested_required = set(prop.get('required', []))
            assert nested_required.issubset(example[key].keys())
            for nested_key, nested_prop in prop.get('properties', {}).items():
                assert nested_key in example[key]
                nested_type = nested_prop.get('type')
                if nested_type in type_map:
                    assert isinstance(example[key][nested_key], type_map[nested_type])


def test_json_timestamp_and_date_formats():
    example = json.loads(JSON_CANONICAL.read_text(encoding='utf-8'))

    # report_date must be ISO date.
    datetime.strptime(example['report_date'], '%Y-%m-%d')

    # timestamp_utc must be parseable RFC3339-like UTC timestamp with Z suffix.
    ts = example['approvals']['timestamp_utc']
    assert ts.endswith('Z')
    datetime.fromisoformat(ts.replace('Z', '+00:00'))
