#!/usr/bin/env python3
"""Validate governance documentation artifacts stay synchronized and well-formed."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

DOC = Path('DAILY_GSIFI_AGI_ASI_GOVERNANCE_2026_2030.md')
JSON_EXAMPLE = Path('artifacts/daily_governance_report.example.json')
JSON_SCHEMA = Path('artifacts/daily_governance_report.schema.json')
REGO_POLICY = Path('policies/sentinel_governance.rego')


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Validate governance artifacts and markdown parity.')
    parser.add_argument('--doc', default=str(DOC), help='Path to governance markdown document')
    parser.add_argument('--json-example', default=str(JSON_EXAMPLE), help='Path to canonical JSON example')
    parser.add_argument('--json-schema', default=str(JSON_SCHEMA), help='Path to canonical JSON schema')
    parser.add_argument('--rego-policy', default=str(REGO_POLICY), help='Path to canonical Rego policy')
    return parser


def _extract_single_fenced_block(markdown: str, language: str) -> str:
    matches = re.findall(rf"```{language}\n(.*?)\n```", markdown, re.DOTALL)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one fenced {language} block, found {len(matches)}")
    return matches[0].strip()


def _validate_example_against_schema(example: dict, schema: dict) -> None:
    if schema.get('type') != 'object':
        raise ValueError('Schema top-level type must be object')

    for key in schema.get('required', []):
        if key not in example:
            raise ValueError(f'Missing required top-level key: {key}')

    type_map = {'string': str, 'integer': int, 'boolean': bool, 'array': list, 'object': dict}
    for key, prop in schema.get('properties', {}).items():
        if key not in example:
            raise ValueError(f'Missing property: {key}')
        t = prop.get('type')
        if t in type_map and not isinstance(example[key], type_map[t]):
            raise ValueError(f'Property {key} has wrong type')

        if t == 'object':
            for sub_key in prop.get('required', []):
                if sub_key not in example[key]:
                    raise ValueError(f'Missing nested property: {key}.{sub_key}')
            for sub_key, sub_prop in prop.get('properties', {}).items():
                if sub_key in example[key]:
                    sub_t = sub_prop.get('type')
                    if sub_t in type_map and not isinstance(example[key][sub_key], type_map[sub_t]):
                        raise ValueError(f'Nested property {key}.{sub_key} has wrong type')


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    doc = Path(args.doc)
    json_example_path = Path(args.json_example)
    json_schema_path = Path(args.json_schema)
    rego_policy_path = Path(args.rego_policy)

    markdown = doc.read_text(encoding='utf-8')
    json_snippet = _extract_single_fenced_block(markdown, 'json')
    rego_snippet = _extract_single_fenced_block(markdown, 'rego')

    json_example_text = json_example_path.read_text(encoding='utf-8').strip()
    rego_policy_text = rego_policy_path.read_text(encoding='utf-8').strip()

    example = json.loads(json_example_text)
    schema = json.loads(json_schema_path.read_text(encoding='utf-8'))

    # snippet parity checks
    if json.loads(json_snippet) != example:
        raise ValueError('JSON snippet does not match canonical JSON example')
    if rego_snippet != rego_policy_text:
        raise ValueError('Rego snippet does not match canonical policy file')

    # schema & format checks
    _validate_example_against_schema(example, schema)
    datetime.strptime(example['report_date'], '%Y-%m-%d')
    ts = example['approvals']['timestamp_utc']
    if not ts.endswith('Z'):
        raise ValueError('timestamp_utc must end with Z')
    datetime.fromisoformat(ts.replace('Z', '+00:00'))

    # basic policy-structure checks
    if len(re.findall(r'deny\[msg\]\s*\{', rego_policy_text)) != 3:
        raise ValueError('Expected exactly 3 deny[msg] rules')

    print('Governance artifacts validation passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
