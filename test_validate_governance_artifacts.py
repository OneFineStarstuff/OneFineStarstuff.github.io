import json

import pytest

import tools.validate_governance_artifacts as vga


def test_validate_example_against_schema_accepts_canonical_artifacts():
    schema = json.loads(vga.JSON_SCHEMA.read_text(encoding='utf-8'))
    example = json.loads(vga.JSON_EXAMPLE.read_text(encoding='utf-8'))

    vga._validate_example_against_schema(example, schema)


def test_validate_example_against_schema_rejects_missing_required_key():
    schema = {
        'type': 'object',
        'required': ['required_key'],
        'properties': {'required_key': {'type': 'string'}},
    }
    example = {}

    with pytest.raises(ValueError, match='Missing required top-level key: required_key'):
        vga._validate_example_against_schema(example, schema)


def test_extract_single_fenced_block_rejects_multiple_matches():
    md = '```json\n{}\n```\n\n```json\n{}\n```\n'

    with pytest.raises(ValueError, match='Expected exactly one fenced json block'):
        vga._extract_single_fenced_block(md, 'json')


def test_build_arg_parser_defaults():
    parser = vga._build_arg_parser()
    args = parser.parse_args([])

    assert args.doc == str(vga.DOC)
    assert args.json_example == str(vga.JSON_EXAMPLE)
    assert args.json_schema == str(vga.JSON_SCHEMA)
    assert args.rego_policy == str(vga.REGO_POLICY)


def test_main_accepts_explicit_paths():
    rc = vga.main([
        '--doc', str(vga.DOC),
        '--json-example', str(vga.JSON_EXAMPLE),
        '--json-schema', str(vga.JSON_SCHEMA),
        '--rego-policy', str(vga.REGO_POLICY),
    ])
    assert rc == 0
