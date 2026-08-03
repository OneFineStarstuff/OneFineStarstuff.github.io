# Governance Report Pack (2026–2030)

This folder includes a multi-audience governance documentation pack:

- `INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md` (master reference)
- `BOARD_BRIEF_AGI_ASI_GOVERNANCE_2026_2030.md` (board package)
- `REGULATOR_EXAM_PACK_AI_GOVERNANCE_2026_2030.md` (regulator packet template)
- `ENGINEERING_IMPLEMENTATION_PLAYBOOK_AI_GOVERNANCE_2026_2030.md` (engineering playbook)
- `governance_reports_manifest.json` (machine-readable report inventory)
- `../schemas/governance_reports_manifest.schema.json` (manifest reference schema)

## Validation

Run the structural validator:

```bash
python3 -m unittest discover tool_tests
python3 tools/validate_governance_reports.py
python3 tools/validate_governance_reports.py --json
make governance-validate-json-check
make governance-check
```

The validator checks:
- required `<title>`, `<abstract>`, `<content>` wrappers
- required section anchors per audience artifact
- basic title-content sanity
- report index consistency in `README_GOVERNANCE_REPORTS.md`
- report inventory consistency in `governance_reports_manifest.json`
- manifest entries must map exactly to the governed report set (no missing or unexpected entries)
- manifest report paths must exist in the repository
- manifest schema integrity for required root/item fields

## Optional local git hook

A local pre-commit configuration is available at repository root:

```bash
pre-commit install
pre-commit run --all-files
```

The hook configuration in `.pre-commit-config.yaml` runs:
- `make governance-validate` on pre-commit (fast local check)
- `make governance-check` on pre-push (full suite)
