# Enterprise AI Governance Artifact Package

This folder contains the machine-readable governance package for the 2026–2030 program.

## Contents

- `enterprise_ai_governance_machine_readable_2026_2030.yaml` — source-of-truth artifact.
- `enterprise_ai_governance_machine_readable_2026_2030.json` — canonical exported JSON.
- `schemas/enterprise_ai_governance_artifact.schema.json` — JSON Schema contract.
- `examples/cicd_policy_gate_manifest.yaml` — CI/CD gate manifest example.
- `examples/regulator_report_template.xml` — regulator report template (`title/abstract/content`).
- `manifest.json` — SHA-256 manifest for package integrity tracking.

## Validation workflow

From repository root:

```bash
pip install -r requirements-dev.txt
# non-mutating freshness checks
make check-governance-json-clean
make check-governance-manifest-clean
make validate-governance
make test-governance
# one-shot full pipeline
make verify-governance
```

`check-governance-json-clean` and `check-governance-manifest-clean` are non-mutating
verification gates that fail when generated artifacts need regeneration.

When intentionally updating generated artifacts, run:

```bash
make build-governance-json
make build-governance-manifest
```

CI uses the same sequence in `.github/workflows/governance-artifact-validation.yml`.

## Custom path usage

Both exporter and validator support path overrides relative to `--root`:

```bash
python scripts/export_governance_artifact_json.py --root . --yaml docs/artifacts/custom.yaml --json docs/artifacts/custom.json
python scripts/validate_governance_artifact.py --root . --yaml docs/artifacts/custom.yaml --json docs/artifacts/custom.json --schema docs/artifacts/schemas/enterprise_ai_governance_artifact.schema.json --cicd docs/artifacts/examples/cicd_policy_gate_manifest.yaml --report docs/artifacts/examples/regulator_report_template.xml
```


## Integrity test

Repository-level artifact integrity is enforced by `test_governance_artifact_integrity.py`, which validates committed YAML/JSON parity and schema conformance against the files in this folder.
