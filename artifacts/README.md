# Governance Artifacts Usage Guide

This folder contains machine-readable assets for enterprise and regulator-facing AI governance workflows.

## Files

- `annex-iv-dossier-schema-v1.json`: JSON Schema for EU AI Act Annex IV dossier payloads.
- `control-catalog-v1.json`: control inventory with ownership, cadence, severity, and framework mappings.
- `roadmap-2026-2030.yaml`: phased implementation and milestone plan.
- `regulator-report-template.xml`: regulator-ready report skeleton.
- `enterprise-civilizational-agi-asi-blueprint-2026-2030.md`: implementation blueprint narrative.
- `examples/annex-iv-dossier-example.json`: sample payload conforming to Annex IV schema.
- `manifest-targets-v1.json`: canonical tracked-file list used by manifest build and validation.
- `schemas/manifest-targets-schema-v1.json`: JSON Schema for manifest-target metadata.
- `schemas/artifact-manifest-schema-v1.json`: JSON Schema for produced checksum manifests.
- `schemas/check-all-result-schema-v1.json`: JSON Schema for unified check JSON output.
- `artifact-manifest-v1.json`: SHA-256 checksum manifest for tamper-evident packaging.
- `validate_artifacts.py`: parser + semantic validation utility.
- `build_manifest.py`: manifest regeneration utility.
- `requirements-artifacts.txt`: pinned runtime/test dependencies for artifact checks.
- `Makefile`: convenience targets for local artifact validation workflows.

## Validation

Human-readable mode:

```bash
python artifacts/validate_artifacts.py
```

Machine-readable JSON mode:

```bash
python artifacts/validate_artifacts.py --json
```

Skip checksum validation (for local editing before manifest regeneration):

```bash
python artifacts/validate_artifacts.py --skip-manifest
```

On validation failure with `--json`, output is `{ "status": "error", "error": "..." }` and exit code is `1`.

Exit behavior: all CLI tools return `0` on success and `1` on validation/check failure.

The validator performs:
1. JSON/YAML/XML parse checks.
2. Required key checks for schema, roadmap, and controls.
3. Annex IV sample semantic checks (types, required fields, enum values, date format).
4. Control mapping cross-reference checks (no unknown control IDs).
5. Regulator XML required section checks.
6. Roadmap milestone date-range checks (2026–2030).
7. Manifest checksum checks for all tracked artifacts.
8. Manifest coverage checks (no missing or unexpected files).

## Regenerate checksum manifest

```bash
python artifacts/build_manifest.py
```

Supports reproducible builds via `SOURCE_DATE_EPOCH`.

Verify manifest freshness without rewriting:

```bash
python artifacts/build_manifest.py --check
python artifacts/build_manifest.py --check --json
```

## Install dependencies

```bash
pip install -r artifacts/requirements-artifacts.txt
# or:
cd artifacts && make deps
# or from repo root:
make -C artifacts deps
```

## Unified check

```bash
python artifacts/check_all.py
python artifacts/check_all.py --json
```

`check_all --json` includes `schema_version`, `checked_at` (UTC ISO-8601), `manifest_fresh`, `validation_ok`, and `errors`.

## Makefile shortcuts

```bash
cd artifacts
make all
# Optional: override interpreter, e.g. PYTHON=python3.12 make all
# or from repo root:
make -C artifacts all
```

Other useful shortcuts:
- `make manifest-check`
- `make validate`
- `make check-all`
- `make test`

## Test

```bash
python -m pytest -q unit_tests/test_artifacts_validation.py
# or from artifacts/: make test
```


CI note: `.github/workflows/artifact-validation.yml` supports `workflow_dispatch` for on-demand re-validation, runs `make -C artifacts all` as the canonical validation entrypoint, and triggers on changes to `artifacts/**`, `unit_tests/**`, `pytest.ini`, and the workflow file itself.
