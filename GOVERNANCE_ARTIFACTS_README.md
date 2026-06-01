# Governance Artifacts Quickstart

This repository includes machine-readable governance artifacts for AI controls:

- `schemas/bbom.schema.json`
- `schemas/arre_record.schema.json`
- `artifacts/bbom/*.json`
- `examples/arre/*.json`
- `tools/validate_ai_governance_artifacts.py`

## Local validation

```bash
python -m pip install -r requirements-governance.txt
python tools/validate_ai_governance_artifacts.py
```

## Custom paths

```bash
python tools/validate_ai_governance_artifacts.py \
  --bbom-dir artifacts/bbom \
  --arre-dir examples/arre \
  --arre-dir evidence/arre
```

## CI

Validation is enforced in `.github/workflows/governance-artifacts.yml`.

The validator enforces both JSON Schema compliance and semantic checks (for example BBOM threshold conformance and ARRE period consistency).

Additional semantic checks include date format validation (via JSON Schema format checking) and duplicate ARRE evidence hash detection.

Generate an auditable machine-readable summary report:

```bash
python tools/validate_ai_governance_artifacts.py --report-file .reports/governance-validation.json
```

Report output includes discovered/checked counters, `passed_files`, `failed_files`, and `errors` for audit trails.

The GitHub Actions workflow also uploads the report as a CI artifact (`governance-validation-report`) for audit retention.

When schema loading fails, reports include `fatal_error: "schema_load_failure"` and the associated error in `errors`.

Report output also includes `validator_version` and overall `status` (`passed`/`failed`) for easier pipeline gating.

Reports include `exit_code` (0 for pass, 2 for validation failure) to simplify CI/CD policy gating.

Per-domain failure counters (`bbom_failed`, `arre_failed`) are included to support targeted remediation dashboards.
