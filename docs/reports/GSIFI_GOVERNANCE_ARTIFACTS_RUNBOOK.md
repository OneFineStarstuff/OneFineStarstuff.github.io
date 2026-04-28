# GSIFI Governance Artifacts Runbook

This runbook defines the minimum operator workflow for maintaining and validating the
GSIFI governance artifact set.

## Artifact inventory

- Schema: `docs/schemas/gien-governance-event.schema.json`
- Sample event: `docs/examples/gien_governance_event_sample.json`
- Rego policy: `docs/policies/sentinel-tiered-autonomy.rego`
- SR-DSL sample: `docs/examples/sr_dsl_fairness_regression_v1.txt`
- Blueprint: `docs/reports/GSIFI_AGI_ASI_GOVERNANCE_BLUEPRINT_2026_2030.md`
- Validator: `scripts/validate_gsifi_governance_assets.py`
- Tests: `tests/` (including `tests/test_validate_gsifi_governance_assets.py` and `tests/test_validate_gsifi_governance_cli.py`)

## Local validation sequence

Quick all-in-one check:

```bash
make check-gsifi-governance
```

Run these commands before pushing changes:

```bash
make validate-gsifi-governance
make validate-gsifi-governance-module
make test-gsifi-governance
make lint-gsifi-governance
```

Optional installed-CLI smoke check (after `pip install -e .[governance]`):

```bash
validate-gsifi-governance-assets --help
validate-gsifi-governance-assets
```

## CI workflow

Workflow file: `.github/workflows/gsifi-governance-artifacts.yml`

CI automatically runs on pull requests and pushes that touch governance artifacts.

## Change policy

1. Keep schema and sample synchronized.
2. Do not remove Tier 3 dual-authorization/human-override controls from Rego examples.
3. Preserve `TEST`, `SCOPE`, `ASSERT`, and `ON_FAIL` directives for SR-DSL samples.
4. Update tests when validator behavior changes.

## Incident response for failed checks

- **Schema/sample failure:** align required fields/types/formats, then rerun validator.
- **Rego fragment failure:** restore required control fragments and violation messages.
- **SR-DSL failure:** fix directive structure and ensure at least two `ASSERT` lines.
- **Markdown lint failure:** fix formatting in the report file or update scoped lint config.

Note: validator failures are emitted to `stderr` with the prefix `VALIDATION FAILED`.
