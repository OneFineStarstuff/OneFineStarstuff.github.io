# Systemic Governance Artifacts

This directory contains machine-readable starter artifacts used by the 2026–2030 governance blueprint.

## Files
- `ai_system_registry.yaml`: inventory of AI systems with risk tier and jurisdiction coverage.
- `control_crosswalk.json`: control-to-framework mapping records.
- `agent_lifecycle_policy.rego`: release/approval policy example for risk-tiered agent deployment.
- `containment_safety_case.jsonld`: safety-case claims and evidence metadata.
- `systemic_risk_bbn_model.bif`: Bayesian Belief Network skeleton for systemic risk propagation.
- `crisis_simulation_catalog.yaml`: scenario catalog for crisis simulation drills.
- `deterministic_replay_manifest.json`: required artifacts for replay-grade forensic reconstruction.
- `regulator_submission_bundle.toml`: jurisdiction-specific submission bundle index.

## Validation
These files are validated by:
- `python3 governance_blueprint/validation/validate_artifacts.py`
- `python3 governance_blueprint/validation/run_validation_suite.py`

JSON artifacts also include local schemas:
- `schemas/control_crosswalk.schema.json`
- `schemas/deterministic_replay_manifest.schema.json`

## Notes
- Artifacts are intentionally lightweight templates and should be adapted per institution.
- Hash integrity is tracked in `governance_blueprint/artifact_manifest.json`.
