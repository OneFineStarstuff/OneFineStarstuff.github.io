"""Shared constants for governance artifact tooling."""

from __future__ import annotations

DEFAULT_YAML = "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.yaml"
DEFAULT_JSON = "docs/artifacts/enterprise_ai_governance_machine_readable_2026_2030.json"
DEFAULT_SCHEMA = "docs/artifacts/schemas/enterprise_ai_governance_artifact.schema.json"
DEFAULT_CICD = "docs/artifacts/examples/cicd_policy_gate_manifest.yaml"
DEFAULT_REPORT = "docs/artifacts/examples/regulator_report_template.xml"
DEFAULT_MANIFEST = "docs/artifacts/manifest.json"

MANIFEST_TRACKED_FILES = [
    DEFAULT_YAML,
    DEFAULT_JSON,
    DEFAULT_SCHEMA,
    DEFAULT_CICD,
    DEFAULT_REPORT,
]
