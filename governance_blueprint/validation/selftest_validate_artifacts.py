#!/usr/bin/env python3
"""Unit tests for validate_artifacts.py using stdlib unittest."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("validate_artifacts.py")
spec = importlib.util.spec_from_file_location("validate_artifacts", MODULE_PATH)
va = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(va)


class ValidateArtifactsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.artifacts = self.tmp_path / "governance_blueprint"
        self._seed_valid_artifacts()
        self.original_artifacts = va.ARTIFACTS
        va.ARTIFACTS = self.artifacts

    def tearDown(self) -> None:
        va.ARTIFACTS = self.original_artifacts
        self.tmp.cleanup()

    def _write(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _seed_valid_artifacts(self) -> None:
        self._write(
            self.artifacts / "control_mapping_matrix.csv",
            "control_family,control_id,description,eu_ai_act_anchor,nist_ai_rmf_anchor,iso_42001_anchor,financial_anchor,evidence_artifacts,control_owner,review_frequency\n"
            "A,B,C,D,E,F,G,H,I,J\n"
            "A2,B2,C2,D2,E2,F2,G2,H2,I2,J2\n"
            "A3,B3,C3,D3,E3,F3,G3,H3,I3,J3\n"
            "A4,B4,C4,D4,E4,F4,G4,H4,I4,J4\n"
            "A5,B5,C5,D5,E5,F5,G5,H5,I5,J5\n",
        )

        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "x",
            "type": "object",
            "required": [
                "event_id",
                "timestamp_utc",
                "event_type",
                "model_id",
                "model_version",
                "risk_tier",
                "policy_bundle_hash",
                "trace_id",
                "jurisdiction_code",
            ],
            "properties": {
                "event_id": {"type": "string"},
                "timestamp_utc": {"type": "string"},
                "event_type": {"type": "string"},
                "model_id": {"type": "string"},
                "model_version": {"type": "string"},
                "risk_tier": {"type": "integer"},
                "policy_bundle_hash": {"type": "string"},
                "trace_id": {"type": "string"},
                "jurisdiction_code": {"type": "string"},
            },
        }
        self._write(self.artifacts / "evidence_event_schema.json", json.dumps(schema))

        self._write(
            self.artifacts / "opa" / "release_gate.rego",
            "package aigov.release\n"
            "default allow = false\n"
            "baseline_requirements { true }\n"
            "allow { input.risk_tier <= 2 }\n"
            "allow { input.risk_tier >= 3 }\n"
            "allow { input.risk_tier == 4 }\n",
        )

        self._write(
            self.artifacts / "roadmap_2026_2030.yaml",
            "program: p\n"
            "version: 1\n"
            "horizon: h\n"
            "phases:\n"
            "  - name: foundation\n"
            "  - name: industrialization\n"
            "  - name: advanced_assurance\n"
            "  - name: resilience_and_advantage\n"
            "workstreams:\n"
            "  - one\n"
            "  - two\n"
            "  - three\n",
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "README.md",
            "# Systemic Governance Artifacts\n",
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "schemas" / "control_crosswalk.schema.json",
            json.dumps({"type": "object", "required": ["control_mappings"]}),
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "schemas" / "deterministic_replay_manifest.schema.json",
            json.dumps({"type": "object", "required": ["version", "required_artifacts"]}),
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "ai_system_registry.yaml",
            "version: 1.0\nsystems:\n  - system_id: x\n    risk_tier: 2\n    jurisdictions: [EU, US]\n",
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "control_crosswalk.json",
            json.dumps({"control_mappings": [{"control_id": "A", "frameworks": ["B"]}]}),
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "agent_lifecycle_policy.rego",
            "package aigov.agent_lifecycle\n"
            "allow_deploy { input.risk_tier <= 2 }\n"
            "allow_deploy {\n"
            "  input.risk_tier >= 3\n"
            "  input.validation_approved\n"
            "  input.safety_case_approved\n"
            "}\n",
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "containment_safety_case.jsonld",
            json.dumps({"@context": "x", "claims": ["y"]}),
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "systemic_risk_bbn_model.bif",
            "network \"x\" {}\nvariable A { type discrete[2] { low, high }; }\nprobability (A) { table 0.5,0.5; }\n",
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "crisis_simulation_catalog.yaml",
            "version: 1.0\nscenarios:\n  - id: s1\n    frequency: quarterly\n",
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "deterministic_replay_manifest.json",
            json.dumps({"version": "1.0", "required_artifacts": ["model_version"]}),
        )
        self._write(
            self.artifacts / "systemic_artifacts" / "regulator_submission_bundle.toml",
            "version = \"1.0\"\n[jurisdictions]\nEU = []\n",
        )

        # Generate manifest hashes for seeded files.
        hash_targets = [
            "control_mapping_matrix.csv",
            "evidence_event_schema.json",
            "opa/release_gate.rego",
            "roadmap_2026_2030.yaml",
            "systemic_artifacts/ai_system_registry.yaml",
            "systemic_artifacts/README.md",
            "systemic_artifacts/schemas/control_crosswalk.schema.json",
            "systemic_artifacts/schemas/deterministic_replay_manifest.schema.json",
            "systemic_artifacts/control_crosswalk.json",
            "systemic_artifacts/agent_lifecycle_policy.rego",
            "systemic_artifacts/containment_safety_case.jsonld",
            "systemic_artifacts/systemic_risk_bbn_model.bif",
            "systemic_artifacts/crisis_simulation_catalog.yaml",
            "systemic_artifacts/deterministic_replay_manifest.json",
            "systemic_artifacts/regulator_submission_bundle.toml",
        ]
        manifest = {
            "package": "test",
            "version": "test",
            "generated_utc": "test",
            "artifacts": {},
        }
        for rel in hash_targets:
            p = self.artifacts / rel
            manifest["artifacts"][rel] = hashlib.sha256(p.read_bytes()).hexdigest()
        self._write(self.artifacts / "artifact_manifest.json", json.dumps(manifest))

    def test_all_validators_pass_for_good_assets(self) -> None:
        self.assertEqual(va.validate_csv(), [])
        self.assertEqual(va.validate_json_schema(), [])
        self.assertEqual(va.validate_rego(), [])
        self.assertEqual(va.validate_yaml_shape(), [])
        self.assertEqual(va.validate_manifest_hashes(), [])
        self.assertEqual(va.validate_systemic_artifacts(), [])

    def test_schema_missing_model_id_fails(self) -> None:
        schema_path = self.artifacts / "evidence_event_schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        schema["properties"].pop("model_id")
        schema_path.write_text(json.dumps(schema), encoding="utf-8")

        errors = va.validate_json_schema()
        self.assertTrue(any("model_id" in e for e in errors))

    def test_rego_missing_blocks_fails(self) -> None:
        (self.artifacts / "opa" / "release_gate.rego").write_text(
            "package aigov.release\ndefault allow = false\nallow { input.risk_tier <= 2 }\n",
            encoding="utf-8",
        )

        errors = va.validate_rego()
        self.assertTrue(any("baseline_requirements" in e or "allow blocks" in e for e in errors))

    def test_manifest_hash_mismatch_fails(self) -> None:
        # Mutate a file after manifest generation.
        (self.artifacts / "roadmap_2026_2030.yaml").write_text(
            "program: changed\nversion: 1\nhorizon: h\nphases:\n  - name: foundation\nworkstreams:\n  - one\n",
            encoding="utf-8",
        )
        errors = va.validate_manifest_hashes()
        self.assertTrue(any("Hash mismatch" in e for e in errors))

    def test_yaml_shape_fails_when_insufficient_workstreams(self) -> None:
        (self.artifacts / "roadmap_2026_2030.yaml").write_text(
            "program: p\n"
            "version: 1\n"
            "horizon: h\n"
            "phases:\n"
            "  - name: foundation\n"
            "  - name: industrialization\n"
            "  - name: advanced_assurance\n"
            "  - name: resilience_and_advantage\n"
            "workstreams:\n"
            "  - one\n"
            "  - two\n",
            encoding="utf-8",
        )
        errors = va.validate_yaml_shape()
        self.assertTrue(any("at least 3 workstreams" in e for e in errors))

    def test_systemic_artifact_token_validation_fails(self) -> None:
        (self.artifacts / "systemic_artifacts" / "control_crosswalk.json").write_text(
            "{}",
            encoding="utf-8",
        )
        errors = va.validate_systemic_artifacts()
        self.assertTrue(any("control_mappings" in e for e in errors))

    def test_systemic_artifact_toml_parse_fails(self) -> None:
        (self.artifacts / "systemic_artifacts" / "regulator_submission_bundle.toml").write_text(
            "version = \n",
            encoding="utf-8",
        )
        errors = va.validate_systemic_artifacts()
        self.assertTrue(any("Invalid TOML" in e for e in errors))

    def test_systemic_artifact_control_crosswalk_shape_fails(self) -> None:
        (self.artifacts / "systemic_artifacts" / "control_crosswalk.json").write_text(
            json.dumps({"control_mappings": [{"frameworks": []}]}),
            encoding="utf-8",
        )
        errors = va.validate_systemic_artifacts()
        self.assertTrue(any("control_id" in e for e in errors))
        self.assertTrue(any("frameworks" in e for e in errors))

    def test_systemic_artifact_registry_semantics_fail(self) -> None:
        (self.artifacts / "systemic_artifacts" / "ai_system_registry.yaml").write_text(
            "version: 1.0\nsystems:\n  - system_id: x\n    risk_tier: 9\n    jurisdictions: EU\n",
            encoding="utf-8",
        )
        errors = va.validate_systemic_artifacts()
        self.assertTrue(any("risk_tier" in e for e in errors))
        self.assertTrue(any("jurisdictions" in e for e in errors))

    def test_systemic_artifact_registry_block_list_jurisdictions_pass(self) -> None:
        (self.artifacts / "systemic_artifacts" / "ai_system_registry.yaml").write_text(
            "version: 1.0\nsystems:\n  - system_id: x\n    risk_tier: 2\n    jurisdictions:\n      - EU\n      - US\n",
            encoding="utf-8",
        )
        errors = va.validate_systemic_artifacts()
        self.assertFalse(any("jurisdictions" in e for e in errors))

    def test_systemic_artifact_agent_lifecycle_rego_semantics_fail(self) -> None:
        (self.artifacts / "systemic_artifacts" / "agent_lifecycle_policy.rego").write_text(
            "package aigov.agent_lifecycle\nallow_deploy { input.risk_tier <= 2 }\n",
            encoding="utf-8",
        )
        errors = va.validate_systemic_artifacts()
        self.assertTrue(any("high-tier deploy rule" in e for e in errors))

    def test_systemic_artifact_schema_validation_fails(self) -> None:
        (self.artifacts / "systemic_artifacts" / "deterministic_replay_manifest.json").write_text(
            json.dumps({"required_artifacts": ["x"]}),
            encoding="utf-8",
        )
        errors = va.validate_systemic_artifacts()
        self.assertTrue(any("schema validation" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
