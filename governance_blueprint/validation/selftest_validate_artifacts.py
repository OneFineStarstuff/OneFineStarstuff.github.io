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
        self.original_root = va.ROOT
        self.original_master_reference = va.MASTER_REFERENCE_DOC
        va.ARTIFACTS = self.artifacts
        va.ROOT = self.tmp_path
        va.MASTER_REFERENCE_DOC = self.tmp_path / "ENTERPRISE_AGI_ASI_GOVERNANCE_MASTER_REFERENCE_2026_2035.md"

    def tearDown(self) -> None:
        va.ARTIFACTS = self.original_artifacts
        va.ROOT = self.original_root
        va.MASTER_REFERENCE_DOC = self.original_master_reference
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
            self.artifacts / "roadmap_2026_2035.yaml",
            "program: p\n"
            "version: 1\n"
            "horizon:\n"
            "  start: 2026-07-01\n"
            "  end: 2035-12-31\n"
            "segments:\n"
            "  - name: phase_0_foundation\n"
            "  - name: phase_1_policy_spec_industrialization\n"
            "  - name: phase_2_containment_perpetual_assurance\n"
            "    exit_criteria:\n"
            "      critical_breach_mttc_seconds_max: 90\n"
            "  - name: phase_3_prudential_stress\n"
            "  - name: phase_4_supervisory_interoperability\n"
            "    exit_criteria:\n"
            "      supervisory_requests_via_api_pct: 95\n"
            "      manual_dossier_assembly_pct_max: 5\n"
            "extension:\n"
            "  - period: 2035\n",
        )
        self._write(
            self.artifacts / "regulatory_playbook_mapping_2026_2035.csv",
            "framework,obligation,control_family,evidence_artifact,automation_mechanism\n"
            "EU AI Act Annex IV,B,C,D,E\nNIST AI RMF 1.0,C,D,E,F\nISO IEC 42001 AIMS,D,E,F,G\n"
            "Basel III IV,E,F,G,H\nUK SMCR,F,G,H,I\nICGC compute governance,G,H,I,J\n"
            "DORA,H,I,J,K\nNIS2,I,J,K,L\nHKMA Fintech 2030,J,K,L,M\nMAS FEAT,K,L,M,N\n",
        )
        self._write(
            self.tmp_path / "ENTERPRISE_AGI_ASI_GOVERNANCE_MASTER_REFERENCE_2026_2035.md",
            "# Enterprise AGI/ASI Governance Implementation Roadmap & Master Reference (2026–2035)\n"
            "## 2) Phased Roadmap (2026–2030) + Extension (2031–2035)\n"
            "## 4) Formal Verification and Policy-as-Code Conformance\n"
            "## 9) Regulatory Mapping Playbooks (Control Objectives)\n"
            "## 11) Quantitative KPI Targets\n",
        )

        # Generate manifest hashes for seeded files.
        hash_targets = [
            "control_mapping_matrix.csv",
            "evidence_event_schema.json",
            "opa/release_gate.rego",
            "roadmap_2026_2030.yaml",
            "roadmap_2026_2035.yaml",
            "regulatory_playbook_mapping_2026_2035.csv",
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
        self.assertEqual(va.validate_roadmap_2035_shape(), [])
        self.assertEqual(va.validate_regulatory_mapping_csv(), [])
        self.assertEqual(va.validate_master_reference_markdown(), [])
        self.assertEqual(va.validate_manifest_hashes(), [])

    def test_master_reference_fails_when_section_missing(self) -> None:
        (self.tmp_path / "ENTERPRISE_AGI_ASI_GOVERNANCE_MASTER_REFERENCE_2026_2035.md").write_text(
            "# Enterprise AGI/ASI Governance Implementation Roadmap & Master Reference (2026–2035)\n",
            encoding="utf-8",
        )
        errors = va.validate_master_reference_markdown()
        self.assertTrue(any("missing required section:" in e for e in errors))

    def test_2035_roadmap_shape_fails_when_phase_missing(self) -> None:
        (self.artifacts / "roadmap_2026_2035.yaml").write_text(
            "program: p\nhorizon: h\nsegments:\n  - name: phase_0_foundation\nextension:\n  - period: 2035\n",
            encoding="utf-8",
        )
        errors = va.validate_roadmap_2035_shape()
        self.assertTrue(any("segment order mismatch" in e for e in errors))

    def test_2035_roadmap_shape_fails_when_semantic_token_missing(self) -> None:
        (self.artifacts / "roadmap_2026_2035.yaml").write_text(
            "program: p\nversion: 1\nhorizon:\n  start: 2026-07-01\nsegments:\n"
            "  - name: phase_0_foundation\n"
            "  - name: phase_1_policy_spec_industrialization\n"
            "  - name: phase_2_containment_perpetual_assurance\n"
            "  - name: phase_3_prudential_stress\n"
            "  - name: phase_4_supervisory_interoperability\n"
            "extension:\n  - period: 2035\n",
            encoding="utf-8",
        )
        errors = va.validate_roadmap_2035_shape()
        self.assertTrue(any("missing required semantic token" in e for e in errors))

    def test_2035_roadmap_shape_fails_on_duplicate_segments(self) -> None:
        (self.artifacts / "roadmap_2026_2035.yaml").write_text(
            "program: p\nversion: 1\nhorizon:\n  start: 2026-07-01\n  end: 2035-12-31\nsegments:\n"
            "  - name: phase_0_foundation\n"
            "  - name: phase_1_policy_spec_industrialization\n"
            "  - name: phase_2_containment_perpetual_assurance\n"
            "  - name: phase_2_containment_perpetual_assurance\n"
            "  - name: phase_4_supervisory_interoperability\n"
            "    exit_criteria:\n"
            "      supervisory_requests_via_api_pct: 95\n"
            "      manual_dossier_assembly_pct_max: 5\n"
            "extension:\n  - period: 2035\n"
            "critical_breach_mttc_seconds_max: 90\n",
            encoding="utf-8",
        )
        errors = va.validate_roadmap_2035_shape()
        self.assertTrue(any("duplicate segment names" in e for e in errors))

    def test_regulatory_mapping_csv_fails_on_missing_column(self) -> None:
        (self.artifacts / "regulatory_playbook_mapping_2026_2035.csv").write_text(
            "framework,obligation,control_family,evidence_artifact\nA,B,C,D\n",
            encoding="utf-8",
        )
        errors = va.validate_regulatory_mapping_csv()
        self.assertTrue(any("missing required headers" in e for e in errors))

    def test_regulatory_mapping_csv_fails_when_required_frameworks_missing(self) -> None:
        (self.artifacts / "regulatory_playbook_mapping_2026_2035.csv").write_text(
            "framework,obligation,control_family,evidence_artifact,automation_mechanism\n"
            "Only One,A,B,C,D\n",
            encoding="utf-8",
        )
        errors = va.validate_regulatory_mapping_csv()
        self.assertTrue(any("missing required framework mappings" in e for e in errors))

    def test_regulatory_mapping_csv_framework_match_is_case_insensitive(self) -> None:
        (self.artifacts / "regulatory_playbook_mapping_2026_2035.csv").write_text(
            "framework,obligation,control_family,evidence_artifact,automation_mechanism\n"
            "eu ai act annex iv,A,B,C,D\nnist ai rmf 1.0,B,C,D,E\niso iec 42001 aims,C,D,E,F\n"
            "basel iii iv,D,E,F,G\nuk smcr,E,F,G,H\nicgc compute governance,F,G,H,I\n"
            "dora,G,H,I,J\nnis2,H,I,J,K\nhkma fintech 2030,I,J,K,L\nmas feat,J,K,L,M\n",
            encoding="utf-8",
        )
        self.assertEqual(va.validate_regulatory_mapping_csv(), [])

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


if __name__ == "__main__":
    unittest.main()
