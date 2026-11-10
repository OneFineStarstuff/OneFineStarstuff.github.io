"""Regression tests for the GIEN Phase 1 evidence and crosswalk contracts."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / "evidence-drawer.schema.json").read_text())
METRICS = json.loads((ROOT / "metric-definitions.v0.2.0.json").read_text())
CROSSWALK = json.loads((ROOT / "oscal_crosswalk_seed.json").read_text())
SOURCES = json.loads((ROOT / "regulatory-source-register.v0.2.0.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())

def digest(algorithm, fill="a"):
    lengths = {"SHA-256": 64, "SHA-384": 96, "SHA-512": 128, "SHA3-512": 128}
    return {"algorithm": algorithm, "value": "0x" + fill * lengths[algorithm]}

def payload(status="OBSERVED", value=0.25, band="AMBER", layer="real"):
    item = {
        "contract_version": "1.1.0",
        "index": {"id": "s_sys", "name": "S_sys", "semantics": "Provisional simulation index"},
        "current": {"observation_status": status, "value": value, "unit": "score_0_to_1", "band": band,
                    "window_id": "GIEN-DOSSIER-2026-314", "metric_definition_id": "s_sys",
                    "metric_definition_version": "0.2.0", "source_observation_ids": ["OBS-1"] if status == "OBSERVED" else []},
        "controls": [],
        "artifacts": [{"type": "SAMPLE", "dossier_id": "GIEN-DOSSIER-2026-314", "evidence_layer": layer,
                       "digest": digest("SHA-384"), "merkle_root": digest("SHA-384", "b")}],
        "verification": {"root_recomputable": False, "verification_status": "NOT_CHECKED"}
    }
    if status in ("UNKNOWN", "NOT_ESTIMATED", "NOT_ASSESSED"):
        item["artifacts"] = []
        item["current"].pop("source_observation_ids")
    return item

def test_schema_2020_12_and_observed_contract():
    Draft202012Validator.check_schema(SCHEMA)
    assert list(VALIDATOR.iter_errors(payload())) == []

def test_simulated_requires_simulation_layer_artifact():
    good = payload("SIMULATED", 0.2, "GREEN", "simulation")
    assert list(VALIDATOR.iter_errors(good)) == []
    bad = payload("SIMULATED", 0.2, "GREEN", "real")
    assert list(VALIDATOR.iter_errors(bad))

def test_unknown_not_estimated_and_not_assessed_are_null_not_green():
    for status, band in [("UNKNOWN", "UNKNOWN"), ("NOT_ESTIMATED", "NOT_ESTIMATED"), ("NOT_ASSESSED", "NOT_ASSESSED")]:
        assert list(VALIDATOR.iter_errors(payload(status, None, band))) == []
    bad = payload("UNKNOWN", 0, "GREEN")
    assert list(VALIDATOR.iter_errors(bad))

def test_digest_length_matches_algorithm():
    good = payload()
    good["artifacts"][0]["digest"] = digest("SHA-384")
    assert list(VALIDATOR.iter_errors(good)) == []
    bad = payload()
    bad["artifacts"][0]["digest"] = {"algorithm": "SHA-384", "value": "0x" + "a" * 64}
    assert list(VALIDATOR.iter_errors(bad))

def test_observed_requires_source_ids_and_artifacts():
    bad = payload()
    bad["current"]["source_observation_ids"] = []
    assert list(VALIDATOR.iter_errors(bad))
    bad = payload()
    bad["artifacts"] = []
    assert list(VALIDATOR.iter_errors(bad))

def test_metric_catalog_has_12_unique_definitions_and_explicit_unresolved_states():
    items = METRICS["metrics"]
    ids = [m["metric_id"] for m in items]
    assert len(items) == 12 and len(ids) == len(set(ids))
    by_id = {m["metric_id"]: m for m in items}
    for key in ("cgr_i", "ccr_i", "g_sri_vii"):
        assert by_id[key]["directionality"] == "UNRESOLVED"
        assert by_id[key]["scalar_display_allowed"] is False
    assert by_id["oscal_drift"]["value_kind"] == "structured_catalog_delta"
    assert by_id["oscal_drift"]["scalar_display_allowed"] is False
    assert {"event_definition", "prediction_horizon", "calibration_method"}.issubset(set(by_id["p_doom"]["required_methodology_fields"]))

def test_crosswalk_has_24_controls_and_separates_real_and_simulation_layers():
    controls = CROSSWALK["controls"]
    assert len(controls) == 24
    ids = [c["id"] for c in controls]
    assert len(ids) == len(set(ids))
    for c in controls:
        if c["layer"] == "simulation":
            assert c["mapping_status"] == "SIMULATION_ONLY"
            assert set(c["regimes"]).issubset(set(CROSSWALK["regimes_simulation"]))
        else:
            assert c["mapping_status"] == "PROPOSED_UNREVIEWED"

def test_sr26_2_current_and_sr11_7_historical_only():
    assert "SR_26_2" in CROSSWALK["regimes_real"]
    assert "SR_11_7" not in CROSSWALK["regimes_real"]
    assert "SR_11_7" in CROSSWALK["regimes_historical"]
    by_id = {c["id"]: c for c in CROSSWALK["controls"]}
    assert "SR_26_2" in by_id["MODEL-01"]["regimes"]
    assert "SR_11_7" not in by_id["MODEL-01"]["regimes"]

def test_analogy_only_is_not_a_direct_compliance_mapping():
    by_id = {c["id"]: c for c in CROSSWALK["controls"]}
    assert "SEC_17A4" not in by_id["CRYPT-01"]["regimes"]
    assert "SEC_17A4" in by_id["CRYPT-01"]["analogy_only"]

def test_source_register_tracks_mas_effective_date_and_fips203_role():
    by_id = {s["framework_id"]: s for s in SOURCES["sources"]}
    assert by_id["MAS_AI_RM_2026"]["effective_date"] == "2027-10-07"
    assert by_id["SR_11_7"]["status"] == "SUPERSEDED_BY_SR_26_2"
    assert "key-encapsulation" in by_id["FIPS_203"]["applicability_note"].lower()
