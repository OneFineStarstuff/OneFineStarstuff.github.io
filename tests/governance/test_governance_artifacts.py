import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]


def test_oscal_control_ids_are_unique_and_mapped():
    catalog_path = ROOT / "governance_artifacts/oscal/sentinel_control_catalog_v1.yaml"
    catalog = yaml.safe_load(catalog_path.read_text())

    control_ids = []
    for family in catalog["control_families"]:
        for control in family.get("controls", []):
            control_ids.append(control["id"])

    assert len(control_ids) == len(set(control_ids)), "Control IDs must be unique"

    mapped_control_ids = {m["control_id"] for m in catalog.get("mapping", [])}
    for cid in mapped_control_ids:
        assert cid in control_ids, f"Mapped control {cid} not found in catalog"


def test_rego_release_gate_references_catalog_controls():
    rego_path = ROOT / "governance_artifacts/rego/release_gate.rego"
    rego = rego_path.read_text()

    # Ensure core containment control and model validation control are hard-gated.
    assert 'input.controls["SAF-OMNI-001"] == true' in rego
    assert 'input.controls["MOD-SR11-7-VAL"] == true' in rego
    assert 'input.supervision.quorum >= 2' in rego


def test_proof_statement_example_matches_schema():
    schema_path = ROOT / "governance_artifacts/zk/proof_statement_schema.json"
    example_path = ROOT / "governance_artifacts/examples/proof_statement_example.json"

    schema = json.loads(schema_path.read_text())
    example = json.loads(example_path.read_text())

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(example), key=lambda e: e.path)
    assert not errors, "Proof statement example must validate against schema"


def test_regulatory_profile_controls_exist_in_catalog():
    profile_path = ROOT / "governance_artifacts/regulatory_profiles/eu_ai_act_annex_iv_profile.yaml"
    catalog_path = ROOT / "governance_artifacts/oscal/sentinel_control_catalog_v1.yaml"

    profile = yaml.safe_load(profile_path.read_text())
    catalog = yaml.safe_load(catalog_path.read_text())

    catalog_controls = {
        c["id"]
        for fam in catalog["control_families"]
        for c in fam.get("controls", [])
    }

    selected_controls = {entry["control"] for entry in profile["profile"].get("selects", [])}
    missing = selected_controls - catalog_controls
    assert not missing, f"Profile selects missing controls: {missing}"

def test_kafka_audit_event_schema_has_required_fields():
    schema_path = ROOT / "governance_artifacts/kafka/audit_event_schema.json"
    schema = json.loads(schema_path.read_text())

    required = set(schema.get("required", []))
    assert {"event_id", "timestamp", "control_id", "decision", "signature"}.issubset(required)


def test_release_gate_deny_fixture_is_non_compliant():
    deny_input_path = ROOT / "governance_artifacts/conftest/release_gate_policy_deny_test.yaml"
    deny_input = yaml.safe_load(deny_input_path.read_text())

    assert deny_input["controls"]["MOD-SR11-7-VAL"] is False
    assert deny_input["supervision"]["quorum"] < 2

def test_proof_schema_rejects_unknown_fields():
    schema_path = ROOT / "governance_artifacts/zk/proof_statement_schema.json"
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(schema)

    invalid = {
        "proof_id": "p1",
        "statement": "s",
        "proving_system": "groth16",
        "public_inputs": [],
        "verification": {"gc_ir_verifier": "v", "key_fingerprint": "k"},
        "unexpected": "nope"
    }

    errors = list(validator.iter_errors(invalid))
    assert errors, "Schema should reject additional top-level properties"


def test_kafka_schema_rejects_unknown_fields():
    schema_path = ROOT / "governance_artifacts/kafka/audit_event_schema.json"
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(schema)

    invalid = {
        "event_id": "e1",
        "timestamp": "2026-01-01T00:00:00Z",
        "control_id": "SAF-OMNI-001",
        "decision": "allow",
        "signature": {"algorithm": "ml-dsa", "value": "abc"},
        "extraneous": "nope"
    }

    errors = list(validator.iter_errors(invalid))
    assert errors, "Kafka schema should reject additional top-level properties"

def test_release_gate_allow_fixture_is_compliant():
    allow_input_path = ROOT / "governance_artifacts/conftest/release_gate_policy_test.yaml"
    allow_input = yaml.safe_load(allow_input_path.read_text())

    assert allow_input["controls"]["MOD-SR11-7-VAL"] is True
    assert allow_input["supervision"]["quorum"] >= 2
    assert allow_input["containment"]["mode"] == "ENFORCED"

def test_validator_writes_pass_report(tmp_path):
    import subprocess

    report_path = tmp_path / "report.json"
    subprocess.run(
        ["python", "tools/validate_governance_artifacts.py", "--report", str(report_path)],
        check=True,
        cwd=ROOT,
    )
    report = json.loads(report_path.read_text())
    assert report["status"] == "pass"
    assert "timestamp_utc" in report


# ---------------------------------------------------------------------------
# OSCAL catalog conformance (prop/href cross-reference integrity).
# These tests guard against the catalog's machine-readable links rotting:
# a tla-spec pointing at a renamed module, a dangling regime #href, an invalid
# feasibility tier, etc. They run the same validator wired into step 12 of
# run_runnable_assurance.sh, plus a negative test proving it is falsifiable.
# ---------------------------------------------------------------------------

OSCAL_VALIDATOR = "governance_artifacts/oscal/oscal_conformance.py"


def test_oscal_conformance_passes_on_repo_catalogs():
    import subprocess

    proc = subprocess.run(
        ["python", OSCAL_VALIDATOR, "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"OSCAL conformance failed:\n{proc.stdout}\n{proc.stderr}"
    report = json.loads(proc.stdout)
    assert report["failed"] == 0
    assert report["passed"] > 0
    # Every result must carry a structured shape.
    for r in report["results"]:
        assert {"check", "catalog", "control", "ok", "detail"} <= set(r)


def test_oscal_conformance_catches_broken_catalog(tmp_path):
    """Falsifiability: inject a dangling href, bad tla-spec, bad tier and bad
    SLA into a copy of a real catalog and confirm the validator fails."""
    import subprocess

    src = ROOT / "governance_artifacts/oscal/catalog_sentinel_v24_excerpt.json"
    doc = json.loads(src.read_text())
    ctrl = doc["catalog"]["groups"][0]["controls"][0]
    ctrl.setdefault("links", []).append({"rel": "regime", "href": "#nonexistent-anchor"})
    for p in ctrl["props"]:
        if p["name"] == "tla-spec":
            p["value"] = "ModuleThatDoesNotExist"
        if p["name"] == "feasibility-tier":
            p["value"] = "Z"
        if p["name"] == "freshness-sla":
            p["value"] = "not-a-duration"

    broken_dir = tmp_path / "oscal"
    broken_dir.mkdir()
    (broken_dir / "catalog_broken.json").write_text(json.dumps(doc))

    proc = subprocess.run(
        ["python", OSCAL_VALIDATOR, "--dir", str(broken_dir), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, "validator must fail on a broken catalog"
    report = json.loads(proc.stdout)
    assert report["failed"] >= 4
    failed_checks = {r["check"] for r in report["results"] if not r["ok"]}
    assert {"C2-tier", "C3-sla", "C4-tla", "C8-href"} <= failed_checks


# ---------------------------------------------------------------------------
# Annex IV dossier generator (OSCAL-native, auto-assembled regulator deliverable).
# Guards: every section maps to known controls; SATISFIED only on a green
# runnable check; the generator refuses unknown control ids (no dangling refs);
# the integrity statement is present (no overclaiming).
# ---------------------------------------------------------------------------

import importlib.util

DOSSIER_GEN = ROOT / "governance_artifacts/oscal/generate_annex_iv_dossier.py"


def _load_dossier_module():
    spec = importlib.util.spec_from_file_location("annex_iv_gen", DOSSIER_GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_annex_iv_section_map_controls_all_resolve():
    """Every control id referenced by the section map must exist in a catalog."""
    mod = _load_dossier_module()
    cfg = yaml.safe_load((ROOT / "governance_artifacts/oscal/annex_iv_section_map.yaml").read_text())
    controls = mod._load_catalogs(cfg["catalogs"])
    for sec in cfg["sections"]:
        for cid in sec.get("controls", []):
            assert cid in controls, f"section {sec['id']} references unknown control {cid}"


def test_annex_iv_dossier_assembles_with_live_evidence():
    mod = _load_dossier_module()
    dossier = mod.build_dossier(verify_evidence=True)["dossier"]

    # Eight Annex IV sections, all present and identified A-H.
    sec_ids = [s["id"] for s in dossier["sections"]]
    assert sec_ids == ["A", "B", "C", "D", "E", "F", "G", "H"]

    # Catalog conformance must be clean for assembly to be trustworthy.
    assert dossier["catalog_conformance"]["failed"] == 0

    # Integrity statement must disclaim conformity (no overclaiming).
    stmt = dossier["integrity_statement"].lower()
    assert "not a conformity assessment" in stmt
    assert "does not assert" in stmt

    # A SATISFIED section must have at least one control whose runnable check passed.
    for s in dossier["sections"]:
        if s["evidence_status"] == "SATISFIED":
            assert any(c["live_evidence"]["passed"] is True for c in s["controls"]), \
                f"section {s['id']} SATISFIED without any green check"


def test_annex_iv_no_verify_does_not_fabricate_satisfied():
    """Without running checks, no section may be reported SATISFIED."""
    mod = _load_dossier_module()
    dossier = mod.build_dossier(verify_evidence=False)["dossier"]
    assert all(s["evidence_status"] != "SATISFIED" for s in dossier["sections"]), \
        "sections must not be SATISFIED when backing checks were not executed"


# ---------------------------------------------------------------------------
# Multi-framework crosswalk deliverables (DORA ICT register + NIST AI RMF
# crosswalk) auto-assembled from the same verified OSCAL catalog. Guards:
# unknown control ids rejected; SATISFIED only on a green runnable check;
# coverage gaps reported honestly; --no-verify never fabricates SATISFIED.
# ---------------------------------------------------------------------------

OSCAL_PKG_DIR = ROOT / "governance_artifacts/oscal"


def _load_oscal_module(filename: str):
    # crosswalk_common must be importable by the generators.
    if str(OSCAL_PKG_DIR) not in sys.path:
        sys.path.insert(0, str(OSCAL_PKG_DIR))
    spec = importlib.util.spec_from_file_location(
        filename.replace(".py", ""), OSCAL_PKG_DIR / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


import sys  # noqa: E402  (used by _load_oscal_module)


def test_dora_register_assembles_with_gaps_reported():
    mod = _load_oscal_module("generate_dora_ict_register.py")
    reg = mod.build_register(verify_evidence=True)["dora_register"]

    assert reg["catalog_conformance"]["failed"] == 0
    # Five DORA pillars present.
    assert [p["id"] for p in reg["pillars"]] == ["P1", "P2", "P3", "P4", "P5"]
    # P4/P5 are coverage gaps (no in-scope control) — reported, not hidden.
    gaps = reg["summary"]["coverage_gaps"]
    assert "P4" in gaps and "P5" in gaps
    for p in reg["pillars"]:
        if p["is_coverage_gap"]:
            assert p["controls"] == []
            assert p["evidence_status"] == "PENDING-EVIDENCE"
        if p["evidence_status"] == "SATISFIED":
            assert any(c["live_evidence"]["passed"] is True for c in p["controls"])
    # Integrity statement must disclaim conformity.
    assert "not a dora conformity attestation" in reg["integrity_statement"].lower()


def test_nist_rmf_crosswalk_full_coverage_with_live_evidence():
    mod = _load_oscal_module("generate_nist_rmf_crosswalk.py")
    cw = mod.build_crosswalk(verify_evidence=True)["nist_rmf_crosswalk"]

    assert cw["catalog_conformance"]["failed"] == 0
    assert [f["id"] for f in cw["functions"]] == ["GOVERN", "MAP", "MEASURE", "MANAGE"]
    ca = cw["coverage_analysis"]
    # Every function maps to >=1 control (no uncovered functions in this map).
    assert ca["functions_uncovered"] == []
    for f in cw["functions"]:
        if f["evidence_status"] == "SATISFIED":
            assert any(c["live_evidence"]["passed"] is True for c in f["controls"])
    assert "not a certification" in cw["integrity_statement"].lower()


def test_crosswalk_generators_no_verify_do_not_fabricate_satisfied():
    dora = _load_oscal_module("generate_dora_ict_register.py")
    nist = _load_oscal_module("generate_nist_rmf_crosswalk.py")
    reg = dora.build_register(verify_evidence=False)["dora_register"]
    cw = nist.build_crosswalk(verify_evidence=False)["nist_rmf_crosswalk"]
    assert all(p["evidence_status"] != "SATISFIED" for p in reg["pillars"])
    assert all(f["evidence_status"] != "SATISFIED" for f in cw["functions"])
