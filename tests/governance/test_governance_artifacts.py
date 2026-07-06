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


# --- Round 6: verified distribution-bundle packager -------------------------

GA_PKG_DIR = ROOT / "governance_artifacts"


def _load_packager_module():
    # The packager lives in governance_artifacts/ and imports stdlib only.
    if str(GA_PKG_DIR) not in sys.path:
        sys.path.insert(0, str(GA_PKG_DIR))
    spec = importlib.util.spec_from_file_location(
        "package_distribution_bundle", GA_PKG_DIR / "package_distribution_bundle.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_distribution_bundle_manifest_is_tamper_evident():
    import hashlib

    pkg = _load_packager_module()
    # Use already-generated deliverables (other tests/suite produce them);
    # regenerate=False keeps this test fast and deterministic.
    manifest = pkg.build_manifest(with_suite=False, regenerate=False)["bundle"]

    # Exactly the three regulator deliverables, six pinned artifacts.
    assert manifest["summary"]["deliverables"] == 3
    assert manifest["summary"]["artifacts"] == 6
    assert manifest["summary"]["all_catalogs_conformant"] is True

    # Every artifact carries a real SHA-256 that matches the file on disk.
    for art in manifest["artifacts"]:
        p = ROOT / art["path"]
        assert p.exists(), f"artifact missing: {p}"
        assert pkg.sha256_file(p) == art["sha256"]

    # The bundle digest must recompute from the sorted per-artifact digests.
    basis = "".join(sorted(a["sha256"] for a in manifest["artifacts"])).encode()
    assert hashlib.sha256(basis).hexdigest() == manifest["bundle_sha256"]

    # Honesty: integrity statement disclaims certification; gaps are reported.
    assert "not a conformity assessment" in manifest["integrity_statement"].lower()
    assert manifest["summary"]["coverage_gaps"] >= 2  # DORA P4/P5 at minimum


def test_distribution_bundle_reports_dora_gaps_not_hidden():
    pkg = _load_packager_module()
    manifest = pkg.build_manifest(with_suite=False, regenerate=False)["bundle"]
    dora = next(d for d in manifest["deliverables"]
                if d["id"] == "dora-ict-risk-register")
    gap_ids = {g["id"] for g in dora["coverage_gaps"]}
    assert {"P4", "P5"} <= gap_ids
    # Annex IV and NIST report no coverage gaps in this state.
    annex = next(d for d in manifest["deliverables"]
                 if d["id"] == "eu-ai-act-annex-iv")
    assert annex["coverage_gaps"] == []


def test_distribution_bundle_refuses_nonconformant_deliverable(monkeypatch):
    pkg = _load_packager_module()
    orig = pkg.summarize_deliverable

    def broken(spec):
        s = orig(spec)
        if spec["id"] == "dora-ict-risk-register":
            s["catalog_conformance_failed"] = 3
        return s

    monkeypatch.setattr(pkg, "summarize_deliverable", broken)
    try:
        pkg.build_manifest(with_suite=False, regenerate=False)
        assert False, "packager must refuse a non-conformant deliverable"
    except ValueError as e:
        assert "refusing to package" in str(e)


def test_distribution_bundle_content_digest_is_reproducible():
    """content_digest must be stable across regenerations (timestamps normalized),
    while bundle_sha256 pins the exact build and may differ."""
    pkg = _load_packager_module()
    # Two independent regenerations with live evidence.
    m1 = pkg.build_manifest(with_suite=False, regenerate=True)["bundle"]
    m2 = pkg.build_manifest(with_suite=False, regenerate=True)["bundle"]

    # The reproducibility digest is identical across runs.
    assert m1["content_digest"] == m2["content_digest"], (
        "content_digest must be reproducible across regenerations")

    # content_digest recomputes from the per-artifact content_sha256 values.
    import hashlib
    basis = "".join(sorted(a["content_sha256"] for a in m1["artifacts"])).encode()
    assert hashlib.sha256(basis).hexdigest() == m1["content_digest"]

    # Every artifact exposes both a byte digest and a (different-purpose)
    # normalized content digest.
    for a in m1["artifacts"]:
        assert len(a["sha256"]) == 64
        assert len(a["content_sha256"]) == 64


def test_distribution_bundle_timestamp_normalization_changes_byte_digest_only():
    """A differing generated_at timestamp must change sha256 but NOT
    content_sha256 for the same logical artifact."""
    pkg = _load_packager_module()
    import hashlib

    sample = (b'{"generated_at": "2026-01-01T00:00:00Z", "x": 1}')
    other = (b'{"generated_at": "2030-12-31T23:59:59Z", "x": 1}')
    norm = lambda raw: hashlib.sha256(
        pkg._ISO_INSTANT_RE.sub(pkg._NORMALIZED_INSTANT, raw)).hexdigest()

    # Raw bytes differ -> raw digests differ.
    assert hashlib.sha256(sample).hexdigest() != hashlib.sha256(other).hexdigest()
    # Timestamp-normalized digests are identical.
    assert norm(sample) == norm(other)
    # A real content change still changes the normalized digest (falsifiable).
    changed = (b'{"generated_at": "2026-01-01T00:00:00Z", "x": 2}')
    assert norm(sample) != norm(changed)


# --------------------------------------------------------------------------
# Recipient-side bundle verifier (verify_distribution_bundle.py, 17th check)
# --------------------------------------------------------------------------

def _load_verifier_module():
    spec = importlib.util.spec_from_file_location(
        "verify_distribution_bundle", GA_PKG_DIR / "verify_distribution_bundle.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fresh_signed_bundle(tmp_path):
    """Package a signed bundle from the existing generated/ deliverables."""
    pkg = _load_packager_module()
    out_dir = tmp_path / "dist"
    manifest = pkg.build_manifest(with_suite=False, regenerate=False)
    pkg.write_bundle(manifest, out_dir)
    pkg.sign_manifest(out_dir / "MANIFEST.json")
    return out_dir


def test_bundle_verifier_verifies_a_freshly_packaged_signed_bundle(tmp_path):
    ver = _load_verifier_module()
    out_dir = _fresh_signed_bundle(tmp_path)

    report = ver.verify_bundle(out_dir, require_signature=True)["verification"]
    assert report["status"] == "VERIFIED", report["errors"]
    by_name = {c["check"]: c["status"] for c in report["checks"]}
    # Every named check must have executed and passed (signature included).
    for name in ("manifest-parse", "artifact-presence", "artifact-byte-digest",
                 "artifact-content-digest", "bundle-digest-recompute",
                 "content-digest-recompute", "digests-distinct",
                 "summary-consistency", "conformance-claims", "signature"):
        assert by_name.get(name) == "PASS", f"{name}: {by_name.get(name)}"


def test_bundle_verifier_is_independent_of_the_packager():
    """The verifier must not vouch for the packager by importing it: its
    digest rules are an independent re-implementation (stdlib only, with the
    optional dilithium-py signature check)."""
    import ast

    src = (GA_PKG_DIR / "verify_distribution_bundle.py").read_text()
    tree = ast.parse(src)
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
    # Never imports the packager (prose references in docstrings are fine).
    assert "package_distribution_bundle" not in imported_roots
    # stdlib only, plus the guarded optional dilithium_py signature import.
    allowed = {"__future__", "argparse", "hashlib", "json", "re", "sys",
               "pathlib", "dilithium_py"}
    assert imported_roots <= allowed, f"unexpected imports: {imported_roots - allowed}"
    # dilithium_py must be a guarded (non-top-level) import so the verifier
    # runs stdlib-only when the library is absent.
    top_level_roots = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_level_roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_level_roots.add(node.module.split(".")[0])
    assert "dilithium_py" not in top_level_roots


def test_bundle_verifier_detects_artifact_tampering(tmp_path):
    ver = _load_verifier_module()
    out_dir = _fresh_signed_bundle(tmp_path)

    target = out_dir / "artifacts" / "dora-ict-risk-register.md"
    target.write_bytes(target.read_bytes().replace(
        b"PENDING-EVIDENCE", b"SATISFIED-EVIDENC", 1))

    report = ver.verify_bundle(out_dir)["verification"]
    assert report["status"] == "FAILED"
    failed = {c["check"] for c in report["checks"] if c["status"] == "FAIL"}
    # Both the byte digest and the timestamp-normalized digest must trip.
    assert "artifact-byte-digest" in failed
    assert "artifact-content-digest" in failed


def test_bundle_verifier_detects_forged_manifest_claims(tmp_path):
    """A manifest that inflates units_satisfied or hides a declared coverage
    gap must FAIL summary-consistency — the verifier recomputes the claims
    from the bundled deliverable JSONs themselves."""
    ver = _load_verifier_module()
    out_dir = _fresh_signed_bundle(tmp_path)

    mpath = out_dir / "MANIFEST.json"
    m = json.loads(mpath.read_text())
    dora = next(d for d in m["bundle"]["deliverables"]
                if d["id"] == "dora-ict-risk-register")
    dora["units_satisfied"] = dora["units_total"]   # inflate
    dora["coverage_gaps"] = []                       # hide P4/P5
    m["bundle"]["summary"]["units_satisfied"] = m["bundle"]["summary"]["units_total"]
    m["bundle"]["summary"]["coverage_gaps"] = 0
    mpath.write_text(json.dumps(m, indent=2) + "\n")

    report = ver.verify_bundle(out_dir)["verification"]
    assert report["status"] == "FAILED"
    failed = {c["check"] for c in report["checks"] if c["status"] == "FAIL"}
    assert "summary-consistency" in failed
    # Editing MANIFEST.json also invalidates the detached signature.
    assert "signature" in failed


def test_bundle_verifier_detects_signature_tampering(tmp_path):
    """Any byte change to MANIFEST.json (even whitespace that leaves all
    digests recomputable) must invalidate the ML-DSA-65 signature."""
    ver = _load_verifier_module()
    out_dir = _fresh_signed_bundle(tmp_path)

    mpath = out_dir / "MANIFEST.json"
    mpath.write_text(mpath.read_text().replace(
        '"deliverables": 3', '"deliverables": 3 ', 1))

    report = ver.verify_bundle(out_dir, require_signature=True)["verification"]
    assert report["status"] == "FAILED"
    failed = {c["check"] for c in report["checks"] if c["status"] == "FAIL"}
    assert failed == {"signature"}, failed


def test_bundle_verifier_require_signature_fails_when_absent(tmp_path):
    ver = _load_verifier_module()
    pkg = _load_packager_module()
    out_dir = tmp_path / "dist"
    manifest = pkg.build_manifest(with_suite=False, regenerate=False)
    pkg.write_bundle(manifest, out_dir)  # NOT signed

    strict = ver.verify_bundle(out_dir, require_signature=True)["verification"]
    assert strict["status"] == "FAILED"
    assert any("MANIFEST.sig.json required" in e for e in strict["errors"])

    # Without --require-signature the absence is reported SKIPPED, not passed.
    lax = ver.verify_bundle(out_dir)["verification"]
    assert lax["status"] == "VERIFIED"
    sig = next(c for c in lax["checks"] if c["check"] == "signature")
    assert sig["status"] == "SKIPPED"


def test_packager_signing_key_is_persistent_and_verifiable(tmp_path):
    """--signing-key must yield a stable signer identity: two bundles signed
    with the same key file expose the same public-key fingerprint, and the
    detached signature verifies against the exact MANIFEST.json bytes."""
    pkg = _load_packager_module()
    key_file = tmp_path / "keys" / "mldsa65.json"

    fingerprints = []
    for i in range(2):
        out_dir = tmp_path / f"dist{i}"
        manifest = pkg.build_manifest(with_suite=False, regenerate=False)
        pkg.write_bundle(manifest, out_dir)
        sig = pkg.sign_manifest(out_dir / "MANIFEST.json", key_file=key_file)
        assert sig["alg"] == "ML-DSA-65"
        assert sig["key_persistence"] == "persistent"
        fingerprints.append(sig["public_key_sha256"])
    assert fingerprints[0] == fingerprints[1], "signer identity must be stable"

    # Key file is created with owner-only permissions.
    assert (key_file.stat().st_mode & 0o777) == 0o600

    # And the recipient-side verifier accepts both bundles in strict mode.
    ver = _load_verifier_module()
    for i in range(2):
        rep = ver.verify_bundle(tmp_path / f"dist{i}",
                                require_signature=True)["verification"]
        assert rep["status"] == "VERIFIED", rep["errors"]


# --- Round 8: evidence freshness-SLA gate ------------------------------------


def _load_freshness_module():
    if str(OSCAL_PKG_DIR) not in sys.path:
        sys.path.insert(0, str(OSCAL_PKG_DIR))
    spec = importlib.util.spec_from_file_location(
        "check_evidence_freshness", GA_PKG_DIR / "check_evidence_freshness.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _synthetic_ledger(mod, path, when=None, passed=True, skip_controls=()):
    """Write a well-formed ledger without executing any checks."""
    import crosswalk_common as cc
    when = when or mod.iso(mod.now_utc())
    entries = []
    for cid in sorted(cc.CONTROL_EVIDENCE):
        if cid in skip_controls:
            continue
        desc = cc.CONTROL_EVIDENCE[cid]
        entry = {"control_id": cid, "check": desc["check"],
                 "evidence_kind": desc["kind"], "command": desc["command"]}
        if desc["command"] is None:
            entry.update(passed=None, evidence_generated_at=None,
                         duration_seconds=None)
        else:
            entry.update(passed=passed, evidence_generated_at=when,
                         duration_seconds=1.0)
        entries.append(entry)
    doc = {"evidence_freshness_ledger": {
        "version": mod.LEDGER_VERSION,
        "generated_at": when,
        "generator": "test-synthetic",
        "digest_convention": "sha256 over canonical entries JSON",
        "entries": entries,
        "ledger_sha256": mod.ledger_digest(entries),
    }}
    path.write_text(json.dumps(doc, indent=2))
    return doc


def test_freshness_sla_parser_uses_stated_convention():
    mod = _load_freshness_module()
    assert mod.parse_sla_seconds("PT5M") == 300
    assert mod.parse_sla_seconds("P1D") == 86400
    assert mod.parse_sla_seconds("P7D") == 7 * 86400
    assert mod.parse_sla_seconds("P3M") == 90 * 86400        # 1M = 30d, stated
    assert mod.parse_sla_seconds("P1D/P90D") == 86400        # first period rules
    for bad in ("P", "PT", "5M", "P-1D", ""):
        try:
            mod.parse_sla_seconds(bad)
            assert False, f"accepted malformed SLA {bad!r}"
        except ValueError:
            pass


def test_freshness_audit_passes_on_fresh_ledger(tmp_path):
    mod = _load_freshness_module()
    ledger = tmp_path / "ledger.json"
    _synthetic_ledger(mod, ledger)

    rep = mod.audit_ledger(ledger)["freshness_audit"]
    assert rep["status"] == "PASS", rep["summary"]
    by = {r["control_id"]: r["status"] for r in rep["controls"]}
    # env-02 has organisational evidence only: disclosed, never counted fresh.
    assert by["env-02"] == "NOT-RUNNABLE"
    assert all(v == "FRESH" for k, v in by.items() if k != "env-02")
    assert rep["summary"]["not_runnable_disclosed"] == 1
    assert "not a certification" in rep["integrity_statement"].lower()


def test_freshness_audit_fails_when_evidence_goes_stale(tmp_path):
    """env-01 declares PT5M: auditing 10 minutes later must flip it STALE
    and fail the gate, while longer-SLA controls stay FRESH."""
    from datetime import timedelta
    mod = _load_freshness_module()
    ledger = tmp_path / "ledger.json"
    now = mod.now_utc()
    _synthetic_ledger(mod, ledger, when=mod.iso(now))

    rep = mod.audit_ledger(ledger, as_of=now + timedelta(minutes=10))[
        "freshness_audit"]
    assert rep["status"] == "FAIL"
    by = {r["control_id"]: r["status"] for r in rep["controls"]}
    assert by["env-01"] == "STALE"
    assert by["cry-05"] == "FRESH"          # P3M is nowhere near exceeded
    assert rep["summary"]["failing_controls"] == ["env-01"]


def test_freshness_audit_detects_ledger_tampering(tmp_path):
    """Editing a recorded timestamp without re-digesting must FAIL the
    ledger-digest check even if every control would otherwise be FRESH."""
    from datetime import timedelta
    mod = _load_freshness_module()
    ledger = tmp_path / "ledger.json"
    # Evidence recorded a minute ago (fresh for every declared SLA)...
    _synthetic_ledger(mod, ledger,
                      when=mod.iso(mod.now_utc() - timedelta(minutes=1)))

    doc = json.loads(ledger.read_text())
    entries = doc["evidence_freshness_ledger"]["entries"]
    victim = next(e for e in entries if e["command"])
    victim["evidence_generated_at"] = mod.iso(mod.now_utc())  # "refreshed"
    ledger.write_text(json.dumps(doc, indent=2))              # digest NOT updated

    rep = mod.audit_ledger(ledger)["freshness_audit"]
    assert rep["status"] == "FAIL"
    assert rep["ledger_digest_ok"] is False
    assert any("ledger-digest MISMATCH" in e for e in rep["errors"])


def test_freshness_audit_failed_check_is_never_fresh(tmp_path):
    mod = _load_freshness_module()
    ledger = tmp_path / "ledger.json"
    _synthetic_ledger(mod, ledger, passed=False)

    rep = mod.audit_ledger(ledger)["freshness_audit"]
    assert rep["status"] == "FAIL"
    runnable = [r for r in rep["controls"] if r["status"] != "NOT-RUNNABLE"]
    assert runnable and all(r["status"] == "FAILED" for r in runnable)


def test_freshness_audit_rejects_future_dated_and_missing_evidence(tmp_path):
    from datetime import timedelta
    mod = _load_freshness_module()

    # Future-dated evidence (forged timestamp / clock skew) is not FRESH.
    ledger = tmp_path / "future.json"
    future = mod.iso(mod.now_utc() + timedelta(hours=2))
    _synthetic_ledger(mod, ledger, when=future)
    rep = mod.audit_ledger(ledger)["freshness_audit"]
    assert rep["status"] == "FAIL"
    assert all(r["status"] == "FUTURE-DATED" for r in rep["controls"]
               if r["status"] != "NOT-RUNNABLE")

    # A runnable control missing from the ledger is NOT-RECORDED -> FAIL.
    ledger2 = tmp_path / "missing.json"
    _synthetic_ledger(mod, ledger2, skip_controls=("cry-02",))
    rep2 = mod.audit_ledger(ledger2)["freshness_audit"]
    assert rep2["status"] == "FAIL"
    by = {r["control_id"]: r["status"] for r in rep2["controls"]}
    assert by["cry-02"] == "NOT-RECORDED"

    # And a missing ledger file altogether fails, never passes vacuously.
    rep3 = mod.audit_ledger(tmp_path / "nope.json")["freshness_audit"]
    assert rep3["status"] == "FAIL"
    assert any("ledger not found" in e for e in rep3["errors"])


def test_freshness_gate_uses_the_shared_evidence_map():
    """The gate must audit the SAME control->check map the regulator
    deliverable generators use (single source of truth): every runnable
    CONTROL_EVIDENCE control with a declared freshness-sla is covered."""
    mod = _load_freshness_module()
    import crosswalk_common as cc

    catalog = cc.load_catalogs()
    runnable_with_sla = {cid for cid, d in cc.CONTROL_EVIDENCE.items()
                         if d["command"] and catalog[cid]["freshness_sla"]}
    assert runnable_with_sla, "no runnable controls with SLAs — map drift?"

    # The repo's committed ledger (written by --run) covers all of them.
    ledger_path = mod.DEFAULT_LEDGER
    assert ledger_path.is_file(), "run check_evidence_freshness.py --run first"
    led = json.loads(ledger_path.read_text())["evidence_freshness_ledger"]
    recorded = {e["control_id"] for e in led["entries"]
                if e["evidence_generated_at"]}
    assert runnable_with_sla <= recorded, (
        f"uncovered controls: {runnable_with_sla - recorded}")
