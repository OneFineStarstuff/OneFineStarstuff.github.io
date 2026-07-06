"""Validation utility for governance artifacts.

Checks include:
- JSON parse checks
- YAML parse checks
- XML parse and required section checks
- Minimal JSON-Schema-like validation for the Annex IV example payload
- Cross-reference checks for control mappings
- Roadmap milestone date-range checks for 2026-2030 and 2026-2035 horizons
- Extended AGI/ASI governance artifact checks for report tags, OSCAL controls,
  regulatory mappings, Rego gates, TLA+ specs, Circom circuits, and templates
- Manifest checksum verification for tamper evidence
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from datetime import date, datetime
from pathlib import Path
from uuid import UUID

import yaml

ARTIFACTS_DIR = Path(__file__).resolve().parent

if __package__ in (None, ""):
    from manifest_utils import load_manifest_targets_from_dir, sha256_file
else:
    from .manifest_utils import load_manifest_targets_from_dir, sha256_file
REQUIRED_REPORT_SECTION_IDS = {
    "scope",
    "obligations",
    "annex_iv",
    "control-testing",
    "safety-evals",
    "incidents",
    "attestation",
}

REQUIRED_EXTENDED_REPORT_SECTION_IDS = {
    "scope",
    "architecture",
    "obligations",
    "annex_iv",
    "model-risk",
    "safety-evals",
    "zk-proofs",
    "incidents",
    "attestation",
}

REQUIRED_REGULATORY_MAPPING_FRAMEWORKS = {
    "EU AI Act Annex IV",
    "EU AI Act GPAI systemic risk",
    "NIST AI RMF 1.0",
    "NIST AI 600-1",
    "ISO/IEC 42001",
    "Basel III IV",
    "SR 11-7",
    "DORA",
    "NIS2",
    "GDPR",
    "FCRA ECOA",
    "MAS HKMA FEAT",
    "FCA SMCR Consumer Duty",
    "ICGC GASO",
}


def load_manifest_targets() -> set[str]:
    try:
        return set(load_manifest_targets_from_dir(ARTIFACTS_DIR))
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc


class ValidationError(Exception):
    """Raised when one or more artifact validation checks fail."""


def display_artifact_path(path: Path) -> str:
    try:
        return str(path.relative_to(ARTIFACTS_DIR))
    except ValueError:
        return str(path)


def load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError as exc:
        raise ValidationError(f"required artifact file missing: {display_artifact_path(path)}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in artifact file: {display_artifact_path(path)}") from exc


def validate_required_keys(obj: dict, required: list[str], label: str) -> None:
    missing = [k for k in required if k not in obj]
    if missing:
        raise ValidationError(f"{label} missing keys: {missing}")


def ensure_type(value: object, expected: str, path: str) -> None:
    if expected == "object" and not isinstance(value, dict):
        raise ValidationError(f"{path} expected object")
    if expected == "array" and not isinstance(value, list):
        raise ValidationError(f"{path} expected array")
    if expected == "string" and not isinstance(value, str):
        raise ValidationError(f"{path} expected string")


def validate_change_log(change_log: list[dict]) -> None:
    for idx, item in enumerate(change_log):
        ensure_type(item, "object", f"change_log[{idx}]")
        validate_required_keys(item, ["date", "change", "approver"], f"change_log[{idx}]")
        try:
            date.fromisoformat(item["date"])
        except ValueError as exc:
            raise ValidationError(f"change_log[{idx}].date is not valid ISO date") from exc


def validate_annex_iv_example(schema: dict, example: dict) -> None:
    validate_required_keys(example, schema.get("required", []), "annex-iv example")

    provider_schema = schema["properties"]["provider"]
    provider = example["provider"]
    ensure_type(provider, provider_schema["type"], "provider")
    validate_required_keys(provider, provider_schema["required"], "provider")

    system_schema = schema["properties"]["system"]
    system = example["system"]
    ensure_type(system, system_schema["type"], "system")
    validate_required_keys(system, system_schema["required"], "system")

    for key in ["intended_purpose", "architecture", "training_data", "performance", "oversight", "post_market_monitoring"]:
        ensure_type(example[key], "string", key)

    allowed_tiers = set(system_schema["properties"]["risk_tier"]["enum"])
    tier = system["risk_tier"]
    if tier not in allowed_tiers:
        raise ValidationError(f"invalid risk_tier: {tier}")

    ensure_type(example["change_log"], "array", "change_log")
    validate_change_log(example["change_log"])


def validate_control_catalog(controls: dict) -> None:
    validate_required_keys(controls, ["version", "catalog", "control_domains", "mappings"], "control catalog")

    known_control_ids: set[str] = set()
    for domain in controls["control_domains"]:
        validate_required_keys(domain, ["domain", "controls"], "control_domain")
        for control in domain["controls"]:
            validate_required_keys(control, ["id", "owner", "test_frequency", "severity_if_failed"], "control")
            known_control_ids.add(control["id"])

    for mapping_name, mapped_ids in controls["mappings"].items():
        for control_id in mapped_ids:
            if control_id not in known_control_ids:
                raise ValidationError(f"mapping {mapping_name} references unknown control id: {control_id}")


def validate_roadmap(roadmap: dict, *, min_year: int = 2026, max_year: int = 2030) -> None:
    validate_required_keys(roadmap, ["version", "name", "horizon", "phases", "milestones"], "roadmap")
    phase_ids: set[str] = set()
    for phase in roadmap["phases"]:
        validate_required_keys(phase, ["id", "window", "outcomes" if max_year > 2030 else "objectives"], "roadmap phase")
        if phase["id"] in phase_ids:
            raise ValidationError(f"duplicate roadmap phase id: {phase['id']}")
        phase_ids.add(phase["id"])
    milestone_ids: set[str] = set()
    for milestone in roadmap["milestones"]:
        validate_required_keys(milestone, ["id", "date", "deliverable"], "milestone")
        if milestone["id"] in milestone_ids:
            raise ValidationError(f"duplicate roadmap milestone id: {milestone['id']}")
        milestone_ids.add(milestone["id"])
        milestone_date = milestone["date"]
        if not isinstance(milestone_date, date):
            milestone_date = date.fromisoformat(str(milestone_date))
        if milestone_date.year < min_year or milestone_date.year > max_year:
            raise ValidationError(f"milestone {milestone['id']} has out-of-range date: {milestone_date}")


def validate_report_template(path: Path) -> None:
    tree = ET.parse(path)
    root = tree.getroot()
    content = root.find("content")
    if content is None:
        raise ValidationError("regulator report template missing <content> element")

    section_ids = {section.attrib.get("id") for section in content.findall("section")}
    missing = REQUIRED_REPORT_SECTION_IDS - section_ids
    if missing:
        raise ValidationError(f"regulator report template missing section ids: {sorted(missing)}")



def validate_balanced_delimiters(text: str, path: Path, pairs: dict[str, str]) -> None:
    stack: list[str] = []
    openers = set(pairs)
    closers = {close: open_ for open_, close in pairs.items()}
    for char in text:
        if char in openers:
            stack.append(char)
        elif char in closers:
            if not stack or stack[-1] != closers[char]:
                raise ValidationError(f"{display_artifact_path(path)} has unbalanced delimiter: {char}")
            stack.pop()
    if stack:
        raise ValidationError(f"{display_artifact_path(path)} has unclosed delimiter: {stack[-1]}")


def validate_extended_markdown_report(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValidationError(f"required artifact file missing: {display_artifact_path(path)}") from exc
    for tag in ["title", "abstract", "content"]:
        if f"<{tag}>" not in text or f"</{tag}>" not in text:
            raise ValidationError(f"extended report missing <{tag}> tag pair")
    required_phrases = [
        "Sentinel AI Governance Stack v2.4",
        "Omni-Sentinel containment",
        "Zero-knowledge regulatory compliance",
        "Kafka-based PQC WORM audit logging",
        "ICGC Phase 1 and Phase 2 zk-verified controls",
    ]
    for phrase in required_phrases:
        if phrase not in text:
            raise ValidationError(f"extended report missing required topic: {phrase}")


def validate_extended_report_template(path: Path) -> None:
    tree = ET.parse(path)
    root = tree.getroot()
    if root.tag != "report":
        raise ValidationError("extended regulator report template root must be <report>")
    if root.find("title") is None or root.find("abstract") is None:
        raise ValidationError("extended regulator report template missing title or abstract")
    content = root.find("content")
    if content is None:
        raise ValidationError("extended regulator report template missing <content> element")
    section_ids = {section.attrib.get("id") for section in content.findall("section")}
    missing = REQUIRED_EXTENDED_REPORT_SECTION_IDS - section_ids
    if missing:
        raise ValidationError(f"extended regulator report template missing section ids: {sorted(missing)}")


def validate_oscal_catalog(catalog: dict) -> None:
    validate_required_keys(catalog, ["catalog"], "OSCAL catalog document")
    root = catalog["catalog"]
    validate_required_keys(root, ["uuid", "metadata", "groups"], "OSCAL catalog")
    try:
        UUID(root["uuid"])
    except (TypeError, ValueError) as exc:
        raise ValidationError("OSCAL catalog uuid must be a valid UUID") from exc
    validate_required_keys(root["metadata"], ["title", "last-modified", "version", "oscal-version", "roles"], "OSCAL metadata")
    try:
        datetime.fromisoformat(root["metadata"]["last-modified"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("OSCAL metadata last-modified must be valid ISO-8601") from exc
    control_ids: set[str] = set()
    for group in root["groups"]:
        validate_required_keys(group, ["id", "title", "controls"], "OSCAL group")
        for control in group["controls"]:
            validate_required_keys(control, ["id", "title", "props", "parts"], "OSCAL control")
            if control["id"] in control_ids:
                raise ValidationError(f"duplicate OSCAL control id: {control['id']}")
            control_ids.add(control["id"])
            if not any(prop.get("name") == "maps-to" for prop in control["props"]):
                raise ValidationError(f"OSCAL control {control['id']} missing maps-to property")
    required_controls = {"SG-01", "SG-02", "OC-01", "OC-02", "ZA-01", "ZA-02"}
    missing_controls = required_controls - control_ids
    if missing_controls:
        raise ValidationError(f"OSCAL catalog missing required controls: {sorted(missing_controls)}")


def validate_regulatory_mapping_csv(path: Path) -> None:
    try:
        with path.open("r", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError as exc:
        raise ValidationError(f"required artifact file missing: {display_artifact_path(path)}") from exc
    required_headers = {"framework", "control_objective", "technical_artifact", "evidence_source", "primary_owner", "cadence"}
    if not rows:
        raise ValidationError("regulatory mapping CSV must contain at least one row")
    if set(rows[0].keys()) != required_headers:
        raise ValidationError("regulatory mapping CSV headers do not match required schema")
    frameworks = {row["framework"] for row in rows}
    missing = REQUIRED_REGULATORY_MAPPING_FRAMEWORKS - frameworks
    if missing:
        raise ValidationError(f"regulatory mapping CSV missing frameworks: {sorted(missing)}")
    for idx, row in enumerate(rows, start=2):
        for header in required_headers:
            if not row[header].strip():
                raise ValidationError(f"regulatory mapping CSV row {idx} has empty {header}")


def validate_rego_policy(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValidationError(f"required artifact file missing: {display_artifact_path(path)}") from exc
    validate_balanced_delimiters(text, path, {"{": "}", "[": "]", "(": ")"})
    required_snippets = [
        "package sentinel.release.v24",
        "default allow := false",
        "deny contains msg if",
        "model_validation_approved if",
        "zk_proof_verified if",
        "annex_iv_complete",
        "gpai_supplier_due_diligence_complete",
        "egress_default_deny",
        "kill_switch_tested",
        "g_sri_score",
    ]
    for snippet in required_snippets:
        if snippet not in text:
            raise ValidationError(f"Rego release gate missing snippet: {snippet}")


def validate_tla_spec(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValidationError(f"required artifact file missing: {display_artifact_path(path)}") from exc
    if text.count("(*") != text.count("*)"):
        raise ValidationError("TLA+ containment spec has unbalanced comments")
    required_snippets = [
        "MODULE OmniSentinelContainment",
        "Vars ==",
        "Fairness ==",
        "NoUnapprovedEgress ==",
        "KillSwitchEventuallyStopsActuation ==",
        "NoPrivilegedSelfModification ==",
        "WitnessConfidentiality ==",
        "THEOREM Spec => []NoUnapprovedEgress",
        "THEOREM Spec => KillSwitchEventuallyStopsActuation",
        "THEOREM Spec => []NoPrivilegedSelfModification",
        "THEOREM Spec => []WitnessConfidentiality",
    ]
    for snippet in required_snippets:
        if snippet not in text:
            raise ValidationError(f"TLA+ containment spec missing snippet: {snippet}")


def validate_circom_circuit(path: Path) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValidationError(f"required artifact file missing: {display_artifact_path(path)}") from exc
    validate_balanced_delimiters(text, path, {"{": "}", "[": "]", "(": ")"})
    required_snippets = [
        "pragma circom 2.1.6;",
        "template GSRIWeightedSum(n)",
        "signal output inBand;",
        "publicPolicyVersion",
        "publicEvidenceCommitment",
        "component main {public [thresholdLow, thresholdHigh, policyVersion, evidenceCommitment]}",
    ]
    for snippet in required_snippets:
        if snippet not in text:
            raise ValidationError(f"Circom G-SRI circuit missing snippet: {snippet}")


def validate_gc_ir_event(event: dict) -> None:
    validate_required_keys(event, ["schema_version", "event_type", "event_id", "submitted_at", "institution_id", "system_id", "jurisdictions", "proof", "selective_disclosure", "signatures"], "GC-IR event")
    if event["event_type"] != "zk_compliance_proof_submission":
        raise ValidationError("GC-IR event_type must be zk_compliance_proof_submission")
    try:
        datetime.fromisoformat(event["submitted_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("GC-IR submitted_at must be valid ISO-8601") from exc
    ensure_type(event["jurisdictions"], "array", "GC-IR jurisdictions")
    proof = event["proof"]
    validate_required_keys(proof, ["proof_id", "circuit_id", "proving_system", "public_signals", "verifier_result"], "GC-IR proof")
    if proof["verifier_result"] != "verified":
        raise ValidationError("GC-IR proof verifier_result must be verified")
    ensure_type(event["signatures"], "array", "GC-IR signatures")
    if not event["signatures"]:
        raise ValidationError("GC-IR event requires at least one signature placeholder")


def validate_extended_artifacts() -> None:
    validate_extended_markdown_report(ARTIFACTS_DIR / "enterprise-agi-asi-governance-reference-architecture-2026-2035.md")
    with (ARTIFACTS_DIR / "roadmap-2026-2035.yaml").open("r", encoding="utf-8") as f:
        validate_roadmap(yaml.safe_load(f), min_year=2026, max_year=2035)
    validate_regulatory_mapping_csv(ARTIFACTS_DIR / "data" / "multi_jurisdiction_regulatory_mapping_2026_2035.csv")
    validate_oscal_catalog(load_json(ARTIFACTS_DIR / "oscal" / "sentinel-ai-control-catalog-oscal.json"))
    validate_rego_policy(ARTIFACTS_DIR / "policies" / "sentinel_ai_release_gate_v24.rego")
    validate_tla_spec(ARTIFACTS_DIR / "tla" / "OmniSentinelContainment.tla")
    validate_circom_circuit(ARTIFACTS_DIR / "circuits" / "g_sri_systemic_risk.circom")
    validate_gc_ir_event(load_json(ARTIFACTS_DIR / "templates" / "gc-ir-bridge-event.json"))
    validate_extended_report_template(ARTIFACTS_DIR / "templates" / "regulator-technical-report-2035.xml")


def validate_manifest(artifacts_dir: Path, manifest: dict) -> None:
    validate_required_keys(manifest, ["version", "generated_at", "files"], "manifest")
    if manifest.get("version") != "1.1":
        raise ValidationError("manifest version must be 1.1")

    try:
        datetime.fromisoformat(manifest["generated_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("manifest generated_at is not valid ISO-8601") from exc

    manifest_files = set(manifest["files"].keys())
    expected_manifest_files = load_manifest_targets()
    missing = expected_manifest_files - manifest_files
    extra = manifest_files - expected_manifest_files
    if missing or extra:
        raise ValidationError(
            "manifest file coverage mismatch: "
            f"missing={sorted(missing)} extra={sorted(extra)}"
        )

    for relative_path, expected_hash in manifest["files"].items():
        file_path = artifacts_dir / relative_path
        if not file_path.exists():
            raise ValidationError(f"manifest references missing file: {relative_path}")
        actual_hash = sha256_file(file_path)
        if actual_hash != expected_hash:
            raise ValidationError(
                f"checksum mismatch for {relative_path}: expected {expected_hash}, got {actual_hash}"
            )


def validate_schema_documents() -> None:
    targets_schema = load_json(ARTIFACTS_DIR / "schemas" / "manifest-targets-schema-v1.json")
    manifest_schema = load_json(ARTIFACTS_DIR / "schemas" / "artifact-manifest-schema-v1.json")
    check_all_schema = load_json(ARTIFACTS_DIR / "schemas" / "check-all-result-schema-v1.json")

    validate_required_keys(targets_schema, ["$schema", "$id", "properties", "required"], "manifest-targets schema")
    validate_required_keys(manifest_schema, ["$schema", "$id", "properties", "required"], "artifact-manifest schema")
    validate_required_keys(check_all_schema, ["$schema", "$id", "properties", "required"], "check-all-result schema")


def run_validation(include_manifest: bool = True) -> dict:
    schema = load_json(ARTIFACTS_DIR / "annex-iv-dossier-schema-v1.json")
    controls = load_json(ARTIFACTS_DIR / "control-catalog-v1.json")
    example = load_json(ARTIFACTS_DIR / "examples" / "annex-iv-dossier-example.json")

    with (ARTIFACTS_DIR / "roadmap-2026-2030.yaml").open("r", encoding="utf-8") as f:
        roadmap = yaml.safe_load(f)

    validate_schema_documents()
    validate_annex_iv_example(schema, example)
    validate_control_catalog(controls)
    validate_roadmap(roadmap)
    validate_report_template(ARTIFACTS_DIR / "regulator-report-template.xml")
    validate_extended_artifacts()

    checks = {
        "schema_documents": "pass",
        "annex_iv_example": "pass",
        "control_catalog": "pass",
        "roadmap": "pass",
        "report_template": "pass",
        "extended_2026_2035_artifacts": "pass",
        "manifest": "skipped",
    }

    if include_manifest:
        manifest = load_json(ARTIFACTS_DIR / "artifact-manifest-v1.json")
        validate_manifest(ARTIFACTS_DIR, manifest)
        checks["manifest"] = "pass"

    return checks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate governance artifacts")
    parser.add_argument("--skip-manifest", action="store_true", help="Skip checksum manifest validation")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    parser.add_argument("--quiet", action="store_true", help="Suppress success message output")
    return parser.parse_args()


def run_cli(args: argparse.Namespace) -> int:
    try:
        checks = run_validation(include_manifest=not args.skip_manifest)
    except ValidationError as exc:
        if args.json:
            print(json.dumps({"status": "error", "error": str(exc)}, indent=2, sort_keys=True))
        else:
            print(f"Validation failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"status": "ok", "checks": checks}, indent=2, sort_keys=True))
        return 0

    if not args.quiet:
        print("All artifact validations passed.")
    return 0


def main() -> None:
    args = parse_args()
    raise SystemExit(run_cli(args))


if __name__ == "__main__":
    main()
