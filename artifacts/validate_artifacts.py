"""Validation utility for governance artifacts.

Checks include:
- JSON parse checks
- YAML parse checks
- XML parse and required section checks
- Minimal JSON-Schema-like validation for the Annex IV example payload
- Cross-reference checks for control mappings
- Roadmap milestone date-range checks for 2026-2030 horizon
- Manifest checksum verification for tamper evidence
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path
import xml.etree.ElementTree as ET

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


def validate_roadmap(roadmap: dict) -> None:
    validate_required_keys(roadmap, ["version", "name", "horizon", "phases", "milestones"], "roadmap")
    for milestone in roadmap["milestones"]:
        validate_required_keys(milestone, ["id", "date", "deliverable"], "milestone")
        milestone_date = milestone["date"]
        if not isinstance(milestone_date, date):
            milestone_date = date.fromisoformat(str(milestone_date))
        if milestone_date.year < 2026 or milestone_date.year > 2030:
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

    checks = {
        "schema_documents": "pass",
        "annex_iv_example": "pass",
        "control_catalog": "pass",
        "roadmap": "pass",
        "report_template": "pass",
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
