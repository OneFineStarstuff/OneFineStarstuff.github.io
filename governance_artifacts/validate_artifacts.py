#!/usr/bin/env python3
"""Validation checks for governance artifacts."""
import json
import argparse
import re
from pathlib import Path
from typing import Any
from datetime import date, datetime, timezone

ROOT = Path(__file__).resolve().parent
REGIME_PATTERN = re.compile(r"^[a-z0-9_]+$")
VALIDATOR_VERSION = "1.0.0"


def get_checks():
    return [
        ("validate_control_library", validate_control_library),
        ("validate_model_registry", validate_model_registry),
        ("validate_control_references", validate_control_references),
        ("validate_incident_taxonomy", validate_incident_taxonomy),
        ("validate_annex_iv_template", validate_annex_iv_template),
        ("validate_runbooks", validate_runbooks),
        ("validate_kpi_kri_schema", validate_kpi_kri_schema),
        ("validate_rego_policy", validate_rego_policy),
    ]


def load_json(path: Path):
    with path.open() as f:
        return json.load(f)


def load_yaml(path: Path):
    import yaml
    with path.open() as f:
        return yaml.safe_load(f)


def assert_keys(obj: dict[str, Any], keys, name):
    missing = [k for k in keys if k not in obj]
    if missing:
        raise AssertionError(f"{name}: missing keys {missing}")




def assert_type(value: Any, expected_type: type, name: str):
    if not isinstance(value, expected_type):
        raise AssertionError(f"{name}: expected {expected_type.__name__}, got {type(value).__name__}")


def assert_non_empty_list(value: Any, name: str):
    assert_type(value, list, name)
    if not value:
        raise AssertionError(f"{name}: list must not be empty")


def assert_iso_date(value: Any, name: str):
    if isinstance(value, date):
        return
    assert_type(value, str, name)
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise AssertionError(f"{name}: invalid ISO date {value}") from exc


def to_date(value: Any, name: str) -> date:
    if isinstance(value, date):
        return value
    assert_type(value, str, name)
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise AssertionError(f"{name}: invalid ISO date {value}") from exc

def validate_control_library():
    data = load_yaml(ROOT / "control_library.yaml")
    assert_keys(data, ["version", "last_updated", "controls"], "control_library")
    assert_iso_date(data["last_updated"], "control_library.last_updated")
    assert_non_empty_list(data["controls"], "control_library.controls")
    seen_control_ids: set[str] = set()
    for idx, control in enumerate(data["controls"]):
        assert_keys(control, ["id", "name", "mapped_regimes", "owner", "evidence"], f"control[{idx}]")
        assert_type(control["id"], str, f"control[{idx}].id")
        if control["id"] in seen_control_ids:
            raise AssertionError(f"duplicate control id detected: {control['id']}")
        seen_control_ids.add(control["id"])
        assert_non_empty_list(control["mapped_regimes"], f"control[{idx}].mapped_regimes")
        for regime in control["mapped_regimes"]:
            assert_type(regime, str, f"control[{idx}].mapped_regimes[]")
            if not REGIME_PATTERN.match(regime):
                raise AssertionError(f"control[{idx}].mapped_regimes contains invalid value '{regime}'")
        assert_non_empty_list(control["evidence"], f"control[{idx}].evidence")


def validate_model_registry():
    data = load_json(ROOT / "model_registry.json")
    assert_keys(data, ["registry_version", "generated_on", "models"], "model_registry")
    assert_iso_date(data["generated_on"], "model_registry.generated_on")
    assert_non_empty_list(data["models"], "model_registry.models")
    seen_model_ids: set[str] = set()
    for m in data["models"]:
        assert_keys(m, ["model_id", "use_case", "risk_tier", "deployment_status", "controls", "validation"], f"model:{m.get('model_id','unknown')}")
        assert_type(m["model_id"], str, f"model:{m.get('model_id','unknown')}.model_id")
        if m["model_id"] in seen_model_ids:
            raise AssertionError(f"duplicate model id detected: {m['model_id']}")
        seen_model_ids.add(m["model_id"])
        assert_non_empty_list(m["controls"], f"model:{m.get('model_id','unknown')}.controls")
        assert_keys(m["validation"], ["last_validation", "next_due", "independent_validation"], f"model:{m.get('model_id','unknown')}.validation")
        last_validation = to_date(m["validation"]["last_validation"], f"model:{m.get('model_id','unknown')}.validation.last_validation")
        next_due = to_date(m["validation"]["next_due"], f"model:{m.get('model_id','unknown')}.validation.next_due")
        if next_due < last_validation:
            raise AssertionError(f"model:{m.get('model_id','unknown')}.validation.next_due precedes last_validation")
        assert_type(m["validation"]["independent_validation"], bool, f"model:{m.get('model_id','unknown')}.validation.independent_validation")


def validate_control_references():
    control_library = load_yaml(ROOT / "control_library.yaml")
    model_registry = load_json(ROOT / "model_registry.json")
    control_ids = {ctrl.get("id") for ctrl in control_library.get("controls", [])}
    for model in model_registry.get("models", []):
        model_id = model.get("model_id", "unknown")
        for control_id in model.get("controls", []):
            assert_type(control_id, str, f"model:{model_id}.controls[]")
            if not control_id.strip():
                raise AssertionError(f"model:{model_id} contains blank control id reference")
            if control_id not in control_ids:
                raise AssertionError(f"model:{model_id} references missing control id {control_id}")


def validate_incident_taxonomy():
    data = load_json(ROOT / "incident_taxonomy_gaics.json")
    assert_keys(data, ["taxonomy", "version", "classes"], "incident_taxonomy")
    assert_non_empty_list(data["classes"], "incident_taxonomy.classes")


def validate_annex_iv_template():
    data = load_yaml(ROOT / "annex_iv_dossier_template.yaml")
    assert_keys(data, ["annex_iv_dossier"], "annex_iv_template")
    assert_type(data["annex_iv_dossier"], dict, "annex_iv_dossier")


def validate_runbooks():
    data = load_yaml(ROOT / "containment_runbooks.yaml")
    assert_keys(data, ["runbooks"], "containment_runbooks")
    assert_non_empty_list(data["runbooks"], "containment_runbooks.runbooks")
    seen_runbook_ids: set[str] = set()
    for r in data["runbooks"]:
        assert_keys(r, ["id", "trigger", "steps"], f"runbook:{r.get('id','unknown')}")
        assert_type(r["id"], str, f"runbook:{r.get('id','unknown')}.id")
        if r["id"] in seen_runbook_ids:
            raise AssertionError(f"duplicate runbook id detected: {r['id']}")
        seen_runbook_ids.add(r["id"])
        assert_type(r["trigger"], str, f"runbook:{r.get('id','unknown')}.trigger")
        if not r["trigger"].strip():
            raise AssertionError(f"runbook:{r.get('id','unknown')} has blank trigger")
        assert_non_empty_list(r["steps"], f"runbook:{r.get('id','unknown')}.steps")


def validate_kpi_kri_schema():
    data = load_json(ROOT / "board_kpi_kri_dashboard_schema.json")
    assert_keys(data, ["$schema", "title", "type", "properties", "required"], "kpi_kri_schema")
    assert_type(data["properties"], dict, "kpi_kri_schema.properties")
    assert_non_empty_list(data["required"], "kpi_kri_schema.required")
    for required_root in ("reporting_period", "kpis", "kris"):
        if required_root not in data["required"]:
            raise AssertionError(f"kpi_kri_schema.required missing {required_root}")
    for section in ("kpis", "kris"):
        if section not in data["properties"]:
            raise AssertionError(f"kpi_kri_schema.properties missing {section}")
        section_obj = data["properties"][section]
        assert_type(section_obj, dict, f"kpi_kri_schema.properties.{section}")
        assert_keys(section_obj, ["type", "properties", "required"], f"kpi_kri_schema.properties.{section}")
        assert_type(section_obj["properties"], dict, f"kpi_kri_schema.properties.{section}.properties")
        assert_non_empty_list(section_obj["required"], f"kpi_kri_schema.properties.{section}.required")


def validate_rego_policy():
    rego_path = ROOT / "rego" / "high_impact_credit.rego"
    if not rego_path.exists():
        raise AssertionError(f"rego policy missing: {rego_path}")
    text = rego_path.read_text()
    required = ["package gsifi.ai.credit", "default allow = false", "deny[msg] if"]
    for token in required:
        if token not in text:
            raise AssertionError(f"rego policy missing token: {token}")


def run_all_checks() -> dict[str, str]:
    checks = get_checks()
    results: dict[str, str] = {}
    for name, fn in checks:
        fn()
        results[name] = "PASS"
    return results


def run_selected_checks(check_names: list[str]) -> dict[str, str]:
    check_map = {name: fn for name, fn in get_checks()}
    deduped_check_names = list(dict.fromkeys(check_names))
    unknown = [name for name in deduped_check_names if name not in check_map]
    if unknown:
        raise AssertionError(f"unknown checks requested: {', '.join(unknown)}")
    results: dict[str, str] = {}
    for name in deduped_check_names:
        check_map[name]()
        results[name] = "PASS"
    return results


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Validate governance artifacts.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output.")
    parser.add_argument("--quiet", action="store_true", help="Suppress success output; failures still print.")
    parser.add_argument("--output", type=str, default="", help="Optional file path to write JSON result payload.")
    parser.add_argument("--list-checks", action="store_true", help="List available check names and exit.")
    parser.add_argument("--check", action="append", default=[], help="Run only the named check(s); repeatable.")
    parser.add_argument("--version", action="store_true", help="Print validator version and exit.")
    args = parser.parse_args(argv)

    if args.version:
        if args.json:
            print(json.dumps({"version": VALIDATOR_VERSION}, indent=2))
        else:
            print(VALIDATOR_VERSION)
        return

    if args.list_checks:
        checks = [name for name, _ in get_checks()]
        if args.json:
            print(json.dumps({"version": VALIDATOR_VERSION, "checks": checks}, indent=2))
        else:
            for check in checks:
                print(check)
        return

    try:
        results = run_selected_checks(args.check) if args.check else run_all_checks()
        payload = {
            "status": "PASS",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "checks": results,
        }
        if args.output:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        if args.json:
            print(json.dumps(payload, indent=2))
        elif not args.quiet:
            print("Governance artifacts validation: PASS")
    except AssertionError as exc:
        payload = {
            "status": "FAIL",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "error": str(exc),
        }
        if args.output:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"Governance artifacts validation: FAIL - {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
