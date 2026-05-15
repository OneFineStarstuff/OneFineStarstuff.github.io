#!/usr/bin/env python3
"""Validate governance report artifacts for required XML-like wrappers and section anchors."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
README_PATH = ROOT / "docs/reports/README_GOVERNANCE_REPORTS.md"
MANIFEST_PATH = ROOT / "docs/reports/governance_reports_manifest.json"
MANIFEST_SCHEMA_PATH = ROOT / "docs/schemas/governance_reports_manifest.schema.json"

REPORT_RULES = {
    "docs/reports/INSTITUTIONAL_GRADE_AGI_ASI_GOVERNANCE_2026_2030.md": [
        "## 3. Regulatory Alignment Matrix (Control-Centric)",
        "## 4. Enterprise AI Reference Architecture (Design + Build)",
        "## 5. AGI/ASI Safety and Containment Framework",
        "## 9. Implementation Roadmap (2026–2030)",
    ],
    "docs/reports/BOARD_BRIEF_AGI_ASI_GOVERNANCE_2026_2030.md": [
        "## 1) Board Decisions Required",
        "## 2) What the Board Should Review Quarterly",
    ],
    "docs/reports/REGULATOR_EXAM_PACK_AI_GOVERNANCE_2026_2030.md": [
        "## 1) Examination Packet Index",
        "## 2) Required Evidence Tables",
    ],
    "docs/reports/ENGINEERING_IMPLEMENTATION_PLAYBOOK_AI_GOVERNANCE_2026_2030.md": [
        "## 1) Build Priorities (First 90 Days)",
        "## 4) CI/CD Governance Gate Template",
    ],
}

REQUIRED_TAGS = ("<title>", "</title>", "<abstract>", "</abstract>", "<content>", "</content>")


def validate_file(path: Path, required_headings: list[str]) -> list[str]:
    errors: list[str] = []
    if not path.exists():
        return [f"missing file: {path}"]

    text = path.read_text(encoding="utf-8")

    for tag in REQUIRED_TAGS:
        if tag not in text:
            errors.append(f"{path}: missing tag {tag}")

    if text.count("<title>") != 1 or text.count("</title>") != 1:
        errors.append(f"{path}: expected exactly one <title> block")
    if text.count("<abstract>") != 1 or text.count("</abstract>") != 1:
        errors.append(f"{path}: expected exactly one <abstract> block")
    if text.count("<content>") != 1 or text.count("</content>") != 1:
        errors.append(f"{path}: expected exactly one <content> block")

    title_match = re.search(r"<title>\s*(.*?)\s*</title>", text, re.DOTALL)
    if not title_match or len(title_match.group(1).strip()) < 10:
        errors.append(f"{path}: title is empty or too short")

    for heading in required_headings:
        if heading not in text:
            errors.append(f"{path}: missing required heading '{heading}'")

    return errors


def validate_readme_index(path: Path, report_paths: list[str]) -> list[str]:
    errors: list[str] = []
    if not path.exists():
        return [f"missing file: {path}"]

    text = path.read_text(encoding="utf-8")
    for report_path in report_paths:
        name = Path(report_path).name
        if name not in text:
            errors.append(f"{path}: missing report reference '{name}'")

    if "governance_reports_manifest.json" not in text:
        errors.append(f"{path}: missing manifest reference 'governance_reports_manifest.json'")
    if "governance_reports_manifest.schema.json" not in text:
        errors.append(f"{path}: missing schema reference 'governance_reports_manifest.schema.json'")

    if "python3 -m unittest discover tool_tests" not in text:
        errors.append(f"{path}: missing unit test command in validation instructions")
    if "python3 tools/validate_governance_reports.py" not in text:
        errors.append(f"{path}: missing validator command in validation instructions")
    if "make governance-check" not in text:
        errors.append(f"{path}: missing make command 'make governance-check' in validation instructions")

    return errors


def _schema_required_sets(schema_path: Path) -> tuple[set[str], set[str], list[str]]:
    errors: list[str] = []
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return set(), set(), [f"{schema_path}: failed to read schema ({exc})"]

    root_required = set(schema.get("required", [])) if isinstance(schema, dict) else set()
    item_required: set[str] = set()
    if isinstance(schema, dict):
        props = schema.get("properties", {})
        reports_prop = props.get("reports", {}) if isinstance(props, dict) else {}
        items = reports_prop.get("items", {}) if isinstance(reports_prop, dict) else {}
        if isinstance(items, dict):
            item_required = set(items.get("required", []))

    if not root_required:
        errors.append(f"{schema_path}: could not determine root required fields")
    if not item_required:
        errors.append(f"{schema_path}: could not determine report item required fields")

    return root_required, item_required, errors


def validate_manifest(path: Path, report_paths: list[str], schema_path: Path | None = None) -> list[str]:
    errors: list[str] = []
    if not path.exists():
        return [f"missing file: {path}"]

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON ({exc})"]

    if not isinstance(data, dict):
        return [f"{path}: manifest root must be an object"]

    root_required = {"version", "report_pack", "reports"}
    item_required = {"path", "audience", "required"}
    if schema_path is not None and schema_path.exists():
        schema_root_required, schema_item_required, schema_errors = _schema_required_sets(schema_path)
        errors.extend(schema_errors)
        if schema_root_required:
            root_required = schema_root_required
        if schema_item_required:
            item_required = schema_item_required

    for field in sorted(root_required):
        if field not in data:
            errors.append(f"{path}: missing required manifest field '{field}'")

    version = data.get("version")
    if "version" in root_required and (not isinstance(version, str) or not version.strip()):
        errors.append(f"{path}: 'version' must be a non-empty string")

    report_pack = data.get("report_pack")
    if "report_pack" in root_required and (not isinstance(report_pack, str) or not report_pack.strip()):
        errors.append(f"{path}: 'report_pack' must be a non-empty string")

    reports = data.get("reports")
    if not isinstance(reports, list):
        return [f"{path}: 'reports' must be a list"]

    manifest_paths: set[str] = set()
    for idx, report in enumerate(reports):
        if not isinstance(report, dict):
            errors.append(f"{path}: reports[{idx}] must be an object")
            continue
        for field in sorted(item_required):
            if field not in report:
                errors.append(f"{path}: reports[{idx}] missing required field '{field}'")

        report_path = report.get("path")
        audience = report.get("audience")
        required = report.get("required")
        if not isinstance(report_path, str):
            errors.append(f"{path}: reports[{idx}].path must be a string")
        else:
            manifest_paths.add(report_path)
            abs_report_path = ROOT / report_path
            if not abs_report_path.exists():
                errors.append(f"{path}: reports[{idx}].path does not exist ({report_path})")
        if not isinstance(audience, str):
            errors.append(f"{path}: reports[{idx}].audience must be a string")
        if not isinstance(required, bool):
            errors.append(f"{path}: reports[{idx}].required must be a boolean")

    missing = set(report_paths) - manifest_paths
    if missing:
        errors.append(f"{path}: missing report entries {sorted(missing)}")
    unexpected = manifest_paths - set(report_paths)
    if unexpected:
        errors.append(f"{path}: unexpected report entries {sorted(unexpected)}")

    return errors


def validate_manifest_schema(path: Path) -> list[str]:
    errors: list[str] = []
    if not path.exists():
        return [f"missing file: {path}"]

    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON ({exc})"]

    if not isinstance(schema, dict):
        return [f"{path}: schema root must be an object"]

    required = schema.get("required")
    if not isinstance(required, list):
        return [f"{path}: schema 'required' must be a list"]

    expected_root_required = {"version", "report_pack", "reports"}
    missing_root_required = expected_root_required - set(required)
    if missing_root_required:
        errors.append(
            f"{path}: schema missing root required fields {sorted(missing_root_required)}"
        )

    props = schema.get("properties")
    if not isinstance(props, dict):
        return [f"{path}: schema 'properties' must be an object"]

    reports_prop = props.get("reports")
    if not isinstance(reports_prop, dict):
        return [f"{path}: schema missing 'reports' property definition"]

    items = reports_prop.get("items")
    if not isinstance(items, dict):
        return [f"{path}: schema 'reports.items' must be an object"]

    item_required = items.get("required")
    if not isinstance(item_required, list):
        return [f"{path}: schema 'reports.items.required' must be a list"]

    expected_item_required = {"path", "audience", "required"}
    missing_item_required = expected_item_required - set(item_required)
    if missing_item_required:
        errors.append(
            f"{path}: schema missing report item required fields {sorted(missing_item_required)}"
        )

    return errors


def collect_validation_errors() -> tuple[list[str], int]:
    all_errors: list[str] = []
    report_count = 0
    for rel_path, headings in REPORT_RULES.items():
        all_errors.extend(validate_file(ROOT / rel_path, headings))
        report_count += 1
    all_errors.extend(validate_readme_index(README_PATH, list(REPORT_RULES.keys())))
    all_errors.extend(validate_manifest(MANIFEST_PATH, list(REPORT_RULES.keys()), MANIFEST_SCHEMA_PATH))
    all_errors.extend(validate_manifest_schema(MANIFEST_SCHEMA_PATH))
    return all_errors, report_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate governance report pack artifacts.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON output.",
    )
    args = parser.parse_args()

    all_errors, report_count = collect_validation_errors()

    if all_errors:
        if args.json:
            print(
                json.dumps(
                    {
                        "status": "failed",
                        "error_count": len(all_errors),
                        "errors": all_errors,
                    }
                )
            )
        else:
            print("Governance report validation failed:")
            for err in all_errors:
                print(f"- {err}")
        return 1

    if args.json:
        print(
            json.dumps(
                {
                    "status": "passed",
                    "validated_report_files": report_count,
                    "validated_index_files": 1,
                    "validated_manifest_files": 1,
                    "validated_schema_files": 1,
                }
            )
        )
    else:
        print("Governance report validation passed.")
        print(
            f"Validated {report_count} report files, 1 report index README, 1 manifest, and 1 schema."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
