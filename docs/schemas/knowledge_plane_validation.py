#!/usr/bin/env python3
"""Validate Knowledge Plane schemas, examples, and cross-record governance invariants."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from jsonschema import FormatChecker

from _validation_deps import require_jsonschema

ROOT = Path(__file__).resolve().parents[2]
PLANE_ROOT = ROOT / "docs" / "knowledge-plane"
STATUS_RANK = {"SIMULATED": 0, "UNVERIFIED": 1, "OBSERVED": 2, "VERIFIED": 3, "INDEPENDENTLY_ASSURED": 4}
SENSITIVE_QUERY_KEYS = {
    "access_token", "api_key", "apikey", "auth", "authorization", "client_secret",
    "code", "credential", "key", "password", "refresh_token", "secret", "signature",
    "sig", "token",
}


class ValidationFailure(ValueError):
    """Raised when a schema or governance invariant fails."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationFailure(f"Unable to load JSON at {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationFailure(f"Expected a JSON object at {path}")
    return value


def _validate_instance(instance: dict[str, Any], schema: dict[str, Any], label: str) -> None:
    validator_cls = require_jsonschema()
    validator_cls.check_schema(schema)
    validator = validator_cls(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda error: (list(error.absolute_path), error.message))
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "<root>"
        raise ValidationFailure(f"{label} schema error at {location}: {first.message}")


def _reject_secret_bearing_uri(uri: str, label: str) -> None:
    parsed = urlsplit(uri)
    if parsed.username is not None or parsed.password is not None:
        raise ValidationFailure(f"{label} must not contain URI user-info credentials")
    sensitive = sorted({key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)} & SENSITIVE_QUERY_KEYS)
    if sensitive:
        raise ValidationFailure(f"{label} contains sensitive query parameter(s): {', '.join(sensitive)}")


def validate_cross_record_invariants(source: dict[str, Any], document: dict[str, Any], evidence: dict[str, Any]) -> None:
    """Enforce invariants that span multiple individually valid records."""
    source_id = source["source_id"]
    if document["source_id"] != source_id:
        raise ValidationFailure("Document version source_id does not match the source record")
    if document["source_revision"] != source["source"]["revision"]:
        raise ValidationFailure("Document source_revision does not match the registered source revision")
    if evidence["source_id"] != source_id:
        raise ValidationFailure("Evidence source_id does not match the source record")
    if evidence["document_id"] != document["document_id"]:
        raise ValidationFailure("Evidence document_id does not match the document version")
    if evidence["document_version_id"] != document["document_version_id"]:
        raise ValidationFailure("Evidence document_version_id does not match the exact document version")
    if evidence["source_content_sha256"] != source["source"]["content_sha256"]:
        raise ValidationFailure("Evidence source digest does not match the registered source digest")
    if evidence["document_content_sha256"] != document["content_sha256"]:
        raise ValidationFailure("Evidence document digest does not match the exact document-version digest")

    source_state = source["lifecycle"]["state"]
    acl_state = source["access_control"]["state"]
    if source_state == "active" and acl_state != "current":
        raise ValidationFailure("An active source must have a current ACL snapshot; retrieval must fail closed")
    if source_state == "active" and source["data_governance"]["license_status"] == "prohibited":
        raise ValidationFailure("A source with prohibited usage rights cannot be active")
    if document["lifecycle"]["state"] == "active":
        if source_state != "active":
            raise ValidationFailure("An active document version requires an active source record")
        if document["access_snapshot"]["state"] != "current":
            raise ValidationFailure("An active document version requires a current ACL snapshot")
    if source["data_governance"]["special_category_data_present"] and not source["data_governance"]["personal_data_present"]:
        raise ValidationFailure("Special-category data must also be classified as personal data")

    source_status = source["provenance"]["trust_status"]
    evidence_status = evidence["evidence_status"]
    if STATUS_RANK[evidence_status] > STATUS_RANK[source_status]:
        raise ValidationFailure("Evidence status cannot exceed the source trust status")
    if source_status in {"VERIFIED", "INDEPENDENTLY_ASSURED"}:
        if source.get("provenance", {}).get("verification", {}).get("result") != "pass":
            raise ValidationFailure("A verified or independently assured source requires a passing verification result")
    if evidence_status in {"VERIFIED", "INDEPENDENTLY_ASSURED"}:
        if evidence.get("verification", {}).get("result") != "pass":
            raise ValidationFailure("Verified evidence requires a passing verification result")

    _reject_secret_bearing_uri(source["source"]["uri"], "source.uri")


def validate_payloads(schemas: dict[str, dict[str, Any]], payloads: dict[str, dict[str, Any]]) -> None:
    """Validate schema conformance and the three-record referential contract."""
    for key in ("source", "document", "evidence"):
        _validate_instance(payloads[key], schemas[key], key)
    validate_cross_record_invariants(payloads["source"], payloads["document"], payloads["evidence"])


def run_validation(root: Path = ROOT) -> dict[str, Any]:
    plane_root = root / "docs" / "knowledge-plane"
    schemas = {
        "source": _load_json(plane_root / "schemas" / "source-record.schema.json"),
        "document": _load_json(plane_root / "schemas" / "document-version.schema.json"),
        "evidence": _load_json(plane_root / "schemas" / "evidence-reference.schema.json"),
    }
    for schema in schemas.values():
        require_jsonschema().check_schema(schema)
    payloads = {
        "source": _load_json(plane_root / "examples" / "source-record.simulated.json"),
        "document": _load_json(plane_root / "examples" / "document-version.simulated.json"),
        "evidence": _load_json(plane_root / "examples" / "evidence-reference.simulated.json"),
    }
    validate_payloads(schemas, payloads)
    return {
        "status": "PASS",
        "schema_version": "1.0.0",
        "schemas_checked": len(schemas),
        "example_records_checked": len(payloads),
        "cross_record_invariants": "PASS",
        "evidence_status": "SIMULATED",
        "operational_connectors_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root")
    parser.add_argument("--quiet", action="store_true", help="Print only the final status")
    args = parser.parse_args()
    try:
        result = run_validation(args.root.resolve())
    except (ValidationFailure, SystemExit) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    if args.quiet:
        print("[OK] Knowledge-plane schemas, examples, and cross-record invariants validated")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
