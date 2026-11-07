"""Tests for the Knowledge Plane source/document/evidence contract."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from knowledge_plane_validation import ValidationFailure, _load_json, run_validation, validate_payloads  # noqa: E402

PLANE = ROOT / "docs" / "knowledge-plane"


def examples():
    return {
        "source": _load_json(PLANE / "examples" / "source-record.simulated.json"),
        "document": _load_json(PLANE / "examples" / "document-version.simulated.json"),
        "evidence": _load_json(PLANE / "examples" / "evidence-reference.simulated.json"),
    }


def schemas():
    return {
        "source": _load_json(PLANE / "schemas" / "source-record.schema.json"),
        "document": _load_json(PLANE / "schemas" / "document-version.schema.json"),
        "evidence": _load_json(PLANE / "schemas" / "evidence-reference.schema.json"),
    }


class KnowledgePlaneValidationTests(unittest.TestCase):
    def test_reference_examples_pass(self):
        result = run_validation(ROOT)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["schemas_checked"], 3)
        self.assertEqual(result["example_records_checked"], 3)
        self.assertFalse(result["operational_connectors_enabled"])

    def test_active_source_fails_closed_when_acl_is_stale(self):
        payload = examples()
        payload["source"]["access_control"]["state"] = "stale"
        with self.assertRaisesRegex(ValidationFailure, "current ACL snapshot"):
            validate_payloads(schemas(), payload)

    def test_evidence_must_reference_exact_document_version(self):
        payload = examples()
        payload["evidence"]["document_version_id"] = "00000000-0000-4000-8000-000000000099"
        with self.assertRaisesRegex(ValidationFailure, "exact document version"):
            validate_payloads(schemas(), payload)

    def test_evidence_digest_must_match_exact_document_bytes(self):
        payload = examples()
        payload["evidence"]["document_content_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValidationFailure, "exact document-version digest"):
            validate_payloads(schemas(), payload)

    def test_secret_bearing_source_uri_is_rejected(self):
        payload = examples()
        payload["source"]["source"]["uri"] = "https://example.invalid/file?access_token=never-store"
        with self.assertRaisesRegex(ValidationFailure, "sensitive query parameter"):
            validate_payloads(schemas(), payload)

    def test_verified_evidence_requires_verification_record(self):
        payload = examples()
        payload["evidence"]["evidence_status"] = "VERIFIED"
        with self.assertRaises(ValidationFailure):
            validate_payloads(schemas(), payload)

    def test_evidence_cannot_overstate_source_assurance(self):
        payload = examples()
        payload["evidence"]["evidence_status"] = "OBSERVED"
        with self.assertRaisesRegex(ValidationFailure, "cannot exceed the source trust status"):
            validate_payloads(schemas(), payload)

    def test_special_category_data_requires_personal_data_classification(self):
        payload = examples()
        payload["source"]["data_governance"]["special_category_data_present"] = True
        payload["source"]["data_governance"]["special_category_condition_ref"] = "gdpr-art9-condition:review-required"
        with self.assertRaisesRegex(ValidationFailure, "must also be classified as personal data"):
            validate_payloads(schemas(), payload)

    def test_document_cannot_remain_active_after_source_revocation(self):
        payload = examples()
        payload["source"]["lifecycle"]["state"] = "revoked"
        payload["source"]["access_control"]["state"] = "revoked"
        with self.assertRaisesRegex(ValidationFailure, "requires an active source record"):
            validate_payloads(schemas(), payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
