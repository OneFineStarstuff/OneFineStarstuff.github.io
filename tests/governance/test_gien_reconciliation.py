"""Unit tests for the dated GIEN evidence-reconciliation register."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.validate_gien_reconciliation import (  # noqa: E402
    ReconciliationError,
    validate_document,
)

REGISTER = ROOT / "docs" / "remediation" / "gien-evidence-conflicts-2026-11-06.json"


class TestGienEvidenceReconciliation(unittest.TestCase):
    """Verify the register rejects unsafe evidence and release dispositions."""

    payload: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        """Load the canonical test fixture once for all regression cases."""
        cls.payload = json.loads(REGISTER.read_text(encoding="utf-8"))

    def test_canonical_register_validates_and_holds_filing(self) -> None:
        """Accept the canonical fixture while retaining its release hold."""
        result = validate_document(copy.deepcopy(self.payload))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["unresolved_p0_count"], 2)
        self.assertEqual(result["external_filing"], "HOLD")
        self.assertEqual(result["release_gate"], "BLOCK")

    def test_unresolved_p0_cannot_be_released(self) -> None:
        """Reject a filing-ready disposition while an unresolved P0 exists."""
        payload = copy.deepcopy(self.payload)
        payload["disposition"]["external_filing"] = "READY"
        with self.assertRaisesRegex(ReconciliationError, "external_filing=HOLD"):
            validate_document(payload)

    def test_unknown_source_reference_is_rejected(self) -> None:
        """Reject findings that reference sources absent from the register."""
        payload = copy.deepcopy(self.payload)
        payload["findings"][0]["source_ids"].append("SRC-NOT-REGISTERED")
        with self.assertRaisesRegex(ReconciliationError, "unknown sources"):
            validate_document(payload)

    def test_duplicate_source_ids_are_rejected(self) -> None:
        """Reject duplicated source identifiers in the evidence catalogue."""
        payload = copy.deepcopy(self.payload)
        payload["sources"].append(copy.deepcopy(payload["sources"][0]))
        with self.assertRaisesRegex(ReconciliationError, "duplicate source_id"):
            validate_document(payload)

    def test_reporting_window_must_be_exactly_24_hours(self) -> None:
        """Reject a reporting window that differs from the canonical 24 hours."""
        payload = copy.deepcopy(self.payload)
        payload["reporting_window"]["end_utc"] = "2026-11-05T08:59:00Z"
        with self.assertRaisesRegex(ReconciliationError, "exactly 24 hours"):
            validate_document(payload)

    def test_operational_assurance_cannot_be_promoted(self) -> None:
        """Prevent a register-only check from claiming operational assurance."""
        payload = copy.deepcopy(self.payload)
        payload["disposition"]["operational_assurance"] = "VERIFIED"
        with self.assertRaisesRegex(
            ReconciliationError, "operational assurance cannot be promoted"
        ):
            validate_document(payload)

    def test_fiction_boundary_is_mandatory(self) -> None:
        """Require all GIEN scenario outputs to retain their simulation label."""
        payload = copy.deepcopy(self.payload)
        payload["fictional_simulation"] = False
        with self.assertRaisesRegex(ReconciliationError, "must be true"):
            validate_document(payload)

    def test_p0_cannot_be_relabelled_partial_to_bypass_hold(self) -> None:
        """Keep the external filing hold when a P0 status is weakened."""
        payload = copy.deepcopy(self.payload)
        for finding in payload["findings"]:
            if finding["severity"] == "P0":
                finding["status"] = "PARTIAL"
        payload["disposition"]["external_filing"] = "READY"
        payload["disposition"]["release_gate"] = "ALLOW"
        with self.assertRaisesRegex(ReconciliationError, "EV-00"):
            validate_document(payload)

    def test_mandatory_p0_severity_cannot_be_downgraded(self) -> None:
        """Keep mandatory P0 severities from being changed to a lower tier."""
        payload = copy.deepcopy(self.payload)
        for finding in payload["findings"]:
            if finding["finding_id"] in {"EV-001", "EV-002"}:
                finding["severity"] = "P1"
                finding["status"] = "PARTIAL"
        payload["disposition"]["external_filing"] = "READY"
        payload["disposition"]["release_gate"] = "ALLOW"
        with self.assertRaisesRegex(ReconciliationError, "EV-00"):
            validate_document(payload)

    def test_mandatory_p0_finding_cannot_be_removed(self) -> None:
        """Require both mandatory P0 evidence conflicts to remain registered."""
        payload = copy.deepcopy(self.payload)
        payload["findings"] = [
            finding
            for finding in payload["findings"]
            if finding["finding_id"] != "EV-001"
        ]
        with self.assertRaisesRegex(ReconciliationError, "missing mandatory P0"):
            validate_document(payload)


if __name__ == "__main__":
    unittest.main()
