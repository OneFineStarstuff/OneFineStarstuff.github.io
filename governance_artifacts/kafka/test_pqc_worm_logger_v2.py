"""Tests for PQC WORM Logger v2 (ML-DSA-65 signed, hash-chained audit log)."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import pytest  # noqa: E402

from pqc_worm_logger_v2 import PQCWormLoggerV2, ALG  # noqa: E402


def _fill(log, n):
    for i in range(n):
        log.add_entry({"event_id": f"e{i}", "control_id": "cry-02", "decision": "allow"})
    log.commit_batch()


def test_alg_is_ml_dsa_65():
    assert ALG == "ML-DSA-65"


def test_chain_verifies_clean():
    log = PQCWormLoggerV2(batch_size_threshold=3)
    _fill(log, 7)
    report = log.verify_chain()
    assert report["status"] == "VERIFIED"
    assert report["batches"] == 3
    assert not report["errors"]


def test_retention_is_compliance_worm():
    log = PQCWormLoggerV2(batch_size_threshold=2)
    _fill(log, 2)
    batch = log._chain[0]
    assert batch.retention["mode"] == "COMPLIANCE"
    assert "retain_until" in batch.retention


def test_tamper_entry_detected():
    log = PQCWormLoggerV2(batch_size_threshold=2)
    _fill(log, 4)
    log._chain[0].entries[0]["decision"] = "TAMPERED"
    report = log.verify_chain()
    assert report["status"] == "FAILED"


def test_chain_reorder_detected():
    log = PQCWormLoggerV2(batch_size_threshold=2)
    _fill(log, 6)
    # Swap two batches -> hash linkage breaks.
    log._chain[0], log._chain[1] = log._chain[1], log._chain[0]
    report = log.verify_chain()
    assert report["status"] == "FAILED"


def test_signature_forgery_detected():
    log = PQCWormLoggerV2(batch_size_threshold=2)
    _fill(log, 2)
    sig = bytearray(bytes.fromhex(log._chain[0].signature_hex))
    sig[0] ^= 0xFF
    log._chain[0].signature_hex = sig.hex()
    report = log.verify_chain()
    assert report["status"] == "FAILED"
