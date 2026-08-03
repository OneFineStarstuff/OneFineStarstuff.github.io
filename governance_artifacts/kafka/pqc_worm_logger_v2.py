#!/usr/bin/env python3
"""
PQC WORM Logger v2 — CRYSTALS-Dilithium (ML-DSA-65 / FIPS 204) signed audit log.
================================================================================
Backs OSCAL control cry-02 (hybrid PQC signatures on governance event envelopes)
and the Kafka/S3 Object Lock WORM evidence pipeline.

Improvements over the original pqc_worm_logger.py (which used an HMAC placeholder):

  * REAL post-quantum signatures via ML-DSA-65 (CRYSTALS-Dilithium), the exact
    algorithm named in cry-02. Each batch is signed; verification uses the public
    key only (asymmetric, unlike the prior HMAC).
  * Tamper-evident HASH CHAIN: each batch records prev_batch_hash, so any
    reordering, deletion, or mutation of historic batches is detectable.
  * WORM semantics modelled: an immutable "retention" record (S3 Object Lock
    COMPLIANCE mode + retain-until date) accompanies each committed batch.
  * verify_chain() re-validates every signature AND the hash linkage; returns a
    machine-readable report suitable for supervisory evidence.

Falls back is intentionally absent: if dilithium_py is unavailable the import
fails loudly rather than silently downgrading crypto.
"""
from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from dilithium_py.ml_dsa import ML_DSA_65

ALG = "ML-DSA-65"  # CRYSTALS-Dilithium, FIPS 204
RETENTION_YEARS = 7  # Basel/DORA-style retention default


def _canon(obj: Any) -> bytes:
    """Deterministic canonical JSON for signing/hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sha256(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


@dataclass
class CommittedBatch:
    batch_id: str
    timestamp: str
    entries: list[dict]
    prev_batch_hash: str
    payload_hash: str
    signature_hex: str
    retention: dict  # S3 Object Lock model

    def to_dict(self) -> dict:
        return {
            "batch_id": self.batch_id,
            "timestamp": self.timestamp,
            "entries": self.entries,
            "prev_batch_hash": self.prev_batch_hash,
            "payload_hash": self.payload_hash,
            "signature_alg": ALG,
            "signature_hex": self.signature_hex,
            "retention": self.retention,
        }


@dataclass
class PQCWormLoggerV2:
    bucket: str = "kacg-gsifi-worm-evidence-prod"
    batch_size_threshold: int = 10
    _pk: bytes = field(default=None, repr=False)
    _sk: bytes = field(default=None, repr=False)
    _pending: list[dict] = field(default_factory=list, repr=False)
    _chain: list[CommittedBatch] = field(default_factory=list, repr=False)
    _genesis: str = "sha256:" + "0" * 64

    def __post_init__(self):
        if self._pk is None or self._sk is None:
            self._pk, self._sk = ML_DSA_65.keygen()

    @property
    def public_key_fingerprint(self) -> str:
        return _sha256(self._pk)

    def add_entry(self, entry: dict) -> CommittedBatch | None:
        self._pending.append(entry)
        if len(self._pending) >= self.batch_size_threshold:
            return self.commit_batch()
        return None

    def commit_batch(self) -> CommittedBatch | None:
        if not self._pending:
            return None
        entries = self._pending
        self._pending = []

        prev_hash = self._chain[-1].payload_hash if self._chain else self._genesis
        ts = datetime.now(timezone.utc).isoformat()
        batch_id = hashlib.sha256(f"{ts}{len(self._chain)}".encode()).hexdigest()[:16]

        # Payload binds entries + the previous hash (chain linkage).
        payload = {"batch_id": batch_id, "timestamp": ts,
                   "entries": entries, "prev_batch_hash": prev_hash}
        payload_bytes = _canon(payload)
        payload_hash = _sha256(payload_bytes)

        # REAL ML-DSA signature over the canonical payload.
        signature = ML_DSA_65.sign(self._sk, payload_bytes)

        retain_until = (datetime.now(timezone.utc)
                        + timedelta(days=365 * RETENTION_YEARS)).isoformat()
        retention = {
            "mode": "COMPLIANCE",            # S3 Object Lock COMPLIANCE mode
            "retain_until": retain_until,
            "legal_hold": False,
            "bucket": self.bucket,
        }

        batch = CommittedBatch(
            batch_id=batch_id, timestamp=ts, entries=entries,
            prev_batch_hash=prev_hash, payload_hash=payload_hash,
            signature_hex=signature.hex(), retention=retention,
        )
        self._chain.append(batch)
        return batch

    def verify_chain(self) -> dict:
        """Re-verify every signature and the hash linkage. Returns a report."""
        errors: list[str] = []
        prev = self._genesis
        for i, b in enumerate(self._chain):
            if b.prev_batch_hash != prev:
                errors.append(f"batch[{i}] {b.batch_id}: broken hash chain link")
            payload = {"batch_id": b.batch_id, "timestamp": b.timestamp,
                       "entries": b.entries, "prev_batch_hash": b.prev_batch_hash}
            payload_bytes = _canon(payload)
            if _sha256(payload_bytes) != b.payload_hash:
                errors.append(f"batch[{i}] {b.batch_id}: payload hash mismatch")
            if not ML_DSA_65.verify(self._pk, payload_bytes, bytes.fromhex(b.signature_hex)):
                errors.append(f"batch[{i}] {b.batch_id}: ML-DSA signature INVALID")
            prev = b.payload_hash
        return {
            "alg": ALG,
            "public_key_fingerprint": self.public_key_fingerprint,
            "batches": len(self._chain),
            "status": "VERIFIED" if not errors else "FAILED",
            "errors": errors,
        }


def _demo() -> int:
    log = PQCWormLoggerV2(batch_size_threshold=3)
    for i in range(7):
        log.add_entry({
            "event_id": f"evt-{i:03d}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "control_id": "cry-02",
            "decision": ["allow", "deny", "escalate"][i % 3],
        })
    log.commit_batch()  # flush remainder

    report = log.verify_chain()
    print("PQC WORM Logger v2 —", ALG)
    print(f"  public key fingerprint: {report['public_key_fingerprint'][:23]}...")
    print(f"  committed batches      : {report['batches']}")
    print(f"  chain verification     : {report['status']}")
    assert report["status"] == "VERIFIED", report

    # Tamper test: mutate a historic entry and confirm detection.
    log._chain[0].entries[0]["decision"] = "TAMPERED"
    bad = log.verify_chain()
    print(f"  after tamper           : {bad['status']} ({len(bad['errors'])} error(s))")
    assert bad["status"] == "FAILED", "tamper went undetected!"
    print("  RESULT: signatures + hash chain verify; tampering detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(_demo())
