"""Offline tests for the S3 Object Lock reference writer."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from governance_artifacts.worm.s3_object_lock_writer import (
    EvidenceObject,
    ObjectLockWriteError,
    S3ObjectLockConfig,
    S3ObjectLockWriter,
)

BUCKET = "gien-evidence-reference"
KMS_ARN = "arn:aws:kms:eu-west-1:111122223333:key/12345678-1234-1234-1234-123456789abc"
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


class FakeS3:
    """In-memory fake; it never performs network or AWS SDK operations."""

    def __init__(self) -> None:
        self.versioning: dict[str, Any] = {"Status": "Enabled"}
        self.lock_configuration: dict[str, Any] = {
            "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}
        }
        self.put_result: dict[str, Any] = {"VersionId": "version-001"}
        self.head_overrides: dict[str, Any] = {}
        self.put_calls: list[dict[str, Any]] = []
        self.head_calls: list[dict[str, Any]] = []

    def get_bucket_versioning(self, **kwargs: Any) -> dict[str, Any]:
        """Simulate the configured bucket versioning response."""
        assert kwargs == {"Bucket": BUCKET}
        return self.versioning

    def get_object_lock_configuration(self, **kwargs: Any) -> dict[str, Any]:
        """Simulate the bucket Object Lock configuration response."""
        assert kwargs == {"Bucket": BUCKET}
        return self.lock_configuration

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        """Record request parameters and emulate a stored object version."""
        self.put_calls.append(kwargs)
        self.stored = {
            "VersionId": self.put_result.get("VersionId", "version-001"),
            "ContentLength": kwargs["ContentLength"],
            "ChecksumSHA256": kwargs["ChecksumSHA256"],
            "ObjectLockMode": kwargs["ObjectLockMode"],
            "ObjectLockRetainUntilDate": kwargs["ObjectLockRetainUntilDate"],
            "ServerSideEncryption": kwargs["ServerSideEncryption"],
            "SSEKMSKeyId": kwargs["SSEKMSKeyId"],
            "Metadata": kwargs["Metadata"],
        }
        return self.put_result

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        """Return fake persisted metadata for the requested object version."""
        self.head_calls.append(kwargs)
        result = dict(self.stored)
        result.update(self.head_overrides)
        return result


def make_config() -> S3ObjectLockConfig:
    """Build an isolated configuration for the fake S3 client."""
    return S3ObjectLockConfig(
        bucket=BUCKET,
        kms_key_arn=KMS_ARN,
        retention_days=2555,
    )


def make_evidence() -> EvidenceObject:
    """Return a fixed fictional evidence payload for repeatable tests."""
    return EvidenceObject(
        evidence_id="EV-2026-11-08-001",
        object_key="gien/2026/11/08/EV-2026-11-08-001.json",
        payload=b'{"evidence":"fictional-test-payload","version":1}',
        content_type="application/json",
        metadata={"source": "offline-test", "classification": "SIMULATED"},
    )


def test_successful_write_returns_verified_receipt() -> None:
    """Verify the receipt and all required PutObject/HeadObject parameters."""
    client = FakeS3()
    evidence = make_evidence()
    receipt = S3ObjectLockWriter(
        client, make_config(), clock=lambda: NOW
    ).write(evidence)

    assert receipt.bucket == BUCKET
    assert receipt.version_id == "version-001"
    assert receipt.lock_mode == "COMPLIANCE"
    assert receipt.retain_until == NOW + timedelta(days=2555)
    assert receipt.sha256_hex == hashlib.sha256(evidence.payload).hexdigest()
    assert receipt.sha384_hex == hashlib.sha384(evidence.payload).hexdigest()
    assert client.put_calls[0]["IfNoneMatch"] == "*"
    assert client.put_calls[0]["ObjectLockMode"] == "COMPLIANCE"
    assert client.put_calls[0]["ChecksumAlgorithm"] == "SHA256"
    assert client.head_calls[0]["VersionId"] == "version-001"
    assert client.head_calls[0]["ChecksumMode"] == "ENABLED"


def test_bucket_versioning_must_be_enabled() -> None:
    """Reject a bucket whose versioning status is not Enabled."""
    client = FakeS3()
    client.versioning = {"Status": "Suspended"}

    with pytest.raises(ObjectLockWriteError, match="versioning"):
        S3ObjectLockWriter(
            client, make_config(), clock=lambda: NOW
        ).write(make_evidence())

    assert not client.put_calls


def test_bucket_object_lock_must_be_enabled() -> None:
    """Reject a bucket without an enabled Object Lock configuration."""
    client = FakeS3()
    client.lock_configuration = {
        "ObjectLockConfiguration": {"ObjectLockEnabled": "Disabled"}
    }

    with pytest.raises(ObjectLockWriteError, match="Object Lock"):
        S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(make_evidence())

    assert not client.put_calls


def test_missing_version_id_fails_closed() -> None:
    """Do not issue a receipt when the put response omits a version ID."""
    client = FakeS3()
    client.put_result = {"VersionId": "null"}

    with pytest.raises(ObjectLockWriteError, match="version ID"):
        S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(make_evidence())


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"ChecksumSHA256": "wrong"}, "checksum mismatch"),
        ({"ObjectLockMode": "GOVERNANCE"}, "COMPLIANCE mode"),
        ({"ContentLength": 1}, "content length mismatch"),
        ({"ServerSideEncryption": "AES256"}, "AWS KMS"),
        (
            {"SSEKMSKeyId": "arn:aws:kms:eu-west-1:111122223333:key/other"},
            "KMS key",
        ),
        (
            {"ObjectLockRetainUntilDate": NOW + timedelta(days=1)},
            "retention date is earlier",
        ),
    ],
)
def test_read_after_write_mismatch_fails_closed(
    override: dict[str, Any], message: str
) -> None:
    """Reject mismatched properties returned by the read-after-write check."""
    client = FakeS3()
    client.head_overrides = override

    with pytest.raises(ObjectLockWriteError, match=message):
        S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(make_evidence())


def test_checksum_is_full_payload_sha256_base64() -> None:
    """Verify the request checksum uses Base64 of the full SHA-256 digest."""
    client = FakeS3()
    evidence = make_evidence()
    S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(evidence)

    expected = base64.b64encode(hashlib.sha256(evidence.payload).digest()).decode("ascii")
    assert client.put_calls[0]["ChecksumSHA256"] == expected


def test_naive_clock_is_rejected_before_s3_calls() -> None:
    """Reject naive timestamps before making any client calls."""
    client = FakeS3()
    def naive_clock() -> datetime:
        return datetime(2026, 11, 8, 12, 0)

    with pytest.raises(ValueError, match="timezone-aware"):
        S3ObjectLockWriter(client, make_config(), clock=naive_clock).write(make_evidence())

    assert not client.put_calls


def test_invalid_object_key_is_rejected_before_s3_calls() -> None:
    """Reject unsafe relative-key shapes before making any client calls."""
    client = FakeS3()
    evidence = make_evidence()
    invalid = EvidenceObject(
        evidence_id=evidence.evidence_id,
        object_key="../escape.json",
        payload=evidence.payload,
        content_type=evidence.content_type,
        metadata=evidence.metadata,
    )

    with pytest.raises(ValueError, match="relative S3 key"):
        S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(invalid)

    assert not client.put_calls


def test_reserved_metadata_cannot_override_integrity_fields() -> None:
    """Prevent caller metadata from replacing computed integrity values."""
    client = FakeS3()
    evidence = make_evidence()
    invalid = EvidenceObject(
        evidence_id=evidence.evidence_id,
        object_key=evidence.object_key,
        payload=evidence.payload,
        content_type=evidence.content_type,
        metadata={"sha384": "caller-supplied"},
    )

    with pytest.raises(ValueError, match="reserved"):
        S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(invalid)

    assert not client.put_calls


def test_missing_head_receipt_fails_closed() -> None:
    """Fail closed if the exact-version read-after-write cannot be performed."""
    class HeadFailure(FakeS3):
        def head_object(self, **kwargs: Any) -> dict[str, Any]:
            """Simulate failure of the post-write object verification call."""
            raise OSError("synthetic offline read-after-write failure")

    with pytest.raises(ObjectLockWriteError, match="read-after-write"):
        S3ObjectLockWriter(HeadFailure(), make_config(), clock=lambda: NOW).write(
            make_evidence()
        )


def test_receipt_reports_actual_stored_retention_if_bucket_extends_it() -> None:
    """Record S3's actual retention date when it exceeds the requested date."""
    client = FakeS3()
    actual_retention = NOW + timedelta(days=3000)
    client.head_overrides = {"ObjectLockRetainUntilDate": actual_retention}

    receipt = S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(
        make_evidence()
    )

    assert receipt.retain_until == actual_retention


def test_retention_period_must_be_an_integer() -> None:
    """Reject non-integer retention intervals in configuration."""
    with pytest.raises(ValueError, match="positive integer"):
        S3ObjectLockConfig(
            bucket=BUCKET,
            kms_key_arn=KMS_ARN,
            retention_days=365.5,  # type: ignore[arg-type]
        )


def test_kms_key_must_be_a_canonical_key_arn() -> None:
    """Require a customer-managed key ARN rather than an alias or free text."""
    with pytest.raises(ValueError, match="canonical KMS key ARN"):
        S3ObjectLockConfig(
            bucket=BUCKET,
            kms_key_arn="alias/evidence-key",
            retention_days=365,
        )



@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_id", 42),
        ("object_key", 42),
        ("payload", bytearray(b"not immutable bytes")),
        ("content_type", 42),
        ("metadata", ["not", "a", "mapping"]),
    ],
)
def test_invalid_evidence_field_types_fail_before_client_calls(
    field: str, value: Any
) -> None:
    """Reject wrong runtime field types before interacting with the S3 client."""
    client = FakeS3()
    evidence = replace(make_evidence(), **{field: value})

    with pytest.raises(ValueError):
        S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(evidence)

    assert not client.put_calls


def test_metadata_keys_must_be_strings() -> None:
    """Reject non-string metadata keys rather than raising incidental errors."""
    client = FakeS3()
    evidence = replace(make_evidence(), metadata={42: "invalid-key"})

    with pytest.raises(ValueError, match="metadata keys"):
        S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(evidence)

    assert not client.put_calls


def test_metadata_keys_must_be_unique_after_case_normalization() -> None:
    """Reject metadata keys that collide under S3's case-insensitive mapping."""
    client = FakeS3()
    evidence = replace(
        make_evidence(),
        metadata={"Evidence-Source": "first", "evidence-source": "second"},
    )

    with pytest.raises(ValueError, match="duplicate metadata key"):
        S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(evidence)

    assert not client.put_calls


def test_metadata_size_limit_is_enforced_before_upload() -> None:
    """Reject user metadata whose UTF-8 key/value bytes exceed the S3 limit."""
    client = FakeS3()
    evidence = replace(make_evidence(), metadata={"x": "a" * 2048})

    with pytest.raises(ValueError, match="2 KiB"):
        S3ObjectLockWriter(client, make_config(), clock=lambda: NOW).write(evidence)

    assert not client.put_calls


def test_receipt_verification_timestamp_is_after_readback() -> None:
    """Record verification time after the exact-version readback has completed."""
    client = FakeS3()
    verification_time = NOW + timedelta(seconds=3)
    clock_values = iter((NOW, verification_time))

    receipt = S3ObjectLockWriter(
        client, make_config(), clock=lambda: next(clock_values)
    ).write(make_evidence())

    assert receipt.verified_at == verification_time


def test_caller_must_inject_client_and_no_sdk_constructor_is_used() -> None:
    """Require an injected client and avoid ambient SDK configuration."""
    # This module defines no boto3 dependency or client-construction path.
    from inspect import signature

    parameters = signature(S3ObjectLockWriter).parameters
    assert "client" in parameters
    assert parameters["client"].default is parameters["client"].empty
