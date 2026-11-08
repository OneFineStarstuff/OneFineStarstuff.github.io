"""Offline-testable, fail-closed S3 Object Lock evidence writer.

This module does not import boto3, construct sessions, resolve credentials, or
create a network client. Callers must inject an authorized S3 client.
"""
from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol


class S3ObjectLockClient(Protocol):
    """Minimal boto3-compatible client surface used by this adapter."""

    def get_bucket_versioning(self, **kwargs: Any) -> Mapping[str, Any]:
        """Return the bucket versioning status."""

    def get_object_lock_configuration(self, **kwargs: Any) -> Mapping[str, Any]:
        """Return the bucket Object Lock configuration."""

    def put_object(self, **kwargs: Any) -> Mapping[str, Any]:
        """Write one versioned, retention-locked object."""

    def head_object(self, **kwargs: Any) -> Mapping[str, Any]:
        """Return metadata for an exact stored object version."""


class ObjectLockWriteError(RuntimeError):
    """Raised when immutable-storage properties cannot be established."""


@dataclass(frozen=True)
class S3ObjectLockConfig:
    """Pin the bucket owner, customer-managed KMS key, and retention interval."""

    bucket: str
    expected_bucket_owner: str
    kms_key_arn: str
    retention_days: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.bucket, str)
            or not self.bucket
            or self.bucket.strip() != self.bucket
        ):
            raise ValueError("bucket must be a non-empty, trimmed name")
        if not isinstance(self.expected_bucket_owner, str) or not re.fullmatch(
            r"\d{12}", self.expected_bucket_owner
        ):
            raise ValueError("expected_bucket_owner must be a 12-digit AWS account ID")
        if not isinstance(self.kms_key_arn, str) or not re.fullmatch(
            r"arn:[a-z0-9-]+:kms:[a-z0-9-]+:\d{12}:key/[A-Za-z0-9-]{1,128}",
            self.kms_key_arn,
        ):
            raise ValueError("kms_key_arn must be a canonical KMS key ARN")
        if (
            isinstance(self.retention_days, bool)
            or not isinstance(self.retention_days, int)
            or self.retention_days <= 0
        ):
            raise ValueError("retention_days must be a positive integer")


@dataclass(frozen=True)
class EvidenceObject:
    """Describe a payload and its immutable evidence-object identity."""

    evidence_id: str
    object_key: str
    payload: bytes
    content_type: str
    metadata: Mapping[str, str]


@dataclass(frozen=True)
class ObjectLockReceipt:
    """Record properties verified from the stored object version."""

    bucket: str
    object_key: str
    version_id: str
    evidence_id: str
    sha256_hex: str
    sha256_base64: str
    sha384_hex: str
    content_length: int
    lock_mode: str
    retain_until: datetime
    kms_key_arn: str
    verified_at: datetime


_RESERVED_METADATA = {"evidence-id", "sha256", "sha384"}
_EVIDENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_METADATA_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _as_utc(value: datetime, field_name: str) -> datetime:
    """Reject naive timestamps and normalize valid values to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _validate_evidence_id(evidence_id: Any) -> None:
    """Require a non-empty identifier from the evidence ID vocabulary."""
    if not isinstance(evidence_id, str) or not _EVIDENCE_ID.fullmatch(evidence_id):
        raise ValueError("evidence_id must be a supported non-empty string")


def _validate_object_key(object_key: Any) -> None:
    """Require a relative, UTF-8 S3 key within the service's byte limit."""
    if not isinstance(object_key, str) or not object_key:
        raise ValueError("object_key must be a non-empty relative S3 key")
    if object_key.startswith("/") or any(
        part in {"", ".", ".."} for part in object_key.split("/")
    ):
        raise ValueError("object_key must not contain absolute or dot segments")
    if any(ord(char) < 32 for char in object_key):
        raise ValueError("object_key must not contain control characters")
    try:
        key_length = len(object_key.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("object_key must be valid UTF-8") from exc
    if key_length > 1024:
        raise ValueError("object_key exceeds the 1,024-byte S3 key limit")


def _validate_content_type(content_type: Any) -> None:
    """Require a trimmed content type without control characters."""
    if (
        not isinstance(content_type, str)
        or not content_type
        or content_type.strip() != content_type
        or any(ord(char) < 32 for char in content_type)
    ):
        raise ValueError("content_type must be a non-empty, trimmed value")


def _normalize_metadata(metadata: Any) -> dict[str, str]:
    """Validate, lowercase, and size-limit S3 user-defined metadata."""
    if not isinstance(metadata, Mapping):
        raise ValueError("metadata must be a mapping of string keys and values")

    result: dict[str, str] = {}
    metadata_size = 0
    for key, value in metadata.items():
        if not isinstance(key, str):
            raise ValueError("metadata keys must be strings")
        normalized_key = key.lower()
        if not normalized_key or normalized_key in _RESERVED_METADATA:
            raise ValueError(f"metadata key is empty or reserved: {key!r}")
        if not _METADATA_KEY.fullmatch(normalized_key):
            raise ValueError(f"metadata key format is invalid: {key!r}")
        if normalized_key in result:
            raise ValueError(f"duplicate metadata key after normalization: {key!r}")
        if not isinstance(value, str) or not value:
            raise ValueError(f"metadata value for {key!r} must be a non-empty string")
        if any(ord(char) < 32 for char in normalized_key + value):
            raise ValueError("metadata must not contain control characters")
        try:
            normalized_key.encode("ascii")
            value.encode("ascii")
            metadata_size += len(normalized_key.encode("utf-8"))
            metadata_size += len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError("S3 user metadata must use US-ASCII text") from exc
        if metadata_size > 2048:
            raise ValueError("user metadata exceeds the 2 KiB S3 limit")
        result[normalized_key] = value
    return result


def _validate_evidence(evidence: EvidenceObject) -> dict[str, str]:
    """Validate an evidence object's type, identity, payload, and metadata."""
    if not isinstance(evidence, EvidenceObject):
        raise ValueError("evidence must be an EvidenceObject")
    _validate_evidence_id(evidence.evidence_id)
    _validate_object_key(evidence.object_key)
    if not isinstance(evidence.payload, bytes) or not evidence.payload:
        raise ValueError("payload must be non-empty bytes")
    _validate_content_type(evidence.content_type)
    return _normalize_metadata(evidence.metadata)


class S3ObjectLockWriter:
    """Write a unique evidence object and verify the stored S3 properties."""

    def __init__(
        self,
        client: S3ObjectLockClient,
        config: S3ObjectLockConfig,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind an explicit client, configuration, and injectable clock."""
        self._client = client
        self._config = config
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _verify_bucket_controls(self) -> None:
        """Require versioning and Object Lock before accepting writes."""
        try:
            versioning = self._client.get_bucket_versioning(
                Bucket=self._config.bucket,
                ExpectedBucketOwner=self._config.expected_bucket_owner,
            )
            lock_result = self._client.get_object_lock_configuration(
                Bucket=self._config.bucket,
                ExpectedBucketOwner=self._config.expected_bucket_owner,
            )
        except Exception as exc:
            raise ObjectLockWriteError("S3 bucket-control preflight failed") from exc

        if not isinstance(versioning, Mapping) or not isinstance(lock_result, Mapping):
            raise ObjectLockWriteError(
                "S3 bucket preflight returned a malformed response"
            )
        if versioning.get("Status") != "Enabled":
            raise ObjectLockWriteError("bucket versioning must be Enabled")
        lock_config = lock_result.get("ObjectLockConfiguration", {})
        if not isinstance(lock_config, Mapping):
            raise ObjectLockWriteError("S3 Object Lock configuration is malformed")
        if lock_config.get("ObjectLockEnabled") != "Enabled":
            raise ObjectLockWriteError("bucket Object Lock must be Enabled")

    def write(self, evidence: EvidenceObject) -> ObjectLockReceipt:
        """Put an immutable object, then verify it by exact version ID."""
        metadata = _validate_evidence(evidence)
        write_started_at = _as_utc(self._clock(), "clock")
        retain_until = write_started_at + timedelta(days=self._config.retention_days)

        sha256_digest = hashlib.sha256(evidence.payload).digest()
        sha256_hex = sha256_digest.hex()
        sha256_base64 = base64.b64encode(sha256_digest).decode("ascii")
        sha384_hex = hashlib.sha384(evidence.payload).hexdigest()
        object_metadata = {
            **metadata,
            "evidence-id": evidence.evidence_id,
            "sha256": sha256_hex,
            "sha384": sha384_hex,
        }

        self._verify_bucket_controls()
        try:
            put_result = self._client.put_object(
                Bucket=self._config.bucket,
                ExpectedBucketOwner=self._config.expected_bucket_owner,
                Key=evidence.object_key,
                Body=evidence.payload,
                ContentLength=len(evidence.payload),
                ContentType=evidence.content_type,
                Metadata=object_metadata,
                ChecksumAlgorithm="SHA256",
                ChecksumSHA256=sha256_base64,
                IfNoneMatch="*",
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=retain_until,
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=self._config.kms_key_arn,
            )
        except Exception as exc:
            raise ObjectLockWriteError("S3 immutable object write failed") from exc

        if not isinstance(put_result, Mapping):
            raise ObjectLockWriteError("S3 write returned a malformed response")
        version_id = put_result.get("VersionId")
        if not isinstance(version_id, str) or not version_id or version_id == "null":
            raise ObjectLockWriteError("S3 write returned no version ID")

        try:
            stored = self._client.head_object(
                Bucket=self._config.bucket,
                ExpectedBucketOwner=self._config.expected_bucket_owner,
                Key=evidence.object_key,
                VersionId=version_id,
                ChecksumMode="ENABLED",
            )
        except Exception as exc:
            raise ObjectLockWriteError(
                "S3 read-after-write verification failed"
            ) from exc

        if not isinstance(stored, Mapping):
            raise ObjectLockWriteError(
                "S3 read-after-write returned a malformed response"
            )
        verified_retain_until = self._verify_stored_object(
            evidence=evidence,
            stored=stored,
            version_id=version_id,
            checksum=sha256_base64,
            metadata=object_metadata,
            retain_until=retain_until,
        )
        verified_at = _as_utc(self._clock(), "verification clock")

        return ObjectLockReceipt(
            bucket=self._config.bucket,
            object_key=evidence.object_key,
            version_id=version_id,
            evidence_id=evidence.evidence_id,
            sha256_hex=sha256_hex,
            sha256_base64=sha256_base64,
            sha384_hex=sha384_hex,
            content_length=len(evidence.payload),
            lock_mode="COMPLIANCE",
            retain_until=verified_retain_until,
            kms_key_arn=self._config.kms_key_arn,
            verified_at=verified_at,
        )

    def _verify_stored_object(
        self,
        evidence: EvidenceObject,
        stored: Mapping[str, Any],
        version_id: str,
        checksum: str,
        metadata: Mapping[str, str],
        retain_until: datetime,
    ) -> datetime:
        """Verify the persisted object and return its actual retention date."""
        if stored.get("VersionId") != version_id:
            raise ObjectLockWriteError("read-after-write version ID mismatch")
        if stored.get("ContentLength") != len(evidence.payload):
            raise ObjectLockWriteError("stored content length mismatch")
        if stored.get("ChecksumSHA256") != checksum:
            raise ObjectLockWriteError("stored SHA-256 checksum mismatch")
        if stored.get("ObjectLockMode") != "COMPLIANCE":
            raise ObjectLockWriteError("stored object is not in COMPLIANCE mode")

        stored_until = stored.get("ObjectLockRetainUntilDate")
        if not isinstance(stored_until, datetime):
            raise ObjectLockWriteError("stored retention date is missing or invalid")
        stored_until = _as_utc(stored_until, "stored retention date")
        if stored_until < retain_until:
            raise ObjectLockWriteError(
                "stored retention date is earlier than requested"
            )
        if stored.get("ServerSideEncryption") != "aws:kms":
            raise ObjectLockWriteError("stored object is not encrypted with AWS KMS")
        if stored.get("SSEKMSKeyId") != self._config.kms_key_arn:
            raise ObjectLockWriteError("stored KMS key does not match configured key")

        actual_metadata = stored.get("Metadata", {})
        if not isinstance(actual_metadata, Mapping):
            raise ObjectLockWriteError("stored object metadata is malformed")
        for key, value in metadata.items():
            if actual_metadata.get(key) != value:
                raise ObjectLockWriteError(f"stored metadata mismatch for {key!r}")
        return stored_until
