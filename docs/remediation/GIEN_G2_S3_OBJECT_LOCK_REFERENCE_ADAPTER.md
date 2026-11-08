# G2 Reference Adapter — S3 Object Lock Evidence Writer

**Status:** REFERENCE IMPLEMENTATION / OFFLINE TESTED / NOT CONNECTED TO AWS  
**Scope:** GIEN simulation and engineering validation only

## Purpose

The existing PQC WORM logger stores committed batches in process memory and emits an Object Lock-shaped metadata dictionary. That does not establish a remote S3 write or an independently verified retention receipt. This separate adapter defines the storage boundary without modifying the existing logger or connecting to a live account.

## Security and storage contract

The adapter requires an explicitly injected S3-compatible client. It does not import boto3, resolve ambient credentials, create a session, select a bucket, or make a network request by itself.

Before writing, it verifies that:
- Bucket versioning reports `Enabled`.
- `GetObjectLockConfiguration` reports `ObjectLockEnabled=Enabled`.
- A canonical KMS key ARN and positive retention period were supplied by the caller.

For each object, it supplies:
- `ObjectLockMode=COMPLIANCE` and a UTC `ObjectLockRetainUntilDate`.
- `ChecksumAlgorithm=SHA256` and the payload's Base64 SHA-256 checksum.
- `IfNoneMatch=*` to avoid accidentally overwriting an existing current key.
- `ServerSideEncryption=aws:kms` with the explicitly configured KMS key ARN.
- An evidence ID and SHA-256/SHA-384 values in object metadata.

A successful receipt requires a version ID and a `HeadObject` read-after-write verification with checksum mode enabled. The writer checks version ID, content length, checksum, COMPLIANCE mode, retention date, KMS encryption/key identity, and evidence metadata. Missing or mismatched evidence raises `ObjectLockWriteError`; it is not converted to a success receipt.

## State sequence

```mermaid
sequenceDiagram
    participant Caller
    participant Writer as S3ObjectLockWriter
    participant S3 as Injected S3 client
    Caller->>Writer: EvidenceObject + configuration
    Writer->>S3: GetBucketVersioning
    Writer->>S3: GetObjectLockConfiguration
    Writer->>S3: PutObject (COMPLIANCE, SHA256, SSE-KMS, If-None-Match)
    S3-->>Writer: VersionId
    Writer->>S3: HeadObject (VersionId, ChecksumMode=ENABLED)
    S3-->>Writer: Stored properties
    Writer->>Writer: Verify integrity, retention, lock mode, KMS
    Writer-->>Caller: Verified receipt or fail-closed exception
```

## Offline tests

`tests/test_s3_object_lock_writer.py` uses an in-memory fake client. It covers a successful write, versioning disabled, Object Lock disabled, missing version ID, checksum mismatch, altered lock mode/retention, wrong encryption/KMS key, naive clock, malformed key, reserved metadata, and read-after-write failure.

No test uses an AWS session, real credentials, network calls, or an actual bucket.

## Production integration prerequisites

Before connecting this interface to a real account, the system owner must approve and supply:
1. AWS account and region, bucket name, bucket Object Lock status, versioning state, replication requirements, and retention policy.
2. KMS key ARN, key policy, role trust policy, least-privilege identity policy, rotation, and break-glass arrangements.
3. Evidence classification, data minimization, retention schedule, legal-hold workflow, deletion/subject-rights handling, and cross-region residency decisions.
4. Independent controls testing, service monitoring, retry/idempotency design, incident response, and disaster recovery.
5. Actual remote receipts, object versions, lock-mode/retain-until checks, and a separately verified audit trail.

A fake-client test proves only that the adapter calls the declared interface and validates the returned shape. It does not prove AWS availability, authorization, bucket configuration, WORM retention, cryptographic custody, or regulatory compliance.

## AWS API references

- [PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)
- [GetObjectLockConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html)
- [HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html)
- [GetBucketVersioning](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html)
