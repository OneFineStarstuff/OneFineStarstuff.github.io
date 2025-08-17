# End-to-End Encryption (E2EE) Design — Option A Sign-off

Status: Draft for review
Owner: Kyaw

## 1. Scope and Goals
- Web-first PWA with future native iOS/Android.
- Protect messages, files/assets (3D/logo/media), docs, and analytics events.
- Privacy-preserving analytics client-side; server-side limited to minimized metadata.
- Retrofit behind feature flags; backward-compatible bridging for non-E2EE content.

## 2. Threat Model
- Adversaries: curious/compromised servers, external attackers (MITM), malicious clients, stolen devices.
- Trust boundaries: Only clients see plaintext/keys. Servers handle ciphertext, minimal metadata, and capability tokens. IdP proves identity only.
- Security goals: Confidentiality & integrity; forward secrecy and post-compromise security; deniable auth for messages; verifiable membership/state.
- Out of scope initial: traffic analysis resistance; plaintext content scanning; hardware tamper beyond platform enclaves.

## 3. Cryptographic Primitives and Libraries
- Ed25519 (signing) for identities and devices.
- X25519 (ECDH) for key agreement; sealed boxes for key wrapping (HPKE-ready abstraction).
- Messaging: Signal/Double Ratchet via libsignal-client (WASM) for 1:1/small groups.
- Large groups: Signal sender keys with periodic rotation; MLS on roadmap.
- Files: AES-256-GCM streaming with HKDF-derived per-chunk nonces; BLAKE3 for chunk and whole-file digests.
- KDF: HKDF-SHA256; Password KDF: Argon2id (high-memory, salted).
- Hashing: BLAKE3 for content addressing and integrity.

## 4. Identity & Device State Machines
### 4.1 Identity Keys
States: uninitialized -> generated -> backed_up (optional) -> compromised(revoked)
Transitions:
- generate: create Ed25519 identity key pair
- backup: wrap private key with Argon2id-derived KEK; store vault in IndexedDB
- revoke: mark identity compromised; re-enroll devices

### 4.2 Device Enrollment
States: new -> pending_attestation -> verified -> revoked
Transitions:
- new: device generates Ed25519 (sign) + X25519 (DH)
- provision: QR shows {device_pubkeys, nonce}; trusted device scans and verifies SAS
- attest: trusted device signs attestation binding device to identity
- verify: server records attestation; device becomes verified
- revoke: immediate revocation; triggers rotations

## 5. Messaging Sessions
- 1:1 and small groups: Double Ratchet with prekeys from libsignal.
- Device revocation: peers refuse messages from revoked devices.
- Group sender keys: per-room sender key rotated on membership change and periodically; per-recipient key wraps.

## 6. File Encryption and Sharing
### 6.1 Streaming Encryption
- Per-file random DEK (256-bit).
- Chunk size 512KB–2MB (adaptive).
- Nonce derivation: nonce_i = HKDF(DEK, info="file-chunk" || chunk_index)[0..12]
- AES-256-GCM over each chunk; produce per-chunk BLAKE3 and cumulative whole-file BLAKE3.

### 6.2 Manifest Format (signed by device Ed25519)
```
version: 1
algo: aes-256-gcm
chunk_size: <bytes>
length: <bytes>
blake3_file: <hex>
chunks:
  - index: 0
    offset: 0
    size: <bytes>
    blake3: <hex>
  - ...
key_wraps: omitted in manifest; stored adjacent by object_id
sig: ed25519(signing_device_pubkey, canonical_json(manifest_without_sig))
```

### 6.3 DEK Sharing
- For each recipient device X25519 pubkey, create sealed box of DEK.
- Store wraps: key_wraps(object_id, device_id, wrap_ciphertext)
- Rekey on membership change; rewrap to active devices.

## 7. Capability Tokens
- Format: PASETO v4.public (Ed25519-signed by server capability key).
Claims:
- sub: user or device id
- scope: [object:get|put, room:read, room:write, membership:manage]
- resource: URI or prefix (e.g., s3://bucket/path/object-id)
- exp: expiry; iat/nbf
- region: data residency constraint
- tid/nonce: unique token id to prevent replay

## 8. APIs (Server)
- POST /devices/attest
- POST /devices/revoke
- POST /rooms
- POST /rooms/:id/members
- POST /rooms/:id/rotate
- POST /capabilities
- PUT /objects/:id (requires capability)
- GET /objects/:id (requires capability)
- WS /events

## 9. Storage Schema (Postgres + S3-compatible)
- users(id, identity_pubkey_hash, oidc_sub, region)
- devices(id, user_id, ed25519_pub, x25519_pub, attestation_sig, status)
- rooms(id, created_by, policy)
- memberships(room_id, device_id, role, since, status)
- sender_keys(room_id, epoch, key_id, wrapped_keys jsonb, created_at)
- objects(id, owner, room_id, bucket, path, blake3_digest, size, manifest_sig, created_at)
- key_wraps(object_id, device_id, wrap_ciphertext)
- audit_events(id, actor, type, target, ts, meta)

## 10. Backup & Recovery
- Key vault: private keys wrapped by Argon2id-derived KEK; IndexedDB on web; Secure Enclave/Keystore on mobile.
- Optional Shamir 2-of-3 recovery (user + admin escrow + HSM) with approvals and audit.

## 11. Metadata Minimization
- Store hashed identity references; coarse timestamps; encrypted membership maps when feasible.
- Avoid plaintext titles/tags. No plaintext in logs.

## 12. Request Signing & Replay Protection
- Client signs sensitive requests with device Ed25519 over canonical payload + timestamp.
- Server enforces skew window and tid uniqueness.

## 13. Performance Targets
- p95 decrypt < 120 ms for 10 MB on desktop.
- Streaming crypto in Web Workers; backpressure-managed I/O.

## 14. Rollout & Kill Switch
- Feature flags per tenant/room.
- Canary cohorts; schema uses sidecar tables for isolation.
- Instant kill-switch disables capability issuance for E2EE objects/rooms; existing ciphertext remains intact.

## 15. CI/CD and Supply Chain
- Renovate/Dependabot with grouped patch/minor; majors manual.
- GitHub Actions: lint/typecheck/tests, CodeQL, SCA, SBOM (Syft), container scanning.
- Signed commits and releases.

## 16. Test Plan (Acceptance Gates)
- Unit and property tests for: keygen, provisioning, sealed box wraps, AES-GCM streaming (vectors), manifest sign/verify, PASETO claims/validation, rotation flows.
- Integration: 1:1 E2EE chat, file upload/download, membership change triggers rewrap/rotation.
- Data residency pinning tests; GDPR DSR exercises.

## 17. Open Items / Future Work
- Evaluate MLS migration path for large rooms.
- HPKE support behind wrapping abstraction.
- Privacy-preserving analytics with DP budget management per org.
