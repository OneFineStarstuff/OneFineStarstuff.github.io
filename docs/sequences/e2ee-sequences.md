# E2EE Sequence Diagrams (Textual)

## 1) Device Provisioning (QR + SAS)
1. New device: gen (Ed25519_sign_D, X25519_D), create nonce N and ts
2. New device -> QR payload: base64url(JSON { device_pubkeys, nonce: N, ts, sig: sign_D(N||ts) })
3. Trusted device scans QR
4. Both devices derive SAS from transcript (hash of {identity_pubkey, device_pubkeys, N, ts}) -> 7 emojis
5. Human verifies SAS match
6. Trusted device signs attestation: sign_T({ user_identity_pub, device_pubkeys, N, ts })
7. Trusted device -> Server: POST /devices/attest(attestation)
8. Server records device; broadcasts WS event

## 2) File Share (Encrypt + Upload + Share DEK)
1. Client picks file; gen random DEK
2. For each chunk i:
   - nonce_i = HKDF(DEK, info="file-chunk"||i)[0..12]
   - c_i = AES-256-GCM(plaintext_i, nonce_i)
   - blake3_i = BLAKE3(c_i)
3. blake3_file = BLAKE3(c_0||c_1||...)
4. Manifest = { version, algo, chunk_size, length, blake3_file, chunks[] }
5. sig = Ed25519.sign(manifest_without_sig)
6. Upload chunks and manifest (ciphertext only)
7. For each recipient device pk_X:
   - wrap = sealed_box(DEK, pk_X)
   - POST key_wraps(object_id, device_id, wrap)

## 3) Membership change -> Rekey
1. Admin changes room members
2. Server emits WS membership-change event
3. Clients rotate sender key and/or rewrap DEKs
4. New wraps stored; old wraps invalidated
5. Capability issuance follows narrow scopes with TTL
