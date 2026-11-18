# Security notes and threat model

## Protected assets

Source and release workflow definitions; dependency graph; image and digest; provenance; signing identity; Pact compatibility results; vulnerability/SBOM findings; approval identities; deployment credentials; customer data; evidence bundles; WORM retention administration.

## Primary threats

- Malicious or compromised dependency, maintainer or action.
- Workflow injection through untrusted pull-request data.
- Build worker compromise or cross-build contamination.
- Provenance subject/source mismatch.
- Signing identity confusion or OIDC subject too broad.
- Mutable image reference / tag substitution.
- SBOM not bound to deployed digest.
- Admission webhook outage or policy bypass.
- Insider bypass of freeze or materiality review.
- Break-glass self-approval or stale authorization.
- Evidence omission, reordering or tampering.
- WORM administrator bypass or incorrect retention configuration.
- Personal data leakage into public transparency logs.

## Required defenses

- Pin third-party GitHub Actions and reusable workflows to full commit SHAs; review and update pins through controlled PRs.
- Restrict write/id-token permissions to minimal jobs; never expose deployment/signing tokens to pull-request builds.
- Protect release tags, workflows, environments and environment reviewers.
- Use ephemeral isolated build runners and protected provenance generation.
- Verify source, builder, image digest, signer identity, SBOM subject and admission decision.
- Enforce immutable digest deployment and fail-closed admission.
- Derive approver identity from an IdP/approval system, not client JSON.
- Enforce independent approval and time-limited emergency scope.
- Keep raw PII, transcripts, secrets, private keys and bearer tokens out of Rekor and evidence manifests.
- Use WORM retention with separated administration and tested independent read access.
- Preserve failed/rolled-back release evidence and incident chronology.

## API limitations

The starter API is an unauthenticated local policy evaluator, has no durable datastore, no cryptographic verification adapters, and no rate limiter. It binds to `127.0.0.1` by default. Its `PASS`/`ALLOW` result is not a release authorization. Before any production use, place it behind authenticated service-to-service access, validate requests against the JSON Schema, enforce authorization server-side, persist signed decisions in an append-only evidence store, and query real verification systems.

## Cryptographic boundaries

SHA-256 hashes and a domain-separated Merkle root detect changes to the collected entries under the stated construction. They do not prove that the collection is complete, truthful or authoritative. A Cosign/Rekor signature proves the root was signed by a given identity and transparently logged; it does not prove the payload's truth. WORM storage protects retention only when storage settings, IAM and operations are correctly configured.
