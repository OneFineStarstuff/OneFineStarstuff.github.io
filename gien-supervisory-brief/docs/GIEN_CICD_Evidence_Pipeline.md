# GIEN-Style Regulator-Defensible CI/CD Pipeline
### Single containerized Node/TypeScript REST API on Kubernetes

## Phase plan (P1–P7)

**P1 — Source and schema.** Schema-first: OpenAPI and JSON Schema committed before handlers. CI
regenerates clients and fails on drift between spec and implementation (`openapi-diff`,
`spectral lint`). Database migrations are forward-only and reviewed against a fixtures corpus.

**P2 — Contract.** Consumer-driven contracts with Pact. The provider verifies all consumer
versions; deployment is gated on `pact-broker can-i-deploy --pacticipant api --to-environment prod`.
Breaking contract = blocked release, no override path.

**P3 — Hermetic build.** Build inside a pinned container with network access only to a proxied
artifact mirror. Emit SLSA v1 provenance at level 3; verify with `slsa-verifier verify-image`
before any tag is promoted. Build inputs are content-addressed and reproducible.

**P4 — Sign and inventory.** Keyless signing with cosign (OIDC identity, Fulcio cert, Rekor
transparency log). Syft generates CycloneDX SBOM; Grype scans; results attached as attestations.
Kyverno admission requires: signed image, SBOM attestation present, no CRITICAL CVEs, provenance
subject digest matching the deployed digest.

**P5 — Deploy and observe.** Progressive rollout (canary 5% → 25% → 100%) with automatic rollback
on error-rate or latency SLO burn. Argo CD sync waves; drift detection reconciles cluster state
to Git hourly.

**P6 — Freeze windows.** Deployment freeze aligned to the supervisory cycle: no production change
between 06:00 and 10:00 UTC (archive transmission and supervisory college receipt) or during
23:59 cycle closure. Exceptions require the material-change gate below.

**P7 — Material-change gate and break-glass.** Any change classified material (model, scoring
logic, data source, auth, cryptography, retention) requires: impact assessment, supervisory
notification where mandated, and four-eyes approval. Break-glass is a distinct role, bound to an
external incident ticket (Jira/ServiceNow) whose ID is embedded in the audit event; it expires in
4 hours, is auto-revoked, and triggers a mandatory post-incident review within 5 business days.

## The eight mandatory controls

1. **Schema-first development with drift gating** — spec, client, and handler cannot diverge silently.
2. **Pact contract tests + can-i-deploy** — consumer expectations block promotion.
3. **Hermetic builds with SLSA L3 provenance** — verified by `slsa-verifier`, digest-bound.
4. **Keyless image signing** — cosign, identity-bound, recorded in Rekor.
5. **SBOM generation and admission enforcement** — Kyverno denies unsigned or uninventoried images.
6. **Freeze windows** — supervisory-cycle-aware, enforced by policy not convention.
7. **Material-change classification gate** — deterministic rubric, documented decision, four-eyes.
8. **Break-glass bound to incident tickets** — external reference, expiry, review, audit trail.

## Evidence Bundle (deterministic, Merkle-rooted)

For every deployment, assemble: commit SHA and signed tag, build provenance, SBOM, scan results,
contract verification, policy evaluation results, approval records, freeze-window check, and the
deployed manifest digest. Canonicalise as RFC 8785 JSON, hash each artefact (SHA-256), build a
binary Merkle tree over sorted leaf hashes, and publish:

- `bundle.json` — metadata, leaf list, root, signer identity
- `bundle.sig` — ML-DSA-65 signature over the root (FIPS 204)
- `anchors.json` — Rekor entry UUID + WORM ledger block height and inclusion proof

Dual anchoring matters: Rekor gives public, third-party-verifiable transparency; the internal WORM
ledger gives retention and legal-hold guarantees under SEC 17a-4(f). Either alone is a single point
of credibility failure.

## Third-party verification harness

A supervisor must be able to verify without trusting the operator. Provide a single command:

```
npx gien-verify --bundle bundle.json --image ghcr.io/org/api@sha256:... \
  --rekor https://rekor.sigstore.dev --ledger https://ledger.example/api
```

It checks: signature over the Merkle root, every leaf hash, provenance subject digest, SBOM
presence, Rekor inclusion, WORM ledger inclusion, freeze-window compliance from signed timestamps,
and that the running image digest equals the attested digest. Output is a signed verification
report, itself anchored.

## Framework mappings

- **DORA (Art. 8–12, 28)** — ICT change management, register of information, testing evidence, third-party register.
- **NIS2 (Art. 21, 23)** — supply-chain security, incident reporting timelines, evidence of measures.
- **EU AI Act Annex IV** — technical documentation: data, model, validation, monitoring, risk management; bundle carries the model card and evaluation results.
- **SR 11-7 / SR 26-2** — model inventory entry, validation record, change log, ongoing monitoring.
- **SEC 17a-4(f)** — WORM retention, audit-trail immutability, designated third party or audited alternative.
- **HKMA AI²** — governance accountability, explainability artefacts, consumer protection evidence.
- **MAS FEAT** — fairness, ethics, accountability, transparency: fairness test results and decision logs.

## Common credibility failures

1. Freeze window asserted in policy but not enforced by admission control.
2. Provenance generated but never verified at deploy time (theatre).
3. SBOM produced after the build, so it describes a different artefact.
4. Evidence bundles without deterministic serialisation — roots differ on re-run.
5. Break-glass with no external ticket or expiry — indistinguishable from abuse.
6. Behavioural evidence missing: pipeline proves the image, not that the model still scores fairly.
7. Timestamps from the operator's clock rather than a signed transparency log.
8. Approval records that name roles rather than identities.
