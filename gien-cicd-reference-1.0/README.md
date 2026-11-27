# GIEN CI/CD Reference Implementation 1.0

**5 November 2026 · Fictional GIEN governance context · Reference implementation only**

A runnable starter for one Node.js/TypeScript REST API and its software-supply-chain assurance controls. It is isolated from the GIEN React dashboard and its 35-file acceptance manifest.

## Scope

- Node.js 22.16+ HTTP API, OpenAPI 3.1 and strict JSON Schema validation.
- C1–C8 release-gate evaluator and material-change classifier.
- Pact Broker deployment scripts, immutable action references, API/schema drift gates.
- CI and manual image-release workflow templates; SLSA provenance generation, Cosign keyless signing, Syft SBOM and Trivy image scan.
- OPA/Rego release policy, Kyverno `ImageValidatingPolicy` example and Kubernetes deployment templates.
- Deterministic evidence bundle builder, SHA-256/RFC 6962-style Merkle tree, local verifier and Rekor/WORM operator scripts.
- 25 automated tests covering release decisions, schema compatibility, HTTP input limits and evidence integrity.

## Assurance boundary

This is not a certified SLSA Build L3 platform, regulatory approval, or independent audit. Build L3 depends on the real builder's security/isolation properties and must be substantiated independently. The local release evaluator consumes supplied claims; it does not authenticate callers, verify external signatures, persist approvals or provide a production release authorization. Approver IDs in JSON are data claims, not verified identities. Do not expose the sample API beyond localhost or use it to authorize production changes until identity, authorization, durable audit, rate-limiting and real verification adapters are implemented.

Pact Broker, GHCR, GitHub OIDC, Cosign/Rekor, OPA, Kyverno/Kubernetes, GitOps and WORM storage are integration points, not live connected services. This repository does not contain actual GIEN production telemetry or prove regulatory compliance.

## Local run

Requirements: Node.js 22.16+, npm 10+.

```bash
npm ci
npm run check
npm run build
npm run dev
# In another terminal:
curl -fsS http://127.0.0.1:8080/healthz
```

The API binds to `127.0.0.1` by default. Set `HOST=0.0.0.0` only inside a controlled container network.

## Repository workflow integration

GitHub discovers workflows only beneath the repository-root `.github/workflows/`. When this project is nested at `gien-cicd-reference-1.0/`, use the repository-root workflows:

- `.github/workflows/gien-cicd-reference-ci.yml` — path-filtered CI, tests, compatibility checks and immutable action pin verification.
- `.github/workflows/gien-cicd-reference-release.yml` — manually dispatched image build/publish, provenance, scan and signing. It does not deploy to Kubernetes.

Before using the release workflow, set `GIEN_NODE_BASE_IMAGE` to an approved digest-pinned base image. Configure both `image-publish` and `supply-chain-attestation` GitHub environments with required reviewers and restrict them to `main`. Protect tags, configure root `.github/CODEOWNERS`, require CI and independent review, and verify minimum token permissions. These repository settings are not changed by the reference PR.

**Build once, promote by digest.** The production image must be the exact image verified in staging. Never rebuild it for promotion.

## Evidence bundle

```bash
node --experimental-strip-types scripts/build-evidence.ts \
  --input ./examples/evidence-input --output ./evidence-bundle \
  --deployment-id DEPLOYMENT-2026-0001 \
  --source-revision <full-git-commit> \
  --image ghcr.io/<org>/gien-cicd-reference@sha256:<digest>
node --experimental-strip-types scripts/verify-evidence.ts --bundle ./evidence-bundle
```

Use `scripts/anchor-evidence.sh`, `scripts/verify-anchors.sh` and `scripts/verify-supply-chain.sh` only after configuring Sigstore, approved signer identities, S3 Object Lock/WORM, and pinned verifier tools. Never put secrets, private keys, raw transcripts or unnecessary personal data in the evidence bundle or public transparency logs. Local hash verification is not proof of evidence completeness, WORM retention, or regulatory compliance.

## Documentation

- [`docs/CONTROL_MATRIX.md`](docs/CONTROL_MATRIX.md) — C1–C8 controls and evidence.
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — P1–P7 release lifecycle.
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — GitHub, Pact, SLSA, Sigstore, Kyverno and WORM integration.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model and security constraints.
- [`docs/LOCAL_VALIDATION.md`](docs/LOCAL_VALIDATION.md) — local checks and untested external integrations.

All GIEN-specific metric names and fictional treaties are simulation/governance constructs. Applicability of real regulatory frameworks requires review by accountable legal, compliance and risk owners.
