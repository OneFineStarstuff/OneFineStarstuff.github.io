# Implementation status and assurance boundary

## Implemented and locally exercised

- Node.js/TypeScript HTTP API and OpenAPI contract.
- Typed C1-C8 policy evaluator and material-change classifier.
- Deterministic, canonical evidence-bundle builder and local Merkle verifier.
- Tamper, extra-file and deployment-metadata tamper tests.
- OPA/Rego policy source and release-policy test source.
- Kyverno `ImageValidatingPolicy` sample requiring a keyless image signature, SBOM, SLSA provenance and signed vulnerability-scan PASS attestation.
- GitHub Actions CI and tag-release workflow with full-SHA action references.
- Trivy scan of the exact image digest, blocking CRITICAL/HIGH vulnerabilities.
- Dockerfile, Kubernetes deployment/service/namespace/network policy templates.
- Pact Broker, SLSA/Cosign verification and S3 Object Lock operator scripts.

## Local validation performed

- `npm ci`
- `npm run check` (21 automated tests passed in the latest recorded local run)
- Shell syntax checks (`bash -n scripts/*.sh`)
- Immutable GitHub Actions SHA reference check
- OpenAPI 3.1 and JSON Schema compatibility checks, including a PR-base comparison test suite
- YAML syntax parsing for workflow, Kubernetes and Kyverno manifests
- Local HTTP smoke test for `/healthz` and release-evaluation endpoint
- Evidence bundle creation and positive/negative integrity verification

The command log is not a signed external audit record. Run the checks again in the target repository and retain their CI evidence.

## Not yet exercised against live infrastructure

- Hosted SLSA builder security controls and a genuine Build L3 claim.
- GHCR push, OIDC identity/certificate, Rekor inclusion and image attestations.
- Pact Broker compatibility matrix with actual consumers/providers.
- OPA execution against the deployed policy bundle (OPA is not assumed installed locally).
- Kyverno CRD/API compatibility, admission webhook, and cluster positive/negative policy tests.
- S3 Object Lock bucket policy, Compliance retention, version retrieval and administrative controls.
- Production authentication, approver identity, audit-event persistence, GitOps promotion, freeze-calendar provider and runtime digest reconciliation.

## Release status

`REFERENCE_IMPLEMENTATION / LOCAL_TESTS_PASS / EXTERNAL_INTEGRATIONS_UNVERIFIED`.

Do not label this repository SLSA Build L3 certified, legally compliant, independently assured, or approved by a regulator. The policy evaluator is a decision-logic example. Its JSON identity fields are claims; they are not authenticated identities and must not be used as the sole production authorization source.
