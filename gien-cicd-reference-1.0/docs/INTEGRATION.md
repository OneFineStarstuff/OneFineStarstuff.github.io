# Integration contract

## GitHub Actions / GHCR

Configure protected default branch, immutable release tags, CODEOWNERS for `.github/workflows/**`, required CI checks, least-privilege `GITHUB_TOKEN`, GHCR package permissions and a protected `supply-chain-attestation` environment. Configure repository variable `GIEN_NODE_BASE_IMAGE` with an approved OCI reference pinned by `@sha256:<64 hex>`. Restrict who can create release tags and approve the signing environment.

The reusable SLSA generator is pinned to a full Git commit SHA. Its container workflow expects `image` without tag/digest and `digest` as `sha256:<hex>`. Revalidate the exact input contract before updating the pin. SLSA Build L3 is a property of the builder and its isolation model, not the workflow string alone.

## Pact Broker

Set the Broker URL and credentials in protected environment secrets. Use the full source commit SHA as the participant version. Publish consumer and provider verification results before asking `can-i-deploy`. Record the actual deployment only after GitOps confirms the expected digest is live.

## Cosign / Rekor

Keyless signing obtains a short-lived certificate from the configured OIDC identity provider. Restrict verifier identity to the trusted workflow identity and issuer. Do not use broad wildcard identities where exact workflow refs are possible. Rekor's transparency record is not a substitute for storing the full evidence bundle.

## Syft / SBOM

Generate the SBOM from `IMAGE@DIGEST`, not from a developer workspace alone. Sign the SBOM as an in-toto attestation against that exact digest. Scan and evaluate vulnerabilities, licenses and policy conditions separately; a signed SBOM only proves the identity/integrity of the inventory statement, not that the inventory is risk-free.

## Kyverno

Install Kyverno and the relevant `ImageValidatingPolicy` CRD before policy deployment. Validate the exact API schema for the installed release. Test policy behavior against both good and deliberately invalid images in a non-production cluster. Scope the subject identity and image glob to the actual registry, repository and release workflow. Keep `failurePolicy: Fail`, digest verification and required validation enabled for production.

## Independent SLSA verification

Use a pinned, reviewed `slsa-verifier` release and the current `build` subcommand with `--require-signatures`, a narrow expected signer specification, and `--level 3`. The harness additionally checks that the verified statement subject includes the exact image digest and that the builder ID matches the expected identifier. Confirm the exact output format of `--print-provenance` for the pinned verifier release before adopting it in a regulated pipeline. A verification tool with a mismatched version or output contract must fail closed.

## WORM storage

Pre-create the bucket with Object Lock enabled at creation, versioning active, legal retention policy defined, administrative separation, audit logging and tested restore/read access. Set retention using the entity's approved record schedule; do not hardcode one duration across jurisdictions. The verification harness checks both the archive and signature-bundle object versions for COMPLIANCE mode, unexpired retention and byte-for-byte retrieval match. This still does not validate the complete bucket policy, account controls, legal hold process or statutory record classification. The example script uses S3 `COMPLIANCE` mode. Validate the bucket configuration, retention date and returned object version. Restrict `s3:BypassGovernanceRetention` and destructive administration. Protect the AWS role with short-lived OIDC credentials; do not store access keys in GitHub secrets.

## OSCAL / GIEN

Map each release control to an OSCAL control implementation and assessment result with a stable control ID, responsible party, evidence location, test method, finding status, assessment timestamp, and exception reference. GIEN indices (S_sys, G-SRI, C-SRI, CGR-I, CCR-I, G-SRI-VII, A-SRI, P-SRI, p(doom), p(doom)_kernel, Δ_drift, Δ_OSCAL) require approved metric definitions, ranges, units, formulas, thresholds and provenance. Do not infer numeric results from the existence of a successful pipeline.

## Vulnerability scan attestation (C5)

The release workflow scans the exact immutable image digest with Trivy v0.36.0. The workflow blocks on any CRITICAL or HIGH finding (including unfixed findings), then signs a compact policy-result predicate as an in-toto attestation. Kyverno requires the attestation signature and `predicate.policyDecision == PASS`. The full `trivy-results.json` report is uploaded as a 14-day workflow artifact for triage; export it into the deployment Evidence Bundle and WORM store under the institution's retention schedule. The GitHub Actions artifact is not WORM storage. The compact predicate includes the SHA-256 of the report, not the report contents. Do not treat this control as complete until the full scan report is exported and included in the deployment Evidence Bundle.

## Install in a larger GitHub repository

GitHub Actions discovers workflows only under the repository-root `.github/workflows/` directory. When this project is stored at `gien-cicd-reference-1.0/`, keep the nested workflow YAML files as portable templates and install the two root-level workflows supplied alongside this project:

- `.github/workflows/gien-cicd-reference-ci.yml` — path-filtered PR/push checks and schema compatibility verification.
- `.github/workflows/gien-cicd-reference-release.yml` — manual image publish, SLSA provenance, SBOM, Trivy scan and Cosign attestations; it does not deploy to Kubernetes.

Before running the release workflow, configure both GitHub environments (`image-publish` and `supply-chain-attestation`) with required reviewers and restrict deployments to `main`. Configure `GIEN_NODE_BASE_IMAGE` as a repository or environment variable containing an approved immutable image reference. Ensure the GitHub Actions token can write packages and verify GHCR package access. These repository settings are intentionally not changed by the integration PR.
