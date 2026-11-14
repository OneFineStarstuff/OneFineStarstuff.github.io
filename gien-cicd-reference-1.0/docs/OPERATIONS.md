# Operations: P1–P7

## P1 — Initiate and classify

Create a change record with source revision, owner, affected service/system/model, business purpose, data-flow impact, risk classification, test plan, rollback target, intended UTC deployment window and evidence-retention classification. For every class 2 or 3 change, require the applicable risk owner and change authority.

## P2 — Verify source and contracts

Validate OpenAPI; compare schema against the last approved baseline; run unit/integration/security tests; publish Pact contracts and provider verification; run `pact-broker can-i-deploy` for the production target. Store versioned, machine-readable results. Missing Broker history is not a pass.

## P3 — Build once

Use an ephemeral hosted builder with isolated build runs and protected provenance generation. Lock dependencies and use a base image pinned by digest. Build one OCI image, record its digest, generate signed provenance and an SBOM tied to that digest. Do not rebuild between environments.

## P4 — Verify and stage

Verify provenance builder identity, source commit, level and subject digest; verify Cosign identity and Rekor inclusion; evaluate SBOM findings; deploy to isolated staging under the same admission policy used in production. Run functional, security, load, recovery and application-specific tests.

## P5 — Authorize

Check the freeze calendar using UTC and the requested environment. Verify materiality decision, approvals, policy version and rollback plan. Use protected GitHub environments and a distinct approver group. Emergency access must use an external incident system, a bounded scope, a short expiry, two distinct authenticated approvers and a post-incident review.

## P6 — Promote by digest

Promote the exact image digest tested in staging. Use GitOps pull-based reconciliation and Kyverno admission. Canary traffic increments are service-specific; predefine error, latency, saturation, fairness and safety abort thresholds. Roll back to a previously verified digest when a threshold trips. Record the actual running image ID from the cluster.

## P7 — Seal and verify

Collect a complete evidence set; canonicalize entries; hash each entry; construct the deterministic Merkle root; sign the root with keyless Cosign; retain the full package and signature bundle in an Object Lock/WORM system; verify the Rekor bundle and WORM object metadata independently; generate the supervisory dossier. Mark incomplete anchors `UNVERIFIABLE`, not `PASS`.

## Daily supervisory window

At every 09:00 UTC cutoff, evaluate the completed interval `[T-24h, T)`. Include pipeline runs, release decisions, deployment/rollback events, admission decisions, runtime telemetry, proof/attestation status, risk-index values with versioned metric definitions, OSCAL/policy diffs, exceptions and remediation evidence. This repository does not contain actual GIEN telemetry or repository audit records; the daily dossier must be generated from connected source systems.

## Rollback and incident handling

Rollback is a new auditable deployment event. It must reference the prior known-good image digest, initiating incident/change record, triggering signal, authorizer, execution time, cluster workload state and post-rollback verification. Do not erase the failed deployment's evidence.
