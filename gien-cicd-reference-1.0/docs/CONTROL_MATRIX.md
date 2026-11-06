# Mandatory release controls C1–C8

| ID | Control | Required evidence | Blocking condition | Main phase |
|---|---|---|---|---|
| C1 | Schema-first and drift gating | Canonical OpenAPI 3.1 JSON, external release JSON Schema, TypeScript runtime validation, API path/operation compatibility guard and backward-compatible schema diff against PR base | Removed route/operation/property, new required input, type/enum/format change or tightened constraint | P2 |
| C2 | Pact contract testing | Broker verification matrix and `can-i-deploy` result for production | Incompatible or missing contract result | P2/P5 |
| C3 | Hermetic build and SLSA L3 | Hosted-builder controls, build identity, signed provenance, source and subject digest | Provenance missing, invalid, wrong source/subject or insufficient level | P3 |
| C4 | Keyless image signing | Cosign signature, certificate identity, issuer and Rekor bundle | Wrong identity, digest or invalid proof | P4 |
| C5 | SBOM and admission | Digest-bound signed SBOM, vulnerability policy, Kyverno admission result | Missing/failed SBOM or non-ALLOW admission | P4/P6 |
| C6 | Supervisory freeze | UTC freeze calendar; if exception is invoked, retain exception ID, scope, approver evidence and future expiry | Freeze active without a valid, scoped, unexpired exception | P5 |
| C7 | Material-change classification | Classification, risk assessment and independent approval; sample evaluator requires one risk approval for Class 2 and two for Class 3 | Unclassified or insufficiently approved material change | P1/P5 |
| C8 | Break-glass | External incident, narrow scope, expiry, two distinct approvers, audit event | Missing incident, requester self-approval, duplicate approvers or expiry | P5/P6 |

## Evidence assertions versus evidence verification

The TypeScript evaluator consumes boolean and identity claims. It is a decision-logic example and does not itself verify the truth of external records. A production release orchestrator must obtain C2–C6 from their actual providers, verify signatures/proofs, authenticate approvers, and persist decision inputs and outputs. A JSON body cannot authenticate an approver.

## Risk-based materiality

The sample classifier places changes to purpose, models, data processing, security boundaries or critical safety controls in Class 3. Operational-impact-only changes are Class 2. Other changes are Class 1. This is a conservative sample taxonomy, not a legal definition of material change. Adapt and approve it for each regulated entity and system inventory.
