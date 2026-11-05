# GIEN-Style Regulator-Defensible CI/CD Pipeline — Design and Step-by-Step Implementation Plan

**Document ID:** GIEN-CICD-REGDEF-2026-11-02
**Work Package:** WP-087
**Date:** 2026-11-02
**Scope:** Single containerized Node/TypeScript REST API deployed to Kubernetes
**Relationship:** Subordinate to the Edition-3 webapp design authority (WP-083); extends Control Domain 08 (Kubernetes/GitOps zero-trust deployment posture)
**Baseline of record:** GIEN-DOSSIER-2026-306
**Classification:** TOP SECRET // SUPERVISORY EYES ONLY (fictional simulation)

> **Fictional simulation notice.** This document is a governance-simulation artefact for the fictional GIEN planetary governance mesh. Pipeline stages, evidence values, and anchors are simulated. References to real-world tools and regulatory frameworks (Sigstore, SLSA, Pact, Kyverno, DORA, NIS2, EU AI Act, SR 11-7, SR 26-2, SEC Rule 17a-4, HKMA, MAS) are alignment context for the simulation, not legal or engineering advice.

---

## 1. Purpose and the regulator-defensibility test

A pipeline is regulator-defensible when a third party with no access to internal systems can, from public keys, transparency logs, and an exported evidence bundle alone, answer five questions for any deployment:

1. **Provenance** — who built this artifact, from what source, with what builder?
2. **Integrity** — is the deployed byte-for-byte artifact the one that was built, signed, scanned, and admitted?
3. **Authorization** — did every promotion pass the contract, change-classification, and freeze gates it should have?
4. **Continuity** — is the evidence for items 1–3 preserved in tamper-evident, WORM-compliant form for the supervisory retention horizon?
5. **Exception discipline** — if normal gates were bypassed, was the break-glass path itself gated, time-boxed, dual-approved, and reviewed?

The design below makes each question machine-checkable by an external verifier. If a claim cannot be verified by the third-party harness in Section 5, it is not evidence — it is marketing.

## 2. Reference architecture

```text
schema repo (OpenAPI 3.1) ---+
api repo (Node/TS) ----------+--> CI: drift gate > unit/integration > Pact verify > hermetic build
consumer pact files ---------+
                                     |
                                     +--> SLSA L3 provenance (slsa-github-generator)
                                     +--> keyless signing (cosign OIDC) --> Sigstore Rekor entry
                                     +--> SBOM (Syft SPDX) + CVE scan (Grype) + cosign attest
                                     +--> Evidence Bundle builder (Merkle) --> dual anchor (Rekor + WORM)

deploy: can-i-deploy gate > material-change gate > freeze-window gate > Kyverno admission
        (signature + provenance + SBOM + CVE + policy exceptions with TTL) --> deploy record --> bundle seal

break-glass: incident tracker > four-eyes approval > TTL-bound Kyverno PolicyException
             + per-incident OIDC credentials --> WORM audit --> 48 h post-incident review
```

Immutable identity spine: every artifact and evidence item is referenced by SHA-256 digest, never by tag. Every deployment references an image digest, a bundle root, and a Rekor entry UUID.

## 3. The eight mandatory controls

### C1 — Schema-first development and drift gating

- **Objective:** the OpenAPI 3.1 specification is the single source of truth; the implementation can never silently drift from it.
- **Implementation:** the spec lives in-repo under `openapi/` with lint (Spectral) and semantic diff (`oasdiff`) on every PR; TypeScript route types are generated from the spec (never hand-written); a CI gate classifies diffs as non-breaking, breaking-annotated, or breaking-unapproved.
- **Enforcement:** breaking-unapproved diffs fail CI; breaking changes require the material-change label (C7) plus a deprecation window for consumers.
- **Evidence:** the normalized diff report and its digest enter the bundle.
- **Failure mode to avoid:** a spec that is documentation rather than a gate — generated from code after the fact, never blocking anything.

### C2 — Pact-based contract testing with can-i-deploy

- **Objective:** no version reaches an environment unless compatibility with every consumer already there is proven.
- **Implementation:** consumer-driven Pact contracts published to a Pact Broker; provider verification runs in CI on every change with real handler fixtures; the pre-deploy step runs the broker compatibility check:

```bash
pact-broker can-i-deploy --pacticipant api --version "$GIT_SHA" --to-environment production
```

- **Enforcement:** a failed or unknown check blocks promotion; the check result JSON (with broker transaction UUID) is a bundle artifact.
- **Failure mode to avoid:** masking unknowns with long retry loops, or querying a different environment than the one actually deployed to.

### C3 — Hermetic builds with SLSA L3 provenance, verified with slsa-verifier

- **Objective:** the build process is isolated from uncontrolled inputs, and its provenance is signed by a hardened builder and independently verifiable.
- **Implementation:** pinned base image by digest; dependencies from an internal registry proxy with a lockfile (`npm ci` only, never `npm install`); no network egress beyond the proxy during build; provenance generated by the SLSA GitHub generator (SLSA v1.0, level 3) bound to the workflow identity:

```bash
slsa-verifier verify-artifact --provenance-path provenance.slsa.json --source-uri "github.com/example/api" --source-tag "v1.2.3" dist/
```

- **Honesty note:** hermetic is not bit-reproducible. The claim the pipeline makes is provenance integrity (verifiable builder, source, and commands), not that two builds yield byte-identical images. Determinism is demanded only of the evidence (Section 4), never asserted of the artifact.
- **Failure mode to avoid:** self-attested provenance produced inside the same untrusted job it describes — that is SLSA L1 dressed as L3. Use a builder whose provenance signing identity is outside the control of the pipeline code it builds.

### C4 — Keyless signing of container images

- **Objective:** signatures are bound to workflow OIDC identity; no long-lived signing keys exist to leak, rotate, or share.
- **Implementation:**

```bash
cosign sign --yes "registry.example.internal/api@sha256:$DIGEST"
cosign verify --certificate-identity-regexp "https://github.com/example/api/.github/workflows/release.yml@refs/heads/main" --certificate-oidc-issuer "https://token.actions.githubusercontent.com" "registry.example.internal/api@sha256:$DIGEST"
```

- Each signature creates a Sigstore Rekor transparency-log entry; the Rekor UUID is recorded back into the bundle (Section 4).
- **Failure mode to avoid:** a private signing key stored in CI secrets — keyless exists precisely to remove this class of failure; an auditor treats long-lived pipeline signing keys as a finding, not a control.

### C5 — SBOM generation and admission-time enforcement with Kyverno

- **Objective:** an SBOM exists for every image, and its constraints are enforced at admission — not filed away.
- **Implementation:** Syft emits SPDX; Grype gates on critical CVEs (deny unless a signed, expiring waiver references a ticket); the SBOM is attached as a cosign attestation; Kyverno verifies at admission time that the image is signed, carries a valid SBOM attestation, and passes the CVE policy.

```yaml
# Illustrative Kyverno policy (audit 2 weeks, then Enforce)
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: api-image-controls
spec:
  validationFailureAction: Enforce
  rules:
    - name: verify-signature-sbom
      verifyImages:
        - imageReferences: ["registry.example.internal/api/*"]
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/example/api/.github/workflows/release.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
          attestations:
            - type: "https://spdx.dev/Document"
              conditions:
                - all: ["{{ data.packages.length() > 0 }}"]
```

- **Failure mode to avoid:** admission policy left in audit mode indefinitely (an enforcement gap between written policy and actual cluster state), or SBOM checks that verify the existence of a document without verifying its digest matches the image.

### C6 — Freeze windows aligned to supervisory cycles

- **Objective:** production changes pause during supervisory-critical windows so telemetry windows stay attributable (in the GIEN mesh: the daily 09:00 UTC dossier window, Saturday weekly aggregation, and live drill execution windows).
- **Implementation:** a `freeze.yaml` calendar in-repo is the source of truth; a CI gate blocks deployment events intersecting a freeze; on the cluster side Kyverno denies deployments carrying no valid freeze-exception label during an active window; the gate result and calendar digest are bundle artifacts.
- **Failure mode to avoid:** a freeze that only gates the pipeline but not direct cluster-access paths — the cluster-side policy is mandatory, which is why enforcement exists in two layers.

### C7 — Material-change classification gates

- **Objective:** every change is classified, and changes that could alter behavior, risk, or regulatory posture receive proportional governance before merge.
- **Implementation:** an automated classifier labels each PR — non-material (docs, tests) vs material (API schema diff, dependency major bump, model/config change, infra change) — using path rules plus the C1 diff verdict; material changes require a second CODEOWNERS reviewer, a short impact-analysis note, and generate a regulatory change-record entry that enters the bundle.
- **Failure mode to avoid:** classification that can be self-served by relabeling — the classifier verdict, not the author opinion, is what the gate consumes.

### C8 — Break-glass procedures bound to an external incident tracker, four-eyes, and audit

- **Objective:** emergency paths exist, are rare, are provably authorized, and are always reviewed.
- **Implementation:**
  1. An incident issue (`INC-*`) in the external tracker is the mandatory entry point; its ID is the correlation key for everything that follows.
  2. Four-eyes: two distinct human identities approve in the tracker and in the deploy environment protection (distinct-account checks; the pipeline author cannot be an approver).
  3. The pipeline mints per-incident, TTL-bound (4 h) credentials via OIDC — no standing break-glass accounts, no shared kubeconfigs.
  4. A Kyverno PolicyException is generated with a TTL equal to the credential TTL and the INC reference; it expires by itself.
  5. Every action emits an audit event into the WORM ledger inside the standard evidence envelope; the exception, its approvers, TTL, and expiry enter the bundle.
  6. A post-incident review (48 h) files findings to the supervisory record — the DORA learning-and-evolving obligation made concrete.
- **Failure mode to avoid:** standing break-glass credentials, unbounded exceptions, or a tracker reference that is a free-text field no one validates against the tracker API.

## 4. Deterministic Merkle-based Evidence Bundle

### 4.1 Canonicalization

All bundle artifacts are JSON documents canonicalized with RFC 8785 (JSON Canonicalization Scheme) before hashing. Two rules make the root deterministic:

- No wall-clock timestamps, no UUIDs, no environment-dependent values inside leaf documents — only content-addressed or window-referenced values.
- Leaves are ordered lexicographically by artifact ID; an identical input set yields an identical root, on any machine, forever.

### 4.2 Tree construction

```text
leaf     = SHA-384("gieneb-leaf/v1" || artifact_id || SHA-384(JCS(artifact)))
node     = SHA-384("gieneb-node/v1" || left_hex || right_hex)
root     = pairwise reduction of the lexicographically-ordered leaf list
manifest = JCS of { bundle_id, deployment_id, image_digest, window_id, artifact_ids,
                    merkle_root, signatures { ml_dsa_87, falcon_1024 } }
```

Mandatory artifact set per deployment (26 items in the GIEN convention): source commit and tree digest; OpenAPI spec digest and drift verdict; unit and integration test reports; Pact verification results and can-i-deploy JSON; SLSA provenance; image digest; cosign signature and Rekor UUID; SBOM (SPDX); CVE scan report and any signed waivers; Kyverno admission decision snapshot; freeze-calendar digest and gate verdict; material-change classification and change record; deployment manifest digest; smoke-test result; bundle manifest signature block.

### 4.3 Dual anchoring

| Anchor | Mechanism | Purpose |
|---|---|---|
| Sigstore Rekor | The signed bundle manifest creates a transparency-log entry; the harness validates the inclusion proof against the Rekor signed tree head | External, third-party-operated, publicly auditable, timestamped commitment |
| Internal WORM ledger | The Merkle root and manifest are appended to an Object Lock bucket (SEC 17a-4 retention profile, 6-year immutability) and to the GIEN PQC Merkle-DAG ledger (ML-DSA-87 primary, Falcon-1024 throughput, SLH-DSA backstop) | Supervisory retention independent of the transparency log |

Both anchors are cross-referenced: the WORM record stores the Rekor UUID, and the harness refuses a bundle whose two anchors disagree.

## 5. Third-party verification harness

A supervisor runs a published, hermetic OCI image; it needs only the exported bundle, public keys, and network access to Rekor — never internal systems.

```bash
docker run --rm --volume "$PWD/evidence:/evidence" ghcr.io/gien-sim/governor-verify:1.0.0 verify-bundle /evidence/bundle.json --policy /evidence/policy.yaml --anchors rekor,worm --out /evidence/verification-statement.md
```

Harness checks, in order — exit 0 only if all pass:

1. Verify the manifest signature (cosign, keyless identity pinned in policy) and the Rekor inclusion proof against the signed tree head.
2. Verify SLSA L3 provenance with slsa-verifier (source URI, tag, builder identity).
3. Recompute every leaf: canonicalize each artifact with JCS, re-hash, rebuild the Merkle root, and compare it to the manifest root.
4. Compare the root against the internal WORM anchor record (and the Rekor UUID cross-reference).
5. Verify the image signature chain and that the deployed digest equals the bundle digest.
6. Validate Kyverno admission decisions for that digest (from the signed policy-report snapshot).
7. Validate Pact verification and can-i-deploy results against the broker transaction records.
8. Validate the freeze-gate verdict, the material-change record, and (if present) the break-glass exception TTL and four-eyes approvals.
9. Emit a signed verification statement: pass/fail per check, inputs, versions, and the harness digest of itself — the statement is itself evidence.

## 6. P1–P7 rollout plan

| Phase | Weeks | Scope | Acceptance criteria |
|---|---|---|---|
| P1 | 1–2 | Schema-first and drift gating (C1); trunk-based development; CI skeleton | 100% of routes declared in the spec; the drift gate blocks an unapproved breaking change in a drill |
| P2 | 2–4 | Pact broker, provider verification, can-i-deploy gate (C2) | Promotion refuses a known-incompatible version in a drill; broker records retrievable |
| P3 | 4–6 | Hermetic build, SLSA L3 provenance, keyless signing (C3, C4) | slsa-verifier passes from a clean machine with pinned identity; no long-lived signing keys exist anywhere |
| P4 | 6–8 | SBOM, CVE gate, Kyverno admission (C5) — audit mode 2 weeks, then Enforce | Unsigned, SBOM-less, or critical-CVE images rejected at admission in a drill; the waiver path works and expires |
| P5 | 8–10 | Evidence bundle builder, dual anchoring, WORM appender | The harness recomputes a root equal to the manifest root from a fresh export on an independent machine |
| P6 | 10–12 | Freeze windows and material-change gates (C6, C7) | A freeze blocks a deploy in a drill; the exception path enforces the calendar digest; classifier verdicts gate reviews |
| P7 | 12–14 | Break-glass (C8), supervisor harness, regulator dry run | Four-eyes and TTL exercised in a drill; the 48 h review is filed; a regulator runs the harness unaided on a frozen historical deployment |

Sequencing rationale: P1–P2 remove silent interface risk first; P3–P4 establish artifact trust; P5 makes trust provable; P6–P7 wrap change governance and exceptions. No phase skips its predecessor — bundle anchoring (P5) without admission enforcement (P4) would produce evidence for a cluster that still accepts unsigned images.

## 7. Regulatory mapping (evidence to obligation)

| Framework | Obligation focus | Controlling evidence |
|---|---|---|
| DORA (Reg. (EU) 2022/2554) | ICT risk-management framework, change management, detection, learning from incidents | Freeze and material-change gates and change records (Arts. 5–6, 9); admission and signature logs (Art. 10); 48 h post-incident reviews of break-glass (Art. 13) |
| NIS2 (Reg. (EU) 2022/2555) | Supply-chain security, secure development, incident handling | SLSA L3 provenance, SBOM and dependency gates, Pact records (Art. 21(2)(d)); incident-linked break-glass trail (Art. 21(2)(e), Art. 23) |
| EU AI Act Annex IV / Arts. 15, 17 | Technical documentation, change logging, accuracy, robustness, cybersecurity | Schema and drift record, regression suite results, evidence bundle change records per release; bundle integrity supports Art. 17 QMS claims |
| SR 11-7 (model risk) | Governance and independent validation of model changes | Material-change gate, second-reviewer requirement, model and config change records entering the bundle |
| SR 26-2 (scenario design) | Sound stress and scenario methodology | Freeze-window and break-glass drills with filed after-action reviews; canary and rollback drill results |
| SEC Rule 17a-4 | WORM-compliant preservation of required records | Internal WORM anchor with Object Lock retention profile; dual-anchor cross-reference; harness-verifiable retrieval |
| HKMA Fintech 2030 AI² | Governance and controls over AI and model deployment | SBOM and model inventory links, deployment decision records, supervisory verification statements |
| MAS FEAT | Fairness, ethics, accountability, transparency | Evidence-qualified deployment record — what was approved, by whom, under which gates, each claim traceable to a sealed artifact |

## 8. Common credibility failures and how this design avoids them

| # | Credibility failure | Why audits fail | Mitigation in this design |
|---|---|---|---|
| 1 | Self-attested evidence (the pipeline grades its own homework) | The verifier shares a trust root with the system under review | The harness (Section 5) is external, hermetic, and pinned; provenance is signed by a builder identity outside pipeline control |
| 2 | Tags instead of digests | A mutable tag can change between build, audit, and rollback | Digest-only references end to end; Kyverno rejects unpinned references |
| 3 | SBOM generated but never enforced | Theater compliance — a document nobody gates on | Admission-time attestation verification plus a CVE gate with expiring signed waivers |
| 4 | can-i-deploy bypassed or retried until unknown | Compatibility theater | The promotion gate consumes the broker verdict; unknown is a fail; the broker transaction ID is bundle evidence |
| 5 | Long-lived signing keys in CI secrets | A single point of catastrophic compromise | Keyless OIDC signing (C4); auditors treat pipeline-held keys as a finding |
| 6 | Provenance from a non-hermetic builder | L1 claims wearing L3 clothing | Hermetic build controls plus slsa-verifier with a pinned builder identity |
| 7 | Freeze windows enforced only in CI | Cluster-side bypass via direct cluster access | Two-layer enforcement: CI gate plus Kyverno cluster policy |
| 8 | Standing break-glass credentials | The emergency path becomes the daily path | Per-incident OIDC credentials, 4 h TTL, tracker-bound exception, 48 h review |
| 9 | Rekor entry never inclusion-proof-checked | An anchor claimed but not verified | The harness validates the inclusion proof against the Rekor signed tree head |
| 10 | Evidence in mutable object storage | Retention that can be edited fails WORM claims | Object Lock WORM plus cross-referenced anchors; any disagreement fails verification |
| 11 | Non-deterministic Merkle root (timestamps, UUIDs in leaves) | A rebuild cannot reproduce the root, so the evidence is unverifiable | RFC 8785 canonicalization plus content-only leaves (Section 4.1) |
| 12 | Policy permanently in audit mode | A written control, unenforced in reality | Audit mode is time-boxed (2 weeks in P4) and the Enforce flip is a material change with a bundle record |

## 9. Evidence index for submission packages

Each deployment produces one submission-ready index in the GIEN title / abstract / content convention:

- Title: deployment identity, image digest, window ID.
- Abstract: gate verdicts (drift, pact, provenance, signature, SBOM and CVE, freeze, material-change, break-glass) — all PASS, or the deployment did not happen.
- Content: the evidence index — 26 artifact IDs, their digests, the Merkle root, both anchor references, and the latest third-party verification statement.

## 10. Integration with the GIEN supervisory mesh

- The bundle Merkle root and gate verdicts are reported into the daily dossier deployment section (Control Domain 08 telemetry).
- Freeze windows align with the 09:00 UTC supervisory window, weekly aggregation editions, and DRILL-0xx live-execution windows (current reference: dossier-306, GitOps 217/217 reconciled, zero drift).
- Break-glass drills file after-action reviews through the same college countersignature path as containment drills.

## 11. Recommendations by audience

- **Supervisors and colleges:** never accept prose controls — demand the harness run on a frozen historical deployment, and demand the inclusion-proof check.
- **Platform engineers:** land P1–P4 before any anchoring claims (P5); evidence without enforcement is failure 3 in the table above.
- **Audit and compliance:** test the exception path, not only the happy path — the credibility of a pipeline is proven by how its break-glass behaves.

---

*This document is a fictional governance-simulation artefact for the GIEN planetary governance mesh. Pipeline stages, evidence values, anchors, and drills are simulated data. Mentions of real-world tools and frameworks are alignment context, not engineering or legal advice.*