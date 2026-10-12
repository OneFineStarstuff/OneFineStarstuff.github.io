# Omni-Sentinel Technical Architecture and 2026–2035 Roadmap

> **Classification:** Fictional reference architecture; engineering design specification  
> **Scope:** Sentinel AI Governance Stack v2.4, Omni-Sentinel Governance Mesh v4.0, SCP v3.0  
> **Deployment posture:** Design proposal; not evidence of a deployed or independently assured system.

## <title>Enterprise AI Governance and DevSecOps Architecture</title>

## <abstract>
 This specification defines an implementation-oriented architecture for AI control evidence across G-SIFIs and large financial institutions. It integrates zero-trust workload governance, confidential-computing attestation, model and Mixture-of-Experts (MoE) routing governance, OSCAL control evidence, OPA/Rego policy tests, post-quantum signed WORM
logging, bounded zero-knowledge
proofs, TLA+ model checking, infrastructure-as-code, and supervisory submission workflows. It explicitly separates technical control observations from legal conclusions and independent assurance.
</abstract>

## <content>1. System boundary and trust model</content>

### Components
- **Sentinel AI Governance Stack v2.4:** model registry, release admission, runtime guardrails, drift detection, human oversight, vulnerability integrations, kill-switch coordination and evidence adapters.
- **Omni-Sentinel Governance Mesh v4.0:** authenticated node membership, cross-region control distribution, policy version reconciliation, signed event exchange, node health and quorum coordination.
- **Unified Supervisory Control Plane v3.0:** cycle orchestration, evidence normalization, control assessment, SLA exceptions, package assembly, retention metadata, and controlled export.
- **Evidence plane:** append-only event feed, signed artefact manifest, Merkle commitments, retention storage, audit query and independent verification service.
- **Proof plane:** bounded zkML/zk-SNARK/zk-STARK generation and verification jobs, verifier registries and proof metadata. Keep proof execution out of high-privilege orchestration where practical.
- **Operator plane:** privileged access management, audited approvals, emergency intervention, two-person rule for high-consequence changes and independent reviewer workflow.
- **Governance application:** React/TypeScript presentation layer. The browser must not be a trust boundary for authorization, key custody, status computation, or verification decisions.

### Trust boundaries
1. User/browser to API: authenticated identity, session protection, server-side authorization, rate limits and audit record.
2. API to control/evidence services: service identity, mTLS or equivalent authenticated transport, least-privilege access, schema validation and request correlation IDs.
3. Workload to confidential enclave: measured launch, attested workload identity, short-lived secrets and policy decision based on an approved measurement set.
4. Evidence writer to signing service: narrow signing API, HSM policy, authenticated attributes and separation of duties.
5. Evidence storage to verifier: retention lock, immutable version IDs, independently retrieved bytes and digest verification.
6. Institution to supervisory recipient: approved endpoint, payload encryption, signature verification, receipt authentication and reconciliation.

### Threats and required mitigations
| Threat | Minimum control | Proof to retain |
|---|---|---|
| Compromised CI credential | short-lived identity, environment protection, least privilege, provenance and rotation | identity audit, job attestation, rotation and revocation events |
| Malicious dependency/build artefact | pinned dependencies, SBOM, signed build provenance, dependency scanning, isolated runner | SBOM, lockfile, provenance statement, scan result |
| Stale or spoofed telemetry | source identity, schema validation, timestamp/freshness SLA, independent cross-check | signed source envelope, ingest log, freshness violations |
| Privileged tampering | split roles, WORM retention, external integrity anchor, monitored break-glass | access log, lock test, root reconciliation |
| Compromised TEE host | quote freshness, trust-chain/revocation validation, measured workload, fail-closed policy | quote, verifier report, PCR/measurement policy, containment |
| Invalid/overbroad policy | peer review, policy tests, negative cases, staged rollout and rollback | policy digest, approvals, test report, decision logs |
| ZK circuit defect | independent circuit review, known-answer and adversarial tests, verifier diversity | source/build digests, audit findings, test vectors |
| Dashboard misrepresentation | provenance-aware status model and API-derived labels | response schema tests, screenshot/accessibility and export tests |
| Cross-jurisdiction mapping error | versioned obligations register, legal owner, applicability review | mapping diff, approval, affected assessment list |

## <content>2. Zero-trust and confidential enclave deployment</content>

### Admission flow
1. CI verifies source revision, lockfile, tests, SBOM, vulnerability policy, artifact signature and build provenance.
2. Release controller checks an approved release policy and authorised reviewer record.
3. Workload identity is issued short-lived and limited to its purpose and environment.
4. Confidential-computing verifier validates the platform quote, nonce, trust chain, firmware state, revocation status and workload measurement against policy.
5. Workload receives only required secrets after successful attestation and policy decision.
6. Runtime monitors policy changes, drift, network egress, identity anomalies and tamper events.
7. Failed or stale attestation blocks protected operations or shifts to an approved safe mode; the exception is logged and escalated.
8. Rollback uses a separately signed known-good release and records who authorized it, what state was restored and whether post-rollback checks passed.

### Attestation record schema
 Required fields: record ID; node/workload ID; cloud/region; hardware technology; manufacturer/model; firmware and TCB level; quote nonce; quote digest; measurement register values or equivalent; image digest; verifier version; trust bundle version; revocation lookup time/result; policy version; observed/expiry time; decision; reason code;
reviewer/automation identity;
remediation ticket. Never store raw secrets or unnecessary personal information in the attestation record.

### Multi-region infrastructure-as-code requirements
 Terraform modules should be reviewed and versioned for each region. Prohibit embedded credentials; use workload identity or short-lived federated credentials. Pin provider/module versions and record the resolved lockfile, plan digest, approval, apply identity, resulting resource IDs and drift scan. Require policy-as-code gates for public exposure,
key policy, network egress,
unencrypted storage, image provenance, logging and destructive changes.

Region-level resilience requires:
- at least two independently recoverable control-plane placements appropriate to the availability objective;
- documented dependencies on identity, KMS/HSM, DNS, logging, policy distribution and evidence storage;
- failure tests for a region, identity provider, signing service and policy distribution plane;
- explicit data residency, cross-border transfer, backup and retention decisions;
- a safe-mode procedure when regions disagree on policy or evidence freshness.

Infrastructure-as-code does not itself establish security: the applied state must be checked against the plan, runtime inventory and external policy.

## <content>3. Model lifecycle, StaR-MoE and autonomous-agent governance</content>

### Model lifecycle gates
For each model, retain owner, use/purpose, affected decisions, materiality/risk tier, training/evaluation provenance where available, feature/data lineage, model and config digest, approval history, applicable jurisdictions, limitations, performance/fairness tests, rollback plan and retirement record.

Gate stages: register → classify → validate → approve → deploy → monitor → intervene → revalidate → retire. Each transition records actor, decision, version, evidence and reason. Production policy must support emergency suspension without deleting historical evidence.

### StaR-MoE routing stability
The fictional StaR-MoE concept should be measured through explicit, reproducible diagnostics rather than a single opaque score:
- expert utilization vector and load imbalance;
- routing entropy with a documented base/log convention;
- percentage routed to fallback/abstention;
- per-expert queue and latency percentiles;
- output quality and safety performance by route;
- drift by segment and evaluation window;
- retry loops, cascade amplification and correlated expert failures;
- routing-policy version and change reason;
- outcomes under missing expert, overloaded expert and adversarial input.
Set alert limits only after baseline measurement, calibration, acceptance criteria and model-risk approval. An entropy threshold such as 1.5 is a fictional policy parameter unless validated for the chosen router and its scale.

### Agent authority and containment
 Each autonomous supervisory agent receives an explicit authority envelope: allowed actions, prohibited actions, resource limits, max duration, data scope, human-confirmation rules and escalation owner. The control plane checks that envelope independently of the agent's own model output. Denials, attempted overrides, tool calls, context identities
and external side effects are
logged with privacy minimization.

Kill-switch design requirements:
- control path independent from the agent being stopped;
- authentication and authorization of the initiator;
- defined action semantics, idempotence and timeout;
- safe handling of partial mesh connectivity;
- test in staging and controlled production drills;
- independent health signal proving the stopped workload no longer performs protected actions;
- restoration requires revalidation and explicit authorization.
An ARMED status only confirms a configured state; test execution and observed effectiveness must be reported separately.

## <content>4. Telemetry and systemic-risk calculations</content>

### Metric data contract
Each metric event includes metric ID/version, raw value, unit, normalization method, population/scope, component input references, input source timestamps, missing-data treatment, threshold-policy version, calculation code digest, uncertainty/quality flag, provenance class and reviewer. Preserve raw components to permit independent recomputation.

### S_sys / G-SRI design expectations
 A composite systemic-risk score requires: well-defined exposure population; dependency/concentration model; component weights; normalization; missing-value policy; sensitivity analysis; calibration evidence; stress and historical backtests where applicable; confidence/uncertainty statement; override rules; model owner; independent validation; and
change control. Report both the
number and the top contributing factors. A dashboard value without these items is an illustrative score, not a supervisory measure.

Distinguish risk indicator, early-warning signal, legal limit and escalation threshold. These are not interchangeable. Threshold breach should create a triaged case with data-quality checks, materiality, incident links, containment decision and next review time.

### Alerts and compute-governance mode
 BASELINE and ELEVATED compute modes must be explicit policy states with authorised entry/exit conditions, resource allocation, prohibited workloads, approval, maximum duration, cost ceiling and audit event. Do not automatically reduce security validation because an elevated mode is costly or time-sensitive. Show resource bars as policy allocation,
not observed usage, unless
connected to measured telemetry.

## <content>5. Post-quantum evidence, HSM and WORM storage</content>

### Event envelope
Canonical fields: event ID, schema version, event type, subject, source identity, observed/ingested timestamps, payload digest, previous event or batch reference, algorithm identifiers, signer/key ID, signature bytes or secure reference, trust-chain reference, retention class, redaction status and validation-result reference.

### Key lifecycle controls
- Separate signing, key encapsulation, encryption-at-rest, transport and tokenization key purposes.
- Keep private keys inside approved HSM/KMS boundaries; prevent export where feasible.
- Use dual control for key generation, high-risk rotation and recovery operations.
- Record key creation/activation, rotation, disablement, revocation, compromise response and destruction.
- Test expired, revoked, unknown-key and algorithm-policy violations; reject rather than silently accept.
- Maintain crypto inventory, dependency graph, algorithm agility and deprecation timeline.

### WORM/Merkle-DAG operations
 For every batch: freeze inventory, canonicalize, digest, link previous root, compute Merkle root, sign manifest, write immutable object, read it back independently, recompute digests, verify signature, test retention metadata, and append a separate verification record. Periodically test restore using a distinct identity and region. Alert on
missing sequence numbers, unexpected
forks, clock rollback, signature downgrade and lock-policy change.

S3 Object Lock is a storage feature, not proof of SEC compliance by itself. Determine which records are subject to which retention rules, configure the allowed retention mode and duration, restrict permissions, and test recovery and audit trail requirements with compliance/legal owners.

### Post-quantum naming and migration
 Use ML-KEM (FIPS 203) for key encapsulation, ML-DSA (FIPS 204; standardized from Dilithium) for signatures, and SLH-DSA (FIPS 205; standardized from SPHINCS+) for hash-based signatures. Kyber and SPHINCS+ are commonly recognized predecessor/project names but should not be separately counted as unrelated final NIST algorithms. Falcon/FN-DSA status
must be rechecked against an
authoritative standards source before being marked approved. Record exact implementation, parameter set and interoperability tests; do not infer cryptographic security from an algorithm name alone.

## <content>6. zkML evidence and proof lifecycle</content>

### Controlled pipeline
Source model/program → approved compiler/toolchain → circuit or proof program → witness/input preparation → prover → local proof sanity checks → independent verifier → policy assertion → signed result manifest → WORM/Merkle anchoring → supervisory export.

The control plane stores job state and manifests; prover workers receive narrowly scoped inputs; verifiers run in a separately controlled service where practicable. A proof-generation success is not a verification success, and a verification success is not equivalent to an approved policy or compliant application.

### Evidence fields
 Model/program digest; circuit digest; source and compiler version; toolchain container digest; proving system; public inputs and their sources; private-input commitment; verification key ID/digest; proof digest; proof size; resource/time percentiles; job result; verification result; failure code; trusted setup metadata if used; independent audit
version/status; privacy
classification; policy interpretation and reviewer approval.

### Choice of proof system
- **Groth16:** compact proofs and fast verification can be useful for defined circuits, but trusted-setup governance and circuit soundness audit are material dependencies.
- **STARK-family approaches:** can avoid a circuit-specific trusted setup under their assumptions, but proof size, proving cost and verifier runtime must be measured for the use case.
- **SnarkPack aggregation:** aggregate only compatible statements and preserve per-item linkage, batch membership, and failure identification.
- **zkML:** test exact model operators, quantization, preprocessing, truncation, nondeterminism, output commitments and error bounds against the reference execution.

Required negative cases: tampered public input, wrong verification key, old circuit, missing batch member, invalid proof, stale model digest, timeout, verifier outage, and proof that verifies for the wrong policy statement.

## <content>7. TLA+ safety invariants and verification claims</content>

Use TLA+/TLC and/or Apalache for bounded state-machine checks of containment and supervisory orchestration. Keep source, constants, tool versions, bounds, result logs and reviewed counterexamples versioned. “No counterexample found under this model/bound” must not be rephrased as universal proof of safety.

Candidate invariants for SentinelContainmentProtocol and SCP v3.0:
- **I-01 AuthorityBounded:** agent side effects stay within the currently granted authority envelope.
- **I-02 HumanGate:** designated high-impact actions cannot commit without required human authorization.
- **I-03 FailClosedOnStaleAttestation:** protected action is blocked if quote or trust evidence is stale/invalid.
- **I-04 MonotonicEvidence:** accepted ledger batches do not silently rewrite prior accepted bytes.
- **I-05 SignedPolicyOnly:** deployment decisions require an approved policy digest and provenance.
- **I-06 QuorumBound:** constitutional changes require the configured quorum before activation.
- **I-07 KillSwitchConvergence:** after a successful containment signal, protected actions eventually cease under stated fairness/communication assumptions.
- **I-08 NoFalseSeal:** archive cannot enter SEALED unless manifest, signatures and retention checks pass.
- **I-09 CycleClosureComplete:** closure requires all mandatory evidence or approved explicit exception dispositions.
- **I-10 RoleSeparation:** no single ordinary operator can author, approve and independently attest the same high-risk change.

For each model, specify state variables, safety/liveness properties, environment assumptions, fairness assumptions, initial states, action relation, bounded parameters and a counterexample review process. Pair formal models with implementation tests, fault injection and independent review.

## <content>8. OSCAL and compliance-as-code engineering</content>

Required record lineage: obligation → applicability decision → GIEN domain/control → OSCAL control/profile → implementation component → assessment objective/method → OPA/Rego rule and tests → observed evidence → finding/POA&M remediation → retest → approver. Model references, control IDs and mappings must be version-pinned.

A minimum Rego pattern should fail closed on missing/stale evidence. Illustrative policy only:

~~~rego
package gien.control_evidence

default allow := false

allow if {
  input.evidence.present == true
  input.evidence.provenance == "verified"
  input.evidence.fresh == true
  input.assessment.status == "pass"
  input.policy.version == input.expected_policy_version
}

deny_reason := "missing, stale, unverified, or failed evidence" if {
  not allow
}
~~~

This snippet is a teaching example; it is not a complete compliance policy and has not been tested against live data. Production policy must define schemas and types, test pass/fail/missing/stale/tampered cases, and use independent peer review.

 OSCAL 1.1.2 should be treated as the explicit compatibility profile when contractually required. Track the supported schema/profile separately from the latest available OSCAL release, validate both required input and output profiles, and plan upgrades with diff reports and regression tests. OSCAL validation proves conformance to a schema/profile,
not legal compliance or
effectiveness.

## <content>9. DevSecOps and release assurance</content>

### Pull-request gates
- TypeScript strict checking and production build.
- Unit and component tests for thresholds, status provenance, filters, drawers, export schemas and simulation state.
- Route smoke test of all required routes.
- Accessibility checks for keyboard operation, focus containment, labels, status semantics and contrast.
- Dependency/SCA, secret scanning, SBOM generation, license policy and container/config scanning where applicable.
- Static checks for unsafe HTML rendering, client-side secrets and browser-only authorization.
- Deterministic fixture tests proving SIMULATED status stays visible in UI and exports.
- Build provenance, signed release artefact, rollback artifact and release approval.

### Deployment and runtime
Use environment separation, approved branches, required reviewers, least-privilege GitHub tokens, protected environments and pinned actions. Record commit SHA, lockfile digest, CI run, test artifacts and deployment identity. Monitor errors, route availability, dependency changes, API authorization failures, stale status data and export failures.

The current repository CI workflow must be observed to pass before declaring the prototype build verified. Configuration alone is not a successful test. The application should not be merged/deployed into an operational setting solely on the strength of a visually complete interface.

## <content>10. Roadmap and acceptance criteria, 2026–2035</content>

| Period | Main work | Acceptance evidence |
|---|---|---|
| 2026 H2 | System/control inventory, data provenance, threat model, OSCAL profile baseline | Approved inventory, data contract, ownership, reproducible CI baseline |
| 2027 | Control tests, remediation workflow, TEE/PQC pilot and jurisdictional readiness | Repeatable evidence pack, attestation negative tests, escalation and recovery drill |
| 2028 | Signed supply-chain releases, policy gates, safe rollback, consumer-impact evaluation | Independently reviewed policy tests, SBOM/provenance, staged/rollback evidence |
| 2029–2030 | Narrow zk proof pilot and hybrid PQC rehearsal | Circuit audit, invalid-proof tests, verifier diversity, measured performance |
| 2031–2032 | Correlated systemic-risk replay and institution dependency model | Methodology approval, backtesting, uncertainty reporting, reviewer challenge |
| 2033–2035 | Cryptographic agility, long-term archive restoration and succession dependencies | Successful restore, migrated-key tests, retained lineage and gate approval |

Every milestone needs named accountable owner, budget/capacity, measurable acceptance criteria, threat-model delta, known limitations, audit evidence, go/no-go decision and independently reviewed closure.

## <content>11. Standards and source register</content>

Check the current edition/version and jurisdictional adoption before using the mapping in a submission.

- NIST AI RMF: <https://www.nist.gov/itl/ai-risk-management-framework>
- NIST AI 600-1: <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>
- NIST OSCAL: <https://pages.nist.gov/OSCAL/>
- NIST FIPS 203: <https://csrc.nist.gov/pubs/fips/203/final>
- NIST FIPS 204: <https://csrc.nist.gov/pubs/fips/204/final>
- NIST FIPS 205: <https://csrc.nist.gov/pubs/fips/205/final>
- Federal Reserve SR 26-2: <https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm>
- European Commission AI Act: <https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai>
- ISO/IEC 42001: <https://www.iso.org/standard/81230.html>
- EU DORA: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>
- EU NIS2: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>
- EU GDPR: <https://eur-lex.europa.eu/eli/reg/2016/679/oj>

**Limitations:** This is a fictional reference architecture. It does not assert deployment, regulatory approval, the completion of cryptographic operations, legal compliance, or independent assurance.
