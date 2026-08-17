# Sentinel GSIFI AI Governance Stack Implementation Blueprint (2026-2035)

**Version:** v2.4 / Omni-Sentinel Mesh v4.0 / Unified Supervisory Control Plane v3.0  
**Audience:** G-SIFIs, Fortune 500 financial institutions, regulators, internal audit, model risk, cloud security, and DevSecOps teams  
**Status:** Implementation blueprint and packaging guide; not legal, supervisory, or investment advice

## 1. Executive implementation thesis

This blueprint converts the Sentinel AI Governance Stack v2.4, Omni-Sentinel Mesh v4.0, and Unified Supervisory Control Plane (SCP) v3.0 into a step-by-step delivery program for systemically important financial institutions from 2026 through 2035. The program treats AI governance as a verifiable production control system rather than a policy document: every high-impact model or agent is inventoried, risk-tiered, policy-gated, enclave-attested where needed, cryptographically logged, continuously monitored, and packaged into regulator-facing evidence bundles.

The target operating model has seven non-negotiable properties:

1. **Zero-trust AI governance:** no model, agent, plug-in, policy bundle, telemetry producer, or reviewer account is trusted by network location or organizational role alone.
2. **Cryptographic evidence:** material decisions and controls are signed at source, chained into Merkle roots, retained in WORM storage, and anchored to independent timestamping or ledger infrastructure.
3. **Confidential execution:** Tier 0 and critical Tier 1 workloads run in trusted execution environments (TEEs) or confidential VMs with remote attestation, measured boot, sealed secrets, and policy-bound release of keys.
4. **Formal safety cases:** containment, delegation, emergency-stop, evidence-freshness, and policy-release invariants are specified in TLA+ and checked in CI before production promotion.
5. **Compliance as code:** OSCAL control catalogs, OPA/Rego policies, Terraform evidence infrastructure, and jurisdictional overlays are versioned as signed artifacts.
6. **Systemic-risk transparency:** privacy-preserving zero-knowledge proofs summarize Basel III/IV-relevant AI risk transitions without exposing customer-level or trade-level data.
7. **Operational resilience:** 24-hour monitoring, integrity checks, dead-man's switch procedures, and federated collective defense sharing keep AI control failures from becoming systemic events.

## 2. Reference architecture

### 2.1 Control-plane layers

| Layer | Primary components | Design intent | Required artifacts |
|---|---|---|---|
| Governance intake | Model registry, AI use-case intake, tiering workflow, accountability matrix | Establish ownership, risk tier, approved use, data boundaries, and supervisory posture | Model card, owner attestation, tier decision, data lineage |
| Policy decision plane | OPA/Rego bundles, OSCAL controls, exception registry, policy signing | Enforce regulatory and institution-specific controls before deployment and at runtime | Signed policy bundle, OSCAL component definition, exception record |
| Runtime containment | Omni-Sentinel Mesh v4.0 sidecars, egress brokers, tool mediators, kill-switch graph | Prevent uncontrolled tool use, network exfiltration, escalation, or autonomous drift | Containment profile, egress allowlist, emergency-stop runbook |
| Confidential compute plane | Enclave/Confidential VM orchestrator, attestation verifier, HSM/KMS integration | Bind secret release and production traffic to measured, approved workloads | Attestation report, measurement allowlist, sealed secret policy |
| Evidence and telemetry plane | Kafka, schema registry, S3 Object Lock WORM, Merkle workers, SIEM/SOAR | Produce tamper-evident, replayable governance evidence | Signed event schema, retention policy, Merkle root ledger |
| Supervisory interface | SCP v3.0 APIs, OSCAL export, regulator sandbox, dossier generator | Support API-first and dossier-based supervisory review | Evidence bundle, assessment results, supervisory briefing |
| Systemic risk analytics | G-SRI engine, concentration metrics, stress scenarios, zk-SNARK proof service | Quantify AI concentration, control degradation, contagion, and capital planning impact | G-SRI report, Basel transition proof, stress pack |

### 2.2 Zero-trust AI governance architecture

Implement zero trust with explicit identity, policy, and evidence checks at each AI transaction boundary:

1. **Workload identity:** use SPIFFE/SPIRE or equivalent identities for models, sidecars, agents, telemetry workers, and control-plane services.
2. **Human identity:** require phishing-resistant MFA, privileged-access management, just-in-time elevation, and separation of duties for model developers, policy approvers, HSM custodians, and production operators.
3. **Policy evaluation:** require an OPA decision for deployment, inference routing, tool invocation, data retrieval, policy override, and evidence-export events.
4. **Network isolation:** place AI workloads in microsegmented namespaces with default-deny ingress and egress; route all external access through inspected brokers.
5. **Data minimization:** enforce purpose-specific retrieval scopes, row/column-level policies, token-level DLP, and customer-data localization constraints.
6. **Continuous verification:** re-evaluate policy on drift, model version changes, prompt-template changes, toolchain upgrades, jurisdiction changes, and stale attestation.

### 2.3 Confidential computing enclave deployment and attestation

For Tier 0 and critical Tier 1 workloads, deploy confidential compute as follows:

1. **Build:** produce reproducible images; generate SBOM and BBOM; sign container digests and policy manifests.
2. **Measure:** capture enclave or confidential-VM measurements for kernel, boot chain, container runtime, model artifact hash, sidecar hash, OPA bundle hash, and telemetry agent hash.
3. **Allowlist:** publish signed measurement allowlists from the governance release process.
4. **Attest:** require remote attestation before joining the service mesh, receiving traffic, unsealing model weights, or obtaining HSM/KMS data keys.
5. **Seal:** bind secrets to approved measurements, workload identity, jurisdiction, and policy-bundle version.
6. **Monitor:** expire attestations on a short TTL; rotate attestation evidence into Kafka and WORM storage; alert on stale, downgraded, or unexpected measurements.
7. **Revoke:** remove measurements from allowlists when vulnerabilities, unapproved drift, or emergency de-autonomization events occur.

## 3. StaR-MoE routing stabilization

StaR-MoE routing stabilization prevents expert-collapse, correlated routing, and policy-bypass through mixture-of-experts routing drift.

**Controls:**

- Track per-expert load, entropy, specialization drift, rejected route count, fallback frequency, and safety-expert activation.
- Require route decisions to include signed context hashes, policy-decision IDs, expert-set version, and confidence bands.
- Use a stability budget: routing distribution shift beyond approved thresholds triggers canary rollback or human review.
- Pin high-impact domains to approved expert subsets and forbid dynamic expert discovery in Tier 0 production.
- Run adversarial prompts, market-shock scenarios, and data-poisoning simulations against routing behavior before release.

**Release gate:** promote only when canary telemetry shows bounded divergence, no unapproved expert activation, and unchanged safety-expert reachability under stress.

## 4. Telemetry attestation and cryptographic integrity

All governance-relevant events use a signed envelope:

```json
{
  "event_id": "uuid-v7",
  "producer_spiffe_id": "spiffe://bank.example/ai/tier0/liquidity-agent",
  "event_type": "policy.decision|model.inference|tool.invocation|attestation.report|kill_switch.test",
  "subject_hash": "sha3-384(...)",
  "policy_bundle_digest": "sha3-384(...)",
  "enclave_measurement": "optional measurement digest",
  "previous_event_hash": "sha3-384(...)",
  "timestamp_utc": "RFC3339",
  "signature": "ML-DSA-or-hybrid-signature"
}
```

**Integrity pattern:** source signs event -> Kafka topic with idempotent producer -> schema validation -> Merkle batcher -> S3 Object Lock COMPLIANCE bucket -> independent root anchor -> OSCAL evidence index update.

## 5. Kafka/S3 post-quantum WORM audit logging

1. **Kafka topics:** separate `governance.decisions`, `governance.attestations`, `governance.telemetry`, `governance.incidents`, and `governance.zkproofs` topics; enforce ACLs per producer identity.
2. **Schema registry:** reject events that lack signatures, policy digests, producer identity, event time, and retention classification.
3. **PQC signatures:** use hybrid classical and post-quantum signing during migration; maintain algorithm metadata in every envelope.
4. **WORM retention:** write validated events to S3 Object Lock COMPLIANCE mode or equivalent immutable storage with retention aligned to regulatory obligations.
5. **Merkle anchoring:** create hourly operational roots and daily supervisory roots; store root, leaf count, topic offsets, and validation status.
6. **Replay:** support deterministic replay by topic, offset range, model version, policy version, control ID, incident ID, and jurisdiction.

## 6. Zero-knowledge systemic-risk proofs for Basel III/IV

The G-SRI proof service proves statements about AI risk posture without exposing underlying positions, customers, or proprietary models.

**Example proof statements:**

- The institution's Tier 0 AI exposure did not exceed board-approved concentration limits during period `P`.
- All credit-decision agents in jurisdiction `J` used approved policy bundle `B` and current attestation `A`.
- A systemic-risk transition from state `S_t` to `S_t+1` was computed from committed inputs and satisfies the Basel scenario constraints.
- Shared-provider concentration, measured by model-lineage HHI, remained below the approved threshold.

**Circuit inputs:** private exposures, model-lineage commitments, policy-decision commitments, risk weights, scenario parameters, and telemetry commitments. Public outputs include G-SRI band, compliance status, Merkle root, proof timestamp, and verifying key identifier.

## 7. OSCAL/OPA compliance-as-code mapping

Maintain a three-level mapping:

1. **Control catalog:** canonical internal controls with IDs, owners, tests, evidence types, regulatory references, and severity.
2. **OSCAL profile:** jurisdiction overlays that select, tailor, and parameterize controls for EU AI Act, NIST AI RMF, ISO/IEC 42001, DORA, SR 11-7-style model risk, OCC/FRB expectations, FCA/PRA, MAS, HKMA, and Basel operational-risk expectations.
3. **OPA policy modules:** executable rules that enforce control intent at deployment and runtime.

**Transformation pipeline:** YAML control catalog -> OSCAL catalog/profile/component definitions -> Rego data documents -> CI policy tests -> assessment-results export -> regulator evidence bundle.

## 8. TLA+ verification of safety and containment invariants

Model the following invariants before production rollout:

- **KillSwitchReachability:** every Tier 0 workload can be quiesced through at least two independent paths.
- **NoUnapprovedAutonomyEscalation:** an agent cannot raise its autonomy tier without human approval and signed policy update.
- **EvidenceFreshness:** supervisory dashboards do not display green status if evidence exceeds freshness SLA.
- **AttestedSecretRelease:** no secret is released unless workload identity, measurement, policy digest, and jurisdiction match an allowlisted tuple.
- **DeadMansSwitchSafety:** missed heartbeats move the workload to safe mode rather than increasing autonomy.
- **PolicyMonotonicityForCriticalControls:** emergency restrictions cannot be weakened by lower-privilege policy commits.

CI should run TLC or Apalache on bounded models and require traceability from TLA+ constants to implementation configuration.

## 9. HSM and Terraform multi-region deployment blueprint

**HSM/KMS:**

- Root governance signing keys reside in FIPS-grade HSMs or cloud HSM equivalents.
- Separate keys for policy bundles, telemetry producers, Merkle roots, attestation allowlists, release manifests, and regulator exports.
- Enforce quorum approval for key creation, key destruction, policy-signing key rotation, and emergency revocation.

**Terraform modules:**

- `sentinel-control-plane`: Kubernetes clusters, OPA, service mesh, policy bundle distribution.
- `sentinel-evidence`: Kafka, schema registry, immutable object storage, Merkle workers, lifecycle policies.
- `sentinel-confidential-ai`: confidential node pools, attestation verifier, sealed secret broker.
- `sentinel-supervisory-api`: SCP v3.0 endpoints, mTLS, OIDC federation, rate limits, regulator sandbox.
- `sentinel-analytics`: G-SRI warehouse, zk proof workers, dashboards, SIEM integrations.

Deploy active-active across at least two regions for control-plane read paths and active-passive for regulator replay sandboxes unless local law requires jurisdiction-specific isolation.

## 10. G-SRI systemic risk index formulation

Compute the Governance Systemic Risk Index as a weighted, explainable composite:

```text
G-SRI = w1*AutonomyExposure
      + w2*ModelConcentration
      + w3*ControlDegradation
      + w4*TelemetryStaleness
      + w5*IncidentVelocity
      + w6*ThirdPartyDependency
      + w7*CrossInstitutionCorrelation
      - w8*VerifiedContainmentCoverage
```

Each factor must have a documented owner, data source, confidence interval, and manipulation-control. Publish bands as Green, Amber, Red, and Black with pre-approved actions, capital-planning implications, and supervisory notification thresholds.

## 11. Federated collective defense network

Create a privacy-preserving collective defense network among institutions, sector utilities, and supervisors:

- Share signed indicators for prompt-injection campaigns, agent collusion patterns, model-supply-chain compromise, suspicious tool-use chains, jailbreak taxonomies, and containment failures.
- Use anonymized or zero-knowledge contribution proofs where disclosure could reveal customer, trading, or security-sensitive data.
- Require contributor reputation, schema validation, replay protection, and legal review before automated blocking.
- Feed vetted indicators into OPA data bundles, SIEM rules, red-team scenarios, and G-SRI third-party/correlation factors.

## 12. Smart-contract and policy-module review patterns

For policy modules, zk circuits, evidence anchoring contracts, and supervisory access contracts:

1. Threat-model privileged roles, upgrade paths, oracle dependencies, governance capture, and pause semantics.
2. Require static analysis, property tests, fuzzing, formal assertions, and independent review for critical modules.
3. Separate author, reviewer, signer, deployer, and break-glass roles.
4. Record every policy and contract deployment as WORM evidence with source digest, build digest, test results, reviewer IDs, and approval record.
5. Use time locks for non-emergency changes and pre-defined emergency restrictions for incident response.

## 13. 24-hour monitoring and integrity checks

**Every 15 minutes:** policy-bundle freshness, telemetry lag, failed OPA decisions, enclave-attestation expiry, Kafka consumer lag, and HSM health.  
**Hourly:** Merkle root generation, topic offset reconciliation, containment heartbeat review, model drift triage, and SIEM correlation.  
**Daily:** WORM retention verification, regulator API synthetic checks, evidence-bundle completeness, G-SRI recalculation, backup restore probe, dead-man's switch drill sample, and stale-exception review.  
**Weekly:** TLA+ model regression, OPA policy coverage, red-team scenario replay, supply-chain vulnerability review, and key-rotation readiness.  
**Monthly:** board dashboard attestation, internal audit sample, regulator sandbox replay, cross-region failover exercise, and incident-notification tabletop.

## 14. zkML and zk-SNARK transition-validity circuits

Use zkML only where the proof cost is justified by supervisory privacy or cross-institution assurance needs. Start with compact transition-validity circuits rather than full model-inference proofs.

**Priority circuits:**

- `PolicyDecisionValidity`: committed decision record satisfies policy hash `H`.
- `RiskTransitionValidity`: G-SRI moved from `S_t` to `S_t+1` using approved formulas and committed data.
- `FairnessAggregateValidity`: aggregate fairness metrics meet thresholds without exposing individual decisions.
- `AttestationContinuity`: all events in a period were generated by workloads with valid attestation.
- `MerkleInclusion`: requested evidence exists in a committed WORM batch.

## 15. Dead-man's switch patterns

Design dead-man's switch behavior to fail safe:

- Require heartbeat from workload, sidecar, telemetry path, and control plane.
- Define safe-mode actions per tier: pause tool use, degrade to recommendation-only, route to human approval, revoke egress, or terminate workload.
- Use independent clocks and control channels to avoid single-point failure.
- Prevent automatic restart into high-autonomy mode after missed heartbeats.
- Evidence every missed heartbeat, safe-mode transition, human override, and recovery approval.

## 16. DevSecOps and GitOps posture

- All infrastructure, policies, OSCAL mappings, circuits, and TLA+ specs are versioned in Git.
- Pull requests require CODEOWNERS review from model risk, security, legal/compliance, and platform engineering for Tier 0/Tier 1 changes.
- CI runs schema validation, Rego tests, Terraform plan checks, TLA+ checks, circuit tests, dependency scanning, secret scanning, SBOM generation, and artifact signing.
- CD promotes only signed release bundles; production clusters pull from immutable digests.
- Drift detection opens incidents, not silent remediation, for Tier 0 controls.

## 17. Six-month 2028 G-SIFI pilot

| Month | Goal | Deliverables | Exit gate |
|---|---|---|---|
| 1 | Scope and baseline | Select two Tier 0 and three Tier 1 use cases; complete inventory and data-flow maps | Board-approved scope and named owners |
| 2 | Build evidence spine | Kafka topics, schema registry, WORM bucket, Merkle worker, HSM keys | Signed event replay succeeds |
| 3 | Enforce policy | OPA deployment gates, runtime tool-use policies, exception registry | No Tier 0 deployment bypasses policy |
| 4 | Deploy confidential runtime | Confidential nodes, attestation verifier, sealed secret broker | Secret release requires valid attestation |
| 5 | Prove and monitor | G-SRI v1, daily roots, first zk transition proof, 24-hour monitoring | Green evidence freshness for 14 days |
| 6 | Supervisory exit | Regulator sandbox, OSCAL assessment-results, pilot report, remediation plan | Joint go/no-go for broader rollout |

## 18. Global rollout plan through 2035

- **2026:** inventory, governance charter, control catalog, shadow-mode policy logging.
- **2027:** enforce OPA for Tier 0/Tier 1, complete OSCAL mapping, start TLA+ release gates.
- **2028:** execute G-SIFI pilot, deploy WORM evidence spine, enclave attestation, and 24/7 monitoring.
- **2029:** integrate AI stress testing, G-SRI, capital-planning links, and federated threat sharing.
- **2030:** expose SCP v3.0 supervisory APIs and regulator sandboxes; automate recurring evidence requests.
- **2031-2032:** expand adaptive governance, diversity-constrained supervisory agents, and cross-border evidence portability.
- **2033-2035:** mature zk proofs, confidential analytics, sector-wide systemic-risk telemetry, and continuous supervisory assurance.

## 19. Packaging and distribution blueprint

Distribute the Sentinel stack as signed, reproducible packages:

1. **Helm charts:** control plane, mesh sidecars, evidence collectors, telemetry validators, proof workers.
2. **Terraform modules:** multi-region evidence infrastructure, confidential compute, supervisory APIs, HSM integration.
3. **Policy packs:** Rego bundles and data documents by jurisdiction, tier, and use case.
4. **OSCAL packs:** catalog, profile, component-definition, assessment-plan, and assessment-results templates.
5. **Formal packs:** TLA+ specs, model-checking configs, counterexample documentation, invariant traceability matrix.
6. **Circuit packs:** Circom/Noir/RISC Zero or equivalent circuits, proving/verifying key metadata, test vectors.
7. **Dossier packs:** board brief, regulator guide, internal audit guide, sandbox-exit request, incident report template.
8. **Evidence tooling:** dynamic evidence fetchers, Merkle inclusion verifier, WORM replay CLI, OSCAL transformer.

Each release must include a manifest with component digests, signatures, SBOM/BBOM, build provenance, compatibility matrix, migration notes, and deprecation dates.

## 20. Dynamic evidence fetching and OSCAL transformation tooling

Dynamic evidence fetchers should resolve control evidence on demand from WORM storage, CI systems, cloud APIs, model registries, and SIEM indices. The fetcher returns a signed evidence descriptor containing source URI, query hash, result digest, collection time, collector identity, and retention class.

The OSCAL transformer maps evidence descriptors to assessment-results observations and findings. It must preserve chain-of-custody links back to Kafka offsets, Merkle leaves, S3 object versions, policy digests, and attestation reports.

## 21. Regulator-facing supervisory documentation

Regulator documentation should be written for reproducibility and challenge:

- Executive summary with risk appetite, material changes, unresolved exceptions, and board actions.
- Architecture diagrams showing identity, policy, telemetry, evidence, and emergency-stop paths.
- Control mapping matrix with legal basis, internal owner, automated test, evidence source, and residual risk.
- Pilot or production results with MTTC, false-positive rate, policy-denial rate, model drift, G-SRI trend, and incident history.
- Known limitations and compensating controls, especially for research-stage zkML, ASI containment assumptions, and cross-border data constraints.
- Independent audit findings, remediation dates, and management attestations.

## 22. Guided execution checklist

### Strategy and governance

- [ ] Board AI risk committee charter approved.
- [ ] Tiering taxonomy adopted for T0-T4 AI systems.
- [ ] Named accountable executive assigned to each T0/T1 system.
- [ ] AI risk appetite linked to G-SRI bands and de-autonomization actions.

### Architecture and security

- [ ] Zero-trust identities issued to workloads, humans, services, and telemetry producers.
- [ ] Default-deny network controls and inspected egress brokers deployed.
- [ ] Confidential compute attestation required for Tier 0 and critical Tier 1 systems.
- [ ] HSM-backed signing keys created with quorum control.

### Evidence and compliance

- [ ] Kafka topics, schemas, signatures, WORM retention, and Merkle anchoring live.
- [ ] OSCAL catalog/profile/component definitions generated from canonical controls.
- [ ] OPA policies tested, signed, and deployed through GitOps.
- [ ] Dynamic evidence fetchers linked to OSCAL assessment-results.

### Formal methods and proofs

- [ ] TLA+ invariants defined for containment, autonomy escalation, evidence freshness, and dead-man's switch behavior.
- [ ] CI model-checking gates block critical releases on invariant violations.
- [ ] zk transition-validity circuits tested with public and private fixtures.
- [ ] Merkle inclusion verification available to internal audit and supervisors.

### Operations and rollout

- [ ] 24-hour monitoring schedule implemented.
- [ ] Dead-man's switch drills performed and evidenced.
- [ ] Six-month 2028 pilot plan staffed and funded.
- [ ] Global rollout roadmap approved through 2035.
- [ ] Packaging manifest, release signatures, SBOM/BBOM, and regulator docs complete.

## 23. Workstream backlog and acceptance gates

| Workstream | Epics | Definition of done | Primary evidence |
|---|---|---|---|
| Governance operating model | Board charter, accountable owner map, tiering taxonomy, model-risk policy addendum | T0/T1 systems have named owners, approved risk appetite, and escalation contacts | Board minutes, RACI, policy attestation |
| Platform foundation | Kubernetes namespaces, service mesh, workload identity, default-deny egress, OPA admission | Any deployment without signed policy and workload identity is rejected | Admission logs, OPA decision exports |
| Evidence spine | Kafka topics, schema registry, S3 Object Lock, Merkle batcher, replay CLI | Signed events can be replayed from Kafka offsets to immutable object versions and Merkle leaves | Event envelope, object version, Merkle proof |
| Confidential runtime | Confidential nodes, attestation verifier, sealed secret broker, HSM/KMS policy | T0 secret release fails closed when measurement, identity, or policy digest changes | Attestation report, denied secret-release event |
| Formal assurance | TLA+ specs, model-check configs, implementation traceability, counterexample process | Release fails when critical invariant checks fail or traceability is missing | TLC/Apalache report, traceability matrix |
| Compliance automation | OSCAL catalog/profile, Rego controls, assessment-results transformer | Regulator pack is generated from live evidence without manual copy-paste | OSCAL bundle, evidence descriptor |
| ZK assurance | Risk transition circuit, Merkle inclusion circuit, verifier service, key ceremony | Proof verifies against public root and fails against tampered commitments | Proof artifact, verification transcript |
| Operations | Monitoring SLOs, dead-man's drills, Red Dawn simulations, incident playbooks | Two consecutive operational cycles meet MTTC and evidence freshness objectives | Drill report, incident timeline |

## 24. Minimum viable repository and package layout

Use a deterministic layout so internal audit, regulators, and downstream institutions can verify releases without relying on tribal knowledge:

```text
sentinel-governance-stack/
  charts/
    sentinel-control-plane/
    omni-sentinel-mesh/
    sentinel-evidence-workers/
  terraform/
    modules/confidential-ai/
    modules/evidence-worm/
    modules/supervisory-api/
    envs/us-prod/
    envs/eu-prod/
  policies/
    rego/common/
    rego/eu-ai-act/
    rego/us-model-risk/
    data/tier-thresholds.yaml
  oscal/
    catalogs/sentinel-control-catalog.json
    profiles/eu-ai-act-profile.json
    profiles/basel-operational-risk-profile.json
    component-definitions/sentinel-stack.json
  formal/
    tla/kill_switch.tla
    tla/evidence_freshness.tla
    tla/attested_secret_release.tla
    configs/apalache/
  circuits/
    risk_transition/
    merkle_inclusion/
    policy_decision_validity/
  tools/
    evidence-fetcher/
    oscal-transformer/
    worm-replay-cli/
  docs/
    regulator-guide.md
    auditor-guide.md
    operator-runbook.md
  release/
    manifest.json
    sbom.spdx.json
    bbom.json
    signatures/
```

Every distributed package should be reproducible from a tagged commit, signed by the release key, and accompanied by a machine-readable compatibility matrix identifying supported Kubernetes, Kafka, OPA, Terraform provider, HSM, and confidential-compute versions.

## 25. Supervisory Control Plane v3.0 API contract

Expose read-only supervisory APIs by default. Mutation endpoints must be separately enabled, legally approved, and scoped to sandbox or emergency workflows.

| Endpoint | Purpose | Required controls | Evidence returned |
|---|---|---|---|
| `GET /v3/evidence/{control_id}` | Fetch current evidence for a control | mTLS, regulator role, purpose binding, rate limit | OSCAL observation, descriptor digest, Merkle proof |
| `GET /v3/attestations/{workload_id}` | Verify confidential workload posture | mTLS, workload scope, freshness SLA | Measurement, verifier decision, policy digest |
| `GET /v3/incidents/{incident_id}` | Review incident timeline | Legal hold check, case scope, redaction policy | Signed timeline, decisions, containment actions |
| `POST /v3/sandbox/replay` | Replay approved decision window in sandbox | Approval workflow, data minimization, synthetic data preference | Replay transcript, policy decisions, divergence report |
| `GET /v3/gsri/{period}` | Retrieve systemic-risk band and proof | Board-approved disclosure profile | G-SRI factors, zk proof reference, root anchor |
| `GET /v3/policies/{bundle_id}` | Inspect policy bundle metadata | Bundle signature verification | Rego digest, OSCAL mapping, test result summary |

Responses should include `response_id`, `request_purpose`, `redaction_profile`, `generated_at`, `evidence_root`, `signature_algorithm`, and `signature` fields.

## 26. Control IDs and regulatory crosswalk seed

| Sentinel control ID | Control objective | OPA decision point | OSCAL evidence type | Regulatory mapping candidates |
|---|---|---|---|---|
| `SEN-ZT-001` | Enforce workload identity for AI services | `deployment.allow` | Admission decision and SPIFFE SVID | NIST AI RMF Govern/Manage, ISO 42001 operations, DORA ICT controls |
| `SEN-TEE-002` | Require valid attestation before secret release | `secret.release.allow` | Attestation report and KMS deny/allow log | Operational resilience, model-risk change control, data-protection safeguards |
| `SEN-WORM-003` | Preserve signed governance evidence immutably | `evidence.write.allow` | Object version, retention lock, Merkle inclusion | SR 11-7-style documentation, DORA logging, EU AI Act technical documentation |
| `SEN-OPA-004` | Gate Tier 0/Tier 1 deployment by policy | `deployment.allow` | Policy decision, bundle digest, approver record | EU high-risk controls, NIST AI RMF Govern, internal model risk |
| `SEN-TLA-005` | Verify kill-switch reachability and safe-mode invariants | `release.allow` | Model-checking result and traceability matrix | Operational resilience, board risk appetite, supervisory challenge |
| `SEN-ZK-006` | Prove systemic-risk transition validity | `proof.publish.allow` | Proof, verifying key, public root | Basel operational/systemic-risk evidence, supervisory stress testing |
| `SEN-GSRI-007` | Compute and publish G-SRI bands | `risk.publish.allow` | G-SRI report and data-quality attestation | Capital planning, concentration-risk governance, board oversight |
| `SEN-DSM-008` | Fail safe on missed heartbeats | `runtime.continue.allow` | Heartbeat log and safe-mode transition | Resilience, incident response, containment evidence |

## 27. CI/CD implementation pattern

A Tier 0 release pipeline should run in this order:

1. **Source checks:** formatting, linting, signed commits, dependency review, secret scanning, SBOM generation.
2. **Policy checks:** Rego unit tests, policy coverage threshold, deny-by-default tests, jurisdiction overlay tests.
3. **Infrastructure checks:** Terraform validate, plan diff risk scoring, cloud-policy checks, network reachability analysis.
4. **Formal checks:** TLA+ model checking, invariant traceability, counterexample archival.
5. **Circuit checks:** witness generation, proof generation, verifier tests, malformed-proof negative tests.
6. **Build and sign:** reproducible image build, provenance, SBOM/BBOM, artifact signing.
7. **Canary deploy:** confidential runtime attestation, OPA dry-run comparison, StaR-MoE routing stability metrics.
8. **Promotion gate:** human approval quorum, policy signer approval, HSM-backed release signature, WORM evidence write.

**Failure rule:** a failed critical check should create an evidence event and block promotion. Override requires named accountable executive approval, expiry date, compensating control, and regulator-notification assessment.

## 28. Security review checklist for deployable modules

### Rego policy bundles

- [ ] Deny-by-default semantics are explicit.
- [ ] Test cases cover allow, deny, exception, stale-evidence, and emergency-mode paths.
- [ ] Bundle data cannot be modified by model developers or runtime agents.
- [ ] Every rule maps to a Sentinel control ID and OSCAL control reference.

### Terraform modules

- [ ] Object Lock or equivalent WORM mode cannot be disabled by module consumers.
- [ ] HSM/KMS keys have separation by purpose and quorum-controlled destructive actions.
- [ ] Public network exposure is denied by default.
- [ ] Region and data-residency controls are parameterized and tested.

### zk circuits and anchoring contracts

- [ ] Trusted setup or proving-key ceremony is documented where applicable.
- [ ] Public inputs are minimal and reviewed for leakage.
- [ ] Negative tests prove tampered roots, stale keys, and malformed witnesses fail.
- [ ] Upgrade and pause paths are reviewed for governance capture.

### Evidence fetchers and transformers

- [ ] Fetchers use least-privilege read-only credentials.
- [ ] Query hashes, result digests, collector identities, and timestamps are signed.
- [ ] Redaction policies are deterministic and reviewable.
- [ ] OSCAL output preserves source links to WORM object versions and Merkle leaves.

## 29. Pilot success metrics and regulator-readiness thresholds

| Metric | Target for six-month pilot | Global rollout target |
|---|---:|---:|
| T0/T1 inventory completeness | 100% in pilot scope | 100% enterprise-wide |
| Policy-gated deployments | 100% of pilot T0/T1 | 100% of enterprise T0/T1 |
| Evidence freshness | 95% within SLA for 14 days | 99% within SLA quarterly |
| Critical telemetry loss | 0 unresolved incidents | 0 unresolved incidents |
| MTTC for Tier 0 containment breach | < 90 seconds in drills | < 60 seconds in mature operations |
| Confidential attestation coverage | 100% of pilot T0 | 100% T0 and critical T1 |
| WORM replay success | 100% sampled events | 99.9% sampled events |
| OSCAL auto-generation | 70% pilot controls | 90% recurring supervisory controls |
| zk proof verification | 1 transition proof | Quarterly systemic-risk proofs |
| Red Dawn remediation aging | No critical past exit | No critical past quarter close |

## 30. Explicit feasibility and assurance taxonomy

Classify each capability so stakeholders do not confuse current engineering practice with research-stage assurance:

- **Deployable now:** OPA policy gates, WORM logging, Merkle batching, HSM signing, Terraform/GitOps, SBOM/BBOM, model registry, SIEM integration, mTLS/OIDC supervisory APIs, and TLA+ model checking for bounded protocols.
- **Deployable with specialist engineering:** confidential-compute attestation at scale, sealed secret release, multi-region immutable evidence replay, production-grade regulator sandboxes, and hybrid post-quantum signature migration.
- **Pilot/research stage:** zkML proofs for non-trivial inference, cross-institution zero-knowledge systemic-risk proofs, privacy-preserving collective defense at sector scale, and automated policy-to-OSCAL semantic verification.
- **Conceptual/high-assurance research:** ASI-grade containment guarantees, autonomous treaty engines, and fully self-adaptive governance without human ratification.

Regulator-facing materials should state this taxonomy plainly, document assumptions, and pair research-stage controls with conventional compensating controls.
