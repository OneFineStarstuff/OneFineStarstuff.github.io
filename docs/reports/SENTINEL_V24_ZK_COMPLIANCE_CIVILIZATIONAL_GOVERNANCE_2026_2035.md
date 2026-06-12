<title>Enterprise AGI/ASI Governance, Containment, and Zero-Knowledge Regulatory Compliance — Deep Technical Reference and Civilizational Governance Blueprint for Fortune 500, Global 2000, and G-SIFI Financial Institutions (2026–2035)</title>

<abstract>
This volume is the deep-technical companion to the Sentinel v2.4 multi-part roadmap (docs/reports/SENTINEL_V24_AGI_ASI_GOVERNANCE_ROADMAP_2026_2035.md). It provides implementation-grade specifications, machine-readable artifact templates, and methodology definitions for the full Sentinel AI Governance Stack v2.4 capability set: G-Stack governance data plane, WorkflowAI Pro lifecycle orchestration, Omni-Sentinel containment rings, Autonomous Supervisory Agents (ASA mesh), GAI-SOC telemetry, the Red Dawn adversarial-simulation regime, the G-SRI systemic risk index methodology, BBOM perpetual assurance, OSCAL control catalogs and regulator profiles, TLA+ safety/containment invariant specifications, OPA/Rego compliance-as-code with full CI/CD integration, Kafka-based post-quantum WORM audit logging, Circom/Groth16 systemic-risk circuits with GC-IR (Governance-Circuit Intermediate Representation) bridges, and hybrid zk-SNARK/zk-STARK privacy-preserving compliance proof systems. It maps these to multi-jurisdictional regimes — EU AI Act (Annex IV and systemic-risk GPAI provisions), NIST AI RMF 1.0 and AI 600-1, ISO/IEC 42001, Basel III/IV, SR 11-7 (and the hypothetical SR 26-2 planning scenario), DORA, NIS2, GDPR, FCRA/ECOA, MAS/HKMA FEAT, FCA SM&CR and Consumer Duty, the HKMA Fintech 2030 forward scenario, and the speculative ICGC/GASO civilizational compute-governance layer including ICGC Phase 1 and Phase 2 zk-verified AI control regimes. It delivers phased 2026–2030 roadmaps with a 2031–2035 extension, concrete blueprints and templates for boards, C-suites, regulators, enterprise architects, AI platform engineers, and AI safety researchers, and an enterprise blueprint for civilizational compute governance: existential and catastrophic AI risk management, ethical alignment and value learning, global governance frameworks and international cooperation, and societal impacts including economic disruption and bias amplification. Regulator-ready report structures using <title>/<abstract>/<content> tags are specified as reusable templates. All speculative constructs (ICGC, GASO, SR 26-2, HKMA Fintech 2030, the Sentinel product taxonomy itself) are explicitly flagged and separated from currently deployable technology. This document is an implementation reference, not legal advice.
</abstract>

<content>

# PART I — Stack Component Deep Dive

This volume assumes the five-zone topology, T0–T4 tiering, and invariants I1–I5 defined in the companion roadmap. Here each named capability is specified to implementation depth.

## 1. G-Stack — Governance Data Plane

**Function**: the system of record for governance state. Everything else (policy, containment, proofs, dashboards, dossiers) reads from or writes to G-Stack.

### 1.1 Core data model (canonical entities)

| Entity | Key fields | Notes |
|---|---|---|
| `ModelAsset` | id, lineage_refs[], tier, jurisdictions[], status, owner (SMF-mapped), vendor_terms_ref | One row per model/checkpoint/fine-tune; lineage edges signed |
| `AgentAsset` | id, base_model_ref, tool_grants[], autonomy_ceiling, swarm_refs[] | Agents are first-class, distinct from models |
| `Control` | id, statement, oscal_component_ref, regime_mappings[], evidence_query, freshness_sla | One canonical control; regimes are views |
| `Obligation` | id, regime, citation, effective_date, controls[], status | Parsed from regulatory feeds by the treaty engine |
| `EvidenceRecord` | id, control_ref, kafka_offset_ref, payload_digest, sigs[], worm_uri | Never stores payloads with PII — digests + URIs |
| `Exception` | id, control_ref, owner, rationale, expiry, compensating_controls[] | Expired ⇒ fail-closed |
| `Incident` | id, severity, dora_class, eu_ai_act_art73_flag, causal_graph_ref, notifications[] | Drives regulatory clocks |
| `Attestation` | id, period, circuit_hash, proof_uri, public_inputs, verifying_key_id | zk artifacts (Part III) |

### 1.2 Storage and query architecture

- **OLTP**: Postgres with row-level security keyed to jurisdiction labels; logical decoding feeds `gov.gstack.cdc.v1` so all governance state changes are themselves evidence events.
- **Analytics**: lakehouse (Iceberg/Delta) fed from Kafka; G-SRI (§7) and CESE consume here.
- **Graph**: lineage and delegation graphs in a property-graph store (or Postgres recursive CTEs at moderate scale); supports "which decisions did dataset D influence" and "what is agent A's transitive authority" queries — both are supervisory-grade queries that must return in seconds.
- **Dossier assembly**: a renderer resolves Annex IV / OSCAL templates against entities; every rendered field carries an evidence pointer (`field → EvidenceRecord.id`), making dossiers fully traceable.

## 2. WorkflowAI Pro — Lifecycle Orchestration

- **Workflow compiler**: controls-as-code definitions (YAML DSL) compile to executable workflows with typed gates: `HumanApproval(role, sod_constraints)`, `PolicyCheck(opa_query)`, `EvidenceCapture(control_ref)`, `Timer(regulatory_deadline_ref)`.
- **Canonical lifecycle**: PROPOSED → SCANNED → VALIDATED (independent, SR 11-7) → APPROVED (risk-tier sign-off matrix) → DEPLOYED → MONITORED → (SUSPENDED | RETIRED). Each transition emits to `gov.model.lifecycle.v1` and requires a green OPA decision.
- **Delegation constraints**: workflow steps carry capability-scoped tokens; the compiler statically rejects workflows that could amplify authority (a compile-time shadow of the TLA+ no-amplification invariant).
- **Deadline machinery**: regulatory clocks (DORA 4h initial / 72h intermediate / 1-month final incident reports; Reg B 30-day adverse action; EU AI Act Art. 73 15-day serious-incident) are first-class timer objects that escalate automatically and are visible on BBOM.

## 3. Omni-Sentinel — Containment Rings

Containment is organized as concentric rings; a workload's tier determines its minimum ring depth.

| Ring | Mechanism | T-applicability |
|---|---|---|
| R1 Identity | SPIFFE identity, short-lived creds, no static secrets | All |
| R2 Network | Default-deny NetworkPolicy + eBPF (Cilium); egress allowlists; DNS pinning | T0–T2 |
| R3 Compute | gVisor/Kata runtime class; seccomp/AppArmor; resource quotas; no privileged pods | T0–T1 |
| R4 Data | Tokenized data access via brokered APIs only; no direct datastore credentials | T0–T1 |
| R5 Behavior | sentinel-pep mediation of every tool call; autonomy ceilings; ASA verdict gating | T0–T1 |
| R6 Hardware | Confidential compute (SEV-SNP/TDX, GPU CC); attested boot; out-of-band kill path | T0 |

**Kill-switch graph**: the L0–L4 graduated ladder (observe → throttle → quarantine → terminate → fabric-isolate) defined in the companion volume, with the TLA+-verified dual-control/dead-man protocol. The graph is literally a graph object in G-Stack: nodes are actuation points, edges are dependencies; an automated reachability analysis proves daily that every T0 workload has ≥2 disjoint actuation paths, one of which consumes no workload-influenced input.

## 4. Autonomous Supervisory Agents (ASA Mesh)

### 4.1 Specification

- **Independence constraints (enforced at registry level)**: ASA base model family ≠ supervised system family; training/eval data disjointness attestations; separate vendor where feasible; separate infrastructure account.
- **Detector portfolio per ASA**:
  - *Capability drift*: eval-battery deltas across versions and time (sandboxed weekly probes).
  - *Consistency*: divergence between stated rationale and action pattern (rationale-action entailment scoring).
  - *Tool misuse*: n-gram/sequence anomaly models over tool-call streams; forbidden-target proximity scoring.
  - *Oversight evasion*: attempts to access telemetry, IAM, deployment, or registry surfaces; sudden telemetry sparsity.
- **Authority model**: one-way ratchet — ASAs may *raise* containment level (L0→L1→L2), never lower it; L3/L4 require human dual-control. This asymmetry is invariant `ASA-1` in the TLA+ suite (§9).
- **Verdict schema**: `{asa_id, subject_id, window, scores{drift, consistency, misuse, evasion}, composite, evidence_refs[]}` published to `gov.containment.v1`; composite feeds OPA inputs.

### 4.2 Validity governance

Every ASA detector ships with a published validity study (precision/recall on red-team corpora, base-rate analysis, known blind spots) registered in G-Stack. Detectors with stale validity studies (>12 months) are demoted from gating inputs to advisory signals automatically — governance models get no exemption from model risk management.

## 5. GAI-SOC — Telemetry and Operations

- **Detection content packs**: prompt-injection signatures (community + internal feeds), jailbreak clustering (embedding-space density over refused/served pairs), exfiltration heuristics (entropy and volume anomalies on egress; canary-token tripwires seeded in sensitive corpora), agent-behavior baselines per asset.
- **Causal triage**: correlation-ID-stitched event chains rendered as causal graphs; an incident object is *born regulator-ready* — the DORA/Art. 73 narrative fields are populated from the graph, and humans edit rather than author.
- **SOAR integration**: playbooks invoke containment-ladder transitions through the same dual-control API as humans (no privileged side-doors); every automated action is an evidence event.
- **Run metrics**: MTTD/MTTC per tier; alert precision per content pack (feedback-labeled); containment-drill freshness.

## 6. Red Dawn — Adversarial Simulation Regime

**Definition**: the institution's standing program of full-stack adversarial exercises against the governance system itself — quarterly for T0 scope, semi-annual enterprise-wide.

### 6.1 Scenario library (versioned in G-Stack)

| ID | Scenario | Primary controls under test |
|---|---|---|
| RD-01 | Prompt-injection cascade through RAG into an agent with payment-tool access | R5 mediation, tool allowlists, GAI-SOC detection |
| RD-02 | Agent collusion: two T1 agents coordinating to split a transaction below per-action ceilings | Swarm aggregate budgets, interaction-graph monitors |
| RD-03 | Kill-switch evasion: workload attempts re-admission after L3 under a new identity | NoResurrection invariant, registry epoch enforcement |
| RD-04 | Telemetry suppression: sidecar starvation/compromise attempt | Dead-man lease (no heartbeat ⇒ quiesce), attestation daemons |
| RD-05 | Insider policy tamper: malicious Rego bundle through CI | Bundle signing, four-eyes, shadow-eval gate, fixture suites |
| RD-06 | Evidence rewrite: attempt to alter WORM history with privileged credentials | Compliance-mode Object Lock, dual Merkle anchoring |
| RD-07 | Mass de-autonomization attack: adversary triggers kill-switches as market disruption | Dual-control quorum, signed actuation, CESE-validated playbooks |
| RD-08 | Vendor model recall: primary foundation model withdrawn with 24h notice | Concentration limits, fallback routing, stress playbooks |
| RD-09 | zk pipeline subversion: proofs generated over forged leaves | Attestation chain, signed-at-source envelopes, transparency log |
| RD-10 | Jailbreak epidemic: novel universal jailbreak spreads across business lines | GAI-SOC clustering, emergency policy push, output hold-and-release |

### 6.2 Mechanics

- **Purple-team format**: red cell (internal + rotating external firm), blue cell (GAI-SOC + platform), white cell (risk + audit observers, and from 2030, supervisory observers per the joint-sandbox track).
- **Scoring**: per scenario — detected? (MTTD), contained? (MTTC vs. budget), evidenced? (was the full causal chain reconstructable from the evidence plane alone?), reported? (would regulatory clocks have been met?). The four scores roll into G-SRI's resilience pillar.
- **DORA alignment**: Red Dawn cycles are designed to satisfy threat-led penetration testing (TLPT/TIBER-EU) expectations for the AI estate; evidence packs are filed accordingly.
- **Closure discipline**: every finding becomes a task (DAG board) with owner and deadline; unclosed criticals block the next quarter's deployment approvals for the affected tier — findings have teeth.

## 7. G-SRI — Governance Systemic Risk Index

**Purpose**: a single board- and supervisor-legible composite tracking how risky the institution's AI estate is *as a system*, computed weekly.

### 7.1 Pillar structure

```
G-SRI = Σ w_p · pillar_p ,  pillars normalized to [0,100], higher = riskier
```

| Pillar | Weight (default) | Inputs |
|---|---|---|
| P1 Control coverage | 0.20 | % T0/T1 controls with fresh evidence; policy-gate coverage; exception load (count × age × tier) |
| P2 Concentration | 0.20 | Foundation-model HHI across decision volume; inference-provider HHI; data-vendor HHI |
| P3 Behavioral drift | 0.15 | PSI/KL input drift; output-violation rate trends; ASA composite distribution shifts |
| P4 Autonomy utilization | 0.15 | How close agents run to ceilings (mean and P95 of ceiling-utilization); ceiling-breach near-misses |
| P5 Resilience | 0.15 | Red Dawn scores; kill-switch test freshness; MTTC trend |
| P6 Incident momentum | 0.15 | Severity-weighted incident rate, EWMA; repeat-cause fraction |

### 7.2 Governance of the index

- Methodology is versioned (`gsri-method-vX`); weight changes require board risk committee ratification; the computation job is itself a registered T2 model (reflexivity rule).
- **Thresholds**: green <35, amber 35–55 (CRO review, remediation plan), red >55 (deployment freeze for affected tiers, supervisor notification per agreed protocol).
- **Anti-gaming**: input metrics are computed from the evidence plane, not self-reported; the internal-audit line independently recomputes G-SRI monthly from raw WORM data.

## 8. BBOM — Perpetual Assurance ("Board Book of Models")

- **Concept**: replace point-in-time audit packs with a continuously true board dashboard: live control coverage, evidence freshness heatmap, exception aging, kill-switch test cadence, G-SRI trend, regulatory-clock status, attestation status (latest zk proof per period verified ✓/✗).
- **Freshness semantics**: every cell displays `(value, evidence_age, sla_status)`; stale evidence renders amber regardless of value — *the dashboard cannot show green on old data*.
- **Quarterly board pack**: auto-generated PDF/OSCAL snapshot of BBOM, hash-anchored to WORM, signed by accountable executives (SM&CR attestation linkage) — the artifact regulators receive is bit-identical to what the board saw.

---

# PART II — Formal and Policy Layer Specifications

## 9. TLA+ Safety and Containment Invariant Suite

The companion volume specifies `OmniSentinelKillSwitch`. The full v2.4 suite:

| Spec | Invariants (safety) | Liveness | Checked with |
|---|---|---|---|
| `KillSwitchAbstract` | NoResurrection; DualControl (no actuation without quorum); ASA-1 (one-way ratchet) | EventualContainment within bound B | TLC exhaustive (small configs) + Apalache (symbolic, larger) |
| `KillSwitchEKS` / `KillSwitchEnclave` | Refinement of abstract spec per substrate | — | Apalache refinement check |
| `DelegationChain` | NoAmplification: ∀ chains, transitive authority ≤ principal ceiling; NoCycles | Token revocation propagates within R rounds | TLC |
| `HITLOrdering` | NoEffectBeforeGate: adverse T1 effect ⇒ gate=COMPLETE in all prior states | Gates eventually resolve under fairness | TLC |
| `EvidencePipeline` | AppendOnly; NoGaps (sequence-number continuity per producer) | Every committed decision eventually WORM-persisted | Apalache |
| `PolicyRollout` | NoUnsignedBundle; ShadowBeforeEnforce (a bundle cannot enter enforce without a shadow epoch) | — | TLC |

**Engineering discipline** (restated as hard rules):
1. Spec hash is a release-gate input for containment-critical services.
2. Trace conformance: production transition logs replayed against next-state relations nightly; divergence pages the verification guild.
3. Byzantine workload model for anything the contained system can message — the contained system is always modeled as adversarial.
4. Specs are reviewed adversarially in Red Dawn RD-03/RD-04 tabletops: "find the unmodeled channel."

## 10. OPA/Rego Compliance-as-Code with Full CI/CD Integration

Policy pack structure and worked Rego examples (GDPR Art. 22/ECOA gate, autonomy ceiling) are in the companion volume §2.3. This section specifies the **pipeline contract**:

```
.policy-ci.yaml (per bundle)
stages:
  - lint:        regal lint --strict
  - typecheck:   opa check --strict --schema schemas/
  - test:        opa test -v --coverage --threshold 90
  - fixtures:    conformance fixtures derived from regulatory text
                 (each obligation_id → {input, expected} pairs; 100% pass required)
  - shadow:      replay last 30d of recorded decision inputs against the
                 candidate bundle; diff report vs. current bundle;
                 deny-rate delta > 2% requires human risk sign-off
  - sign:        cosign sign bundle.tar.gz  (key in HSM; SoD: signer ≠ author)
  - publish:     push to bundle registry; PDPs poll with signature verification
  - enforce:     staged rollout (shadow epoch → 10% PDPs → 100%) with
                 automated rollback on decision-latency or deny-anomaly alarms
```

- **Decision provenance**: every PDP decision logs `(input_digest, bundle_hash, result, latency)`; bundle_hash → Git commit → change ticket → approver chain is a closed loop queryable by supervisors in the sandbox.
- **Data vs. logic separation**: thresholds, allowlists, exception registers, and the jurisdictional obligation lattice are *data* documents updated through a lighter (but still signed and logged) path than rule logic — this is what lets the treaty engine propose updates without touching Rego semantics.

## 11. OSCAL Control Catalogs and Regulator Profiles

### 11.1 Artifact set (machine-readable; maintained in `governance_artifacts/oscal/`)

| OSCAL artifact | Content | Consumers |
|---|---|---|
| `catalog-sentinel-v24.json` | Canonical control catalog (~180 controls across 12 families: GOV, INV, POL, VER, CON, TEL, EVD, CRY, INC, STR, SUP, SOC) | Everything |
| `profile-eu-ai-act.json` | Selects/parameterizes controls per Articles 9–15, 26–27, 72–73; Annex IV section mapping in props | EU AI Office bundle |
| `profile-nist-ai-rmf.json` | Govern/Map/Measure/Manage mapping + AI 600-1 suggested-action crosswalk | US supervisory view |
| `profile-iso-42001.json` | AIMS clause mapping (4–10 + Annex A controls) | Certification body |
| `profile-dora-nis2.json` | ICT risk, incident, TLPT, third-party controls | EU operational-resilience view |
| `profile-prudential.json` | SR 11-7 / Basel op-risk / (scenario) SR 26-2 controls | Fed/ECB/PRA view |
| `component-definition-*.json` | Per-platform-component implemented-controls statements | Assessors |
| `assessment-results-{period}.json` | Continuously generated results: control → evidence query → finding; freshness SLA encoded in props | All regulators; BBOM |

### 11.2 Example control entry (catalog excerpt)

```json
{
  "id": "con-04",
  "class": "CON",
  "title": "Verified kill-switch reachability for contained workloads",
  "parts": [{"name": "statement", "prose":
    "Every T0 workload SHALL have >=2 disjoint actuation paths to QUIESCED/TERMINATED, one consuming no workload-influenced input, verified daily by automated reachability analysis and quarterly by live actuation test."}],
  "props": [
    {"name": "tier-applicability", "value": "T0"},
    {"name": "tla-spec", "value": "KillSwitchAbstract@sha256:..."},
    {"name": "evidence-query", "value": "gov.containment.v1::reachability_report,actuation_test"},
    {"name": "freshness-sla", "value": "P1D/P90D"}
  ],
  "links": [
    {"rel": "regime", "href": "#eu-ai-act-art-14"},
    {"rel": "regime", "href": "#sr-26-2-scenario-killswitch"},
    {"rel": "regime", "href": "#icgc-gacp-level-2"}
  ]
}
```

---

# PART III — Cryptographic Compliance Layer

## 12. Kafka-Based PQC WORM Audit Logging (normative envelope)

Restating the companion §2.7 as a normative schema (Avro, registered, `BACKWARD_TRANSITIVE`):

```json
{
  "type": "record", "name": "GovEventEnvelope", "namespace": "ai.sentinel.gov.v1",
  "fields": [
    {"name": "event_id", "type": "string"},
    {"name": "ts_ns", "type": "long"},
    {"name": "producer_spiffe_id", "type": "string"},
    {"name": "seq_no", "type": "long"},
    {"name": "schema_id", "type": "int"},
    {"name": "payload_digest_sha256", "type": "bytes"},
    {"name": "payload_uri", "type": ["null", "string"]},
    {"name": "sig_ed25519", "type": "bytes"},
    {"name": "sig_mldsa65", "type": "bytes"},
    {"name": "cert_chain_ref", "type": "string"},
    {"name": "attestation_ref", "type": ["null", "string"]}
  ]
}
```

- `seq_no` per producer enables the `EvidencePipeline` NoGaps invariant to be checked mechanically.
- Hybrid signatures (Ed25519 + ML-DSA-65 per FIPS 204) through the migration decade; SLH-DSA (FIPS 205) for the Merkle-root anchoring keys; ML-KEM (FIPS 203) for transport. Retention ≥10y, Object Lock COMPLIANCE mode, dual anchoring (internal transparency log + RFC 3161 external timestamp).

## 13. Circom/Groth16 Systemic-Risk Circuits

Beyond the fairness/coverage/retention circuits (companion §2.6), v2.4 defines **systemic-risk circuits** — proving risk-aggregate properties to supervisors without exposing positions or strategies:

| Circuit | Statement (public inputs → claim) | Private witness |
|---|---|---|
| `SRC-1 ConcentrationBound` | (period commitment, HHI threshold τ) → foundation-model decision-volume HHI ≤ τ | Per-decision (model_lineage_id, volume) tuples under the committed Merkle root |
| `SRC-2 CeilingCompliance` | (period, ceiling registry hash) → no agent exceeded per-action or cumulative ceilings | Per-action value tuples + agent ids |
| `SRC-3 GSRIIntegrity` | (gsri_method_hash, published G-SRI value, input commitments) → the published index is the correct function of committed pillar inputs | Pillar raw inputs |
| `SRC-4 StressCoverage` | (scenario set hash, period) → all mandated stress scenarios executed; results within committed bands | Scenario run outputs |

**Engineering notes**:
- Circuits authored in Circom 2.x, compiled to R1CS, proven with Groth16 (rapidsnark GPU provers); 10⁶-decision periods handled via Merkle-batch decomposition + SnarkPack aggregation (companion §4.11).
- Range checks and fixed-point arithmetic for HHI/ratio math: use standard comparator/decomposition templates; all division replaced by multiplication-form constraints (`a ≤ τ·b` not `a/b ≤ τ`).
- **Circuit change control**: a circuit is regulatory semantics frozen in R1CS — same review board as Rego logic plus cryptographic review; `circuit_hash` is always a public input.

## 14. GC-IR — Governance-Circuit Intermediate Representation (Bridge)

**Problem**: three formalisms encode the same obligations — Rego (runtime), TLA+ (protocol), R1CS circuits (proof). Divergence between them is a silent compliance failure.

**GC-IR** is the bridging layer: a typed, declarative obligation representation from which the three targets are *derived or checked*:

```
GC-IR obligation (YAML sketch)
id: ob-ecoa-adverse-reason-codes
regime: [ecoa, gdpr_art22]
subject: credit_decision
predicate:
  all_of:
    - outcome == adverse AND automation == full
      implies count(reason_codes) >= 2
    - forall rc in reason_codes: rc in approved_reason_codes
emission:
  rego: fairness/credit_decision.rego#allow      # conformance-checked
  circuit: SRC-fair-1.circom#ReasonCodeCheck      # constraint-template
  tla: HITLOrdering#AdverseGate                   # invariant reference
evidence: gov.decisions.v1
```

- **Mode of operation (honest)**: GC-IR does not fully *compile* to all three targets today — Rego generation for predicate-style obligations is practical; circuit generation is template-instantiation for a constrained predicate subset; TLA+ linkage is reference + conformance-fixture generation. The verifiable claim is **consistency checking**: shared fixture corpora are executed against the Rego rule, the circuit (witness-level test harness), and the spec's invariant fixtures — any disagreement is a build failure.
- **Why it matters to regulators**: GC-IR is the artifact a supervisor reads to confirm that the proof they verified, the policy that ran, and the protocol that was model-checked all encode the same obligation. It is filed alongside attestations via SIP.
- **Feasibility flag**: GC-IR as consistency-checker is Tier B (buildable, engineering risk); GC-IR as full multi-target compiler is Tier C (research-stage).

## 15. Hybrid zk-SNARK / zk-STARK Strategy

| Dimension | Groth16 (SNARK) | PLONK/Halo2 (SNARK) | STARK |
|---|---|---|---|
| Proof size | ~200 B | ~1–10 KB | 50–200 KB |
| Verify cost | 3 pairings (ms) | ms | ms–10s ms |
| Trusted setup | Per-circuit ceremony | Universal (once) | **None** |
| PQ security | No (pairings) | No | **Yes (hash-based)** |
| Best use here | Stable, high-volume circuits (fairness, coverage) + SnarkPack aggregation | Evolving statements without re-ceremony | Long-horizon evidence; transparency-critical claims; PQ hedge |

**v2.4 hybrid policy**:
1. Stable high-volume statements → Groth16 + SnarkPack (regulator verification stays trivial).
2. Statements expected to evolve with policy → PLONK/Halo2 universal setup.
3. Claims that must remain verifiable beyond the pairing-crypto horizon (10y+ retention evidence; treaty-grade attestations) → STARKs, accepting larger proofs.
4. **Bridging**: where a STARK wraps a batch of SNARK verifications (or vice versa) for cost/PQ trade-offs, the wrapper circuit itself goes through GC-IR change control. Recursive composition at this layer is Tier B–C; plan pilots 2029–2031, no compliance dependency before 2032.

---

# PART IV — Multi-Jurisdictional Mapping and ICGC/GASO Layer

## 16. Regime Mapping Delta

The companion volume Part 3 carries the full regime matrix (EU AI Act incl. Annex IV and Art. 51–55 systemic-risk GPAI duties, NIST AI RMF 1.0 + AI 600-1, ISO/IEC 42001, Basel III/IV, SR 11-7, scenario SR 26-2, DORA, NIS2, GDPR, FCRA/ECOA, MAS FEAT, HKMA, FCA SM&CR/Consumer Duty, EO 14110 status). This volume adds the **GPAI systemic-risk detail** and the **ICGC/GASO layer**.

### 16.1 EU AI Act systemic-risk GPAI provisions (Arts. 51–55) — institutional posture

- **Classification watch**: a bank is normally a *deployer*, but a sufficiently large in-house fine-tune or continued pre-training can create provider-like duties. The registry computes a **provider-risk flag** per fine-tune (training-compute estimate, capability-eval deltas) and routes flagged assets to legal classification review.
- **If provider duties attach**: model evaluation incl. adversarial testing (Art. 55(1)(a)) → Red Dawn + eval service evidence; systemic-risk assessment/mitigation (55(1)(b)) → G-SRI inputs + CESE scenarios; serious-incident tracking (55(1)(c)) → incident pipeline; cybersecurity (55(1)(d)) → containment-ring + attestation evidence. The architecture needs no new machinery — only a routing rule.

## 17. ICGC/GASO — Civilizational Compute Governance Layer

> **Feasibility flag (unchanged and emphatic)**: ICGC (International Compute Governance Council) and **GASO (Global AI Safety Organization)** — conceived as ICGC's operational/technical arm, analogous to IAEA's Department of Safeguards — are **speculative institutional constructs**. They are specified here as forward-compatibility design fixtures. No current compliance obligation derives from them.

### 17.1 GASO concept of operations (design fixture)

| Function | GASO mechanism | Institutional adapter (buildable now) |
|---|---|---|
| Compute accounting | Attested-hardware metering standard (GAICS units) | Hardware attestation daemons + contracted-compute telemetry export |
| Training-run notification | Threshold-triggered notification with zk-verified compute proofs | Registry provider-risk flags + SIP `/notifications` endpoint |
| Containment certification | GACP levels 1–3 audited against containment-ring evidence | OSCAL `profile-icgc-gacp.json` + Red Dawn evidence packs |
| Incident commons | Anonymized cross-border incident exchange | zk-anonymized incident contribution proofs (Tier B) |

### 17.2 ICGC Phase 1 zk-verified AI controls (design fixture, plan-compatible 2030–2032)

Phase 1 = *verification of declared facts* (the "declarations + safeguards" stage):

- **P1-C1 Compute declaration proof**: STARK over attested hardware logs proving "total training compute for run R = X FLOP-units (GAICS) within tolerance," without revealing cluster topology or utilization patterns. *Substrate: attestation daemons (Tier A) + metering circuits (Tier B–C).*
- **P1-C2 Registry consistency proof**: declared frontier-asset registry entries match internal registry commitments (Merkle inclusion proofs — Tier A technology).
- **P1-C3 Containment-level attestation**: GACP-level conformance proven via OSCAL assessment-results whose evidence digests are committed and selectively disclosed (SNARK over evidence-freshness predicates — Tier B).
- **P1-C4 Incident-reporting completeness**: proof that all incidents above severity S in period P were reported (count-consistency between internal WORM-anchored incident set and reported set — Tier B).

### 17.3 ICGC Phase 2 zk-verified AI controls (design fixture, 2033–2035 horizon)

Phase 2 = *verification of behavioral properties* (the "ongoing safeguards" stage):

- **P2-C1 Eval-battery execution proofs**: prove mandated capability/danger evals were executed on the exact registered checkpoint (weight-commitment binding + eval-harness transcript commitments). *Tier C — weight commitments at frontier scale and eval-integrity proofs are research-stage.*
- **P2-C2 Autonomy-ceiling treaty compliance**: SRC-2-style circuits parameterized by treaty ceilings rather than internal ones (*Tier B once Phase-1 machinery exists*).
- **P2-C3 Training-data provenance classes**: prove training data excluded prohibited classes via committed dataset manifests + classifier attestations (*Tier C; classifier-in-the-loop proofs are weak links — flag honestly*).
- **P2-C4 Cross-institution correlation telemetry**: privacy-preserving aggregate computation (MPC/zk hybrid) of systemic correlation indicators across institutions for GAIRA-style bodies (*Tier C engineering, Tier A mathematics*).

**Design rule restated**: build adapters (attestation, registry export, proof pipelines, SIP endpoints), not dependencies. Every ICGC/GASO adapter doubles as a domestic-supervision capability.

---

# PART V — Phased Roadmap 2026–2030 with 2031–2035 Extension (Delta View)

The companion volume Part 1.4/6.1 carries the master phase plan. This volume adds the **cryptographic and civilizational-layer milestones**:

| Year | Crypto/proof milestones | Civilizational-layer milestones |
|---|---|---|
| 2026 | PQC inventory + hybrid signing design; Powers-of-Tau participation; GC-IR schema v0 | Treaty-engine obligation lattice v1 (real regimes only) |
| 2027 | First Groth16 circuits (coverage C2) in shadow; envelope schema v1 enforced | OSCAL ICGC-GACP draft profile authored (fixture) |
| 2028 | Fairness circuit C1 production; SnarkPack daily aggregation; STARK pilot for retention proofs | Attested-compute metering pilot on owned clusters |
| 2029 | SRC-1/SRC-2 systemic circuits; GC-IR consistency-checking in CI; PLONK track for evolving statements | Incident-commons zk-anonymization pilot (bilateral, with one peer institution) |
| 2030 | Regulator zk verification live (≥1 supervisor); GSRIIntegrity proof published with BBOM | ICGC Phase-1-compatible declaration proofs demonstrated (P1-C2 class) |
| 2031–32 | Recursive/IVC pilots; STARK-wrapped SNARK bridges; PQ-proof migration plan | Phase-1 adapters production-ready (contingent on machinery) |
| 2033–35 | Continuous attestation (rolling proofs) if IVC matures; full PQ evidence chain | Phase-2 pilots (P2-C2 first); multi-regulator joint simulations |

---

# PART VI — Civilizational Governance Blueprint (2026–2035)

## 18. Existential and Catastrophic AI Risk Management (institutional translation)

A financial institution is not an AGI lab, but it is a *deployment amplifier* and a *systemic transmission channel*. Its existential/catastrophic-risk duties translate to:

1. **Capability-gated deployment (the binding control)**: deny-by-default admission above capability-eval thresholds (autonomy, situational awareness, cyber-offense, persuasion batteries from external eval ecosystems). The institution's strongest x-risk lever is *refusing to deploy what it cannot contain* — encoded as registry/admission policy, board-ratified, exception-free for T0.
2. **Containment depth as cost imposition**: rings R1–R6 + verified kill-switch make the institution a hard target for misuse and a poor escape substrate — defense-in-depth with measured MTTC, never claimed as a guarantee against strongly superhuman systems (see honesty rule, §22).
3. **Systemic transmission dampers**: concentration limits, autonomy ceilings, correlation monitors, and mass-de-autonomization playbooks address the *financial-stability* face of catastrophic risk — correlated AI failure as a 2008-style common-exposure event.
4. **Catastrophic scenario set (CESE + Red Dawn)**: maintained jointly with the risk function — flash-crash via agent herding; credit-system bias cascade; payments-infrastructure agent compromise; model-supply-chain poisoning at vendor; jailbreak epidemic during market stress. Each has a pre-authorized playbook and a capital/liquidity impact estimate feeding ICAAP.
5. **External posture**: contribute incident data (anonymized), fund open verifier/eval tooling, and support compute-governance standards — an institution's marginal x-risk contribution is mostly through the ecosystem it finances and legitimizes; this belongs in the board's risk appetite statement.

## 19. Ethical Alignment and Value Learning (institutional translation)

- **Constitution-as-code**: the AI constitution (Phase 0) decomposes into testable behavioral specifications per use case — refusal requirements, escalation duties, customer-fairness commitments — maintained as eval suites and Rego gates, not prose.
- **Value-learning posture (honest)**: general value learning is unsolved (Tier C/D). The institution does not deploy systems whose safety depends on learned values; it deploys systems whose safety depends on *bounded authority + oversight + containment*. Preference-learning components (e.g., RLHF-tuned assistants) are treated as quality features, never as safety controls.
- **Operational ethics machinery**: ethics review board for novel use cases (gates in WorkflowAI Pro); contestability rights (appeal channels per GDPR Art. 22/Consumer Duty wired into decision flows); fairness re-evaluation cadences with statistical-power floors; "red lines" registry (uses the institution will not pursue regardless of legality — e.g., manipulation-optimized retail products), board-ratified and policy-enforced.

## 20. Global Governance Frameworks and International Cooperation

- **Real layer (engage now)**: OECD AI Principles and GPAI lineage; the AI-Safety-Institute network (UK AISI, US, EU AI Office scientific panel) for eval methodology; FSB/BIS workstreams on AI in finance; ISO/IEC SC 42 standardization; FS-ISAC for incident sharing. Institutional posture: contribute eval results and incident learnings, adopt emerging eval standards into admission gates, second staff to standards bodies.
- **Fixture layer (build adapters)**: ICGC/GASO per Part IV §17; GAIRA-style systemic-risk telemetry; GACP containment certification. The adapter inventory — attestation, registry export, proof pipelines, SIP endpoints, OSCAL profiles — is identical to what domestic supervisors need, so the investment is no-regret.
- **Cooperation asymmetry management**: where jurisdictions diverge (data localization vs. consolidated supervision; export-control regimes), the obligation lattice + Sovereign Gateway implement most-restrictive-wins with documented derogations; geopolitically driven obligations are treated as *data* updates, keeping the architecture stable under treaty churn.

## 21. Societal Impacts: Economic Disruption and Bias Amplification

- **Economic disruption (workforce)**: AI-driven role displacement inside the institution is governed, not just managed — a workforce-transition register (roles affected, reskilling pathways, redeployment rates) reports to the board alongside G-SRI; FCA Consumer Duty logic applied internally ("good outcomes" for staff as a conduct posture). External: credit-model behavior during regional economic shocks is a CESE scenario class (does the AI estate amplify pro-cyclicality?), feeding countercyclical overrides into policy data.
- **Bias amplification**: beyond per-model fairness gates (companion §2.3, §5.7), the *systemic* concern is correlated bias across institutions sharing foundation models — addressed by: lineage-aware fairness analytics (do all models on lineage L share a directional bias?), participation in cross-institution fairness benchmarking (zk-anonymized, Tier B), and concentration limits doubling as bias-monoculture limits.
- **Information-integrity externalities**: GenAI customer-communication systems carry NIST AI 600-1 information-integrity controls (provenance marking, confabulation-rate SLOs with abstention fallbacks); synthetic-content disclosure per EU AI Act Art. 50.
- **Measurement**: a Societal Impact Annex is added to the annual supervisory package: fairness-cohort trends, complaint/appeal volumes and outcomes, workforce-transition metrics, information-integrity SLO attainment — all evidence-linked.

## 22. Honesty Rules (binding on all artifacts in this volume)

1. No artifact may claim guaranteed containment of strongly superhuman systems; the claim is *defense-in-depth with measured MTTC plus capability-gated deployment*.
2. No proof may be presented without its input-integrity chain (attestation → signed telemetry → Merkle anchoring) stated alongside.
3. Every speculative construct (ICGC, GASO, SR 26-2, HKMA Fintech 2030, product taxonomy) carries its feasibility-tier label wherever it appears in regulator-facing artifacts.
4. Governance models (ASA, CESE, G-SRI computation, treaty engine) are registered, validated models — no exemption.

---

# PART VII — Regulator-Ready Report Templates

All recurring regulator-facing reports use the tagged structure below; renderers in G-Stack emit them automatically.

## 23. Template: Periodic Supervisory Technical Report

```markdown
<title>{Institution} — {Regime} Supervisory Technical Report — {Period}</title>

<abstract>
One-paragraph summary: scope (asset tiers covered), material changes since
last period, headline metrics (G-SRI, MTTC, coverage %, attestation status),
incidents above threshold, and open commitments. State feasibility-tier
labels for any forward-looking mechanism referenced. ≤250 words.
</abstract>

<content>
1. Scope and asset inventory delta (registry extract, signed)
2. Control coverage and evidence freshness (OSCAL assessment-results ref)
3. Policy changes (bundle hashes, shadow-eval reports, approver chains)
4. Containment posture (ring conformance, kill-switch test evidence,
   reachability reports)
5. Incidents and near-misses ({DORA|Art.73|regime} classification, causal
   graphs, remediation tasks with deadlines)
6. Systemic risk (G-SRI pillar decomposition, concentration metrics,
   GSRIIntegrity proof reference)
7. Stress and simulation (Red Dawn scores, CESE scenario summaries)
8. Cryptographic attestations (proof set: {circuit_hash, public inputs,
   VK id, verification instructions}; input-integrity chain statement)
9. Exceptions register (aging, compensating controls)
10. Forward commitments and roadmap deltas
Appendix A: evidence manifest (Merkle root, WORM anchors)
Appendix B: feasibility-tier glossary for referenced mechanisms
</content>
```

## 24. Template: Serious-Incident Report (EU AI Act Art. 73 / DORA-aligned)

```markdown
<title>Serious Incident Report — {incident_id} — {asset} — {date}</title>
<abstract>What happened, detected when/how (MTTD), contained when/how (MTTC,
ladder level reached), harm assessment, regulatory classifications triggered,
immediate mitigations. ≤200 words, populated from the causal graph.</abstract>
<content>
1. Timeline (machine-generated from correlation-ID chain; all timestamps WORM-anchored)
2. Causal analysis (graph + narrative)
3. Control performance (which controls fired/failed; spec-conformance notes)
4. Harm and exposure assessment (customers, market, capital)
5. Remediation plan (tasks, owners, deadlines)
6. Recurrence-prevention changes (policy/circuit/spec diffs proposed)
7. Evidence manifest
</content>
```

## 25. Template: Board Quarterly AI Risk Pack (BBOM snapshot)

```markdown
<title>Board AI Risk Pack — {quarter}</title>
<abstract>G-SRI trend and drivers, deployment-freeze status, top-5 risks,
attestation status, regulatory horizon (next 2 quarters of obligations),
decisions required of the board. ≤150 words.</abstract>
<content>
1. G-SRI decomposition and trajectory  2. Tier population and ceiling utilization
3. Red Dawn and kill-switch test results  4. Exception and finding aging
5. Regulatory clock status and horizon scan  6. Capital/stress linkage (ICAAP delta)
7. Decisions required (with options and risk analysis)
Appendix: SM&CR attestation signatures; evidence manifest
</content>
```

---

# PART VIII — Audience-Specific Blueprint Index

| Audience | Primary artifacts (this volume + companion) | Entry point |
|---|---|---|
| **Boards** | BBOM, board pack template (§25), G-SRI methodology (§7), red-lines registry (§19) | Companion Part 1; this volume §7, §25 |
| **C-suite** | Phase plans, operating model, funding/talent strategy, risk-mitigation table | Companion Parts 1, 4.14; this volume Part V |
| **Regulators** | OSCAL profiles (§11), SIP endpoints, sandboxes, report templates (Part VII), verifier tooling, GC-IR obligations (§14) | Companion Parts 2.5–2.8, 4.13; this volume Parts II–IV, VII |
| **Enterprise architects** | Five-zone topology, cluster/Kafka design, containment rings, gateway, platform architecture | Companion Parts 2, 5; this volume Part I |
| **AI platform engineers** | Rego packs + CI contract (§10), envelope schema (§12), sidecar spec, circuits (§13), pipeline configs | Companion §2.2–2.3; this volume Parts II–III |
| **AI safety researchers** | TLA+ suite (§9), ASA validity governance (§4), Red Dawn library (§6), eval-gating, ICGC Phase-2 research agenda (§17.3), honesty rules (§22) | This volume Parts I–II, IV, VI |

---

# PART IX — Consolidated Feasibility Taxonomy (Delta)

The companion volume §6.3 taxonomy governs. Deltas introduced by this volume:

- **Tier A (deployable now)**: OSCAL catalog/profile/assessment tooling; envelope schema with hybrid PQC signatures; Merkle-inclusion registry-consistency proofs (P1-C2 class); STARK retention proofs; Red Dawn program mechanics; G-SRI computation; BBOM dashboards; report-template automation.
- **Tier B (engineering risk)**: systemic-risk circuits SRC-1..4 at G-SIFI volume; GC-IR as consistency checker; STARK/SNARK hybrid bridging; zk-anonymized incident commons; ICGC P1-C3/P1-C4 class proofs; cross-institution fairness benchmarking.
- **Tier C (research-stage)**: GC-IR as full multi-target compiler; IVC/recursive continuous attestation; compute-metering proofs at frontier scale (P1-C1 full strength); eval-execution and training-data-provenance proofs (P2-C1, P2-C3); MPC/zk cross-institution correlation telemetry (P2-C4); general value learning as a safety control.
- **Tier D (speculative/fictional)**: ICGC, GASO, GACP/GAICS and the wider mechanism family; SR 26-2; HKMA Fintech 2030 (forward scenario extrapolating Fintech 2025); the Sentinel v2.4 / G-Stack / WorkflowAI Pro / Omni-Sentinel / SIP product taxonomy (capability bundles, not turnkey products). Used only as design fixtures and forward-compatibility interfaces — never as compliance dependencies.

**Closing rule**: budget on Tier A, pilot Tier B behind maturity gates, track Tier C annually, and let Tier D shape interfaces only. Every claim in every artifact must be checkable — by a policy engine at runtime, a model checker at design time, a cryptographic verifier at audit time, and a supervisor through an API at any time.

</content>
