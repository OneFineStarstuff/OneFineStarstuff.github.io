# Governance Integrity Ecosystem Specification (GIES) v1.0

**Formal constitutional specification for the Sentinel AI Governance Stack v2.4 / Omni-Sentinel Mesh v4.0**
**Status:** Authoritative single source for supervisory digital twin design and monograph chapter architecture
**As of:** 27 June 2026
**Verification anchor:** `governance_artifacts/run_runnable_assurance.sh` — 19/19 PASS at head
**Index:** Sentinel Governance Index v6.0 (`governance_artifacts/sentinel_governance_index_v6.yaml`, 24 artifacts, validated by suite step 19)

---

## 0. Constitutional preamble and normative conventions

GIES is written in a **constitutional style**: every clause is either

- **[N]** *Normative* — a MUST/SHALL requirement stated as an invariant over system state, analogous to a TLA+ `INVARIANT`, and where runnable, mapped to a verifying artifact; or
- **[I]** *Informative* — rationale, threat context, or deployment guidance carrying no conformance weight.

Keywords MUST / SHALL / MUST NOT are per RFC 2119. Every normative clause carries a **canonical reduction**: the chain from prose requirement → formal invariant → runnable check → OSCAL control → regulatory obligation. A GIES deployment is **conformant** iff every Tier-A clause's verifying check passes and every non-runnable clause is explicitly disclosed (never silently assumed).

**Feasibility tiers (honest-disclosure rule, [N] GIES-0.1):** every clause SHALL be tagged A (runnable + verified in-repo), B (runnable design-level model), C (declarative, schema-validated), or D (organisational/prose). A deployment MUST NOT represent Tier B/C/D clauses as machine-verified.

---

## 1. GIES module architecture

GIES decomposes governance integrity into four modules forming a strict verification pipeline:

```
GIMM  ──produces──▶  GIAF  ──feeds──▶  GEE  ──reports to──▶  META
(models)            (evidence)        (enforcement)         (meta-governance)
```

| Module | Name | Constitutional role | SGI artifacts |
|---|---|---|---|
| **GIMM** | Governance Integrity Model Module | Formal models whose invariants define what "safe" means. Nothing is enforceable until it is *definable*. | SGI-01..05 (TLA+ models) |
| **GIAF** | Governance Integrity Assurance Fabric | Cryptographic evidence plane: proofs, signed WORM logs, OSCAL catalogs, regulator deliverables, distribution bundles, freshness ledger. | SGI-08/09, SGI-12..19 |
| **GEE** | Governance Enforcement Engine | Runtime gates that make GIMM invariants *binding*: OPA/Rego admission and release gates, routing stabilizers, on-chain treaty hardening. | SGI-06/07, SGI-10/11 |
| **META** | Meta-Governance | Governs the governance: index integrity, pilot acceptance gates, schema validation, the assurance suite itself, decadal roadmap. | SGI-20..24 |

**[N] GIES-1.1 (Module ordering invariant).** No GEE gate SHALL enforce a predicate that is not derived from a GIMM invariant; no GIAF evidence object SHALL attest to a claim without a named producing check; META SHALL be able to falsify any Tier-A claim by re-execution.
*Canonical reduction:* → SGI index cross-references (every tier-A artifact names invariants + verifying step) → `validate_governance_index.py` IDX-6/IDX-7/IDX-8 → suite step 19.

---

## 2. GIMM — Governance Integrity Model Module

### 2.1 Constitutional invariants (all Tier A unless noted)

**[N] GIMM-1 Containment ratchet.** Containment severity SHALL be monotonically non-decreasing absent quorum: `ASARatchet ∧ TerminalNeedsQuorum`.
*Reduction:* `tla/KillSwitchAbstract.tla` → suite step 2 → OSCAL `con-04`/`con-07` → EU AI Act Art. 14 (human oversight), DORA response & recovery.

**[N] GIMM-2 Attested admission.** No T0/T1 workload SHALL execute without a valid, non-stale hardware attestation: `OnlyAttestedRun ∧ NoRunOnStaleTCB ∧ PCRMatchWhileRun`.
*Reduction:* `tla/AdmissionWithAttestation.tla` → suite step 3 → OSCAL `env-01` (freshness-SLA PT5M) → EU AI Act Art. 15, NIS2 Art. 21, NIST AI RMF MEASURE.

**[N] GIMM-3 Dead-man's switch.** Once tripped, containment SHALL stay tripped; no unsanctioned high-risk state is reachable: `TrippedStaysTripped ∧ NoUnsanctionedHighRisk ∧ KillSwitchIntegrity`.
*Reduction:* `tla/SentinelContainmentProtocol.tla` → suite step 4 → OSCAL `con-04` → ISO/IEC 42001 §8 operational control.

**[N] GIMM-4 Federated non-equivocation (Tier B).** No institution SHALL present divergent signed tree heads for the same epoch without detection: `NoSilentDivergence`.
*Reduction:* `tla/sip_v3/SIPv3_Federated_Protocol.tla` → design-level model (disclosed: not yet TLC-gated in suite) → GIEN/SIP v3.0 → DORA Ch. V (third-party/interconnection risk).

**[N] GIMM-5 Multi-jurisdiction override consistency (*Lex Severior*).** The effective enforcement posture SHALL equal the most restrictive active supervisory override; no jurisdiction may unilaterally weaken it; HALT→NORMAL de-escalation SHALL be unanimously released and logged:
`MultiJurisdictionOverrideConsistency ∧ NoUnilateralWeakening ∧ HaltReleaseAudited ∧ LogWellFormed`.
*Reduction:* `tla/MultiJurisdictionOverride.tla` (2,523 states, mutation-tested) → suite step 19 → EU AI Act Arts. 65–68 market surveillance, cross-border supervisory colleges. **This is the invariant under forensic analysis in SGI v6.0 (§ Annex F of the monograph and `PHASE_V_VI_SUPERVISORY_DESIGN.md`).**

### 2.2 [I] Model discipline
State spaces are deliberately small and exhaustively checked; the models are *control-discipline* proofs, not capability-safety proofs for arbitrarily capable agents (Tier D boundary, stated in every derived document).

---

## 3. GIAF — Governance Integrity Assurance Fabric

**[N] GIAF-1 Evidence authenticity.** Every audit-relevant event SHALL be recorded in a hash-chained, ML-DSA-65 (FIPS 204) signed WORM log; tampering, reordering or forgery SHALL be detectable.
*Reduction:* `kafka/pqc_worm_logger_v2.py` → suite step 9 → OSCAL `cry-02` (SLA P1D) → GDPR Art. 22 (contestability record), EU AI Act Art. 12.

**[N] GIAF-2 Zero-knowledge systemic-risk proof.** Concentration-bound compliance SHALL be provable without disclosing positions (Groth16 over SRC-1); non-compliant witnesses SHALL be rejected (soundness).
*Reduction:* `zk/` Circom+snarkjs → suite steps 6–7 → OSCAL `cry-05` (SLA P3M) → Basel III/IV large-exposure discipline, DORA ICT-risk reporting.

**[N] GIAF-3 Catalog conformance.** Every OSCAL control prop (`tla-spec`, `rego-policy`, `circuit`, `simulator`, regime `#href`, `feasibility-tier`, `freshness-sla`) SHALL resolve to a real artifact or anchor.
*Reduction:* `oscal/oscal_conformance.py` (43 checks) → suite step 12 → OSCAL 1.1.2 → all mapped regimes.

**[N] GIAF-4 Regulator deliverables are generated, never hand-written.** Annex IV dossier (8 sections), DORA ICT-risk register (5 pillars, gaps disclosed), NIST AI RMF crosswalk (4 functions) SHALL assemble only from conformant catalogs.
*Reduction:* suite steps 13–15 → EU AI Act Annex IV, DORA, NIST AI RMF 1.0.

**[N] GIAF-5 Verifiable distribution.** Bundles SHALL carry a deterministic content digest and detached ML-DSA-65 manifest signature, independently re-verifiable by the recipient (10 checks).
*Reduction:* suite steps 16–17 → supervisory filing integrity.

**[N] GIAF-6 Evidence freshness.** Every runnable control's evidence SHALL be no older than its catalog-declared SLA, recorded in a digest-protected ledger; stale/failed/future-dated/tampered evidence SHALL fail the gate; organisational evidence SHALL be disclosed NOT-RUNNABLE.
*Reduction:* `check_evidence_freshness.py` → suite step 18 → EU AI Act Art. 12, DORA monitoring.

---

## 4. GEE — Governance Enforcement Engine

**[N] GEE-1 Deny-by-default release gate.** Model release SHALL be denied unless every required control attests PASS; attestation gates SHALL require PCR_MATCH.
*Reduction:* `rego/` (21 OPA tests) → suite step 1 → OSCAL `env-01` → EU AI Act Art. 15.

**[N] GEE-2 Cross-target semantic agreement.** The Rego policy, the arithmetic circuit, and the declared expectation SHALL agree on every fixture (no enforcement/proof drift).
*Reduction:* GC-IR harness → suite step 5.

**[N] GEE-3 Routing stability.** MoE routing SHALL maintain entropy ≥ floor, load-ratio ≤ bound, zero drops under the SARA/ACR stabilizers.
*Reduction:* routing harness → suite step 8 → OSCAL `rte-01` (SLA P1D) → NIST AI RMF MEASURE, SR 11-7.

**[N] GEE-4 On-chain treaty hardening.** The OmegaActual dead-man's switch SHALL be one-way at contract level (SEC-01..06 hardened, 7 logic tests).
*Reduction:* `OmegaActualTreatyEngine.sol` → suite step 10.

---

## 5. META — Meta-Governance

**[N] META-1 Index integrity.** The Sentinel Governance Index SHALL truthfully enumerate all constitutional artifacts (24 in v6.0), with existing paths, canonical IDs, valid GIES modules, complete tier-A verification chains, and TLA invariant names that actually exist.
*Reduction:* `validate_governance_index.py` (8 IDX checks) → suite step 19.

**[N] META-2 Suite as meta-gate.** The assurance suite SHALL fail fast on any step; conformance claims are valid only at a commit where the suite exits 0.
*Reduction:* `run_runnable_assurance.sh` (SGI-24, self-verifying).

**[N] META-3 Pilot gates.** 2028 G-SIFI pilot acceptance SHALL be evaluated by the runnable gate checklist, mixing automated results with staged manual evidence, never prose-only.
*Reduction:* `pilot/run_pilot_acceptance_gates.py` (SGI-20).

**[I] META-4 Roadmap.** Phases I–VIII (2026–2035) are machine-readable (`roadmap_2026_2035.yaml`, SGI-23); Phase V/VI expansion design lives in `PHASE_V_VI_SUPERVISORY_DESIGN.md`.

---

## 6. Integrated GIES → SDT → PMGF architecture

### 6.1 Integration diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PLANETARY META-GOVERNANCE FRAMEWORK (PMGF)                │
│         (Monograph Ch. 8 — Tier B/D: treaty layer, GIEN federation,          │
│          civilizational compute governance; OmegaActual treaty engine)       │
│   ▲ aggregated G-SRI, equivocation alerts, jurisdictional override states    │
├───┼─────────────────────────────────────────────────────────────────────────┤
│   │              SUPERVISORY DIGITAL TWIN (SDT)  (Monograph Ch. 7)           │
│   │   Regulator-side replica: re-runs GIMM models (TLC), re-verifies GIAF    │
│   │   bundles (step 17 verifier), re-audits freshness (step 18), watches     │
│   │   MJO override lattice (step 19). The SDT trusts NOTHING it cannot       │
│   │   independently re-verify — its API is exactly the assurance suite.      │
│   ▲ signed bundles, freshness ledger, override log, telemetry attestations   │
├───┼─────────────────────────────────────────────────────────────────────────┤
│   │                     GIES  (deployed institution side)                    │
│   │  ┌────────┐    ┌────────┐    ┌────────┐    ┌────────┐                    │
│   │  │  GIMM  │───▶│  GIAF  │───▶│  GEE   │───▶│  META  │──── reports ───▶   │
│   │  │ models │    │evidence│    │enforce │    │ audits │                    │
│   │  └────────┘    └────────┘    └────────┘    └────────┘                    │
│   │   SGI-01..05    SGI-08/09,    SGI-06/07,    SGI-20..24                   │
│   │   TLA+/TLC      12..19        10/11                                      │
│   │                 zk+WORM+OSCAL OPA+Sol+MoE                                │
└───┴─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Canonical-reduction chain (the constitutional spine)

Every governance claim in the stack reduces along this single chain:

```
Regulatory obligation (EU AI Act / DORA / NIS2 / Basel / GDPR / NIST RMF / ISO 42001)
  └─▶ OSCAL 1.1.2 control (catalog_sentinel_v24_*.json; regime #href anchors)
        └─▶ Constitutional invariant (TLA+ INVARIANT / Rego deny-rule / circuit constraint)
              └─▶ Runnable check (assurance suite step 1..19)
                    └─▶ Evidence object (WORM entry / freshness ledger row /
                          signed bundle artifact — ML-DSA-65, SHA-256)
                          └─▶ Supervisory action (SDT re-verification; MJO
                                override raise/release; pilot gate decision)
```

**[N] GIES-6.1.** A claim that cannot be placed on this chain SHALL be tagged Tier D and excluded from conformance statements. **[N] GIES-6.2.** The SDT SHALL accept only evidence objects that re-verify locally (steps 12, 17, 18, 19 are the SDT's minimum ingestion gate). **[N] GIES-6.3.** PMGF aggregation SHALL preserve MJO semantics globally: the planetary effective posture for a shared model class is the *Lex Severior* max over all federated jurisdictions' postures (Tier B — modelled, not yet deployed).

---

## 7. Conformance clause

A deployment claims **"GIES v1.0 conformant"** iff: (a) suite exits 0 at the attested commit; (b) SGI index validates (META-1); (c) freshness audit PASS (GIAF-6); (d) all Tier B/C/D clauses disclosed in the filing. Partial conformance SHALL be expressed per-module (e.g. "GIMM+GEE conformant, GIAF-2 pending") — never as unqualified conformance.

---

*This specification is the single authoritative source referenced by the monograph (`SENTINEL_MONOGRAPH_ARCHITECTURE.md`), the crosswalk register (`CRYPTO_ANCHORS_OSCAL_CROSSWALKS_2026-06-27.md`), and the Phase V/VI supervisory design (`PHASE_V_VI_SUPERVISORY_DESIGN.md`).*
