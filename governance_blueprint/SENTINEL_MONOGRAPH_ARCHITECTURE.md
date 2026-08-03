# Sentinel AI Governance Monograph — Complete Architecture, Front Matter & Annexes

**Title:** *Constitutional AI Governance: The Sentinel Stack v2.4 and Omni-Sentinel Mesh v4.0 — From Formal Invariants to Planetary Meta-Governance*
**Edition:** 1.0 (27 June 2026)
**Normative basis:** GIES v1.0 (`GIES_FORMAL_SPECIFICATION.md`); Sentinel Governance Index v6.0 (24 artifacts); runnable assurance suite 19/19 PASS.

---

## Part I — Preface (fully drafted)

> Regulation of advanced AI has produced an abundance of principles and a scarcity of proofs. Between the paragraph of law and the line of code lies a gap into which most governance programmes fall: controls that are asserted rather than checked, evidence that is compiled rather than generated, and supervision that reads reports rather than re-executes them.
>
> This monograph closes that gap for one concrete, fully published system. Every normative claim in the chapters that follow is anchored to a runnable artifact in the accompanying repository — a TLA+ model checked by TLC, an OPA policy with passing tests, a Groth16 proof that rejects violating witnesses, an ML-DSA-65-signed WORM log that detects tampering, an OSCAL catalog whose every cross-reference resolves, a freshness ledger that fails when evidence goes stale, and an index that is itself validated. The reader is never asked to trust prose: the single command `bash governance_artifacts/run_runnable_assurance.sh` re-establishes, in minutes, every Tier-A claim in this book.
>
> We write in a constitutional style. Chapters state invariants the way constitutions state rights: minimally, precisely, and with enforcement machinery attached. Where our reach exceeds our proofs — organisational controls, federated deployment at planetary scale, the containment of systems more capable than their overseers — we say so explicitly, using a four-tier feasibility taxonomy that appears beside every claim. Honesty about the boundary between the verified and the aspirational is, we argue, itself a governance control — perhaps the most important one.
>
> The monograph is addressed simultaneously to three audiences: engineers who must build such systems, supervisors who must examine them, and standards bodies who must generalise them. Chapters 1–4 build the constitutional core; Chapters 5–8 scale it from a single institution's telemetry to a planetary federation; Chapters 9–10 hand it to the supervisor and the standards community. The annexes make the book auditable: a glossary with normative definitions, complete evidence-object and telemetry-signal catalogs, and the WORM schema against which every log line in the repository validates.
>
> — *The authors, 27 June 2026*

## Part II — Abstract (fully drafted)

> We present a complete, runnable constitutional-governance architecture for high-risk AI systems in globally systemic financial institutions. The Governance Integrity Ecosystem Specification (GIES) organises governance into four modules — formal models (GIMM), a cryptographic assurance fabric (GIAF), a runtime enforcement engine (GEE), and meta-governance (META) — connected by a single canonical-reduction chain from regulatory obligation (EU AI Act, DORA, NIS2, Basel III/IV, GDPR, NIST AI RMF, ISO/IEC 42001) through OSCAL 1.1.2 controls and machine-checked invariants to signed evidence objects and supervisory actions. Nineteen falsifiable assurance checks — TLC model checking (including the multi-jurisdiction *Lex Severior* override invariant, 2,523 states), 21 OPA policy tests, Groth16 zero-knowledge systemic-risk proofs, FIPS 204 ML-DSA-65 WORM logging, generated regulator dossiers, deterministic signed distribution bundles, an evidence freshness-SLA gate, and a validated 24-artifact governance index — execute in a single command and gate every conformance claim. On this base we specify a regulator-side Supervisory Digital Twin whose ingestion API is the assurance suite itself, and a Planetary Meta-Governance Framework federating jurisdictional postures under most-restrictive-wins semantics. All feasibility boundaries are explicitly tiered; containment results are presented as control-discipline proofs, not capability-safety guarantees.

---

## Part III — Ten-chapter architecture and summary

| Ch. | Title | Constitutional payload | Verified anchor |
|---|---|---|---|
| 1 | The Case for Constitutional AI Governance | Tier taxonomy; canonical-reduction chain; honesty-as-control | GIES §0, §6.2 |
| 2 | Formal Foundations: Invariants as Rights | GIMM-1..3 (ratchet, attested admission, dead-man's switch) | Suite steps 2–4 |
| 3 | The Enforcement Engine | GEE-1..4 (deny-by-default, cross-target agreement, on-chain hardening) | Steps 1, 5, 10 |
| 4 | The Assurance Fabric | GIAF-1..6 (WORM, zk proofs, OSCAL, dossiers, bundles, freshness) | Steps 6–7, 9, 12–18 |
| **5** | **Systemic-Risk Telemetry & Mixture-of-Experts Stability** | see §III.5 | Steps 6–8 |
| **6** | **Federated Defense: GIEN and SIP v3.0** | see §III.6 | SGI-04 (Tier B) |
| **7** | **The Supervisory Digital Twin** | see §III.7 | Steps 12, 17–19 |
| **8** | **The Planetary Meta-Governance Framework** | see §III.8 | SGI-05, SGI-11, SGI-22 |
| 9 | Supervision in Practice: Pilots, Filings, Stress Tests | META-3; pilot gates; consolidated filing strategy | SGI-20; Phase V/VI doc |
| 10 | Standardisation and the Road to 2035 | Submission packages (ISO/IEC JTC 1/SC 42, NIST); roadmap VIII | SGI-22/23 |

### III.5 — Chapter 5: Systemic-Risk Telemetry & Mixture-of-Experts Stability

**Normative core [N]:** GEE-3 (entropy floor, load-ratio bound, zero-drop — `rte-01`, SLA P1D, suite step 8); GIAF-2 (Groth16 SRC-1 concentration proof — `cry-05`, SLA P3M, steps 6–7); telemetry events enter the GIAF WORM log (GIAF-1). Canonical reduction: *Basel III/IV large-exposure + SR 11-7 model risk → OSCAL `rte-01`/`cry-05` → SARA/ACR invariants + circuit constraints → steps 6–8 → G-SRI evidence objects → SDT ingestion.*
**Informative [I]:** G-SRI construction; why MoE routing collapse is a *prudential* event (expert monoculture = concentration risk); zk-STARK migration path; stabilizer tuning studies.
**Sections:** 5.1 Telemetry as prudential data · 5.2 The G-SRI · 5.3 MoE instability as concentration risk · 5.4 SARA/ACR invariants [N] · 5.5 SRC-1 zero-knowledge proof [N] · 5.6 WORM-anchored telemetry [N] · 5.7 Regulatory alignment (Basel/DORA/NIST MEASURE) · 5.8 Limits [I].

### III.6 — Chapter 6: Federated Defense — GIEN and SIP v3.0

**Normative core [N]:** GIMM-4 `NoSilentDivergence` (SIP v3.0 signed-tree-head gossip; equivocation detectable by roots); federation messages signed ML-DSA-65; missing-attestation windows bounded (`MaxMissingWindows`). Canonical reduction: *DORA Ch. V interconnection risk + NIS2 Art. 21 → SIP v3.0 protocol invariants → SIPv3_Federated_Protocol.tla (Tier B, disclosed) → equivocation-alert evidence objects → GIEN collective response.*
**Informative [I]:** GIEN topology (institutions/roots/supervisory observers); why certificate-transparency-style gossip beats a central registry for cross-border trust; upgrade path to TLC-gating the SIP model (declared Phase V/Pass B work).
**Sections:** 6.1 Threat model: silent divergence · 6.2 SIP v3.0 protocol [N] · 6.3 Non-equivocation invariant [N, Tier B] · 6.4 GIEN membership & governance · 6.5 Collective-defense playbooks [I] · 6.6 Regulatory alignment (DORA/NIS2) · 6.7 Honest gap statement.

### III.7 — Chapter 7: The Supervisory Digital Twin

**Normative core [N]:** The SDT SHALL independently re-verify everything it consumes: bundle verification (step 17, 10 checks incl. ML-DSA-65 signature), catalog conformance (step 12), freshness audit (step 18), MJO override-lattice monitoring (step 19). The SDT's *ingestion API is the assurance suite* — no bespoke trust. Constitutional guardrail runtime monitor: the SDT re-runs TLC on institution-declared model files and diffs invariants against the SGI. Canonical reduction: *EU AI Act Arts. 65–68 market surveillance → SDT ingestion gates → suite steps 12/17/18/19 → verified twin state → supervisory action (raise/release in MJO lattice).*
**Informative [I]:** Twin architecture (read-only replica, no control-plane access); dashboard KPIs/KRIs; how a college of supervisors shares one twin under MJO semantics.
**Sections:** 7.1 Why a twin, not a portal · 7.2 Ingestion gates [N] · 7.3 Guardrail runtime monitor [N] · 7.4 Override lattice & *Lex Severior* [N] · 7.5 Stress-test playbook integration · 7.6 College operation [I] · 7.7 GDPR Art. 22 contestability via WORM replay.

### III.8 — Chapter 8: The Planetary Meta-Governance Framework

**Normative core [N]:** PMGF aggregates jurisdictional postures under GIES-6.3 (*planetary Lex Severior*, Tier B); OmegaActual treaty engine provides the on-chain one-way commitment layer (GEE-4, Tier A at contract-logic level); compute-governance thresholds per `civilizational_compute_governance_framework.yaml` (Tier C/D, disclosed). Canonical reduction: *treaty commitments → OmegaActual invariants (SEC-01..06) → step 10 → treaty-event WORM objects → GIEN-federated PMGF posture.*
**Informative [I]:** Institutional design (who convenes the planetary college); relationship to ICGC/GACP-style speculative regimes (kept Tier D); 2030–2035 phase-in.
**Sections:** 8.1 From colleges to a planetary lattice · 8.2 PMGF posture algebra [N, Tier B] · 8.3 Treaty engine [N] · 8.4 Compute governance [C/D] · 8.5 Failure modes & exit rights [I] · 8.6 Alignment: everything reduces to the same chain.

---

## Part IV — Mappings: invariants → supervisory actions → evidence → regulation

| Constitutional invariant | Supervisory action enabled | Evidence object | Regulatory requirement |
|---|---|---|---|
| `ASARatchet`, `TerminalNeedsQuorum` (GIMM-1) | Verify de-escalations were quorum-backed | TLC run record; WORM quorum entries | EU AI Act Art. 14; ISO 42001 §8 |
| `OnlyAttestedRun`, `PCRMatchWhileRun` (GIMM-2) | Reject filings with unattested T0 workloads | Attestation evidence ≤ PT5M (freshness ledger) | EU AI Act Art. 15; NIS2 Art. 21 |
| `TrippedStaysTripped` (GIMM-3) | Confirm kill-switch integrity post-incident | TLC record + on-chain state | DORA response/recovery |
| `NoSilentDivergence` (GIMM-4, B) | Cross-institution equivocation alert | Gossiped STH conflict record | DORA Ch. V |
| `MultiJurisdictionOverrideConsistency` + companions (GIMM-5) | Coordinate college overrides; audit de-escalation | Append-only override log; `unanimous_release` record | EU AI Act Arts. 65–68 |
| `ReleaseGateDenyByDefault` (GEE-1) | Examine release decisions against policy | OPA test results; decision logs | NIST RMF MANAGE |
| Entropy/load/drop invariants (GEE-3) | Prudential review of routing stability | Step-8 harness output in ledger | Basel; SR 11-7 |
| `ConcentrationBoundSoundness` (GIAF-2) | Accept zk proof in lieu of position disclosure | Groth16 proof + verifier calldata | Basel large exposures; GDPR minimisation |
| `ChainIntegrity` (GIAF-1) | Forensic replay of any decision | ML-DSA-65 WORM segment | GDPR Art. 22; AI Act Art. 12 |
| `EvidenceFresh` (GIAF-6) | Reject stale-evidence filings | Freshness ledger + digest | DORA monitoring |
| `IndependentVerification` (GIAF-5) | Verify bundle without trusting sender | MANIFEST.sig.json (ML-DSA-65) | Filing integrity |
| `AllRunnableChecksPass` (META-2) | One-command conformance re-establishment | Suite exit code + transcript | All of the above |

---

## Part V — Informative Annexes (fully drafted)

### Annex D (Informative) — Glossary
*Normative terms are defined where first tagged [N]; this annex is a reader aid.*
**Canonical reduction** — the obligatory chain regulation→OSCAL→invariant→check→evidence→action (GIES §6.2). **Constitutional invariant** — a machine-checked safety predicate treated as a right: violation is definitionally non-conformance. **Evidence object** — a signed, digest-protected record produced by a named check (Annex E). **Feasibility tier** — A/B/C/D honesty label (GIES-0.1). **G-SRI** — Governance Systemic-Risk Index, the aggregated telemetry signal of Ch. 5. **GIEN** — Governance Integrity Exchange Network, the SIP v3.0 federation of Ch. 6. **GIES / GIMM / GIAF / GEE / META** — see GIES §1. ***Lex Severior*** — most-restrictive-wins override rule (GIMM-5). **MJO** — MultiJurisdictionOverride model. **PMGF** — Planetary Meta-Governance Framework (Ch. 8). **SDT** — Supervisory Digital Twin (Ch. 7). **SGI** — Sentinel Governance Index (v6.0, 24 artifacts). **STH** — Signed Tree Head (SIP v3.0). **WORM** — write-once-read-many, here: hash-chained + ML-DSA-65-signed.

### Annex E (Informative) — Evidence-Object Catalog
| ID | Object | Producer | Integrity mechanism | Consumed by |
|---|---|---|---|---|
| EO-01 | TLC verification transcript | Suite steps 2–4, 19 | Suite transcript + commit hash | SDT §7.3 |
| EO-02 | OPA test report (21 tests) | Step 1 | Suite transcript | SDT; release audit |
| EO-03 | Groth16 proof + public signals | Steps 6–7 | Proof soundness; verifier contract | Basel exposure review |
| EO-04 | WORM log segment | Step 9 producer | SHA-256 chain + ML-DSA-65 per-entry | Forensic replay; GDPR 22 |
| EO-05 | OSCAL conformance report (43 checks) | Step 12 | Regenerable; catalog digests | Dossier generators |
| EO-06 | Annex IV dossier / DORA register / RMF crosswalk | Steps 13–15 | Generated-only rule (GIAF-4) | Regulator filing |
| EO-07 | Distribution bundle + MANIFEST.sig.json | Steps 16–17 | Deterministic content digest + detached ML-DSA-65 | SDT ingestion gate |
| EO-08 | Evidence freshness ledger | Step 18 | SHA-256 ledger digest (not a signature — disclosed) | Filing freshness check |
| EO-09 | Override log (raise/release/unanimous_release) | MJO runtime (modelled step 19) | Append-only; audited by `HaltReleaseAudited` | Supervisory college |
| EO-10 | SGI v6.0 validation report (8 IDX checks) | Step 19 | Regenerable against repo | Everything (index of all) |

### Annex F (Informative) — Telemetry-Signal Catalog
| Signal | Source | Constitutional consumer | SLA |
|---|---|---|---|
| TS-01 routing entropy | MoE router | GEE-3 entropy floor | P1D (`rte-01`) |
| TS-02 expert load ratio | MoE router | GEE-3 load bound | P1D |
| TS-03 token drop rate | MoE router | GEE-3 zero-drop | P1D |
| TS-04 attestation quote + PCRs | TEE agent | GIMM-2 admission | PT5M (`env-01`) |
| TS-05 heartbeat counter | Containment runtime | GIMM-3 dead-man trigger | model const |
| TS-06 concentration witness | Position system | GIAF-2 zk proof input | P3M (`cry-05`) |
| TS-07 STH publications | Institution log server | GIMM-4 gossip | epoch-bounded |
| TS-08 override state vector | Supervisory college | GIMM-5 posture computation | event-driven |
| TS-09 G-SRI composite | Aggregator | Ch. 5 / SDT dashboards | P1D |

### Annex G (Informative) — WORM Record Schema (normative schema lives with the logger)
```json
{ "$comment": "governance_artifacts/kafka/pqc_worm_logger_v2.py is authoritative",
  "type": "object",
  "required": ["seq", "ts", "event_type", "payload_digest", "prev_hash", "entry_hash", "sig_mldsa65"],
  "properties": {
    "seq":            {"type": "integer", "minimum": 0},
    "ts":             {"type": "string", "format": "date-time", "$comment": "UTC, RFC 3339"},
    "event_type":     {"enum": ["telemetry", "attestation", "release_decision",
                                "override_raise", "override_release", "unanimous_release",
                                "containment_trip", "proof_verified", "bundle_published"]},
    "payload_digest": {"type": "string", "$comment": "SHA-256 hex of canonical payload JSON"},
    "prev_hash":      {"type": "string", "$comment": "entry_hash of seq-1; genesis = 64x'0'"},
    "entry_hash":     {"type": "string", "$comment": "SHA-256(seq||ts||event_type||payload_digest||prev_hash)"},
    "sig_mldsa65":    {"type": "string", "$comment": "FIPS 204 ML-DSA-65 over entry_hash; dilithium-py reference impl — NOT side-channel hardened; production signing in env-02 enclave (disclosed)"}
  }
}
```
Consistency notes: `event_type` values for overrides mirror the MJO log-record kinds (GIMM-5), tying Annex G to Normative Annexes A–C (A: TLA+ modules; B: OSCAL catalogs; C: Rego policies — all in-repo, suite-verified) and to the GIES→SDT→PMGF integration (§6).

---

*Chapter architecture, front matter, and annexes are consistent with GIES v1.0 and SGI v6.0 by construction; all Tier-A anchors re-verifiable via the 19-step suite.*
