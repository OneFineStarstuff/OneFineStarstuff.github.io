# Cryptographic Anchors, OSCAL Mappings & Regulatory Crosswalks — Register as of 27 June 2026

**Companion to:** GIES v1.0 · SGI v6.0 · Sentinel Monograph 1.0
**Also contains:** publication-ready layout, standards-body submission package, presentation-layer packaging options, and archival/submission next steps (§4–§6).

---

## 1. Cryptographic anchors

| Anchor | Algorithm / standard | Where used | Verified by | Honest limits (disclosed) |
|---|---|---|---|---|
| CA-01 | **ML-DSA-65** (FIPS 204) | WORM per-entry signatures; detached bundle manifest signature `MANIFEST.sig.json` | Suite steps 9, 17 | `dilithium-py` reference impl: FIPS-204-aligned but not constant-time; production signing belongs in env-02 enclave (Tier B) |
| CA-02 | **SHA-256** (FIPS 180-4) | WORM hash chain; bundle per-artifact + content digests; freshness-ledger digest; SGI/OSCAL regeneration digests | Steps 9, 16–18 | Ledger digest detects casual edits, is **not** a signature — pair with CA-01 |
| CA-03 | **Groth16** over BN254 (Circom 2.1.9 / snarkjs) | SRC-1 systemic-risk concentration proof; Solidity verifier + calldata relayer | Steps 6–7 | Trusted-setup ceremony is demo-grade; zk-STARK migration declared for Phase V/Pass B |
| CA-04 | **vTPM PCR_MATCH** attestation predicate | OPA admission gate; AdmissionWithAttestation model | Steps 1, 3 | Live TEE quote verification is IaC/policy-layer (Tier B); hardware loop not exercised in sandbox |
| CA-05 | **Keccak-256 / EVM** state commitments | OmegaActualTreatyEngine one-way switch | Step 10 | Contract-logic level; not deployed to a public chain in-repo |
| CA-06 | ISO-8601 durations as **freshness SLAs** | `freshness-sla` props (PT5M / P1D / P7D / P3M / P90D) | Steps 12, 18 | Conversion convention stated: 1M=30d, 1Y=365d; compound `P1D/P90D` enforces first period |

**Post-quantum posture:** signing (CA-01) is PQC today; proof system (CA-03) is classical — the register notes this asymmetry explicitly and schedules STARK migration; FIPS 203 (ML-KEM) and 205 (SLH-DSA) are referenced in the catalogs for the enclave-custody path.

## 2. OSCAL control mappings (OSCAL 1.1.2, both catalogs conformance-checked: 43/43)

| Control | Title | GIES clause | Invariant / check | Suite step | Freshness SLA |
|---|---|---|---|---|---|
| `con-04` | Containment ratchet & kill-switch | GIMM-1/-3 | `ASARatchet`, `TrippedStaysTripped` | 2, 4 | P1D/P90D |
| `con-07` | Terminal de-escalation quorum | GIMM-1 | `TerminalNeedsQuorum` | 2 | P7D |
| `cry-02` | PQC WORM audit logging | GIAF-1 | `ChainIntegrity`, tamper detection | 9 | P1D |
| `cry-05` | zk systemic-risk concentration bound | GIAF-2 | Groth16 soundness (violation rejected) | 6–7 | P3M |
| `env-01` | Hardware-attested admission | GIMM-2, GEE-1 | `OnlyAttestedRun`, `PCRMatchWhileRun`, PCR_MATCH gate | 1, 3 | PT5M |
| `env-02` | Enclave-bound key custody | GIAF-1 (custody) | organisational — disclosed NOT-RUNNABLE | 18 (disclosure) | — |
| `rte-01` | SARA/ACR MoE routing stability | GEE-3 | entropy/load/drop invariants | 8 | P1D |

*(GIMM-5 `MultiJurisdictionOverrideConsistency` is presently anchored in the SGI + suite step 19; adding an `ovr-01` control to the OSCAL catalog is declared Phase V/Pass B work — disclosed, not claimed.)*

## 3. Regulatory crosswalks (as of 27 June 2026)

| Regime | Obligation (anchor) | GIES / control | Evidence object |
|---|---|---|---|
| **EU AI Act** | Art. 12 record-keeping | GIAF-1/-6 · `cry-02` | EO-04, EO-08 |
| | Art. 14 human oversight | GIMM-1/-3 · `con-04/07` | EO-01 |
| | Art. 15 accuracy/robustness/cybersecurity | GIMM-2, GEE-1/-3 · `env-01`, `rte-01` | EO-01/02 |
| | Annex IV technical documentation | GIAF-4 | EO-06 (generated dossier, 8 sections) |
| | Arts. 65–68 market surveillance | GIMM-5, SDT Ch. 7 | EO-09, EO-10 |
| **DORA** | ICT risk framework (Ch. II) | GIAF-4 register · `rte-01` | EO-06 (5 pillars, gaps disclosed) |
| | Incident response/recovery | GIMM-1/-3 | EO-01, EO-04 |
| | Third-party/interconnection (Ch. V) | GIMM-4 (Tier B) | EO-06 gap rows + SIP model |
| **NIS2** | Art. 21 cyber-risk measures | GIMM-2 · CA-04 | EO-01, attestation records |
| **Basel III/IV** | Large exposures / concentration | GIAF-2 · `cry-05` | EO-03 (zk proof, no position disclosure) |
| | SR 11-7 model risk | GEE-3 · `rte-01` | EO-02 harness output |
| **GDPR** | Art. 22 automated-decision contestability | GIAF-1 replay | EO-04 WORM segment |
| | Data minimisation | GIAF-2 (zk: prove w/o disclose) | EO-03 |
| **NIST AI RMF 1.0** | GOVERN/MAP/MEASURE/MANAGE | GIAF-4 crosswalk | EO-06 (4 functions) |
| **ISO/IEC 42001** | §8 operational control; §9 evaluation | GIMM-3, META-2 | EO-01, suite transcript |

Register discipline **[N]:** a crosswalk row may only cite obligations that reduce along the canonical chain (GIES-6.1); rows without a runnable anchor are marked Tier C/D. All 30 rows above are Tier A except where noted (GIMM-4: B; env-02: D-disclosed).

---

## 4. Publication-ready layout

```
Front matter   : Title · Abstract · Preface · Tier taxonomy notice · How to re-verify (1 page)
Part I  (Ch 1) : Constitutional case
Part II (Ch 2–4): The GIES core — GIMM / GEE / GIAF
Part III(Ch 5–8): Scaling — Telemetry & MoE / GIEN federation / SDT / PMGF
Part IV (Ch 9–10): Supervision in practice / Standardisation & 2035 roadmap
Normative annexes  : A — TLA+ modules (verbatim) · B — OSCAL catalogs · C — Rego policies
Informative annexes: D — Glossary · E — Evidence-Object Catalog · F — Telemetry-Signal
                     Catalog · G — WORM schema · H — SGI v6.0 (full index) · I — MJO
                     forensic analysis (from PHASE_V_VI_SUPERVISORY_DESIGN.md)
Colophon       : commit hash, suite transcript digest, bundle MANIFEST.sig.json fingerprint
```
Production notes: A4 + US Letter duals; monospaced verbatim annexes; every [N] clause margin-tagged with its suite step; the colophon makes the book itself an evidence object (EO-07 fingerprint printed).

## 5. Standards-body submission package

**Target 1 — ISO/IEC JTC 1/SC 42 (AI):** contribution type *Technical Report seed* → propose GIES §§1–6 as a PWI on "Runnable conformance architectures for AI management systems", positioning against 42001 (management) and 42006 (audit): GIES supplies the *machine-verifiable* conformance layer both assume. Package: GIES spec + monograph Ch. 2–4 + suite transcript + SGI v6.0.
**Target 2 — NIST AI RMF:** contribution type *Profile submission* → the generated RMF crosswalk (EO-06) as a candidate "Financial-Sector High-Risk Profile" with runnable MEASURE/MANAGE anchors. Package: crosswalk JSON + generator source + freshness-gate description.

**Standards-Body Cover Letter (draft):**
> To the Convenor, ISO/IEC JTC 1/SC 42/WG 1 — We submit for consideration the Governance Integrity Ecosystem Specification (GIES v1.0), a constitutional-style conformance architecture in which every normative clause is bound to a machine-checkable invariant and a falsifiable, single-command verification suite (19 checks: TLC model checking, OPA policy tests, Groth16 proofs, FIPS 204 signatures, generated regulator deliverables, evidence-freshness enforcement, and a validated artifact index). We believe this addresses the recognised gap between AI management-system standards and their auditable enforcement, and we propose it as seed material for a preliminary work item. All artifacts are public, MIT-licensed, and reproducible from a clean checkout; feasibility boundaries are explicitly tiered. We welcome the opportunity to present at the next plenary. — *The Sentinel Governance authors, 27 June 2026*

**Presentation-layer packaging options:**
1. **Publication-Ready Layout** (§4) — full monograph, archival quality (Zenodo DOI, as with the existing 10.5281/zenodo.14504697 line).
2. **Standards-Body Cover Letter Edition** — GIES spec + Annexes A–C + cover letter + suite transcript (~60 pp).
3. **G-SIFI Executive Summary Edition** — 12 pp: Abstract, canonical-reduction chain diagram, Part IV mapping table, Phase V/VI supervisory filing strategy, one-page "run this command" re-verification insert; board-ready, no formal notation beyond the diagram.

## 6. Recommended next steps (archival / submission)

1. **Freeze & tag** — tag the conformant commit (`sentinel-monograph-1.0`), attach the signed bundle (EO-07) as the release artifact. *(Owner: maintainers; immediate.)*
2. **Archive** — deposit Edition 1 on Zenodo under the existing project DOI lineage; record the DOI in the colophon. *(Immediate.)*
3. **Submit** — send Edition 2 to SC 42 national body for PWI sponsorship; file the RMF profile via NIST's AI RMF profile intake. *(Within Q3 2026.)*
4. **Close declared gaps** (Phase V/Pass B, see `PHASE_V_VI_SUPERVISORY_DESIGN.md`): TLC-gate SIP v3.0; add `ovr-01` OSCAL control for GIMM-5; STARK migration spike. *(2026 H2.)*
5. **Pilot** — enter the 2028 G-SIFI pilot with the SDT ingestion gates as the supervisory interface (SGI-20). *(Per roadmap Phase V.)*
