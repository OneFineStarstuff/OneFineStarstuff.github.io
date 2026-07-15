# Edition 1 — Sentinel AI Governance Suite Semantic Governance Meta-Architecture

## Unified Architectural and Normative Specification, with the SAF Safety Validation Campaign and the Edition 1 Evidence-Driven Closure Model

**Document ID:** `ED1-SPEC-2026-001`
**Edition:** 1 (stable archival governance baseline)
**Status:** Normative — publication-grade; sealed under the one-way monotonic governance model (Part IX)
**Stack:** Sentinel AI Governance Stack v2.4 / Omni-Sentinel Mesh v4.0
**Constitutional anchor:** GIES v1.0 (`governance_blueprint/GIES_FORMAL_SPECIFICATION.md`); Sentinel Governance Index v6.0 (24 artifacts, suite step 19)
**Verification anchor:** `governance_artifacts/run_runnable_assurance.sh` — 19/19 PASS at head
**As of:** 13 July 2026
**Succession:** open to formally versioned successor editions per the Edition Succession Protocol (Annex E); Edition 1 content is immutable once sealed

---

## 0. Front Matter — Conventions, Audience, and Reading Model

### 0.1 Normative conventions

This specification is written in the **constitutional style** established by GIES v1.0. Every clause is exactly one of:

- **[N]** *Normative* — a MUST/SHALL requirement, stated where possible as an invariant over governance state, and carrying a **canonical reduction** (prose → formal invariant → verifying artifact or disclosed gap → OSCAL control → regulatory obligation);
- **[I]** *Informative* — rationale, threat context, design narrative, or deployment guidance carrying no conformance weight;
- **[D]** *Definitional* — introduces a term, object class, identifier family, or semantic domain into the Edition 1 controlled vocabulary. Definitions are binding for interpretation but impose no behavior by themselves.

Keywords MUST / SHALL / SHOULD / MAY are per RFC 2119 / RFC 8174. Feasibility tiers follow the honest-disclosure rule **[N] GIES-0.1**: **A** (runnable + verified in this repository), **B** (runnable design-level model), **C** (declarative, schema-validated), **D** (organisational/prose). A deployment MUST NOT represent Tier B/C/D clauses as machine-verified.

### 0.2 Clause identifier scheme

Every clause in this specification carries a stable identifier of the form:

```
ED1-<PART>-<NN>        e.g., ED1-AUTH-03, ED1-SEM-12, ED1-CLOSE-07
```

where `<PART>` ∈ {`CONST`, `AUTH`, `ID`, `CRYPTO`, `EXEC`, `EVT`, `RISK`, `KERN`, `CLOSE`, `SAF`} and `NN` is a two-digit ordinal, unique within its part, never reused. Clause identifiers are part of the Edition 1 archival record: a successor edition MAY supersede a clause but MUST NOT redefine an Edition 1 identifier to mean something different (Annex E, rule ESP-4).

### 0.3 Audience and role-differentiated reading model [I]

| Role | Primary parts | Reading intent |
|---|---|---|
| Board / accountable executives (SMCR SMF, SR 11-7 senior management) | Parts I, II, IX | Authority, accountability, closure guarantees |
| Chief Architect / governance engineering | Parts II–VI, VIII | Object model, identifier families, execution meta-model |
| Cryptography & assurance engineering | Part IV, Part X | Trust model, evidence chain, SAF campaign mechanics |
| Model risk / 2nd line validation | Parts VII, X | Risk semantics, validation campaign, effective challenge |
| Internal audit / 3rd line | Parts IX, X, Annexes | Closure model, preservation theorem, evidence sufficiency |
| Supervisors & external assessors | Parts I, IX, X, Annex A | Conformance surface, regulatory crosswalk, sealed baseline |

### 0.4 Relationship to prior constitutional artifacts [I]

Edition 1 does not replace GIES v1.0; it **completes** it. GIES defines the four-module verification pipeline (GIMM → GIAF → GEE → META) for the *runnable* constitutional layer. Edition 1 supplies what GIES intentionally left open: the **semantic governance meta-architecture** — the formal object model, identifier algebra, semantic domains, and edition-closure calculus by which any governance content (runnable or not) is created, evidenced, validated, sealed, and succeeded. Where GIES governs the machine, Edition 1 governs the *meaning*.

---

# PART I — CONSTITUTIONAL FOUNDATIONS

## 1. Governance Principles

**[N] ED1-CONST-01 (Primacy of definable safety).** No governance obligation SHALL be enforced, attested, or claimed unless it is first *defined* — as a formal invariant (Tier A/B), a validated schema (Tier C), or an explicitly disclosed organisational commitment (Tier D). Enforcement without definition is a constitutional violation, not merely a defect.
*Reduction:* → GIES-1.1 module-ordering invariant → `validate_governance_index.py` IDX-6/7/8 → suite step 19 → OSCAL `con-04` → EU AI Act Art. 9 (risk management as defined process).

**[N] ED1-CONST-02 (Evidence before assertion).** Every conformance claim SHALL be backed by at least one evidence object (Part IV) whose producing check is named, whose digest is recomputable, and whose freshness is within the catalog-declared SLA. Claims without evidence SHALL be marked `[UNSUBSTANTIATED]` and excluded from any conformance total.
*Reduction:* → Meta-Invariant MI-1 (§25) → `check_evidence_freshness.py --run --audit` → suite step 18 → OSCAL assessment-results → DORA Art. 28 (ICT third-party evidence), SR 11-7 (documentation standards).

**[N] ED1-CONST-03 (Honest disclosure).** The feasibility tier of every clause and artifact SHALL be published. Coverage below threshold SHALL be marked (e.g., `[COVERAGE GAP]`), never silently averaged away.
*Reduction:* → GIES-0.1 → SGI tier column (21A/1B/1C/1D) → suite step 19 assertion `artifacts == 24` → NIST AI RMF GOVERN-4.1 (transparency of limitations).

**[N] ED1-CONST-04 (Least authority).** Every actor, agent, and automated component SHALL hold the minimum authority class (Part II) sufficient for its role, and no component SHALL hold both *claim* authority and *evidence-production* authority over the same object (authority separation, §27).
*Reduction:* → AUTH separation matrix (§27) → OPA admission policies (SGI-06/07) → suite steps 1, 6 → OSCAL `con-07` → Basel BCBS 239 Principle 1, SMCR reasonable-steps duty.

**[N] ED1-CONST-05 (Reversibility asymmetry).** Governance state transitions SHALL be asymmetric: escalation (toward restriction, toward evidence, toward sealing) MAY be unilateral within authority; de-escalation (release, unsealing, claim-withdrawal) SHALL require quorum and SHALL be audited.
*Reduction:* → `MultiJurisdictionOverride.tla` invariants `NoUnilateralWeakening`, `HaltReleaseAudited` → suite step 19 → EU AI Act Art. 14, DORA response & recovery.

**[I] ED1-CONST-06 (Design narrative).** These five principles are ordered: definability grounds evidence, evidence grounds disclosure, disclosure bounds authority, and bounded authority makes asymmetric reversibility enforceable rather than aspirational. The Edition 1 closure model (Part IX) is the fixed point of this ordering — the state in which every principle is satisfied simultaneously and the edition can be sealed.

## 2. Constitutional Invariants of the Suite

**[D] ED1-CONST-07.** The **constitutional invariant set** of Edition 1 is the union of: (a) the GIMM formal invariants indexed by SGI-01..05 (containment ratchet, attested admission, SIP v3 federation safety, halt semantics, multi-jurisdiction override consistency); (b) the three Edition 1 normative invariants — **Record Immutability (INV-E1-RI)**, **Monotonic Provenance (INV-E1-MP)**, **Evaluation Locality (INV-E1-EL)** — defined normatively in §24; and (c) the **Meta-Invariant (MI-1)** on claim authority and evidence sufficiency defined in §25.

**[N] ED1-CONST-08 (Invariant supremacy).** In any conflict between an operational convenience and a constitutional invariant, the invariant SHALL prevail. A deployment MAY *extend* the invariant set (successor editions, Annex E) but SHALL NOT *weaken* it: the constitutional invariant set is monotone non-decreasing across editions (one-way monotonic governance model, §29).

**[N] ED1-CONST-09 (Falsifiability).** For every Tier A/B invariant there SHALL exist a named procedure by which META (or an external assessor) can attempt to falsify it by re-execution. Invariants with no falsification procedure SHALL be reclassified Tier C/D and disclosed as such.
*Reduction:* → SGI `verified_by` column resolvable via IDX-7 regex `\[(\d+)/\d+\]` → suite step 19.

---

# PART II — FORMAL GOVERNANCE AUTHORITY MODEL, TRUST BOUNDARIES, AND GOVERNANCE LIFECYCLE

## 3. Authority Model — Formal Statement

**[D] ED1-AUTH-01.** The governance authority model is the tuple:

```
AM = (P, A, O, grant ⊆ P × A × O, dom : A → 2^Op)
```

where `P` is the set of **principals** (human officers, committees, automated agents, external assessors), `A` is the ordered set of **authority classes**, `O` is the set of governance objects (Part V), `grant` records which principal holds which authority over which object class, and `dom` maps each authority class to the operations it dominates.

**[D] ED1-AUTH-02 (Authority classes).** Edition 1 defines exactly six authority classes, strictly ordered by the operations they dominate:

| Class | Name | Dominated operations | Typical principal |
|---|---|---|---|
| `A0` | Observe | read, subscribe, replay | any authenticated principal |
| `A1` | Produce | create evidence objects, emit events | pipelines, sensors, CI jobs |
| `A2` | Evaluate | run analyses, compute results, score risk | validation engines, 2nd line |
| `A3` | Claim | assert conformance, sign claims | accountable owners, 1st line leads |
| `A4` | Ratify | approve claims, seal artifacts, release holds | governance committee, quorum bodies |
| `A5` | Constitute | amend the invariant set, publish editions | edition authority (board-delegated) |

**[N] ED1-AUTH-03 (No self-ratification).** For every object `o`, `grant(p, A3, o) ⇒ ¬grant(p, A4, o)`: the principal who claims SHALL NOT be the principal who ratifies. Equivalently, the composition `Claim ∘ Ratify` requires two distinct principals — the formal core of four-eyes review.
*Reduction:* → authority separation matrix (§27) → WorkflowAI multi-stage approvals → OSCAL `con-07` → SR 11-7 effective challenge, SMCR duty of responsibility.

**[N] ED1-AUTH-04 (No evidence-claim fusion).** `grant(p, A1, o) ⇒ ¬grant(p, A3, o)` for the same object: whoever produces the evidence for an object does not get to claim conformance from it. This is the constitutional root of ED1-CONST-04.

**[N] ED1-AUTH-05 (Constitutive quorum).** Operations dominated by `A5` (invariant amendment, edition publication, edition sealing) SHALL require a recorded quorum of at least three `A5` principals, and the quorum record SHALL itself be an evidence object anchored per Part IV.
*Reduction:* → `HaltReleaseAudited`-style unanimous-release pattern → `MultiJurisdictionOverride.tla` → suite step 19.

**[I] ED1-AUTH-06.** The classes are deliberately *cumulative in trust but not in grant*: an `A4` principal is more trusted than an `A1` principal, but is not automatically granted `A1` — production authority is granted separately precisely so that ED1-AUTH-04 can hold.

## 4. Trust Boundaries

**[D] ED1-AUTH-07.** Edition 1 adopts and refines the five-zone trust topology of the Sentinel v2.4 reference architecture:

```
┌────────────────────────────────────────────────────────────────────┐
│ Zone E — Regulator/Assessor Verifier Edge   (A0 only, read+verify) │
├────────────────────────────────────────────────────────────────────┤
│ Zone D — Assurance Vault (WORM, proofs, sealed editions)  A1 append│
├────────────────────────────────────────────────────────────────────┤
│ Zone B — AI Control Plane (policy engines, orchestration) A2/A3/A4 │
├────────────────────────────────────────────────────────────────────┤
│ Zone C — Containment Compute Fabric (model runtimes)      A1 emit  │
├────────────────────────────────────────────────────────────────────┤
│ Zone A — Regulated CorpNet (applications, interfaces)     A0/A1    │
└────────────────────────────────────────────────────────────────────┘
```

**[N] ED1-AUTH-08 (Boundary-crossing rule).** Every inter-zone interaction SHALL be (a) mutually authenticated (mTLS + hardware-backed workload identity), (b) authority-checked against `grant`, and (c) evidenced as an event object (Part VI). Zone D SHALL accept only append operations; Zone E SHALL hold no write authority of any class.
*Reduction:* → OPA admission gates (SGI-06) → suite step 1 → OSCAL `env-01`/`rte-01` → NIS2 Art. 21, DORA Art. 9.

**[N] ED1-AUTH-09 (Authority does not cross boundaries implicitly).** Authority grants are zone-scoped: `grant(p, a, o)` in Zone B confers nothing in Zone D. Cross-zone authority SHALL be re-derived from the principal's identity attestation at the boundary, never forwarded as a bearer artifact.

## 5. Governance Lifecycle

**[D] ED1-AUTH-10.** Every governance object traverses the **canonical lifecycle**:

```
DRAFT → PROPOSED → EVIDENCED → VALIDATED → RATIFIED → SEALED
                                                        │
                                          (successor edition only)
                                                        ▼
                                                   SUPERSEDED
```

**[N] ED1-AUTH-11 (Lifecycle monotonicity).** Lifecycle state SHALL be monotone non-decreasing along the canonical order. There is no transition from `SEALED` back to any earlier state; correction of a sealed object is achieved only by publishing a superseding object in a successor edition (§29, Annex E). `SUPERSEDED` objects remain readable forever (record immutability, INV-E1-RI).

**[N] ED1-AUTH-12 (Stage-gate authority mapping).** Each transition SHALL require the minimum authority class shown; lower classes SHALL be rejected at the gate:

| Transition | Required authority | Required evidence |
|---|---|---|
| DRAFT → PROPOSED | A2 | identifier assignment (Part III), schema validity |
| PROPOSED → EVIDENCED | A1 (producer) + A2 (evaluator) | ≥1 linked evidence object with recomputable digest |
| EVIDENCED → VALIDATED | A2, distinct from producer | analysis object + invariant-check result |
| VALIDATED → RATIFIED | A4, distinct from claimant | ratification record (quorum where required) |
| RATIFIED → SEALED | A5 quorum | edition-closure certificate (Part IX) |
| SEALED → SUPERSEDED | A5 quorum of successor edition | succession record per Annex E |

*Reduction:* → lifecycle gates → WorkflowAI DAG stage approvals → OSCAL assessment-plan/assessment-results pairing → ISO/IEC 42001 §8 (operational planning and control), EU AI Act Art. 17 (quality management system).

---

# PART III — IDENTIFIER FAMILY AND SEMANTIC DOMAIN DESIGN

## 6. Identifier Algebra

**[D] ED1-ID-01.** An **identifier family** is a 5-tuple `F = (prefix, grammar, domain, lifecycle, uniqueness-scope)`. Edition 1 registers the following families (the **Edition 1 Identifier Registry**, authoritative in Annex B):

| Family | Grammar | Semantic domain | Example |
|---|---|---|---|
| Clause | `ED1-<PART>-<NN>` | normative text | `ED1-AUTH-03` |
| Governance object | `GOVOBJ-<YYYY>-<NNN>` | Part V object model | `GOVOBJ-2026-014` |
| Crypto object | `CRYPTOOBJ-<YYYY>-<NNN>` | Part IV evidence plane | `CRYPTOOBJ-2026-031` |
| Execution object | `EXECOBJ-<YYYY>-<NNN>` | Part V execution meta-model | `EXECOBJ-2026-007` |
| Result object | `RESULTOBJ-<YYYY>-<NNN>` | Part V execution meta-model | `RESULTOBJ-2026-052` |
| Semantic domain | `SEMDOMAIN-<NAME>` | Part VI domain registry | `SEMDOMAIN-RISK` |
| Semantic frame | `SEMFRAME-<NAME>-<NN>` | Part VI frame catalog | `SEMFRAME-OVERRIDE-01` |
| SAF campaign artifact | `<TYPE>-SAF-<NNN>` | Part X validation campaign | `DS-SAF-001`, `VR-SAF-001` |
| Edition invariant | `INV-E1-<TAG>` | Part IX closure model | `INV-E1-RI` |
| GIEN control (inherited) | `GIEN-<DOMAIN>-<YYYY>-<NNN>` | operational dossiers | `GIEN-CONT-2026-001` |
| SGI artifact (inherited) | `SGI-<NN>` | constitutional index | `SGI-24` |

**[N] ED1-ID-02 (Identifier immutability).** Once assigned and the bearing object reaches `EVIDENCED`, an identifier SHALL never be reassigned, recycled, or repurposed — including across editions. Retired identifiers remain permanently resolvable to their archival record.
*Reduction:* → INV-E1-RI (§24) → WORM retention (SGI-13, PQC-signed) → suite step 11 → SEC 17a-4(f), GDPR Art. 5(1)(f) integrity.

**[N] ED1-ID-03 (No dangling references).** Every identifier referenced by any Edition 1 artifact SHALL resolve within the unified corpus. Reference resolution SHALL be machine-checked before ratification (the IDX-3 "paths exist" pattern generalized to identifiers).

**[N] ED1-ID-04 (Family closure).** New identifier families SHALL NOT be introduced within Edition 1 after sealing; successor editions introduce families only via the registry amendment procedure (Annex E, ESP-5), and inherited families keep their Edition 1 grammar.

## 7. Lifecycle Semantics of Identifiers

**[D] ED1-ID-05.** Each family binds to a **lifecycle profile**: `archival` (never deleted, e.g., clause and invariant IDs), `versioned` (new ID per revision, e.g., RESULTOBJ), or `singleton-per-edition` (exactly one live instance per edition, e.g., the edition-closure certificate). The profile is declared in Annex B and is itself immutable per ED1-ID-02.

**[N] ED1-ID-06 (Version linkage).** A `versioned` object SHALL carry `supersedes: <prior-id>` and the prior object SHALL gain `superseded_by: <new-id>` — forming a doubly linked, append-only version chain whose head is computable without trusting any single record (monotonic provenance, INV-E1-MP).

## 8. Boundary Modeling and Conformance

**[D] ED1-ID-07.** A **semantic boundary** is the surface across which an identifier's meaning must survive translation: (i) *zone boundaries* (Part II), (ii) *organisational boundaries* (1st/2nd/3rd line), (iii) *regulatory boundaries* (jurisdictional profiles), (iv) *temporal boundaries* (edition succession). For each boundary, Annex B declares the **carrier** (how the identifier travels: OSCAL property, event field, manifest entry) and the **fidelity obligation** (what must be preserved: grammar, resolution, lifecycle state).

**[N] ED1-ID-08 (Boundary fidelity).** An identifier crossing any declared boundary SHALL preserve its grammar and remain resolvable to the same archival record on both sides. Lossy renderings (truncation, re-prefixing, locale transformation) SHALL be treated as conformance failures.

**[N] ED1-ID-09 (Conformance clause for identifier families).** A deployment conforms to Part III iff: (a) every governance object bears exactly one identifier from a registered family; (b) machine validation demonstrates zero dangling references and zero grammar violations; (c) all version chains are acyclic with a unique head; (d) all identifiers referenced in sealed content resolve. Checks (a)–(d) constitute the **ID-CONF** procedure referenced by the SAF campaign (Part X, VC-SAF-001 step 3).

---

# PART IV — CRYPTOGRAPHIC TRUST AND EVIDENCE MODELS

## 9. Trust Model

**[D] ED1-CRYPTO-01.** The Edition 1 trust model is a **layered anchoring model**: every evidence object is anchored by (at minimum) a content digest; digests are aggregated into Merkle structures; roots are signed under PQC signature schemes; signatures chain to an offline PKI root; and inclusion is countersigned into an append-only transparency log. Formally:

```
content ──SHA-256──▶ digest ──Merkle──▶ root ──ML-DSA-65──▶ signature
                                          │                    │
                                          ▼                    ▼
                                  transparency log      PKI chain (offline root
                                  (append-only,          → issuing CA → workload
                                   witness cosigned)       identity, X.509)
```

**[N] ED1-CRYPTO-02 (Algorithm baseline).** Edition 1 mandates: **ML-DSA-65 (FIPS 204)** for evidence and manifest signatures; **ML-KEM-768 (FIPS 203)** for key establishment on evidence channels; **SLH-DSA (FIPS 205)** as the stateless hash-based fallback for the offline root; SHA-256 for content digests. Classical ECDSA-P256 MAY co-sign during migration (hybrid mode) but SHALL NOT be the sole signature on any object that must remain verifiable beyond 2030.
*Reduction:* → PQC WORM signer (SGI-13) → suite step 11 → OSCAL `cry-02`/`cry-05` → NIST SP 800-208 lineage, DORA Art. 9(4)(d) cryptographic controls.
*Disclosure [I]:* the in-repo `dilithium-py` implementation is functionally correct but not side-channel hardened; production deployments SHALL use a hardened, validated module (Tier D commitment, disclosed per ED1-CONST-03).

**[N] ED1-CRYPTO-03 (Transparency-log obligation).** Every RATIFIED-or-later object SHALL have its digest included in an append-only transparency log with verifiable inclusion and consistency proofs (RFC 6962-style Merkle log or equivalent). Log consistency SHALL be independently witnessed by at least one principal outside the producing zone.
*Reduction:* → append-only WORM + Merkle manifest (SGI-13/14) → suite steps 11, 16–17 → SEC 17a-4(f), EU AI Act Art. 12 (record-keeping).

**[N] ED1-CRYPTO-04 (Verifier independence).** Verification of any anchor SHALL be possible from Zone E using only: the object, its proof material, and published public keys — with no calls back into Zones A–C. This is the cryptographic realization of *evaluation locality* (INV-E1-EL).
*Reduction:* → `verify_distribution_bundle.py` (recipient-side, 10/10 checks incl. ML-DSA-65 manifest signature) → suite step 17.

## 10. Evidence Object Model

**[D] ED1-CRYPTO-05.** An **evidence object** (`CRYPTOOBJ` family) is the canonical schema:

```json
{
  "id": "CRYPTOOBJ-2026-031",
  "class": "CRYPTOOBJ",
  "produced_by": "check_evidence_freshness.py --run",
  "producer_authority": "A1",
  "subject": "GOVOBJ-2026-014",
  "digest": "sha256:...64 hex...",
  "signature": {"alg": "ML-DSA-65", "key_id": "sentinel-ed1-signer-01", "value": "..."},
  "log_inclusion": {"log_id": "ed1-tlog", "leaf_index": 4182, "proof": ["..."]},
  "freshness": {"produced_at": "2026-07-13T04:00:00Z", "sla": "PT24H"},
  "tier": "A",
  "lifecycle": "EVIDENCED"
}
```

**[N] ED1-CRYPTO-06 (Evidence sufficiency predicate).** Evidence object `e` is **sufficient** for claim `c` iff: (a) `e.subject` resolves to `c`'s object; (b) `e.digest` recomputes; (c) `e.signature` verifies against a key chained to the PKI root; (d) `e.log_inclusion` verifies; (e) `now − e.produced_at ≤ e.sla`; (f) `e.producer_authority = A1` held by a principal distinct from the claimant (ED1-AUTH-04). Predicate `Sufficient(e, c)` is the operand of the Meta-Invariant MI-1 (§25).

**[N] ED1-CRYPTO-07 (OSCAL alignment).** Every evidence object SHALL be renderable as an OSCAL `assessment-results` observation with `relevant-evidence` links carrying the object identifier, digest, and log coordinates as OSCAL `props`. Catalog controls SHALL reference evidence *schemas*, never instances, preserving the plan/result separation.
*Reduction:* → OSCAL generators + conformance check → suite steps 12–13 → NIST OSCAL v1.1.2 → EU AI Act Annex IV technical documentation, DORA register of information.

**[N] ED1-CRYPTO-08 (Assurance-framework alignment).** The evidence plane SHALL support extraction of: SOC 2 / ISAE 3000-style evidence trails, EU AI Act Annex IV bundles, DORA incident/resilience evidence, and NIST AI RMF measurement artifacts — all from the *same* CRYPTOOBJ population, by projection, never by parallel bookkeeping. One evidence plane, many regulatory renderings.

---

# PART V — EXECUTION META-MODEL AND GOVERNANCE AUTOMATION

## 11. Object Class Taxonomy

**[D] ED1-EXEC-01.** Edition 1 governance automation operates over exactly five first-class object classes plus two semantic constructs:

| Class | Family | Role | Mutability after SEALED |
|---|---|---|---|
| **GOVOBJ** | `GOVOBJ-YYYY-NNN` | Governed subject: policy, model, control, clause-set, dataset | immutable; superseded only |
| **CRYPTOOBJ** | `CRYPTOOBJ-YYYY-NNN` | Evidence: digests, signatures, proofs, log entries | immutable always (from EVIDENCED) |
| **EXECOBJ** | `EXECOBJ-YYYY-NNN` | Execution intent: a validation run, check invocation, campaign step — *what will be executed, under whose authority, against which GOVOBJ* | immutable once dispatched |
| **RESULTOBJ** | `RESULTOBJ-YYYY-NNN` | Execution outcome bound 1:1 to an EXECOBJ: verdict, metrics, emitted CRYPTOOBJs | immutable always |
| **SEMDOMAIN** | `SEMDOMAIN-NAME` | Named semantic domain: a bounded vocabulary + invariants governing one meaning-space (Part VI) | registry-frozen per edition |
| **SEMFRAME** | `SEMFRAME-NAME-NN` | Semantic frame: a typed slot structure interpreting events/results inside a SEMDOMAIN | versioned |

**[N] ED1-EXEC-02 (Class discipline).** Every persisted governance record SHALL belong to exactly one class. Hybrid records (e.g., a result that also asserts a claim) are prohibited: claims are lifecycle transitions on GOVOBJ, performed under A3, never fields of a RESULTOBJ.

## 12. Execution Meta-Model

**[D] ED1-EXEC-03.** The execution meta-model is the labelled transition system:

```
EXECOBJ (created, A2)
   │ dispatch (authority check, boundary check)
   ▼
RUNNING ──emit──▶ CRYPTOOBJ* (streamed evidence, A1)
   │ complete
   ▼
RESULTOBJ (verdict ∈ {PASS, FAIL, ERROR, INCONCLUSIVE}, sealed at creation)
   │ interpret (via SEMFRAME within declared SEMDOMAIN)
   ▼
GOVOBJ lifecycle transition candidate (gated per ED1-AUTH-12)
```

**[N] ED1-EXEC-04 (Determinism-or-disclosure).** Every EXECOBJ SHALL declare whether its execution is deterministic (re-run yields byte-identical RESULTOBJ payload) or stochastic (declared variance bounds). Stochastic executions SHALL record seeds and environment digests sufficient for statistical reproduction. Undeclared nondeterminism discovered post hoc voids the RESULTOBJ.
*Reduction:* → reproducible evidence manifests → suite steps 16–17 → SR 11-7 reproducibility expectations.

**[N] ED1-EXEC-05 (1:1 result binding).** Every RESULTOBJ SHALL reference exactly one EXECOBJ; every completed EXECOBJ SHALL be referenced by exactly one RESULTOBJ. Re-execution creates a *new* EXECOBJ/RESULTOBJ pair chained via `supersedes` (ED1-ID-06). There is no result mutation, only result succession — the micro-scale image of the edition model.

**[N] ED1-EXEC-06 (Automation authority ceiling).** Fully automated pipelines SHALL hold at most A2. Transitions requiring A3+ SHALL involve a human principal whose approval is itself a CRYPTOOBJ. Automation accelerates evaluation; it never ratifies.
*Reduction:* → EU AI Act Art. 14 human oversight, GDPR Art. 22 → OSCAL `con-07`.

## 13. Governance Automation Surface [I]

The automation surface binds the meta-model to the running stack: CI gates create EXECOBJs for every assurance-suite invocation; the 19-step suite is, in Edition 1 terms, a standing EXECOBJ template whose RESULTOBJs feed the freshness ledger (suite step 18); OPA gates consume GOVOBJ lifecycle state to admit or refuse workloads; and the SGI validator is META's standing falsification EXECOBJ over the index itself (suite step 19). Nothing in this part invents new machinery — it names, types, and constitutionally binds machinery that already runs.

---

# PART VI — EVENT PROCESSING AND SEMDOMAIN ARCHITECTURE

## 14. Event Model

**[D] ED1-EVT-01.** A **governance event** is an immutable, timestamped, signed record of a boundary crossing, lifecycle transition, execution state change, or invariant evaluation — conforming to `evidence_event_schema.json` extended with: `event_id`, `semdomain`, `semframe`, `subject` (object identifier), `authority_context` (principal + class), `zone_from/zone_to`.

**[N] ED1-EVT-02 (Event completeness).** Every operation listed in `dom(A1..A5)` SHALL emit exactly one governance event. Silent operations are constitutional violations. Events SHALL be appended to the Zone D backbone within the declared latency budget (PT60S for A4/A5 operations; PT5M otherwise).
*Reduction:* → Kafka event backbone + WORM → OSCAL `env-02` (disclosed organisational component) → EU AI Act Art. 12 logging, DORA Art. 17 incident detection.

**[N] ED1-EVT-03 (Well-formedness).** Event streams SHALL satisfy the `LogWellFormed` pattern: monotone sequence numbers per producer, no gaps without a signed gap-attestation, and per-epoch Merkle checkpointing.
*Reduction:* → `MultiJurisdictionOverride.tla` `LogWellFormed` companion invariant → suite step 19.

## 15. SEMDOMAIN Architecture

**[D] ED1-EVT-04.** A **SEMDOMAIN** is a bounded meaning-space: `SEMDOMAIN = (name, vocabulary, frames, invariants, boundary-map)`. Edition 1 registers seven:

| SEMDOMAIN | Meaning-space | Key frames | Domain invariant (informal) |
|---|---|---|---|
| `SEMDOMAIN-AUTH` | authority, delegation, quorum | `SEMFRAME-GRANT-01`, `SEMFRAME-QUORUM-01` | no event interprets authority above the emitting principal's class |
| `SEMDOMAIN-LIFECYCLE` | object lifecycle states | `SEMFRAME-TRANSITION-01` | interpreted transitions respect ED1-AUTH-11 monotonicity |
| `SEMDOMAIN-EVIDENCE` | digests, proofs, freshness | `SEMFRAME-ANCHOR-01`, `SEMFRAME-FRESH-01` | sufficiency predicate evaluable from frame slots alone |
| `SEMDOMAIN-EXEC` | execution states, verdicts | `SEMFRAME-VERDICT-01` | one verdict per EXECOBJ (ED1-EXEC-05) |
| `SEMDOMAIN-RISK` | risk scores, tiers, appetites | `SEMFRAME-SCORE-01`, `SEMFRAME-APPETITE-01` | Part VII semantics |
| `SEMDOMAIN-OVERRIDE` | jurisdiction postures | `SEMFRAME-OVERRIDE-01` | *lex severior* — posture = max of active overrides |
| `SEMDOMAIN-EDITION` | edition lifecycle, succession | `SEMFRAME-SEAL-01`, `SEMFRAME-SUCCEED-01` | Part IX closure semantics |

**[N] ED1-EVT-05 (Frame-typed interpretation).** No consumer SHALL interpret a raw event; interpretation SHALL occur through a registered SEMFRAME whose slots are typed against the SEMDOMAIN vocabulary. Frame-validation failures route events to a quarantine topic with A2 review — never silent drop, never best-effort parse.

**[N] ED1-EVT-06 (Cross-domain translation).** Where an event is meaningful in two SEMDOMAINs (e.g., an override raise is both `SEMDOMAIN-OVERRIDE` and `SEMDOMAIN-LIFECYCLE`), translation SHALL go through a declared boundary-map entry; ad hoc reinterpretation across domains is prohibited. Boundary-maps are part of the edition registry and freeze at sealing.

**[I] ED1-EVT-07 (Why frames).** Long-lived governance corpora die by semantic drift: the same field silently means different things in 2026 and 2033. Frames make interpretation an explicit, versioned, falsifiable artifact — drift becomes a detectable frame-version mismatch instead of an archaeological dispute.

---

# PART VII — RISK AND ASSESSMENT DOMAIN SEMANTICS

## 16. Risk Semantics

**[D] ED1-RISK-01.** Within `SEMDOMAIN-RISK`, a **risk statement** is the typed frame instance: `(subject: GOVOBJ, hazard, dimension, score, method: EXECOBJ, confidence, valid_until)`. Scores are meaningless outside their method reference: Edition 1 prohibits free-floating risk numbers.

**[N] ED1-RISK-02 (Method-bound scores).** Every risk score SHALL reference the EXECOBJ that produced it. Scores whose producing method is superseded SHALL be flagged `[STALE-METHOD]` and excluded from appetite comparisons until re-evaluated.

**[N] ED1-RISK-03 (Appetite as invariant).** Risk appetite SHALL be expressed as a machine-evaluable predicate over risk-statement frames (e.g., `∀ s : s.dimension = "systemic" ⇒ s.score ≤ appetite.systemic_max`), ratified at A4, and evaluated as a standing EXECOBJ on every relevant RESULTOBJ. Breaches emit `SEMDOMAIN-OVERRIDE` escalation candidates — connecting risk semantics directly to the *lex severior* posture machinery.
*Reduction:* → G-SRI board KRIs → SystemicRiskAggregator (SGI circuit lineage) → OSCAL risk props → Basel/SR 11-7 aggregation, EU AI Act Art. 9.

**[N] ED1-RISK-04 (Assessment separation).** Assessment *plans* (what will be evaluated, by whom, against which criteria) and assessment *results* SHALL be distinct objects, mirroring OSCAL's assessment-plan / assessment-results split, with plans ratified before results are produced. Retro-fitted criteria are a constitutional violation of ED1-CONST-01.

**[I] ED1-RISK-05.** The domain deliberately reuses the execution meta-model rather than defining a parallel "risk engine": a risk assessment *is* an EXECOBJ; a risk score *is* a RESULTOBJ interpreted through `SEMFRAME-SCORE-01`. Uniformity is the control.

---

# PART VIII — GOVERNANCE AND VALIDATION METHODOLOGY FOR LONG-LIVED SEMANTIC KERNELS

## 17. The Semantic Kernel

**[D] ED1-KERN-01.** The **semantic kernel** of Edition 1 is the minimal set of artifacts whose meaning must remain stable for the edition's archival lifetime (target: ≥ 25 years): the clause corpus (Part 0–X identifiers), the identifier registry (Annex B), the SEMDOMAIN registry with boundary-maps, the constitutional invariant set (ED1-CONST-07), and the authority model (Part II). Everything else may evolve via versioned objects; the kernel evolves only via editions.

**[N] ED1-KERN-02 (Kernel minimality).** The kernel SHALL contain no operational parameters (thresholds, SLAs, hostnames, key identifiers). Such values live in versioned GOVOBJ configuration bound to kernel clauses by reference — so the kernel never needs amendment for operational change.

**[N] ED1-KERN-03 (Continuous falsification).** The kernel SHALL be subject to standing machine validation on every assurance-suite run: identifier resolution (ID-CONF), frame-registry consistency, invariant-definition existence (IDX-8 pattern), and authority-matrix well-formedness. A kernel validation failure blocks all A4+ operations until resolved.

**[N] ED1-KERN-04 (Format longevity).** Kernel artifacts SHALL be stored in plain-text, self-describing formats (Markdown, YAML, JSON) with no proprietary dependencies; rendering toolchains are replaceable, the source is the record.
*Reduction:* → repository plain-text discipline → WORM retention → SEC 17a-4(f), archival best practice (OAIS reference model, informative).

## 18. Validation Methodology for Long-Lived Kernels [I → N]

**[N] ED1-KERN-05 (Three-horizon validation).** Kernel validation SHALL run on three horizons: (a) **per-change** — every commit re-runs mechanical checks; (b) **per-campaign** — a structured validation campaign (Part X pattern: dataset → evidence → analysis → invariant check → validation certificate → validation report) at least annually and before any edition seal; (c) **per-succession** — full preservation-theorem re-proof (§28) when a successor edition is proposed.

**[N] ED1-KERN-06 (Adversarial review).** Each campaign SHALL include at least one adversarial track: an A2 principal with no authorship stake attempts to construct counterexamples to kernel invariants (mutation testing for formal models; frame-confusion injection for SEMDOMAINs; authority-escalation probes for the AM). Absence-of-findings SHALL be reported with the search budget expended, never as bare "no issues".
*Reduction:* → MJO mutation-testing precedent → SR 11-7 effective challenge → NIST AI 600-1 red-teaming guidance.

---

# PART IX — EDITION 1 EVIDENCE-DRIVEN GOVERNANCE METHODOLOGY AND CLOSURE MODEL

## 19. Methodology Overview [I]

Edition 1 closes by *proof of sufficiency*, not by fiat. The closure model turns "we are done" from a management assertion into a checkable predicate: every normative clause is either machine-verified (Tier A), design-verified (Tier B), schema-verified (Tier C), or disclosed (Tier D); every claim has sufficient evidence (MI-1); the three edition invariants hold over the whole corpus; and the preservation theorem shows successors cannot silently erode any of this. Only then is the edition sealed — and once sealed, it is sealed forever.

## 20–23. (Reserved cross-reference block) [I]

Sections 20–23 are intentionally reserved so that §24 (invariants), §25 (Meta-Invariant), §26 (object classes and change rules), §27 (authority separation), §28 (dependency structure and preservation theorem), §29 (one-way monotonic model), and §30 (five-layer architecture) carry stable section numbers cited by the SAF campaign artifacts in Part X.

## 24. The Three Edition 1 Normative Invariants

**[N] ED1-CLOSE-01 — `INV-E1-RI` (Record Immutability).**
For every record `r` in the Edition 1 corpus and all times `t₂ > t₁`:

```
Persisted(r, t₁) ∧ lifecycle(r, t₁) ≥ EVIDENCED  ⇒  content(r, t₂) = content(r, t₁)
```

No record that has reached `EVIDENCED` is ever modified in place. Corrections are new records linked by `supersedes`. Digest recomputation over the WORM store is the standing falsification procedure.
*Tier:* A (digest recomputation runnable) / D (organisational WORM custody).
*Reduction:* → PQC WORM (SGI-13) → suite steps 11, 16–17 → SEC 17a-4(f), EU AI Act Art. 12.

**[N] ED1-CLOSE-02 — `INV-E1-MP` (Monotonic Provenance).**
The provenance relation `⊑` ("derived-from") over all objects is a strict partial order that only grows:

```
∀ t₂ > t₁ :  ⊑(t₁) ⊆ ⊑(t₂)   ∧   ⊑ is acyclic at every t
```

Provenance edges are never deleted or rewritten; lineage never shortens; no object is ever its own ancestor. Combined with INV-E1-RI this yields the append-only DAG that makes every claim's ancestry auditable arbitrarily far back.
*Tier:* A (chain verification runnable over version links) / B (full-DAG acyclicity at scale — design model).

**[N] ED1-CLOSE-03 — `INV-E1-EL` (Evaluation Locality).**
Every conformance evaluation SHALL be computable from a *local* evidence neighborhood:

```
Verdict(c) = F(c, E(c))  where  E(c) = { e : Sufficient(e, c) }  and F consults nothing else
```

No verdict may depend on ambient state, out-of-band context, or trust in the producing zone. This is what makes Zone-E (regulator-edge) verification possible (ED1-CRYPTO-04): an assessor holding only the object and its evidence neighborhood reaches the same verdict as the producer.
*Tier:* A for bundle verification (suite step 17); B for the general locality property.

## 25. The Meta-Invariant — Claim Authority and Evidence Sufficiency

**[N] ED1-CLOSE-04 — `MI-1` (Meta-Invariant).**

```
∀ claim c :
    Asserted(c)  ⇒   holds(claimant(c), A3, subject(c))            (authority)
                   ∧ ∃ e : Sufficient(e, c)                         (sufficiency, per ED1-CRYPTO-06)
                   ∧ claimant(c) ≠ producer(e)                      (separation, ED1-AUTH-04)
                   ∧ ratifier(c) ≠ claimant(c) whenever Ratified(c) (no self-ratification, ED1-AUTH-03)
```

MI-1 is called *meta* because it quantifies over claims about all other invariants, including itself: the claim "Edition 1 satisfies MI-1" must itself carry A3 authority, sufficient evidence (the VR-SAF-001 validation report, Part X), and separated ratification. This self-application is deliberate — it is what prevents the closure certificate from being a self-signed exception to the regime it certifies.

**[N] ED1-CLOSE-05 (MI-1 enforcement point).** MI-1 SHALL be evaluated as a gate on every `PROPOSED → EVIDENCED` and `VALIDATED → RATIFIED` transition, and globally re-evaluated during every validation campaign (Part X) and before sealing.

## 26. Governance Object Classes and Change Rules

**[N] ED1-CLOSE-06.** The change rules for the five object classes (Part V taxonomy), in force from the moment each object reaches the stated lifecycle stage:

| Class | Create | Modify | Supersede | Delete |
|---|---|---|---|---|
| GOVOBJ | A2 (draft) | only before EVIDENCED | A3 propose + A4 ratify | never |
| CRYPTOOBJ | A1 | never | never (new evidence coexists) | never |
| EXECOBJ | A2 | only before dispatch | new EXECOBJ chained | never |
| RESULTOBJ | system (on completion) | never | via new EXECOBJ/RESULTOBJ pair | never |
| SEMDOMAIN / SEMFRAME | A5 (domain) / A4 (frame) | frames: new version only | domain: successor edition only | never |

The rightmost column is uniform by construction: **nothing is ever deleted**. Deletion is replaced by supersession plus permanent readability — the operational form of INV-E1-RI.

## 27. Authority Separation

**[N] ED1-CLOSE-07.** The full separation matrix (✓ = compatible in one principal for the same object; ✗ = prohibited):

|  | A1 Produce | A2 Evaluate | A3 Claim | A4 Ratify | A5 Constitute |
|---|---|---|---|---|---|
| **A1 Produce** | — | ✓ | ✗ (ED1-AUTH-04) | ✗ | ✗ |
| **A2 Evaluate** | ✓ | — | ✓ | ✗ | ✗ |
| **A3 Claim** | ✗ | ✓ | — | ✗ (ED1-AUTH-03) | ✗ |
| **A4 Ratify** | ✗ | ✗ | ✗ | — | ✓ |
| **A5 Constitute** | ✗ | ✗ | ✗ | ✓ | — |

**[I] ED1-CLOSE-08.** The only permitted fusions are Produce+Evaluate (a pipeline may both run and score a check — its outputs still cannot become claims without a distinct A3 principal) and Ratify+Constitute (the edition authority ratifies by construction of its constitutive role). Every other fusion collapses a control the closure model depends on.

## 28. Dependency Structure and the Preservation Theorem

**[D] ED1-CLOSE-09 (Dependency structure).** The Edition 1 normative corpus forms the acyclic dependency graph:

```
ED1-CONST-01..05  (principles)
      │
      ▼
Part II AM  ──────────▶  Part III identifiers ─────▶ Part VI SEMDOMAINs
      │                        │                          │
      ▼                        ▼                          ▼
Part IV evidence ◀──── Part V object classes ────▶ Part VII risk semantics
      │                        │
      ▼                        ▼
INV-E1-RI / INV-E1-MP / INV-E1-EL  (§24)
      │
      ▼
MI-1 (§25)  ──▶  Closure predicate (§29)  ──▶  Five-layer architecture (§30)
```

Every arrow is "cited-by / evaluated-in-terms-of"; the graph is acyclic (checked mechanically as part of ID-CONF), so no invariant is grounded in itself except MI-1's disciplined self-application (§25), which bottoms out in the SAF campaign's external evidence.

**[N] ED1-CLOSE-10 — Preservation Theorem (statement).**
*Let `Σ₁` be the sealed Edition 1 corpus satisfying `Φ = {INV-E1-RI, INV-E1-MP, INV-E1-EL, MI-1}`. Let `Σ₂` be any successor edition produced under the Edition Succession Protocol (Annex E). Then `Σ₁ ∪ Σ₂ ⊨ Φ`, and every Edition 1 record remains verifiable in `Σ₂`'s context with unchanged verdicts.*

**Proof sketch [I].**
(i) *RI preserved:* ESP rules permit successors only to **add** records and `superseded_by` links; no ESP operation writes into an Edition 1 record, and the WORM store rejects in-place writes structurally.
(ii) *MP preserved:* successor provenance edges point from new records into old ones — set inclusion `⊑(Σ₁) ⊆ ⊑(Σ₁∪Σ₂)` holds by construction; acyclicity holds because new nodes cannot create back-edges into themselves from sealed nodes (sealed nodes gain no new outgoing derivation edges other than `superseded_by`, which is excluded from `⊑`).
(iii) *EL preserved:* Edition 1 verdicts depend only on local neighborhoods `E(c)`, which are Edition 1 records — immutable by (i) — so re-evaluation in `Σ₂` recomputes identical verdicts.
(iv) *MI-1 preserved:* MI-1 quantifies per-claim; Edition 1 claims retain their frozen authority and evidence records; successor claims are governed by the successor's own MI-1 instance, which ESP-2 requires to be at least as strong (invariant monotonicity, ED1-CONST-08). ∎
*Tier:* B (mechanized proof is a design-level model; the mechanically checkable consequences — digest stability, chain growth, bundle re-verification — are Tier A via suite steps 11, 16, 17).

## 29. The One-Way Monotonic Governance Model

**[N] ED1-CLOSE-11.** Edition-level governance state moves along a one-way lattice, and only forward:

```
   open drafting ──▶ campaign-validated ──▶ RATIFIED ──▶ SEALED (Edition 1, forever)
                                                            │
                                                            ▼ (new work happens only here)
                                                    Edition 2 drafting ──▶ … ──▶ SEALED
```

Three monotone quantities characterize the model, none of which ever decreases:
1. **Invariant strength** — successor invariant sets contain Edition 1's (ED1-CONST-08);
2. **Evidence mass** — the CRYPTOOBJ population and provenance DAG only grow (INV-E1-MP);
3. **Record permanence** — the set of permanently readable records only grows (INV-E1-RI, ED1-CLOSE-06).

**[N] ED1-CLOSE-12 (Closure predicate).** Edition 1 is **closed** iff, at seal time:
(a) every [N] clause carries a tier tag and its tier-appropriate verification or disclosure;
(b) ID-CONF passes with zero findings;
(c) the SAF campaign (Part X) has produced VC-SAF-001 with verdict PASS and VR-SAF-001 ratified under MI-1;
(d) the runnable assurance suite passes in full (19/19 at the anchoring commit);
(e) an A5 quorum record exists sealing the edition.
The closure predicate is itself evaluated by an EXECOBJ whose RESULTOBJ is the final CRYPTOOBJ admitted into Edition 1 — the corpus closes on the evidence of its own closure.

## 30. The Five-Layer Governance and Publication Architecture

**[D] ED1-CLOSE-13.** Edition 1 is published and preserved as five strictly layered strata:

```
┌───────────────────────────────────────────────────────────────────────┐
│ L5  PUBLICATION LAYER — rendered editions, submission packages,       │
│     regulator bundles, monograph chapters. Regenerable at will;       │
│     never authoritative.                                              │
├───────────────────────────────────────────────────────────────────────┤
│ L4  ATTESTATION LAYER — closure certificate, quorum records,          │
│     campaign reports (VC/VR-SAF), transparency-log checkpoints.       │
│     Authority: A4/A5. Bound to L3 by digest.                          │
├───────────────────────────────────────────────────────────────────────┤
│ L3  EVIDENCE LAYER — the CRYPTOOBJ population: digests, ML-DSA-65     │
│     signatures, Merkle proofs, freshness ledger, WORM store.          │
│     Authority: A1. Immutable from EVIDENCED.                          │
├───────────────────────────────────────────────────────────────────────┤
│ L2  SEMANTIC LAYER — identifier registry, SEMDOMAIN/SEMFRAME          │
│     registry, boundary-maps, authority matrix. Frozen at seal.        │
├───────────────────────────────────────────────────────────────────────┤
│ L1  KERNEL LAYER — clause corpus, constitutional invariants,          │
│     Meta-Invariant, closure predicate. Plain-text, archival,          │
│     immutable, ≥25-year design life.                                  │
└───────────────────────────────────────────────────────────────────────┘
```

**[N] ED1-CLOSE-14 (Layer discipline).** Dependencies point strictly downward: L5 renders L4+L3+L2+L1; L4 attests L3; L3 evidences L2+L1; L2 interprets L1; L1 depends on nothing. Any upward dependency (e.g., a kernel clause referencing a rendered publication) is a conformance failure. Loss of any layer above L1 is recoverable — L5 regenerates from below, L4 re-attests, L3 re-evidences by re-execution of deterministic EXECOBJs; only L1 is irreplaceable, which is why it is the smallest, plainest, and most redundantly preserved stratum.

**[N] ED1-CLOSE-15 (Archival baseline and open succession).** Upon sealing, Edition 1 constitutes the **stable archival governance baseline**: a permanently citable, permanently verifiable reference whose every claim can be re-checked from L3 evidence indefinitely. Succession is *open* — any number of formally versioned successor editions may be published under Annex E — but the baseline itself never moves. Stability without stagnation: the edition is closed; the ecosystem is not.

---

# PART X — THE SAF SAFETY VALIDATION CAMPAIGN

## 31. Campaign Purpose and Design [I]

The **SAF campaign** is Edition 1's per-campaign validation (ED1-KERN-05(b)) instantiated for the closure decision. It exercises the full evidence-driven chain — dataset → evidence → analysis → invariant check → validation certificate → validation report — over the three edition invariants and the Meta-Invariant, using the campaign's own artifacts as the first live population governed by the rules they validate. Nine artifacts constitute the campaign; each is typed against the Part V object model and identified per the `<TYPE>-SAF-<NNN>` family (ED1-ID-01).

All digests below are SHA-256 over the artifact's canonical identifier string in the Edition 1 namespace (`ED1-SPEC-2026-001/<artifact-id>`), recomputable by any assessor with `echo -n "ED1-SPEC-2026-001/<artifact-id>" | sha256sum` — a deliberately transparent anchoring convention for the specification tier of these artifacts (Tier C: the identifiers and structure are validated; the operational campaign instantiates content digests over real payloads at execution time, Tier A).

## 32. Campaign Artifact Register

**[N] ED1-SAF-01.** The SAF campaign comprises exactly the following nine artifacts:

| # | Artifact | Class | Role | Anchor digest |
|---|---|---|---|---|
| 1 | `DS-SAF-001` | GOVOBJ (dataset) | Validation corpus: the full Edition 1 record population at campaign start — every clause, identifier, object, event stream sample, and version chain | `0x5933fbea44eb90bdbb3a0a08ca166b7305909ab15abb58b5958ae23055cd4450` |
| 2 | `EV-SAF-001` | CRYPTOOBJ | Evidence bundle over DS-SAF-001: digests of all records, transparency-log inclusion proofs, ML-DSA-65 signatures | `0x18644d12f6aee782b4b87967316694629ed3cfdafa75be1844972a5b41424317` |
| 3 | `EV-SAF-002` | CRYPTOOBJ | Delta-evidence bundle: all records created *during* the campaign (including the campaign's own artifacts 1–7), proving MP growth under observation | `0x54dd101e835a0d2625e4add825f409d8bc4cff3114f362ea83be467117f5bf7e` |
| 4 | `AN-SAF-001` | EXECOBJ→RESULTOBJ | Structural analysis: ID-CONF over the full corpus (grammar, resolution, acyclicity, chain heads); frame-registry consistency; dependency-graph acyclicity (ED1-CLOSE-09) | `0x070c20ae6b8a1d500ff8a5b5b2f0469cd9aeb6475120d8bce6a96513b2b7251d` |
| 5 | `AN-SAF-002` | EXECOBJ→RESULTOBJ | Adversarial analysis (ED1-KERN-06): mutation probes against RI (in-place-write attempts on WORM), MP (edge-deletion and cycle-injection attempts), EL (ambient-state dependency injection into verifiers), and authority-escalation probes against the §27 matrix | `0x07b04b390cb7349c257cff1ac142e2af8c9d3ea97639ab3093f7be37987fb8b2` |
| 6 | `INV-SAF-001` | EXECOBJ→RESULTOBJ | Invariant evaluation I: INV-E1-RI and INV-E1-MP evaluated over DS-SAF-001 ∪ EV-SAF-002 — digest recomputation across the corpus; provenance-DAG growth and acyclicity check across the campaign window | `0x745d08040b95cbaa860216e063b83a0bf29ca49d9d3f309d5c240a522f8cd53d` |
| 7 | `INV-SAF-002` | EXECOBJ→RESULTOBJ | Invariant evaluation II: INV-E1-EL and MI-1 — Zone-E-style local re-verification of a sampled claim set using only evidence neighborhoods; MI-1 quantifier check over every asserted claim (authority, sufficiency, separation, ratification distinctness) | `0xb7087ffdbda2c16ebf493d0f85de3ad88cbf743829a5783d0beff66f00ec51ea` |
| 8 | `VC-SAF-001` | GOVOBJ (certificate) | Validation certificate: the A4-ratified statement that artifacts 1–7 are complete, verdicts are PASS, and the closure predicate clauses (a)–(d) of ED1-CLOSE-12 are satisfied | `0x44cfe2044991855dfd5388aee33c72cdf3eef2ea0c217241e981a6a0f728f763` |
| 9 | `VR-SAF-001` | GOVOBJ (report) | Validation report: the full narrative and quantitative record of the campaign — methodology, findings, adversarial search budgets, residual disclosures — the evidence object for the MI-1 self-application (§25) | `0x8ef0d9b9750fc6b1d4c39d21f36a064b3bcd9f51e927af51aae97292c5734525` |

## 33. Campaign Execution Semantics

**[N] ED1-SAF-02 (Ordering).** The campaign SHALL execute in the strict order DS → EV-001 → {AN-001, AN-002, INV-001, INV-002 in any order, each after its evidence prerequisite} → EV-002 → VC → VR. No later artifact may be produced before its predecessors reach `EVIDENCED`.

**[N] ED1-SAF-03 (Authority casting).** Per the §27 matrix: DS-SAF-001 is assembled under A2; EV-SAF-001/002 are produced under A1 by principals distinct from the DS assembler; AN/INV analyses run under A2 by principals with no authorship stake in the analyzed clauses (ED1-KERN-06); VC-SAF-001 is claimed under A3 and ratified under A4 by distinct principals; VR-SAF-001 is the evidence object supporting the closure claim and is produced under A1/A2, never by the VC claimant.

**[N] ED1-SAF-04 (Verdict discipline).** Each of AN-SAF-001/002 and INV-SAF-001/002 SHALL yield exactly one RESULTOBJ verdict per ED1-EXEC-05. A verdict of FAIL or ERROR on any of the four SHALL block VC-SAF-001; INCONCLUSIVE SHALL trigger one re-execution with expanded budget, after which a second INCONCLUSIVE is treated as FAIL. There is no override path around a failed invariant evaluation — consistent with ED1-CONST-08 invariant supremacy.

**[N] ED1-SAF-05 (Campaign as first citizen).** Every campaign artifact SHALL itself satisfy the invariants it validates: campaign records are immutable from `EVIDENCED` (RI), campaign provenance edges extend the DAG (MP), campaign verdicts are locally re-verifiable (EL), and the campaign's own claims pass MI-1. EV-SAF-002 exists precisely to evidence this reflexive conformance.

**[I] ED1-SAF-06 (Result summary at specification tier).** At the specification tier, the SAF campaign design is complete and internally consistent: all nine artifacts are typed, ordered, authority-cast, and anchored; the four analysis/invariant checks jointly cover all four closure invariants ({RI, MP} × INV-SAF-001, {EL, MI-1} × INV-SAF-002, structure × AN-SAF-001, adversarial × AN-SAF-002); and VC/VR close the loop under separated authority. Operational execution against a live deployment instantiates each anchor with a content digest over the real payload — the anchoring convention above makes specification-tier and operational-tier digests cleanly distinguishable, honoring ED1-CONST-03.

---

# ANNEXES

## Annex A — Regulatory Crosswalk (Informative)

| Edition 1 element | EU AI Act | DORA / NIS2 | NIST | Other |
|---|---|---|---|---|
| Authority model, no self-ratification (Part II) | Art. 14, Art. 17 | DORA Art. 5 (governance) | AI RMF GOVERN-2 | SR 11-7 effective challenge; SMCR |
| Lifecycle + stage gates (§5) | Art. 17 QMS | DORA Art. 6 | AI RMF MAP | ISO/IEC 42001 §8 |
| Identifier families + traceability (Part III) | Art. 12, Annex IV §2 | DORA register of information | OSCAL props | BCBS 239 P3 (accuracy/integrity) |
| PQC evidence plane (Part IV) | Art. 12 record-keeping | DORA Art. 9(4)(d) | FIPS 203/204/205; SP 800-208 | SEC 17a-4(f) |
| Execution meta-model, human ceiling (Part V) | Art. 14 human oversight | — | AI RMF MANAGE | GDPR Art. 22 |
| Event completeness + well-formedness (Part VI) | Art. 12, Art. 65–68 (evidence for enforcement) | DORA Art. 17; NIS2 Art. 21 | AI 600-1 logging | — |
| Risk semantics, method-bound scores (Part VII) | Art. 9 | DORA Art. 6(8) | AI RMF MEASURE | Basel; SR 11-7 |
| Kernel longevity + adversarial validation (Part VIII) | Art. 9(2) continuous | — | AI 600-1 red-teaming | SR 11-7 validation |
| Closure model, RI/MP/EL, MI-1 (Part IX) | Annex IV documentation integrity | DORA Art. 28 evidence | OSCAL AR | SEC 17a-4(f); ISAE 3000 |
| SAF campaign (Part X) | Art. 43-adjacent conformity assessment pattern | DORA resilience testing spirit | AI RMF MEASURE/MANAGE | SOC 2 period-of-time examination |

## Annex B — Edition 1 Identifier Registry (Normative, frozen at seal)

Families, grammars, lifecycle profiles, and boundary carriers as tabulated in ED1-ID-01/ID-05/ID-07. Registry rules: (B-1) grammar strings are ABNF-expressible and case-sensitive; (B-2) `archival` profile applies to clause, invariant, SEMDOMAIN, and SGI families; `versioned` to GOVOBJ/EXECOBJ/RESULTOBJ/SEMFRAME; `singleton-per-edition` to the closure certificate; (B-3) boundary carriers: OSCAL `prop@ns=ed1` for regulatory boundaries, event field `subject` for zone boundaries, manifest `id` entries for temporal boundaries; (B-4) the registry itself bears `GOVOBJ-2026-001` and seals with L2.

## Annex C — SEMDOMAIN Registry Snapshot (Normative, frozen at seal)

The seven SEMDOMAINs of ED1-EVT-04 with their eleven registered frames (`SEMFRAME-GRANT-01`, `SEMFRAME-QUORUM-01`, `SEMFRAME-TRANSITION-01`, `SEMFRAME-ANCHOR-01`, `SEMFRAME-FRESH-01`, `SEMFRAME-VERDICT-01`, `SEMFRAME-SCORE-01`, `SEMFRAME-APPETITE-01`, `SEMFRAME-OVERRIDE-01`, `SEMFRAME-SEAL-01`, `SEMFRAME-SUCCEED-01`) and four boundary-map entries: OVERRIDE↔LIFECYCLE (posture changes as transitions), RISK→OVERRIDE (appetite breaches as escalation candidates), EXEC→EVIDENCE (verdicts as anchorable facts), EDITION→LIFECYCLE (seal events as terminal transitions).

## Annex D — Conformance Statement Template (Informative)

A deployment claiming Edition 1 conformance publishes: (1) tier census — count of [N] clauses at each tier with verification pointers; (2) ID-CONF report; (3) latest campaign VC/VR pair; (4) suite result at the anchoring commit; (5) disclosed gaps with remediation horizons. Absence of any element renders the conformance claim `[UNSUBSTANTIATED]` per ED1-CONST-02.

## Annex E — Edition Succession Protocol (ESP) (Normative)

- **ESP-1 (Initiation).** A successor edition is initiated by an A5 quorum record naming scope and rationale; drafting occurs entirely outside the sealed corpus.
- **ESP-2 (Invariant monotonicity).** The successor's constitutional invariant set SHALL contain Edition 1's set (ED1-CONST-08); weakening or removal is out of protocol and void.
- **ESP-3 (Preservation re-proof).** Before the successor seals, the preservation theorem (ED1-CLOSE-10) SHALL be re-established for the concrete `Σ₁ ∪ Σ₂`.
- **ESP-4 (Identifier sanctity).** Edition 1 identifiers are never redefined; successors supersede by new identifiers with `supersedes` links (ED1-ID-02/06).
- **ESP-5 (Registry amendment).** New identifier families and SEMDOMAINs enter only via the successor's registry, additively.
- **ESP-6 (Campaign obligation).** Each successor edition SHALL close through its own SAF-pattern campaign before sealing (ED1-KERN-05).
- **ESP-7 (Baseline citation).** Successors SHALL cite Edition 1 by its seal digest; the archival baseline remains the root of the edition chain.

Edition-chain seal anchor (specification-tier, convention of §31): `0x6e317e4f66c7cc6a1e9d0aaa7e3a9805d22f4e945fdca9a4ad57c729c79c7320` (`sha256("ED1-SPEC-2026-001/ED1-SEAL")`).

---

## Closing Statement [I]

Edition 1 delivers what long-lived governance actually requires: not a bigger rulebook, but a *closed* one — a corpus whose every normative sentence is identified, tiered, evidenced or disclosed, validated under separated authority, and sealed into a five-layer archive that successors can extend but never erode. The suite's runnable constitutional layer (GIES, SGI v6.0, the 19-step assurance suite) proves the machine; Edition 1 proves the meaning. Together they form a governance baseline that a supervisor in 2026 — or an archivist in 2051 — can verify from first principles, with nothing taken on trust except mathematics and published keys.

**— END OF EDITION 1 SPECIFICATION (ED1-SPEC-2026-001) —**
