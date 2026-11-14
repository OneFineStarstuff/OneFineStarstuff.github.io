# WP-103 — P0 Evidence and Metric Contract Reconciliation for the GIEN Supervisory Webapp

<title>WP-103 — P0 Evidence and Metric Contract Reconciliation for the GIEN Supervisory Webapp</title>

<abstract>
**Status:** Proposed work package; documentation-only draft for review. **Baseline:** `main` at `e5a39728e21b9ec5951dc7cad8bcb36092766c52`. **Target:** the merged `webapp/` Phase 2
M1 static shell and briefing viewer. **Objective:** prevent simulated, unresolved or unverified GIEN dossier content from being rendered as observed supervisory assurance;
establish one versioned evidence and metric contract shared by the dossier, webapp, API and compliance crosswalk. This package does not implement live telemetry, authorise
production use, make legal applicability determinations, merge dependent pull requests or deploy infrastructure.
</abstract>

<content>

## 1. Decision requested

Approve WP-103 as the P0 reconciliation work package for the GIEN governance webapp.

The immediate decision is to make the newly merged `webapp/` application the target of the Phase 2 M1-to-M2 evidence-contract work, subject to product-owner confirmation. Do not create a third frontend or silently redirect the older `gien-platform/` and `gien-supervisory-brief/` applications. Record their relationship and supported status in an architecture decision.

The work package is split into reviewable gates:

1. Reconcile existing evidence-contract and P0 remediation branches.
2. Ratify a canonical metric/evidence contract.
3. Make the M1 viewer display simulation and assessment state without false assurance.
4. Align the Phase 1 schema, metric catalogue, crosswalk, dossier fixture and future API contract.
5. Add regression, accessibility and export-safety tests.
6. Hold M2 live telemetry integration until the contract and authorization boundary pass review.

**Requested disposition:** review and approve the plan; implementation changes must be submitted in separate, test-backed PRs.

## 2. Baseline and observed defects

### 2.1 Current canonical application

The latest relevant main-branch commit is `e5a39728e21b9ec5951dc7cad8bcb36092766c52`, which merged PR #256 (WP-102 Phase 2 M1). The merged `webapp/` application contains a React 18, TypeScript, Vite, Tailwind, React Router and Lucide shell, plus a static briefing viewer using the dossier-316 fixture.

Relevant current-main files:

- `webapp/src/data/dossier-2026-316.ts`
- `webapp/src/types/gien.ts`
- `webapp/src/components/BandBadge.tsx`
- `webapp/src/pages/BriefingViewer.tsx`
- `webapp/phase1/01_evidence_model.md`
- `webapp/phase1/evidence-drawer.schema.json`
- `webapp/phase1/oscal_crosswalk_seed.json`
- `webapp/README.md`

The M1 application is a static simulation viewer. The fixture identifies dossier-316 and its 11–12 November reporting window. It is not a live evidence adapter.

### 2.2 P0 defects requiring correction

| ID | Current evidence | Defect / supervisory risk |
|---|---|---|
| EVC-01 | `dossier-2026-316.ts` gives numeric/string values and GREEN bands to all displayed indices | The fixture does not represent evidence origin, method maturity or verification state. A simulated scenario band can be mistaken for a real supervisory assessment. |
| EVC-02 | `types/gien.ts` defines `Band = GREEN | AMBER | RED`; `IndexReading` has value, delta and band only | The type system cannot express SIMULATED, UNKNOWN, NOT_ASSESSED, UNRESOLVED, or a null observation. |
| EVC-03 | `BandBadge.tsx` renders the supplied band directly | No guard prevents an unassessed or simulated control claim from appearing as a positive assurance state. |
| EVC-04 | The Phase 1 evidence-drawer schema requires numeric `current.value`, a GREEN/AMBER/RED `band`, at least one control and artifact, and a boolean `root_recomputable` | Missing, unresolved and not-yet-verified evidence cannot be represented honestly. Required artifact/control arrays can pressure authors to invent references. |
| EVC-05 | The Phase 1 evidence model states that every digest is 64 lowercase hex characters while the dossier and UI describe SHA-384 artifacts | Digest size and algorithm are conflated; SHA-384 requires a 96-hex-character digest. A Merkle root may use a different, explicitly declared algorithm. |
| EVC-06 | The current crosswalk seed includes SR 11-7 in the real-regime mapping and places SEC Rule 17a-4 under a WORM mapping | The seed does not yet distinguish current/historical guidance, direct legal applicability and analogy-only control mappings. |
| EVC-07 | The dossier fixture includes three signature-labelled strings of 64 hex characters | These are not established as complete raw signatures. They must be typed as identifiers/fingerprints unless the actual signature artifacts are supplied and verified. |
| EVC-08 | The Phase 1 schema and metric model do not define `Δ_OSCAL` as a structured catalog diff | A scalar control count cannot describe additions, removals, modifications, unchanged controls or applicability changes. |
| EVC-09 | M1's README describes a static fixture viewer; package scripts include dev/build/preview but no test command or lockfile in the M1 file set | The merged M1 slice has no demonstrated, app-local regression suite or deterministic npm install contract. |
| EVC-10 | The static shell uses a “TOP SECRET // SUPERVISORY EYES ONLY” classification banner | A formal security classification is not established by this simulation repository. The UI must not imply a classification authority that has not been documented. |

### 2.3 Metric-specific interim disposition

The proposed WP-098 contract in PR #248 is not merged and must not be described as ratified. It nevertheless identifies a material inconsistency that WP-103 must resolve.

Until an approved catalogue says otherwise:

| Metric / family | Interim rendering rule |
|---|---|
| `S_sys`, `G-SRI`, `C-SRI`, `A-SRI`, `P-SRI` | May be displayed as scenario values only when marked `SIMULATED`; any scenario band must be visually and semantically separate from an assurance/control state. |
| `CGR-I`, `CCR-I`, `G-SRI-VII` | No scalar or GREEN/AMBER/RED supervisory band until definition, directionality and methodology are approved. Represent as `UNRESOLVED` / `NOT_ASSESSED`, with null scalar values. |
| `p(doom)`, `p(doom)_kernel` | Suppress numeric estimates and bands until the event definition, population, prediction horizon, calibration, validation and uncertainty method are approved. |
| `Δ_drift` | No assurance band until detector, population, baseline, sign convention and aggregation method are ratified. It may appear as simulation-only explanatory text when the fixture supplies it. |
| `Δ_OSCAL` | Store and render a structured catalog diff; any scalar count is derived summary text, never the canonical field. |
| Evidence quote age | Treat as evidence freshness metadata with a stated denominator and time basis, not as an additional systemic-risk index. |

Do not automatically infer that an unresolved metric has a value of zero. Missing, unknown, not assessed and not estimated are different states.

### 2.4 Static review findings for candidate PR #248

PR #248 supplies useful draft material and its Phase 1 contract workflow passed on its own branch. A static review of its current schema, metric catalogue, crosswalk and tests identifies the following issues that must be reconciled before the branch is treated as the WP-103 implementation baseline:

1. **Unvalidated probability display conflict:** the `p_doom` and `p_doom_kernel` metric definitions are marked `PROVISIONAL_UNVALIDATED`, yet both set `scalar_display_allowed:
true`. This conflicts with WP-103's interim rule to suppress numeric estimates and bands until the event definition, horizon, calibration, validation and uncertainty method are
approved. Set display permission to false until an explicit approval record authorizes it.
2. **Band/state conflation:** the evidence-drawer schema uses one `current.band` property for GREEN/AMBER/RED and UNKNOWN/NOT_ESTIMATED/NOT_ASSESSED. It also permits a simulated observation to carry GREEN. Separate `scenario_band` from `assessment_state`; only the former may carry a simulation threshold result, and it must never imply control effectiveness or assurance.
3. **Incomplete evidence dimensions:** the candidate payload includes observation origin and verification, but does not carry the full methodology, freshness, applicability and approval states required by WP-103. Add these as distinct fields with defined nullability and validation rules rather than embedding them only in narrative notes.
4. **Merkle construction remains underspecified:** the schema reuses the generic digest object for both artifact digests and Merkle roots. Record the tree hash algorithm, leaf/node encoding, domain-separation convention, ordering, and root verification procedure separately from an artifact's content digest.
5. **Signature records remain insufficiently typed:** the drawer has signature status and signer reference, but does not yet bind a signature algorithm, signature artifact/reference, key or certificate identity, signed payload digest and verifier result as one verifiable record. Do not interpret existing short hex fixture strings as raw signatures.

The branch also contains material improvements to preserve: algorithm-specific digest lengths, unresolved scalar handling for CGR-I/CCR-I/G-SRI-VII, structured-only Δ_OSCAL, SR 26-2 as the current model-risk reference with SR 11-7 historical, and SEC 17a-4 kept as an analogy-only relationship for the fictional WORM ledger.

**Candidate branch validation is not merge readiness.** Its Phase 1 workflow passed, while the recorded external status still includes pre-commit.ci failure, DeepSource Python failure and a pending Codeac result. Re-run validation after the above amendments and review the resulting contract independently.

## 3. Scope

### In scope

- Versioned evidence-origin, verification, methodology, freshness, applicability and approval states.
- A metric catalogue with units, definitions, directionality, calculation versions, display permission and threshold policy.
- Nullable scalar values and explicit unresolved/not-assessed states.
- A structured OSCAL catalogue-diff object.
- Algorithm-specific digest metadata and separate signature-artifact metadata.
- Correct classification of simulation, historical, proposed, unverified and analogy-only regulatory mappings.
- Safe rendering and role-aware disclosure for the merged `webapp/` M1 viewer.
- Fixture, schema, UI, API-contract and export regression tests.
- A documented decision on the relationship between `webapp/`, `gien-platform/` and `gien-supervisory-brief/`.

### Explicitly out of scope

- Connecting live financial-institution or supervisory-authority telemetry.
- Enabling any write path, emergency-stop operation, autonomous intervention or infrastructure control.
- Claiming production readiness, regulatory approval, legal compliance or independent assurance.
- Performing a legal applicability determination on behalf of a regulated entity.
- Deploying to production or changing Vercel, Kubernetes, object-storage, secrets, GitHub environment or branch-protection settings.
- Replacing all legacy applications or merging unrelated stale PRs as part of this work package.

## 4. Canonical contract requirements

### 4.1 Independent evidence dimensions

The contract must not collapse all evidence meaning into a single `status` or colour.

| Dimension | Initial allowed values |
|---|---|
| Origin | `OBSERVED`, `SIMULATED`, `UNKNOWN` |
| Verification | `VERIFIED`, `FAILED`, `PARTIAL`, `NOT_CHECKED`, `NOT_APPLICABLE` |
| Methodology | `VALIDATED`, `PROVISIONAL`, `UNVALIDATED`, `UNRESOLVED` |
| Freshness | `CURRENT`, `STALE`, `UNKNOWN` |
| Applicability | `APPLICABLE`, `NOT_APPLICABLE`, `UNDETERMINED` |
| Approval | `APPROVED`, `PENDING`, `REJECTED`, `NOT_REQUIRED` |

An observed value is not necessarily verified; a valid digest does not validate the method; a simulated scenario band is not a control-effectiveness assessment; an OPA test pass does not decide legal applicability.

### 4.2 Metric observation model

At minimum, each displayed metric observation must carry:

- `metric_id`, `definition_version`, `unit`, `window_id`.
- `value: number | null` and an explicit `value_state`.
- The six independent evidence dimensions above.
- Observation timestamp, source observation IDs and ingestion timestamp where applicable.
- Methodology/version reference, denominator/sample size and uncertainty metadata where defined.
- Source artifact IDs and algorithm-labelled digests.
- Reviewer/approval metadata when approval is required.

A schema validator must reject impossible combinations. Examples: an `UNKNOWN` or `NOT_ASSESSED` observation carrying a numeric value; a `SIMULATED` fixture declared as an observed source; an unresolved metric with a GREEN assurance state; or an observed value lacking source-observation provenance.

### 4.3 Scenario band versus assurance state

If a metric has approved scenario thresholds, the interface may display `scenario_band` for the fictional simulation. It must remain separate from `verification`, `methodology`, `approval` and any control-effectiveness result. The UI must label it “simulation band” and visibly display the `SIMULATED` origin.

Do not use a green badge as a substitute for the evidence state. A neutral text status is the default for missing or unassessed evidence.

### 4.4 Structured OSCAL diff

Canonical `Δ_OSCAL` data must include:

- Base and target catalog identifiers, versions and digests.
- Added, removed, modified and unchanged control IDs.
- Control-level content and parameter changes.
- Applicability/mapping changes and their review state.
- Diff generator and version, timestamp and reviewer.

A human-readable count may be derived from this structure, but the count is not the canonical metric.

### 4.5 Cryptographic object semantics

Store artifact digests, Merkle roots, signature bytes, signature digests, key fingerprints and algorithm identities as distinct fields.

Minimum digest rules:

- SHA-256: 64 hexadecimal characters.
- SHA-384: 96 hexadecimal characters.
- SHA-512 and SHA3-512: 128 hexadecimal characters.

The Merkle-root algorithm must be declared independently from the leaf-artifact digest algorithm. Do not assume a SHA-384 leaf digest implies a SHA-384 Merkle root.

Use NIST algorithm names correctly: FIPS 203 ML-KEM is key encapsulation/key establishment, not a signature; FIPS 204 ML-DSA and FIPS 205 SLH-DSA are signature standards.
Falcon-1024 must be recorded separately from those three FIPS standards. A short 64-hex string is not a raw signature merely because a UI labels it “signature”; absent raw
signature bytes and a verifier result, represent it as an identifier or fingerprint.

## 5. Regulatory and control mapping requirements

Every mapping must be independently typed as one of:

- `DIRECT_PROPOSED` — proposed direct mapping, not yet reviewed.
- `DIRECT_REVIEWED` — reviewed mapping with applicability rationale and evidence.
- `HISTORICAL` — superseded or retained for lineage.
- `ANALOGY_ONLY` — useful control pattern but not a direct legal obligation.
- `SIMULATION_ONLY` — fictional GIEN treaty or simulation control.
- `UNVERIFIED_REFERENCE` — source identity or authority not established.

Required mapping metadata: full instrument title, issuer, jurisdiction, source URL, publication/effective dates, binding status, entity/system scope, exact provision, applicability decision and rationale, linked control, evidence IDs, reviewer and review date.

Specific crosswalk corrections for review:

1. Use Federal Reserve SR 26-2 as the current model-risk reference within its supervisory scope; retain SR 11-7 as historical lineage only.
2. Do not map SEC Rule 17a-4 as a universal WORM mandate. Scope it to covered records/entities and record the qualifying audit-trail alternative where relevant.
3. Keep MAS FEAT separate from HKMA Fintech 2030 AI².
4. Record ICGC/GASO as `UNVERIFIED_REFERENCE` until the full instrument title, issuer, jurisdiction and authoritative source are identified.
5. Keep Interstellar AI Governance Accord, Galactic Treaty Framework, CFE-1.0, SGR-028 and GIEN phase constructs tagged `SIMULATION_ONLY`.
6. Do not render `PASS` or `COMPLIANT` solely because an OPA test suite passed. Separate policy-test outcome, control implementation, control effectiveness, legal applicability and compliance assessment.

## 6. Dependency and overlap register

The following repository work must be reconciled before implementation is split into further PRs:

| Existing item | Current position observed | WP-103 treatment |
|---|---|---|
| PR #248 — WP-098 evidence contract and crosswalk | Open draft; based on older main; contains nullable states, metric catalogue and mapping changes | Primary contract input. Review and rebase or supersede explicitly; do not assume merged/ratified. |
| PR #196 — P0 evidence-qualified telemetry/API boundary | Open, large, older branch; targets `gien-platform/` and a standalone evidence API | Reuse only after scope/security review and a current-main rebase. Do not copy its old frontend target into the new M1 app without an architecture decision. |
| PR #234 — fail-closed evidence reconciliation | Open draft; old base; description retains EV-001 and EV-002 as mandatory P0/unreconciled release blockers | Preserve the blockers and fail-closed release hold until their independent closure evidence is reviewed. Rebase/revalidate separately. |
| PR #252 — WP-101 supervisory viewer design | Open draft; design target is the older `gien-supervisory-brief/` application | Review for reusable semantics; update the target-application decision to account for merged `webapp/` M1. Do not silently treat its old target as current. |
| PR #256 — WP-102 Phase 2 M1 | Merged; introduced the current `webapp/` static shell and dossier-316 viewer | Current implementation baseline. Keep its M1 scope intact; apply changes through focused follow-on PRs. |
| PR #255 — WP-102 dossier line-length fix | Open non-functional formatting PR | Independent documentation maintenance; not a dependency for the evidence contract. |
| PR #217 — CI/CD reference implementation | Open, older branch; isolated reference pipeline and deployment examples | Later supply-chain/deployment workstream; no production release is authorized by WP-103. |
| PR #223 — Knowledge Plane contracts | Open, older branch; source/document/evidence provenance contracts | Consider as a source-provenance dependency after rebase and compatibility review. |

No existing PR is merged, approved or validated merely because it is listed here. A dependency owner must record whether to rebase, split, supersede or close each overlapping draft. Do not close, merge or rewrite another work package without its explicit review authority.

## 7. Implementation sequence and exit gates

### Gate 0 — Reconcile scope and dependencies

**Deliverables**
- Architecture decision naming the Phase 2 canonical application and its relationship to legacy apps.
- Dependency disposition for PRs #248, #196, #234, #252 and #223.
- Preserved P0 conflict register; unresolved findings remain blocking.

**Exit criteria**
- No competing evidence schema is silently designated as canonical.
- No unresolved P0 finding is downgraded or removed without independently reviewed closure evidence.
- A reviewer approves the intended target path: `webapp/`.

### Gate 1 — Ratify evidence and metric contracts

**Deliverables**
- Versioned JSON Schema and matching TypeScript types.
- Metric definition catalogue and migration note for the legacy fixture.
- Algorithm-specific digest/signature schema and structured `Δ_OSCAL`.
- Validator and negative tests.

**Exit criteria**
- Unresolved and unassessed values are representable without fabricated artifacts or scalar values.
- The validator rejects impossible state combinations.
- Regulatory mapping types distinguish direct, proposed, historical, analogy-only, simulation-only and unverified entries.
- The contract receives independent governance, engineering and compliance review.

### Gate 2 — Correct the M1 static viewer

**Deliverables**
- Evidence-aware TypeScript model and display components.
- Updated dossier-316 fixture marked `SIMULATED`.
- Explicit simulation banner and simulation-band labels.
- Unresolved metrics shown as null/unresolved rather than GREEN.
- Signature fields labelled as references/fingerprints unless real signature artifacts are supplied.
- Classification banner replaced with a truthful simulation/test-fixture classification pending a documented classification decision.

**Exit criteria**
- No M1 fixture value is rendered as a live observation or verified control outcome.
- No unresolved metric receives a numeric GREEN/AMBER/RED assurance badge.
- Existing navigation, responsive layout and role-based presentation remain functional.
- Role selection is documented as presentation only; no frontend selector is treated as authorization.

### Gate 3 — Reconcile crosswalk, dossier and API contracts

**Deliverables**
- Updated Phase 1 evidence model and evidence-drawer schema.
- Corrected source register and crosswalk seed with mapping status and applicability metadata.
- API OpenAPI schema aligned to the same metric/evidence contract.
- Window/catalog version consistency checks.

**Exit criteria**
- Dossier, API and UI identify the same window and catalogue versions when they claim to represent the same snapshot.
- `Δ_OSCAL` is structured end-to-end.
- SR 26-2/SR 11-7 lineage and SEC 17a-4 scope are explicitly represented.
- No mapping is rendered as reviewed or compliant solely from test success.

### Gate 4 — Regression, accessibility and security verification

**Deliverables**
- Schema/semantic regression tests.
- Component and browser tests for evidence-state rendering.
- API contract tests and stale-window tests.
- Export safety tests.
- Accessibility and security review record.

**Exit criteria**
- Required tests pass in CI on the PR head.
- Failed, null, stale, unresolved and simulated cases are covered, not just happy paths.
- No secret, token or private institutional evidence is included in fixtures.
- Any security or accessibility exceptions have owners, rationale and expiry.

### Gate 5 — M2 readiness review

M2 may begin only after Gates 0–4 are accepted. M2 can then add telemetry adapters, evidence drawers and Merkle inspection in read-only mode. Live institution connections require separate identity, tenant isolation, legal basis, privacy, security and source-owner approvals.

## 8. Acceptance criteria

| ID | Acceptance criterion | Required test/evidence |
|---|---|---|
| AC-01 | Every M1 fixture observation explicitly declares origin | Schema and fixture contract test |
| AC-02 | The dossier-316 fixture is rendered as SIMULATED | Component render test and browser assertion |
| AC-03 | A simulated scenario band is labelled separately from assurance state | Visual/component test |
| AC-04 | Unknown, not-assessed and unresolved states cannot carry numeric values or assurance bands | Negative semantic-validator tests |
| AC-05 | `CGR-I`, `CCR-I`, `G-SRI-VII` are not scalar/banded until definitions are approved | Metric-catalogue tests |
| AC-06 | `p(doom)` estimates are suppressed until methodology and calibration gates pass | Metric-policy tests |
| AC-07 | `Δ_OSCAL` is a structured catalog diff | Schema, API and UI contract tests |
| AC-08 | Drift sign, baseline and aggregation are explicit before banding | Metric-definition completeness test |
| AC-09 | SHA-256/384/512/SHA3-512 digest lengths are validated by algorithm | Positive and negative cryptographic metadata tests |
| AC-10 | Merkle root algorithm is explicit and independent of leaf digest algorithm | Evidence-manifest contract test |
| AC-11 | Signature bytes, signature digest and key fingerprint are distinct | Schema tests; short fingerprint cannot be accepted as raw signature |
| AC-12 | FIPS 203/204/205 roles are correctly typed | Algorithm-registry tests |
| AC-13 | Direct, historical, analogy-only, simulation-only and unverified mappings are distinguishable | Crosswalk validation tests |
| AC-14 | SR 26-2 is current and SR 11-7 historical in the Federal Reserve crosswalk | Regulatory-source register test |
| AC-15 | SEC Rule 17a-4 is scoped and not presented as universal WORM | Crosswalk assertion and reviewer sign-off |
| AC-16 | All times use explicit UTC instants and one consistent reporting-window identity | Boundary/timezone tests |
| AC-17 | Stale or mismatched catalog/window snapshots are rejected or marked stale | API/fixture contract tests |
| AC-18 | Role selection does not authorize access to protected data | Security-boundary test/review |
| AC-19 | Classification banner makes no unsupported formal classification claim | Content and UI assertion |
| AC-20 | Exports preserve simulation/evidence labels and escape spreadsheet formula injection | CSV/JSON export tests |
| AC-21 | Keyboard, focus, semantic table and screen-reader requirements pass | Automated accessibility checks plus manual keyboard review |
| AC-22 | App build and deterministic dependency install pass on the supported Node LTS runtime | CI build record using committed lockfile |
| AC-23 | No production deployment or live-source write occurs in this work package | PR scope review and deployment record check |

## 9. Test plan

Minimum automated suites:

1. **Schema tests:** valid simulated observation; valid observed observation with source IDs; nullable unknown; not-assessed; unresolved metric; structured catalog diff; digest/signature metadata.
2. **Semantic tests:** reject simulated-as-observed, unknown-with-value, unresolved-with-band, missing observed source IDs, unsupported direct mapping, malformed digest length and fingerprint-as-signature.
3. **Metric-policy tests:** scalar-display permissions, directionality, threshold version, unvalidated probability suppression and drift methodology gating.
4. **Rendering tests:** simulation banner, scenario-band labeling, neutral unresolved display, no GREEN assurance state for unassessed fixture data.
5. **Integration tests:** dossier snapshot → API schema → webapp type/renderer; catalog revision and reporting window agreement; invalid API response fail-closed behavior.
6. **Security/export tests:** role parameter cannot grant access; CSV formula injection is neutralized; HTML/Markdown content is escaped; no credentials in source URIs.
7. **Accessibility tests:** keyboard navigation, focus order, labels, table semantics, contrast and non-colour status distinction.
8. **Build reproducibility:** committed npm lockfile, `npm ci`, TypeScript/Vite build and test command in CI.

Do not claim test success until a hosted workflow run on the final PR head is complete and reviewed. Unit tests validate implementation behavior, not production operation or regulatory compliance.

## 10. Ownership and review responsibilities

| Review area | Accountable function | Required reviewer contribution |
|---|---|---|
| Metric semantics | Model risk / governance owner | Definition, directionality, thresholds and methodology approval |
| Evidence schema | Data/evidence architecture owner | Provenance, null semantics, schema compatibility and lineage |
| Cryptographic metadata | Security/cryptography owner | Algorithm roles, digest rules, signature verification model |
| Regulatory mappings | Legal/compliance owner | Source authority, entity scope, applicability and obligation mapping |
| Frontend rendering | Webapp engineering owner | State-safe rendering, accessibility and export fidelity |
| API boundary | Platform/security owner | Authentication, tenant isolation, read-only scope and fail-closed behavior |
| Independent challenge | QA / independent validation | Negative tests, reconciliation and reproducibility |

The author of a metric or regulatory mapping must not be its sole approver.

## 11. Release controls and stop conditions

The following are release blockers:

- Any unassessed or unresolved value shown as GREEN assurance.
- Any simulated data represented as observed.
- Any unvalidated `p(doom)` number presented as an established estimate.
- Any missing evidence converted to zero or a successful result.
- Any signature/digest ambiguity that prevents verification.
- Any regulatory mapping presented as direct and reviewed without an applicability decision.
- Any mismatch between dossier window, API snapshot and catalogue version.
- Any unresolved P0 reconciliation item designated as closed without independent closure evidence.

Until the gates pass, the webapp remains a read-only simulation viewer. External filing and production deployment remain outside WP-103 and must follow their own authority, evidence and approval process.

## 12. Definition of done

WP-103 is complete when:

- Gates 0–4 have evidence-backed approval.
- The metric/evidence contract is versioned and is the only source for state semantics.
- M1 displays dossier-316 as a simulation fixture without assurance-like GREEN claims.
- The dossier, API and webapp agree on snapshot and catalogue identities.
- All acceptance tests pass on the final reviewed PR head.
- Regulatory and cryptographic corrections have the required specialist review.
- The remaining P0 issues are either independently closed or remain explicitly open with release HOLD.
- A follow-on M2 plan is approved without enabling live ingestion by default.

**Final disposition for this PR:** planning specification only. No application code, evidence records, secrets, external services, production resources, regulatory submissions or existing PR states are changed.

</content>
