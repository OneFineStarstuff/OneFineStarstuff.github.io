# GIEN Governance Research Plan and Supervisory Reference Architecture

**Research snapshot:** 12 October 2026  
**Status:** Design specification / evidence-qualified research plan  
**Scope:** Fictional GIEN governance mesh and Omni-Sentinel platform; enterprise AI governance for G-SIFIs, LFIs and other high-assurance organisations  
**Primary implementation baseline:** Existing React + TypeScript + Vite application in \`gien-platform/\`

> **Boundary statement.** GIEN phases, GIEN control-domain identifiers, CFE-1.0, Protocol SGR-028, the Interstellar AI Governance Accord, the Galactic Treaty Framework, ICGC/GASO, fictional risk indices, Guardian Attestation milestones and Ω-GAR are project constructs unless a separately identified authoritative instrument says otherwise. They must never be represented as enacted law, a real regulator, live telemetry or independent assurance. This document is architecture guidance, not legal advice or a declaration of compliance.

## <title>Purpose and intended audiences</title>

## <abstract>

Design one multi-stakeholder supervisory application that presents traceable risk telemetry, AI governance evidence, control assessments, cryptographic integrity results and scenario-replay records at different levels of detail. The system must distinguish observed evidence from demonstration fixtures, derived indicators, forecasts, policy interpretations and unverified claims. It must provide a defensible chain from applicable requirement to control implementation, test, evidence artifact, finding, accountable owner and closure review.

The recommended strategy is to extend the repository’s current React 18, TypeScript, Vite, React Router, Tailwind and Lucide baseline rather than rewrite it immediately. Use D3 for highly customized SVG visualizations, Recharts for routine time-series and comparison charts, and server-side services—not browser state—as authorities for identity, authorization, policy decisions, evidence validation and emergency actions. Reconsider a Next.js App Router deployment only if server rendering, a server-side backend-for-frontend, protected document delivery or application hosting requirements justify the migration.

## <content>

## 1. Primary purpose and audience model

### 1.1 Primary purpose

The platform has four connected purposes:

1. **Regulatory and supervisory briefing.** Supply an evidence-qualified view of systemic risk, material exceptions, control coverage, remediation, resilience tests and submission readiness.
2. **Institutional governance engineering.** Let authorized G-SIFIs and LFIs manage model inventories, RAG data lineage, controls, evaluations, findings, policy tests, attestations, evidence retention and remediation.
3. **Executive decisions and escalation.** Translate detailed technical state into exposure, business impact, decision needed, accountable owner, deadline, uncertainty and residual risk.
4. **Education and GIEN scenario planning.** Explore hypothetical GIEN phases VI-δ through XIII and Ω-GAR with visibly synthetic scenarios, versioned assumptions and reproducible replay inputs. Educational scenarios must not be merged into a live evidence store.

### 1.2 Core audience / disclosure matrix

| Audience / role | Default landing view | Default depth | Allowed capabilities |
|---|---|---|---|
| Regulator / supervisory authority | Supervisory Overview, exceptions and filing status | Decision summary, evidence status, trends, crosswalk and artifacts | Read authorized institutions and packages; request evidence; record supervisory actions; approve receipt only where formally authorized |
| Institution risk/compliance | Compliance Matrix, model inventory, open findings | Control mappings, residual risk, applicability and POA&M | Manage assigned findings, attestations, assessments and submission drafts |
| Governance engineer / SRE / security | Operations, telemetry lineage, CI/CD, proof and TEE health | Raw events, configuration hashes, policy tests, trace IDs and verifier diagnostics | Run approved diagnostics and tests; submit remediation evidence; no unilateral risk acceptance |
| Executive leadership / accountable owner | Executive Summary, material changes and decisions due | Impact, options, risk owner, deadlines and decision log | Approve scoped decisions according to delegated authority; cannot erase evidence or self-certify independent review |
| External auditor / independent assessor | Evidence explorer and assessment workspace | Provenance, sampling, tests, exceptions and chain verification | Read-only or explicitly scoped sampling, annotations and findings; independent identity and conflict-of-interest controls |
| Education / research | Scenario Planner and governance timeline | Explanations, examples and synthetic data | Run isolated simulated scenarios; no access to production tenants or submission signing |

Role-based display is not an authorization boundary. Every server endpoint, object lookup, export, websocket subscription, evidence download and action must enforce tenant, institution, region, classification and role permissions server-side. Apply least privilege, separation of duties, dual control for material actions, and step-up authentication for privileged operations.

### 1.3 Progressive disclosure

Each material item should expose three consistent layers:

- **Executive:** state, material impact, confidence/freshness, change from prior cycle, required decision and due date.
- **Governance engineering:** controls, sources, data lineage, tests, policy versions, findings, replay results and remediation links.
- **Cryptographic / examiner detail:** canonical artifact bytes, digests, signer/key identifiers, certificate or trust-chain result, Merkle proofs, verifier version, schema version and reproducibility procedure.

Do not hide a failure behind a single composite score. A summary must preserve “unknown,” “stale,” “not assessed,” “exempted,” and “failed” as different conditions.

## 2. Official-reference research and version controls

The following references were reviewed for this design snapshot on 12 October 2026. Regulatory text and vendor/library documentation change; operational policy must pin exact source version, access date, jurisdiction and applicability assessment.

### 2.1 AI regulation and risk management

| Source | Relevant use | Design rule |
|---|---|---|
| [EU AI Act Service Desk — Article 113](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113) and [FAQ](https://ai-act-service-desk.ec.europa.eu/en/faq) | Consolidated implementation and enforcement timeline | Record the exact legal-text version and applicable date per obligation. The official service desk notes amended passages in its consolidated text as of 27 July 2026. Do not hard-code an old timeline into the application. |
| [EU AI Act — Annex IV](https://ai-act-service-desk.ec.europa.eu/en/ai-act/annex-4), [Article 11](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-11), [Article 15](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-15), [Article 51](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-51) | Technical documentation, accuracy/robustness/cybersecurity and GPAI systemic-risk classification | Build a requirement-to-evidence map; preserve the difference between a high-risk AI system and a GPAI model classified as systemic risk. |
| [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) | Govern, Map, Measure and Manage lifecycle | Use as a voluntary risk-management crosswalk, not as a statute. NIST says AI RMF 1.0 is being revised and published a concept note for a Trustworthy AI in Critical Infrastructure profile on 7 April 2026. |
| [NIST AI 600-1 — Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) | GenAI-specific risks and suggested actions | Map GenAI-specific failure modes to evaluations, monitoring, human review and incident response. |
| [NIST AI Resource Center](https://airc.nist.gov/) | Testing, evaluation, verification and validation material | Pin the version and date of any profile or guidance used to justify a control. |

**EU AI Act article-number disambiguation:** Article 15 concerns accuracy, robustness and cybersecurity for high-risk AI systems. Article 17 concerns the provider’s quality-management system. Article 22 concerns authorised representatives of certain providers established outside the Union. Article 35 concerns identification numbers and lists of notified bodies. Article 51 concerns classification of general-purpose AI models with systemic risk. Annex IV concerns high-risk AI system technical documentation. **GDPR Article 35**, by contrast, concerns data protection impact assessments; **GDPR Article 22** concerns certain solely automated decisions with legal or similarly significant effects. The platform must store framework identifier and jurisdiction alongside every article number to prevent cross-framework collisions.

### 2.2 OSCAL and machine-readable control evidence

- [OSCAL project release news](https://pages.nist.gov/OSCAL/about/news/) lists **OSCAL 1.2.3**, announced 6 August 2026, as the latest patch release in the research snapshot.
- [OSCAL 1.1.2 reference](https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/) remains useful where a recipient or legacy integration explicitly requires that baseline.
- [Open Policy Agent policy testing](https://www.openpolicyagent.org/docs/policy-testing) explains Rego unit testing, result reporting and coverage.

Support OSCAL 1.1.2 as a **pinned compatibility profile where required**, while creating a controlled migration plan to a newer supported schema. Never silently rewrite a signed submission into a new schema. Validate JSON/XML syntax, OSCAL schema and constraints, model references, identifiers, required fields, semantic cross-links and signing manifests separately. A schema-valid object does not prove the control is effective.

### 2.3 ISO management and impact-assessment standards

- [ISO/IEC 42001:2023](https://www.iso.org/standard/42001) specifies requirements and guidance for an AI management system (AIMS).
- [ISO/IEC 42005:2025](https://www.iso.org/standard/42005) provides guidance for AI system impact assessment.
- [ISO/IEC 42006:2025](https://www.iso.org/standard/42006) adds requirements for bodies auditing and certifying AIMS against ISO/IEC 42001.
- [ISO/IEC TS 42119-2:2025](https://www.iso.org/standard/84127.html) provides an overview of AI-system testing using a risk-based approach.

These standards have different scopes. An organization’s AIMS, an AI-system impact assessment, a certification body’s competence and a technical test methodology are not interchangeable artifacts. Store the edition, status, scope and claimed conformity separately.

### 2.4 Cryptography and post-quantum migration

| Standard / scheme | Correct role | Platform requirements |
|---|---|---|
| [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) | Key encapsulation and shared-secret establishment | Use for supported key-establishment workflows; do not label it a digital-signature algorithm. Check current errata before a compliance baseline is frozen. |
| [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) | Digital signatures; parameter sets include ML-DSA-65 and ML-DSA-87 | Pin algorithm and parameter set; validate key lifecycle, implementation and current NIST errata. The CRYSTALS-Dilithium name refers to the selected predecessor family, not a license to omit the standardized ML-DSA identifier. |
| [NIST FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) | Stateless hash-based digital signatures, based on SPHINCS+ | Record SLH-DSA as the standard algorithm identifier and keep parameter set explicit. |
| [NIST FIPS 206 / FN-DSA (Falcon) conference materials](https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon) | Candidate/future-standard tracking | In the official material located for this snapshot, a final FIPS 206 publication was not confirmed. Treat Falcon/FN-DSA as a transition-watch item until authoritative publication and the target compliance profile are checked; do not assert that it is a final FIPS standard. |

Cryptographic assurance is not synonymous with a hash string in a UI. Generate digests over documented canonical bytes, sign manifests using a trusted service with approved keys, verify signatures and key status on the server, and retain the inputs and verification report. WORM retention, Merkle inclusion proofs, signer identity, authorization and trusted time solve different problems and must be assessed separately.

### 2.5 Front-end and visualization references

- [React + TypeScript](https://react.dev/learn/typescript) and the [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/) support typed component contracts and static checking.
- [Next.js App Router](https://nextjs.org/docs/app) supports file-system routing, React Server Components, streaming and server-side capabilities.
- [D3](https://d3js.org/) provides low-level scales, selections, transitions and custom data-driven SVG/DOM graphics.
- [Observable Plot](https://observablehq.com/plot/) offers a concise grammar for tabular-data charts and exploratory analysis.
- [Plotly.js](https://plotly.com/javascript/basic-charts/) supports interactive chart types; [its WebGL/SVG comparison](https://plotly.com/javascript/webgl-vs-svg/) informs large-rendering decisions.
- [OpenAI Platform documentation](https://platform.openai.com/docs/overview) should be treated as a model-provider integration reference only; application policy, data authorization, audit, and independent evaluation remain the application owner’s responsibilities.

### 2.6 RAG and AI application security

[OWASP’s GenAI Security Project](https://owasp.org/www-project-top-10-for-large-language-model-applications/) includes prompt injection and insecure output handling; its [2025 vector and embedding weakness entry](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/) describes issues relevant to RAG, including access-control failures, data poisoning and leakage. RAG controls must cover the ingestion pipeline, source identity, permissions, embeddings, retrieval filters, model context, tool execution and output—not only the prompt template.

The [2025 survey of zero-knowledge proof-based verifiable machine learning](https://arxiv.org/abs/2502.18535) is a research entry point for proof taxonomy and performance trade-offs. Treat research findings as evidence to review, not a substitute for validating the chosen proving system, circuit, trusted setup assumptions, verifier and workload.

## 3. Recommended technology decision

### 3.1 Recommendation for this repository

**Keep React + TypeScript + Vite + React Router + Tailwind + Lucide React as the current implementation baseline.** The application already exists in that shape and lives under gien-platform/ to avoid replacing the repository’s root website. A framework migration before build, tests, identity boundaries and data provenance work would increase change surface without itself providing assurance.

Use:
- React + TypeScript for typed role-specific screens, forms, drawers, evidence views and workflow states.
- React Router for existing routes; use server authorization regardless of client routing.
- Tailwind for a tokenized, accessible design system.
- Lucide React for consistent icons.
- Recharts for routine metrics, time series and comparisons where it improves implementation speed.
- D3 with SVG for custom fairness heatmaps, phase timelines, dependency graphs, containment topology and cross-framework maps.
- Observable Plot only for optional analyst/exploratory views, not as another mandatory chart layer.
- Plotly only if a specific scientific/large-data workflow requires it, after testing bundle cost, accessibility, hosting and licensing. Prefer WebGL for dense point clouds only when the chart remains understandable and a non-WebGL equivalent is provided.
- jsPDF and JSON for generated drafts; final regulator packages must be assembled and sealed by a trusted backend, not by an authoritative browser-only exporter.
- Fuse.js for a user-interface search experience only; it is not an authorization filter. Filter permissible records on the server before returning them to search clients.
- react-diff-viewer for human review of prompt, policy, configuration, model-card or control changes, with the old/new source hashes and author preserved.
- Web Speech API as an opt-in accessibility aid for dictated queries and navigation. Spoken input is untrusted and may be misheard; it must never bypass identity, confirmation or authorization for material actions.

### 3.2 When to consider Next.js

Choose Next.js App Router for a future deployment if server rendering, protected document delivery, a server-side backend-for-frontend (BFF), integrated authentication patterns, routing conventions or deployment constraints clearly require it. The existence of Server Components does **not** guarantee security. Server endpoints must still verify identity, authorization, tenant isolation and object-level access; client bundles must not contain secrets or privileged decision logic.

Avoid operating React+Vite and Next.js as two overlapping front ends unless there is a defined boundary (for example, public documentation versus authenticated supervisor workspace). A static site generator with embedded D3 is appropriate for read-only, non-sensitive publication artifacts, but not sufficient by itself for real-time, role-scoped supervisory workflows.

### 3.3 Visualization choice matrix

| Use case | Recommended visualization | Key safeguards |
|---|---|---|
| S_sys / G-SRI and auxiliary time series | Recharts line/area charts plus a text summary | Units, source timestamp, baseline, uncertainty, null gaps and explicit threshold annotation |
| Domain-by-framework compliance | Accessible HTML table; optional D3 SVG heatmap | Keyboard/screen-reader table equivalent, clear NOT_ASSESSED versus FAIL states |
| GIEN phase / epoch timeline | D3 SVG timeline | Label hypothetical future periods as scenarios, not forecasts |
| Cross-framework and control dependency graph | D3 SVG for moderate size; Canvas/WebGL only for very large graphs | Explain links, allow non-graph table navigation, avoid color-only encoding |
| Fairness evaluation | D3 heatmap and tabular metrics with intervals and cohort counts | Disaggregate, disclose sample size, suppress unsafe small cells, include legal/domain interpretation |
| Attestation regions / RTEE topology | D3 SVG diagram with region table | Show missing/stale state distinctly; do not imply trust from a green-colored node alone |
| Dense replay/trace dataset | Plotly or WebGL after benchmark | Cap and aggregate data, document downsampling, preserve exportable source data |
| Executive dashboard | Small set of stable cards and trends | Avoid overloading with animated charts; every risk claim links to supporting evidence |

For regulator-grade output, every chart needs a title, plain-language takeaway, units, evaluation interval, source status, freshness marker, thresholds, accessible alternative and export semantics. Color must not be the sole carrier of status. Avoid unlabeled dual axes, truncated time windows without explanation and smooth interpolation across missing data.

## 4. Reference architecture and trust boundaries

### 4.1 Logical components

1. **Presentation layer:** React application with audience views, accessible tables/charts, query filters, evidence drawers, alert history and package previews.
2. **Identity and access layer:** Enterprise identity provider, MFA, scoped roles, tenant/region claims, session renewal, step-up auth and server-side object authorization.
3. **BFF / supervisory API:** Validates requests and roles, applies rate limits, returns only authorized records, resolves stable object IDs and provides signed-download URLs or audited actions.
4. **Telemetry intake:** Source-specific adapters for model operations, infrastructure, policy decisions, CI/CD, TEE attestation, proof verifiers and incident systems. Every adapter emits source identity, event time, receive time, schema version and source health.
5. **Policy and assessment services:** OPA/Rego evaluation, policy unit tests, OSCAL schema/model validation, control mapping, assessment state and finding lifecycle.
6. **AI and RAG gateway:** Model registry, approved model versions, prompt/template registry, retrieval service, output checks, tool broker, quotas, redaction and human approval gates.
7. **Cryptographic verification service:** Canonicalization, hash calculation, signature checks, key state, Merkle inclusion and checkpoint continuity, WORM retention checks and verifier reports.
8. **Trusted-execution verifier:** Validates quote freshness, challenge, chain, measurements, revocation and approved PCR policy; provides a server-signed verdict.
9. **Digital Twin / replay worker:** Executes versioned scenarios from controlled fixtures or authorized captured state; emits immutable inputs, run environment, deviations and results.
10. **Evidence and reporting plane:** Object store with enforced retention, metadata database, time-series store, manifest/lineage index and trusted package-sealing service.
11. **Observability and security operations:** OpenTelemetry-style traces/metrics/logs, secret scanning, SAST/DAST, dependency and SBOM checks, SIEM integration, audit monitoring and incident response.

Keep the user-interface plane separate from signing keys, authoritative state, TEE verifiers, policy deployment credentials, WORM administration and release approval. The browser must not be the trust anchor.

### 4.2 Example logical flow

~~~text
Authoritative source
  -> authenticated adapter
  -> schema / provenance / freshness validation
  -> versioned telemetry and evidence records
  -> policy and control evaluation
  -> independent verifier / scenario runner
  -> finding and action workflow
  -> signed package manifest
  -> authorized supervisory dashboard and export
~~~

Any step can return NOT_PROVIDED, STALE, INVALID, INDETERMINATE, FAIL or PASS. A pipeline error must not silently become a zero risk value or a passing control.

## 5. Machine-readable supervisory data model

Model an evaluation as a sealed, versioned record with separate fields for source status and calculation result. Do not use one status field for both evidence availability and control outcome.

### 5.1 Core object types

- **SupervisoryRun:** run ID, evaluation interval, tenant, governance epoch, start/end times, source manifest, status, schema versions, software/build provenance.
- **IndicatorObservation:** metric ID/version, value, units, aggregation method, window, source IDs, calculation version, threshold policy ID, uncertainty/confidence fields, freshness and missing-data state.
- **ControlAssessment:** control ID, requirement reference, implementation reference, assessment method, assessor, result, evidence IDs, exceptions, review time and next review date.
- **EvidenceArtifact:** artifact ID, media type, canonicalization profile, content digest, byte size, source, collection time, classification, retention policy, manifest reference and verification results.
- **AttestationResult:** node/workload, region, quote/challenge references, measurements profile, trust-chain version, policy version, freshness, verifier and verdict.
- **ProofResult:** proof class, circuit/model/policy/verification-key versions, job ID, proof digest, generation and verification latency, outcome, error/timeout, public inputs and claim scope.
- **ReplayBundle:** scenario ID/version, initial-state manifest, inputs/seed, environment/model/policy versions, expected invariants, observed outcome, reproducibility envelope, result digest and deviations.
- **Finding / POA&M:** severity, impact, cause, owner, due date, mitigation, exception approval, change reference, retest results and closure reviewer.
- **FrameworkMapping:** jurisdiction, instrument/version, article/control identifier, applicability status, control mapping, evidence requirement, implementation/test reference, counsel review and change history.
- **GovernancePhase:** phase ID, in-universe period, scenario/live flag, dependencies, preconditions, invariants and transition approval. Future GIEN phases are scenarios, not observed operational states.

### 5.2 Suggested observation record

~~~json
{
  "run_id": "RUN-2026-10-12-0900Z-DEMO",
  "metric_id": "G-SRI",
  "metric_version": "g-sri-v1",
  "value": null,
  "unit": "project-defined index",
  "evaluation_window": {
    "start": "2026-10-11T09:00:00Z",
    "end": "2026-10-12T09:00:00Z"
  },
  "source_status": "NOT_PROVIDED",
  "assessment_status": "NOT_VERIFIED",
  "source_refs": [],
  "calculation_version": null,
  "threshold_policy_id": null,
  "uncertainty": null,
  "notes": "No authenticated observation supplied; do not infer a value."
}
~~~

The example is explicitly a schema illustration, not production telemetry. Production objects require schema validation, controlled enumeration values, access classification, provenance rules and signed artifact references.

## 6. Risk indices, telemetry quality and alerts

GIEN names are fictional/project-defined unless supported by a separate empirical model and published specification. Define each metric before charting it.

| Metric | Required definition fields |
|---|---|
| S_sys, G-SRI, C-SRI | Component variables, normalization, weighting, aggregation, scope and model version |
| CGR-I, CCR-I, G-SRI-VII | Invariant definition, phase or mesh boundary, coherence/resilience semantics and data coverage |
| A-SRI, P-SRI | Asset/system scope, population, risk taxonomy and reference baseline |
| p(doom), p(doom)_kernel | Model and event definition, calibration dataset, probability horizon, assumptions, confidence/uncertainty and limitations |
| Δ_drift | Comparison method, baseline version, population, observation interval and alert policy |
| Δ_OSCAL | Mapping, profile/schema, assessment state and policy-diff definition |
| Proof performance | Proof type, hardware, batch size, model/circuit, p50/p95/p99, queue depth, timeout, verifier failures and liveness |
| Attestation density/coherence | Eligible-node denominator, freshness window, region/criticality distribution, trust policy and excluded nodes |
| RAG quality/security | Retrieval precision/recall, citation support, abstention, source freshness, leakage, injection resilience, refusal correctness, latency and cost |
| Fairness | Use-case-specific measures, cohorts, sample counts, confidence intervals, missing groups, decision threshold and legally reviewed interpretation |

### 6.1 Missing-data and uncertainty rules

- A missing observation is null with a reason code, not zero.
- Stale evidence must retain the original timestamp and age; do not refresh its displayed timestamp.
- A composite indicator must report component coverage and weighting. Missing high-impact components should trigger an indeterminate state rather than hide uncertainty.
- Forecasts must be labeled forecasts and show horizon, model version and calibration evidence.
- A displayed risk threshold must point to its source and approval date. Do not copy a threshold from a hypothetical project specification into an assertion about law.
- p(doom) or p(doom)_kernel must not be presented as an objective probability of existential catastrophe without a defined event, credible data, calibration, independent validation and stated uncertainty.

### 6.2 Alert lifecycle

Represent status as a controlled state machine, for example: OBSERVED -> TRIAGED -> ACKNOWLEDGED -> MITIGATING -> VERIFYING -> CLOSED, with separate ESCALATED and REOPENED states. Every transition records actor, reason, timestamp, evidence and prior state. Closure requires objective retest criteria and the designated reviewer; a green dashboard does not close a finding.

## 7. Zero-trust deployment, TEE and GitOps

- Pin container images by digest, enforce signed build provenance and generate an SBOM.
- Require review and automated checks for infrastructure changes; use least-privilege deployment identities and environment separation.
- Enforce policy on cluster admission and runtime, not only in a dashboard.
- Treat TEE/TPM/vTPM attestation as a freshness-bound verdict for a specific measurement profile, workload and policy version.
- Track registered, eligible, fresh, valid, failed, stale, revoked and unreachable nodes separately.
- Require nonce/challenge binding, trust-chain validation, approved PCR measurements, event-log interpretation, revocation checks and a reason-coded verdict.
- Do not infer PCR_MATCH=TRUE from a monitoring placeholder or a developer-supplied boolean. The verifier must compute or attest the result from authentic quote material.
- Bind the authorization decision to workload/image/model/policy hashes and re-attest after relevant deployment or configuration changes.
- GIEN-ZTAI-02 remains OPEN_OR_UNVERIFIED until a documented finding, change record, regression tests, post-deployment evidence and authorized closure review are present.

## 8. zkML, fairness and autonomous-agent controls

### 8.1 Proof pipeline measurements

Separate proving from verification. Report queued, attempted, completed, valid, invalid, timed-out and rejected jobs; generation and verification p50/p95/p99; proof and public-input sizes; hardware/circuit versions; resource consumption; and per-stage failures. Maintain a verification-key registry with activation time, old/new key references, test evidence, rotation owner and rollback procedure.

A zero-knowledge proof establishes a property of a defined statement under the proof system’s assumptions. It does not prove that the statement describes the right real-world property, that training data are fair, that an outcome is lawful, or that a model behaves safely outside the proven computation.

### 8.2 Fairness and lending

Use a panel of measures appropriate to the decision context, including selection/approval rates, false-positive/false-negative differences where relevant, calibration, subgroup performance, intersectional analysis, outcome quality, confidence intervals and sample counts. A ratio such as the commonly discussed 0.80 selection-rate heuristic is not a universal fairness test or legal safe harbor. FCRA/ECOA applicability and adverse-action obligations require jurisdiction- and product-specific legal review.

Never expose small sensitive cohorts where a dashboard might make a person identifiable. Suppress or aggregate small cells and retain the suppression rule in exported results.

### 8.3 Autonomous Supervisory Agent

The agent may recommend actions and assemble evidence but must not self-authorize its own privilege escalation, modify protected policy without review, certify its own independent assurance, or silently close a material finding. Use scoped tools, typed action schemas, policy checks before execution, human approval for consequential actions, idempotency keys, bounded retries, independent audit events and emergency-stop verification.

## 9. RAG and CCaaS generative summarization governance

### 9.1 RAG lifecycle

1. **Ingest:** authenticate source and tenant; validate media type; scan for malware; normalize; record rights, license, classification, owner and retention.
2. **Provenance:** calculate the document digest over canonicalized content; preserve original artifact and a transformation log; identify OCR/extraction/normalization versions.
3. **Prepare:** detect hidden text or suspicious instructions; classify data; redact or tokenize PII where appropriate; create chunk and embedding lineage.
4. **Index:** apply tenant and document ACLs; enforce metadata filters before content reaches the prompt; record corpus, embedding model and index versions.
5. **Retrieve:** return evidence IDs, source and segment offsets, freshness, access decision and relevance scores. Prevent a vector similarity result from overriding access permissions.
6. **Generate:** distinguish system policy, user instruction and retrieved untrusted content; defend against direct and indirect prompt injection; restrict tools, credentials and network destinations.
7. **Verify:** check citation support, factual consistency, disclosure policy, output schema, data leakage and prohibited actions. Abstain or escalate if supporting evidence is weak.
8. **Monitor:** measure retrieval quality, answer groundedness, citation validity, refusal correctness, attacks detected, user feedback, latency, cost, drift and data freshness.
9. **Change control:** evaluate new sources, chunking, embedding, reranker, prompt, model and tools separately; compare against a frozen test set; require authorized promotion.

Never let retrieved text become executable instructions by default. Keep model output separate from tool execution and require server-side policy authorization for every tool action.

### 9.2 CCaaS call summarization and privacy-enhancing technologies

For call transcription/summarization, minimize data captured, document purpose and legal basis, apply notice/transparency requirements, classify voice and transcript data, pseudonymize or redact unnecessary identifiers, restrict model-provider processing, configure regional processing and retention where available, and complete a DPIA where required. Encryption and pseudonymization are safeguards but do not by themselves make processing compliant with GDPR.

Keep source audio/transcript, transformation log, summary, citations, model/version, confidence, human corrections and retention disposition linked by stable IDs. Restrict access and deletion consistently across audio, transcripts, embeddings, caches and exports. Human review is required for material customer or credit decisions; a summary must not silently become the authoritative transaction record.

### 9.3 Recommended RAG evaluations

Maintain a versioned suite for: retrieval recall/precision, citation entailment, answer groundedness, abstention, contradictory-source handling, stale-source detection, tenant leakage, prompt injection, poisoned documents, exfiltration attempts, unauthorized tool access, toxicity/harassment, sensitive-data exposure, latency, token cost and accessibility. Report absolute values plus baseline deltas, sample sizes and error bars. Record model/provider version and test corpus digest.

## 10. Compliance-as-code and OSCAL workflow

The compliance pipeline maps a requirement to a control objective, control implementation, test method, evidence type, owner, frequency, applicability, status and remediation path.

### 10.1 Regulatory crosswalk design

Prioritize legal applicability in the following order, with the exact scope determined for the regulated entity and use case:

1. **EU / EEA:** EU AI Act as applicable, GDPR, DORA, NIS2 (subject to scope and national transposition), and relevant financial-services law.
2. **United States:** Federal Reserve SR 26-2 where in scope; keep SR 11-7 as historical or transition context where applicable; ECOA/FCRA and SEC Rule 17a-4 only for relevant products/entities/record types.
3. **International management and risk references:** NIST AI RMF 1.0, NIST AI 600-1, ISO/IEC 42001, ISO/IEC 42005 and applicable information-security controls.
4. **Asia-Pacific / UK:** MAS FEAT, applicable MAS supervisory guidance, HKMA guidance including Fintech 2030, and FCA SM&CR / Consumer Duty depending on regulated activity and jurisdiction.
5. **Bank risk reporting:** applicable Basel Committee standards and supervisory expectations, including BCBS 239 for risk-data aggregation/reporting where in scope; “Basel IV” is a common informal label, not a distinct single treaty instrument.
6. **GIEN-only scenario instruments:** CFE-1.0, SGR-028, ICGC/GASO, Interstellar AI Governance Accord and Galactic Treaty Framework. Tag as fictional/project-defined until canonical instruments and competent authority are established.

The framework catalog must include owner, official source, version/effective date, jurisdiction, applicability rationale, change-monitoring subscription, legal-review owner and crosswalk approval. An AI RMF or ISO mapping supports risk management; it does not itself establish compliance with legislation.

### 10.2 OSCAL artifact workflow

1. Pin the target OSCAL version and retrieve its official schema and constraints.
2. Validate JSON/XML syntax and model conformance.
3. Validate ID/reference integrity, controlled vocabularies, required objects and cross-object relationships.
4. Evaluate Rego policy against typed input fixtures, including positive, negative, boundary and missing-data tests.
5. Generate SSP, assessment-results and POA&M artifacts with evidence references and responsible parties.
6. Run independent verification of manifest, signatures, artifact retention and bundle completeness.
7. Review failures and exceptions; document applicability decisions and residual risk.
8. Freeze the signed artifact set and transmit through an authenticated, receipted channel.

Keep the existing OSCAL 1.1.2 integration as an explicitly pinned compatibility profile. Assess migration to the newer supported patch release only through an impact analysis, dual validation, change approval and recipient compatibility test. Do not edit previously signed packages in place.

### 10.3 Policy examples and automated testing

Policy bundles should be versioned, reviewed, signed and promoted through CI/CD. Tests should cover allowed and denied cases, missing inputs, malformed data, stale source timestamps, inconsistent identifiers, privilege boundaries, tenant isolation and exception handling. CI must fail if no tests were discovered, if schema validation fails or if an unapproved policy bundle is loaded.

The policy simulator should show the policy version, input fixture, decision, rule path, warnings and test coverage. Never allow a client-side simulation to authorize an actual production action.

## 11. Cryptographic evidence, WORM and Merkle-DAG

Each evidence object should have an artifact ID, source identity, timestamp/clock assumptions, media type, classification, canonicalization profile, byte digest, signer identity, algorithm identifier, key ID, retention policy, parent references and validation report.

Required controls:

- Establish the hash over documented canonical bytes; never assume JSON object ordering is stable.
- Build a signed manifest binding each artifact digest, schema, version, timestamp and parent/root reference.
- Verify signature cryptographically and check the key’s status/authorization at the relevant time.
- Verify Merkle inclusion and prior-checkpoint continuity; detect missing records, duplicates and unexpected reorderings.
- Configure and test WORM retention independently from application claims; restrict and audit privileged storage administration.
- Exercise backups/restores, retention locks, legal holds, key revocation and signing-key recovery.
- Keep FIPS 203 key establishment separate from FIPS 204/205 signing functions.
- Record algorithm migration as old/new verifier support, activation boundary, test coverage, historical-verification plan and rollback process.
- Store large raw evidence in the appropriate controlled object repository; use signed references and bounded metadata in the dashboard.

“Merkle-DAG valid” should be a verifier output with explicit scope, not a decorative green badge. A valid signature says which key signed the bytes; authorization, correctness, completeness and lawful provenance remain separate questions.

## 12. System components and route map

| Route / component | Function and principal inputs |
|---|---|
| Dashboard / ExecutiveSummary | Cycle state, material incidents, trend deltas, top exceptions and decisions due |
| SystemicRiskTelemetry / GlobalStatusOverview | Versioned indices, source freshness, confidence, threshold policy and time-series |
| ComplianceMatrix / ComplianceRegulatory | Frameworks × controls, applicability, evidence, tests, gaps, owners and review dates |
| GovernanceStacks | Sentinel v2.4, Omni-Sentinel v4.0 and SCP v3.0 configuration and status—only from verified sources |
| ControlDomains | CD-01–CD-10 catalog, assessment and evidence drill-down |
| CryptographicIntegrity | Key inventory, signatures, Merkle continuity, WORM state and historical verifier results |
| RAGHealthMonitor | Retrieval quality, source freshness, citations, attack tests, cost and latency |
| RAGDataAudit / RAGDataProvenance | Source lineage, transformation log, content digest, access decision, embedding/index revisions |
| PromptArchitect / TemplateLibrary | Versioned templates, variables, constraints, diff, evaluation set, approval and rollback |
| GovernancePolicySimulator / OPAPolicyScanner | Rego evaluation and test fixture; no production authorization from browser simulation |
| FairnessHeatmap / ParityDashboard | Cohort-level metrics, sample counts, uncertainty and tool/capability parity |
| SDTStressDrills / Digital Twin | DRILL-042–047, Panels 13–15, deterministic input/output manifests and deviations |
| IASOS / CivilizationalReadinessMonitor | Fictional readiness metrics with definition, horizon, provenance and assumptions |
| MaterialChangeTracker | Model, data, prompt, policy, key, dependency and infrastructure changes with approvers and post-change tests |
| VoiceCommander | Accessible search/navigation and draft dictation; no unconfirmed speech-triggered privileged action |
| AlertHistory / RealTimeNotificationService | Source timestamp, severity, owner, acknowledgement, SLA clock, escalation and export |
| RegulatoryRoadmap / GovernanceHierarchy | Versioned legal milestones and fictional GIEN phase timeline shown on separate tracks |
| GlobalSearch | Server-filtered accessible objects, then local Fuse.js search over the authorized result set |
| SubmissionPackages / RegulatorExport | Preview and draft export; final package assembled, validated, signed and receipted by backend |
| AppWalkthrough | Role-based onboarding, evidence-status legend and safe-use warnings |

### 12.1 API outline

Use versioned, authenticated APIs such as:

- GET /api/v1/supervisory-runs
- GET /api/v1/indicators?runId=...
- GET /api/v1/controls?framework=...&status=...
- GET /api/v1/evidence/{artifactId}/manifest
- POST /api/v1/evidence/{artifactId}/verify
- GET /api/v1/attestations?region=...&freshness=...
- GET /api/v1/proof-jobs?status=...
- POST /api/v1/replays (authorized, isolated scenario execution)
- POST /api/v1/policy-evaluations (server-side evaluation; fixture-scoped by default)
- POST /api/v1/findings/{id}/evidence
- POST /api/v1/submission-packages (creates a draft)
- POST /api/v1/submission-packages/{id}/validate
- POST /api/v1/submission-packages/{id}/seal (strong authorization, dual control and backend key)
- POST /api/v1/submission-packages/{id}/dispatch (authorized channel, receipt and idempotency key)

Mutation endpoints require request IDs, actor and reason, optimistic concurrency controls, replay protection and idempotency semantics. Do not expose endpoints that accept a client-claimed signature status, attestation truth value, trusted root or arbitrary risk score as authoritative data.

## 13. UX, voice, notifications and emergency action

- Provide role-specific navigation, keyboard operation, skip links, readable typography, chart alternatives, focus management, visible loading/error/empty states and responsive layouts.
- Surface freshness, scope and evidence quality beside every significant figure.
- Keep chart state and data-table state synchronized. Provide CSV/JSON export with source timestamps, units, filters and definitions.
- Use notifications as alerts, not evidence. Each notice links to a canonical record and can be acknowledged with actor and timestamp.
- Use Web Speech API only with explicit permission. Show the recognized text for confirmation; allow correction and keyboard alternatives.
- An emergency-stop control must be implemented on the server, with strong authorization, anti-CSRF protection where relevant, replay-resistant requests, a reason, explicit confirmation, idempotent action semantics, and an independent audit entry. Display request accepted, execution confirmed and execution failed as distinct states. Client UI cannot assert that a control-plane stop has occurred merely because a button was clicked.
- Design a hierarchy of safing actions: stop new work, revoke a scoped tool credential, suspend a model route, disable a privileged workflow, and invoke institution-approved incident procedures. Execution should follow the approved risk analysis and authority model, not a generic browser action.
- Ensure the emergency-stop surface does not become an unauthenticated denial-of-service mechanism.

## 14. Supervisory daily cadence and package template

### 14.1 Time-bound evaluation

For a reporting window ending at 09:00 UTC, explicitly label the interval, for example 11 October 2026 09:00 UTC to 12 October 2026 09:00 UTC. Freeze the snapshot at the cutoff. If the operational archive transmission is scheduled at 08:00 UTC and cycle closure at 23:59 UTC, keep their event records distinct from the 09:00 snapshot; do not backdate late-arriving evidence into the frozen snapshot.

Suggested sequence:

1. Ingest events and source health continuously; preserve event time and receive time.
2. At 08:00 UTC, run the nominated archive-transmission workflow and capture receipt status if available.
3. At 09:00 UTC, freeze the evaluation window and record which sources were missing, stale or delayed.
4. Validate controls, indicators, attestations, proofs, replay records and ledger continuity.
5. Derive the cross-jurisdictional compliance bundle; unresolved validations create explicit exceptions.
6. Assign owners and SLA deadlines, and preserve decisions and acknowledgements.
7. At 23:59 UTC, execute closure checks and seal the daily archive only if required artifacts and signing/verification operations actually succeed.

### 14.2 Submission format

~~~xml
<submission>
  <title>GIEN Daily Supervisory Brief — YYYY-MM-DD</title>
  <abstract>Evidence-qualified summary, evaluation interval, material exceptions and decisions required.</abstract>
  <content>
    <scope>Institutions, systems, jurisdictions and source versions.</scope>
    <status>Observed, demonstration, missing, stale and unverified states.</status>
    <riskIndicators>Versioned results, confidence, baseline and threshold policies.</riskIndicators>
    <controls>GIEN CD-01 to CD-10 and applicable external control references.</controls>
    <evidence>Artifact identifiers, digests, signature and verifier result references.</evidence>
    <findings>Severity, owner, deadline, mitigation and closure evidence.</findings>
    <replays>Scenario IDs, panel, inputs, run environment and outcomes.</replays>
    <compliance>Applicability decisions and OSCAL/policy validation status.</compliance>
    <decisions>Approver, authority, rationale and residual risk.</decisions>
    <limitations>Data gaps, assumptions, uncertainty and assurance boundary.</limitations>
  </content>
</submission>
~~~

The wrapper is an illustrative project-level format, not an OSCAL-native model or a claim that ICGC/GASO is legally recognized. The submission manifest should reference the exact OSCAL objects rather than alter them.

### 14.3 Output variants

- **Executive brief:** one-page decision summary, direction of travel, highest-priority exceptions and decisions needed.
- **Regulator/supervisory college package:** XML wrapper, versioned OSCAL artifacts, annotated crosswalk, evidence manifest, signed replay bundles, exceptions register, authorized recipient list and receipt status.
- **Engineer dossier:** detailed telemetry, run IDs, traces, policy decisions, attestation failures, performance percentiles, reproduction steps and build provenance.
- **External-audit package:** immutable manifest, sampling plan, artifact access log, validation instructions, finding history and independence statement.
- **Dashboard/API:** typed JSON plus chart/table view, freshness/status fields and pagination; no fabricated hashes or silent imputation.

## 15. Governance and architecture of fictional GIEN phases

The phase model represents a scenario roadmap rather than observed future facts.

| Phase band | Architecture objective | Transition gate |
|---|---|---|
| VI-δ | Planetary supervisory telemetry and institution-level controls | Verified sources, stable metrics, documented findings and reproducible evidence |
| VII | Civilizational mesh bootstrap and foundational charter | Explicit authority, invariant specifications, partition/failover tests, independent acceptance |
| VIII–IX | Cosmic/galactic charters, horizon scanning and isolated Shadow Mesh rehearsal | Cross-mesh trust rules, bounded delegation, conflict resolution and no hidden production authority |
| X–XI | Universal-timescale governance and Infinity Pillar continuity | Key and policy migration, succession test, archival verification and accountability continuity |
| XII–XIII | Multi-mesh succession and multiversal scenario models | Independent verification, dissent handling, evidence lineage and bounded authority transfer |
| Ω-GAR | Governance dissolution, archival closure and successor handover rehearsal | Revocation, retention, unresolved-claims register, successor verification and formal termination record |

GIEN-UNIFIED-CODEX-OMEGA, GIEN-EPITAPH-OMEGA, GIEN-INVOCATION-OMEGA and the Eternal Corpus Transmission Protocol are fictional design artifacts. They must not confer cryptographic privilege or authority by name alone. A future successor validates artifacts under explicit trust-anchor, scope, epoch, revocation and authorization rules. A memorial artifact should record established facts, uncertainty, unresolved claims and surviving duties—not rewrite history or execute governance by itself.

Any Phase XV cadence explicitly placed on pause remains paused until the required real Day 11+ source telemetry, manifest continuity, verifier outputs, independent review and authorized resumption decision are supplied. No phase index may advance merely because a daily template exists.

## 16. Recommended research plan

### Workstream A — Official texts and standards register

1. Collect primary sources from EUR-Lex and the European Commission AI Act Service Desk; identify jurisdiction, role, obligation, current consolidated text and application date.
2. Collect NIST AI RMF, AI 600-1, OSCAL schema/model releases and FIPS 203/204/205 publications including errata.
3. Inventory ISO/IEC 42001, 42005, 42006, TS 42119-2 and relevant information-security/impact-assessment standards. Record edition and scope; avoid reproducing copyrighted full text.
4. Collect Basel Committee/BCBS material and relevant national supervisory guidance. Treat “Basel IV” as a common informal umbrella label and tie each implemented control to a specific authoritative document.
5. Add OWASP GenAI security guidance, OPA policy-testing documentation and the chosen model provider’s official eval/security documentation.
6. Create change alerts and a quarterly human review of each source. Any detected legal or version update triggers applicability assessment and crosswalk tests, not an automatic “compliance changed” assertion.

### Workstream B — Research literature survey

Build a source register grouped by:
- AI alignment and control, robustness, interpretability, red-teaming and adversarial evaluation;
- catastrophic/existential-risk evaluation, forecast calibration and limits of risk aggregation;
- RAG grounding, source provenance, prompt injection, poisoning, access controls and privacy;
- zero-knowledge and verifiable ML (training, inference and testing), proof size/latency, circuit limitations and soundness assumptions;
- systemic risk in financial/AI dependencies, contagion, common-mode failure, concentration and operational resilience;
- human factors, fairness, contestability, accessibility and governance effectiveness.

For each source record: citation, publication date, venue, study type, system/model scope, evaluation method, evidence limitations, conflicts, practical implications and transferability to the GIEN scenario. Prefer peer-reviewed and primary sources when available; include reproducibility artifacts where accessible. Do not claim consensus from a handful of papers.

### Workstream C — Technology and DevSecOps inventory

Evaluate the pinned React/Vite implementation and candidate alternatives against:
- active maintenance and official documentation;
- security advisories, dependency provenance, SBOM and supply-chain controls;
- accessibility and non-color status encoding;
- renderer performance under the expected dataset size;
- server authorization and auditability;
- deployment, observability, testing and rollback;
- licensing and operational cost.

Benchmark D3 SVG, Recharts, Observable Plot and Plotly with representative datasets on the target browsers. Measure initial bundle size, interaction latency, memory, accessibility and export fidelity. Keep only libraries that solve distinct needs.

### Workstream D — Crosswalk and evidence model

Create a versioned requirement-to-control-to-test-to-evidence matrix. Validate that every applicable requirement has an owner, implementation reference, test frequency, evidence type, retention rule, exception process and legal-review owner. Test both positive and negative cases. Preserve non-applicability decisions and the evidence supporting them.

### Workstream E — Reference implementation and acceptance tests

Deliver in the following sequence:

1. Typed synthetic data contracts and clear DEMONSTRATION banners.
2. Server-side identity, tenancy and object-level authorization boundary.
3. Versioned metric registry, source freshness and indeterminate-state UX.
4. Control assessment and OPA/Rego test pipeline.
5. OSCAL pinned-schema validation and migration test.
6. Evidence manifests, canonicalization and independent verification service.
7. RAG ingestion and evaluation harness with attack fixtures.
8. TEE/TPM attestation adapters and a dedicated test environment.
9. Digital Twin replay bundle and deterministic/within-tolerance comparison.
10. Role-specific export, sealed submission path, incident/notification integration and accessible UI regression testing.

### Workstream F — Acceptance and operational gates

Release requires:
- clean production build, lint, unit/integration/e2e and accessibility checks;
- dependency/license/SBOM and secret scans;
- tests for tenant isolation, role escalation, insecure direct object references and export permission bypass;
- schema, signature, Merkle-continuity and retention tests against non-production fixtures;
- missing-data, stale-data, delayed-source and contradictory-source tests;
- prompt-injection, RAG-poisoning, citation-validation and unauthorized-tool tests;
- fairness metrics with documented populations, cohort sizes and confidence intervals;
- failure-injection / recovery tests for attestation, proof verification, policy service and evidence storage;
- review of the final submission by accountable compliance/legal owners and independent assessors where required;
- a documented rollback and incident procedure.

## 17. Delivery roadmap

| Stage | Deliverable | Exit criteria |
|---|---|---|
| Stage 0 — evidence baseline | Source register, data classification, role model and metric definitions | Owners approve scope, no unknown source is represented as live |
| Stage 1 — app foundation | Dashboard, role-aware views, accessible tables/charts and typed demo data | Build/test gates pass; demonstration state visible on every relevant screen |
| Stage 2 — control engine | Framework catalog, OSCAL validation, OPA unit tests, finding/POA&M lifecycle | Reproducible positive/negative policy tests and traceable artifact IDs |
| Stage 3 — evidence integrity | Manifest, canonicalization, signature verifier, Merkle/WORM evidence service | Independent verification succeeds on controlled fixtures; key custody is server-side |
| Stage 4 — AI/RAG assurance | Corpus provenance, evaluations, prompt/tool controls and drift monitoring | Security/evaluation suites run against fixed versions and document limitations |
| Stage 5 — live integrations | Authenticated telemetry adapters, attestation and proof-verifier adapters | Source health, freshness and schema failures surfaced; no synthetic fill-in |
| Stage 6 — supervisory release | Sealed package workflow, receipt tracking, independent audit and operational runbooks | Build, security, evidence, authority and recovery gates all approved |
| Stage 7 — long-horizon scenarios | Phase VII–XIII and Ω-GAR scenario lab | Scenario fixtures isolated and phase transitions explicitly approved |

The 2026–2035 program should prioritize evidence provenance, institution-level controls, legal applicability, operational resilience, cryptographic agility and independently testable claims. The 2035–2100+ view is a scenario design horizon, not a prediction or a claim that a multiversal governance system exists. Re-evaluate assumptions at defined governance reviews instead of presenting speculative phase dates as certainty.

## 18. Immediate implementation priorities

1. Keep the current Vite front end and avoid a framework rewrite until the existing build and test pipeline is reliable.
2. Make source status explicit everywhere: LIVE_VERIFIED, DEMONSTRATION, STALE, NOT_PROVIDED, INVALID or NOT_ASSESSED.
3. Establish metric specifications before adding further charts.
4. Implement server-side RBAC, tenancy and export authorization before connecting real telemetry.
5. Add OSCAL version pinning and Rego tests to CI, including “fail on empty test suite.”
6. Integrate only real verifiers for signatures, Merkle chains and TEE quotes; remove any path that converts placeholders into green status.
7. Keep GIEN phase scenarios and treaty artifacts separate from legally applicable requirement records.
8. Treat Guardian Attestation and historical filing IDs as milestones that need original artifacts, authorized countersignatures and verification output—not as completed merely because the date passed.
9. Resolve the known CI startup/build verification issue before merge or deployment.
10. Have legal/compliance owners confirm applicability for each regulated entity and product; the platform supports evidence organization, not a substitute for professional regulatory determinations.

## Appendix A — Evidence-state vocabulary

| State | Meaning |
|---|---|
| OBSERVED | Data retrieved from a named source with a traceable source timestamp |
| VERIFIED | A specified validator independently confirmed the relevant property; scope of verification must be stated |
| DEMONSTRATION | Synthetic fixture or illustrative scenario only |
| NOT_PROVIDED | Required source artifact absent from the current run |
| STALE | Artifact exists but exceeds the configured freshness policy |
| INVALID | A specific validator failed |
| INDETERMINATE | Evidence conflicts, is insufficient or the validator cannot decide |
| NOT_ASSESSED | A control was not tested in the period |
| NOT_APPLICABLE | Applicability decision recorded with rationale and approving owner |
| EXCEPTION_APPROVED | Designated authority accepted a bounded exception, with expiry and review date |

“Verified” must always identify who/what performed the verification, which property was checked and which input version was used. A successful hash check, schema validation, Rego test or proof verification must not be generalized to “system compliant.”

## Appendix B — Core external source register

1. [European Commission AI Act Service Desk — Article 113](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-113) — consolidated applicability timeline; check the specific text version.
2. [AI Act Service Desk — Annex IV](https://ai-act-service-desk.ec.europa.eu/en/ai-act/annex-4) — high-risk technical documentation.
3. [AI Act Service Desk — Article 15](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-15) — accuracy, robustness and cybersecurity.
4. [AI Act Service Desk — Article 51](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-51) — GPAI models with systemic risk.
5. [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) and [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf).
6. [OSCAL release news](https://pages.nist.gov/OSCAL/about/news/) and [OSCAL 1.1.2 reference](https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/).
7. [ISO/IEC 42001](https://www.iso.org/standard/42001), [42005](https://www.iso.org/standard/42005), [42006](https://www.iso.org/standard/42006) and [TS 42119-2](https://www.iso.org/standard/84127.html).
8. [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).
9. [Open Policy Agent — policy testing](https://www.openpolicyagent.org/docs/policy-testing).
10. [OWASP GenAI Security Project](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and [LLM08:2025 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/).
11. [Zero-Knowledge Proof Based Verifiable Machine Learning survey](https://arxiv.org/abs/2502.18535) — research review; assess assumptions and scope before selecting a system.
12. [React TypeScript guide](https://react.dev/learn/typescript), [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/), [Next.js App Router](https://nextjs.org/docs/app), [D3](https://d3js.org/), [Observable Plot](https://observablehq.com/plot/) and [Plotly.js](https://plotly.com/javascript/basic-charts/).

**Maintenance note:** recheck source status before using this document for a regulatory submission. This file is a researched design reference; it does not establish that any GIEN system has run, that any metric has been observed, or that any regulatory obligation has been met.
