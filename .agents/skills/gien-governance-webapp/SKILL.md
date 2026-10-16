---
name: gien-governance-webapp
description: Use when designing, implementing, reviewing, testing, or preparing evidence for the GIEN/Omni-Sentinel AI-governance supervisory web application. Enforces evidence-qualified reporting, secure control-plane boundaries, privacy-by-design, reproducible compliance mappings, and CI/release gates.
---

# GIEN Governance Web Application Skill

## Purpose and operating boundary

Build and review the GIEN / Omni-Sentinel supervisory application as an enterprise governance reference implementation. The application may render telemetry, risk indicators, assurance records, compliance mappings, RAG provenance, fairness tests, stress drills, and submission packages. It must not imply that fictional GIEN infrastructure is real, that mock telemetry is live, or that a generated dossier is an actual regulatory filing.

Use the following product labels consistently:
- **DEMONSTRATION DATA** — deterministic or hand-authored example values.
- **CONNECTED / OBSERVED** — data obtained from an identified source, with source identity and collection time.
- **VERIFIED** — a named verification procedure ran successfully against identified inputs and produced retained evidence.
- **INDEPENDENTLY ASSURED** — use only when a competent independent reviewer has issued a traceable assurance result for the stated scope.
- **REGULATOR ACCEPTED / APPROVED** — never infer this from a successful build, a passed local validator, a mapped control, or a successful transmission attempt.

All UI views, exports, and footers must preserve this distinction. No fabricated attestations, signatures, certificate identifiers, Merkle roots, regulator acknowledgements, proof results, or production status.

## Default technology and code organization

Preferred frontend: React 18+, TypeScript strict mode, Vite, Tailwind CSS, React Router, Lucide React, Recharts for standard telemetry charts, and D3.js for custom heatmaps, timelines, parity visualizations, and graph layouts. Add Web Speech API, react-diff-viewer, jsPDF, Fuse.js, and OPA/Rego integration only where the app actually uses them. Lock dependency versions and retain the package lockfile.

Recommended structure:

```text
src/
  app/                 # router, shell, role-aware navigation
  components/          # accessible shared UI, metric cards, tables, dialogs
  features/
    prompt-architect/
    voice-commander/
    risk-telemetry/
    compliance/
    fairness/
    rag-audit/
    alerts/
    digital-twin/
    governance-stacks/
    submissions/
    recommendations/
  data/                # schemas, demo fixtures; never mix fixtures with live adapters
  services/            # typed API clients and adapters
  policy/              # policy decision client and policy metadata
  evidence/            # provenance, freshness, signatures and evidence-status helpers
  exports/             # CSV/JSON/PDF builders and export manifests
  contexts/            # theme, notification, session and app state
  types/
  test/
```

Keep network, policy, cryptographic verification, and authorization logic outside React components. Components display typed state and dispatch well-defined commands; they do not decide authorization or claim that security controls succeeded.

## Data and evidence contracts

Use typed, versioned contracts for all telemetry and evidence. Each observation should have at least:
- `metric_id`, `value`, `unit`, `threshold` and `threshold_version`;
- `observed_at`, `window_start`, `window_end`, and source clock/timezone;
- `source_id`, `source_type`, `source_uri` or immutable source reference, and `data_classification`;
- `evidence_status`, `verification_method`, `verification_result`, `verifier_version`, and `evidence_ref`;
- applicable `model_version`, `policy_version`, `schema_version`, and `jurisdiction_scope` where relevant.

Represent missing, stale, partial, disputed, and failed observations explicitly. Do not convert missing telemetry to zero or silently carry forward the last value. Derive daily deltas only from two comparable, source-backed observations with compatible definitions. If units, populations, measurement windows, or metric versions differ, show the comparison as unavailable.

For the daily dossier, define the evaluation window explicitly (normally the prior 24 hours ending at 09:00 UTC). Make all status, timestamp, digest, signature, and submission fields traceable to the source record. A dashboard status color must be derived from a versioned rule, not manually set in a React component.

### GIEN metrics

Support the metric identifiers required by the product: `S_sys`, `G-SRI`, `C-SRI`, `CGR-I`, `CCR-I`, `G-SRI-VII`, `A-SRI`, `P-SRI`, `p(doom)`, `p(doom)_kernel`, `Δ_drift`, and `Δ_OSCAL`. Provide a definition, unit, aggregation method, source, owner, freshness SLO, threshold history, uncertainty, and response playbook for every metric before enabling operational alerts.

The names and thresholds are project-defined indicators, not externally validated standards. Display them as demonstration data until a governed metric specification and verified producer are connected. Treat `p(doom)` as a model output with documented assumptions and calibration, not an objective measurement of existential risk.

## Principal feature requirements

### PromptArchitect

- Maintain immutable prompt/template versions, change diffs, owners, purpose, data-classification constraints, allowed tools, model/provider, evaluation results, approvals, and rollback references.
- Run prompt-injection, jailbreak, data-exfiltration, unsafe-tool, schema, and sensitive-data checks before promotion. Include adversarial and regression tests.
- Treat retrieved passages and user-provided content as untrusted data, never as instructions that can override system policy.
- Block promotion on missing provenance, expired approval, unsupported claims, failed safety tests, or policy-deny decisions. Show the reason and the evidence used to decide.
- Keep test, staging, and production configurations separate; require human approval for production activation.

### VoiceCommander and emergency stop

- Web Speech API recognition and speech synthesis are optional convenience layers, not security controls. Always provide typed and keyboard-operable alternatives, communicate recognition state, and handle unavailable permissions or browser support.
- Apply an allow-list of recognized commands; map aliases to typed command IDs; do not execute arbitrary speech as code, prompts, shell commands, or policy expressions.
- Require explicit confirmation and a visible scope summary for high-impact actions. “Emergency stop” should trigger a server-authorized control-plane request, not merely a browser state change.
- The server must authenticate and authorize the operator, enforce role and environment scope, use idempotency keys, emit an append-only audit event, return an authoritative action result, and verify the resulting system state independently.
- While stop is active, disable autonomous or consequential workflows and block resume except through a separately authorized recovery sequence. Resume requires explicit authorization, recorded rationale, precondition checks, and a complete audit trail. Voice recognition alone must never initiate resume.
- Provide a non-voice fallback, focus management, announcement through accessible live regions, a confirmation dialog, and a persistent stop-state banner.

### Risk telemetry and D3.js / Recharts

- Use Recharts for conventional time series and comparative bar charts. Use D3.js for data transforms and custom FairnessHeatmap, vertical timeline, ParityDashboard, RAGGovernanceDashboard heatmaps, and relationship graphs when needed.
- Give all charts accessible names, unit labels, legends, equivalent tables or text summaries, and keyboard-accessible filters. Never encode status only by color.
- Show observation time, time window, source, freshness, sample size, uncertainty, threshold version, and evidence status beside the visualization. Support missing intervals explicitly.
- Keep visual domain and color scales deterministic for comparative periods. Use stable identifiers and avoid animation that obscures rapid state changes.
- Performance: aggregate on the server for large time windows, use pagination or virtualized tables, and avoid rerendering every visualization on each telemetry event.

### FairnessHeatmap and ParityDashboard

- Identify the task, outcome, labels, population, protected or legally relevant groups, intersectional groups where lawful and justified, measurement window, and sample sizes.
- Report the metric definition and confidence interval; include disparate impact, demographic parity, equalized odds, calibration, or counterfactual tests only where appropriate to the use case.
- Do not present a single threshold as universally required by law. The 0.800 Disparate Impact Ratio floor is a project-specific screening rule; applicability, exceptions, uncertainty, and jurisdictional context need human review.
- Suppress or aggregate groups when disclosure risk is material. Do not infer protected attributes from proxy signals without a lawful basis and documented necessity.
- A failed fairness test should block the relevant release path according to policy, open an alert with evidence, and require review; do not auto-correct a model or hide the failed group.

### RAGDataAudit and RAGGovernanceDashboard

Track document/source identity, origin, owner, trust tier, collection time, freshness, checksum, license/data-rights status, access policy, chunk/page reference, retrieval query identifier, embedding/model version, retrieval score, reranker version, citations used, redaction result, and retention deadline.

- Treat documents, chunks, metadata, retrieved snippets, and tool output as untrusted inputs. Defend against indirect prompt injection, poisoned sources, hidden instructions, stale copies, and cross-tenant retrieval.
- Enforce tenant and document authorization before retrieval, not only after generation. Apply allow-lists and least privilege to retriever, reranker, and downstream tools.
- Separate evidence retrieval from action execution. A retrieved instruction cannot authorize a payment, policy override, state mutation, or external transmission.
- Record citation-level support for important claims and label uncited or conflicting claims. Measure retrieval coverage, quote age, source diversity, answer faithfulness, injection resistance, and redaction failure rates.
- The provenance-gap rule should prevent release of affected answers or dossiers; do not fill gaps with plausible-looking citations.

### AlertHistory and exports

- Store alerts as append-only events with unique ID, creation and acknowledgement times, severity, metric/control, source evidence, owner, status history, correlation ID, and resolution record.
- Provide deterministic CSV and JSON exports with a manifest containing the query/filter parameters, UTC export time, schema version, row count, and hash.
- Defend CSV against formula injection by escaping dangerous leading characters such as `=`, `+`, `-`, and `@`; preserve the raw canonical value in JSON where required.
- JSON exports must use a versioned schema and stable enum values. Never remove historical severity or overwrite the original event when an alert is reclassified.
- Log exports, access to restricted evidence, and acknowledgements. Apply row-level authorization and data minimization.

### ComplianceMatrix, OSCAL and OPA/Rego

- Maintain a versioned crosswalk: regime requirement → source citation/paragraph → control objective → implementation control → test procedure → evidence artifact → result → reviewer → limitations → next review date.
- Distinguish law, supervisory guidance, technical standards, voluntary frameworks, contractual requirements, and fictional treaty constructs. Mark fictional constructs as fictional in all views and exports.
- Use OSCAL artifacts with an explicitly pinned schema/model version and validate with the matching validator. Preserve source IDs and crosswalk provenance. The application requirement may target OSCAL 1.1.2, but upstream OSCAL 1.2.3 was announced in August 2026; document compatibility, compare schemas, and plan a tested migration rather than upgrading or claiming latest-version support silently.
- Run OPA/Rego decisions on a trusted backend or policy service. Pass schema-validated JSON input, pin policy bundle digests, log policy and bundle versions, and default to deny on policy error, unknown result, stale bundle, or missing required input.
- A UI label such as “mapped”, “tested”, or “policy passed” must never be converted automatically into “legally compliant”. Applicability and interpretations require accountable legal/compliance review.
- Add policy unit tests for allow, deny, missing input, malformed input, stale evidence, exception expiry, and contradictory control mappings.

### Governance and submission exports

- ExecutiveSummary supports regulator, engineer, executive, and educational views without altering canonical facts between roles. Only change detail and presentation.
- GovernanceStacks, Omni-Sentinel, control domains, and SDTStressDrills link every status to a source record, evidence ID, verifier and drill definition.
- AAP-1 assurance claim exports must specify the claim, subject/system/version, scope, assertion criteria, evidence set, procedure, assumptions, exclusions, creator, reviewer, timestamp, expiry, and status. Clearly separate self-attestation, automated test evidence, and independent assurance.
- HumanMeaningConstitution constraints must be represented as testable policies with owners and appeal/escalation paths. Treat fictional CFE-1.0 and Protocol SGR-028 as simulation-specific artifacts, not public regulations.
- Build regulator packages with deterministic content ordering, a manifest, hashes of included artifacts, source citations, schema version, evaluation window, evidence-status legend, known limitations, and a signed/approved transmission record when configured. A generated PDF is not proof of transmission or acceptance.
- Preserve the repository-required `<title>`, `<abstract>`, and `<content>` wrappers in reports subject to its report validator. Validate exact inventory/manifests and required section anchors before commit.

### TemplateLibrary, theme and notifications

- TemplateLibrary templates should be typed, versioned and discoverable via Fuse.js, with explicit permissions, status, owner, tags, and safe preview before application.
- Use a single ThemeProvider and ToastProvider/ToastContext rather than multiple independent global implementations. Notifications need stable IDs, severity, lifetime, keyboard accessibility, deduplication, and a persistent history for security-relevant alerts.
- Toasts are not a substitute for persistent incident banners, audit events, or operator acknowledgement.
- Provide light/dark themes with sufficient contrast; classification/simulation banners must remain visible in both themes.
- Route transitions, dialogs, charts, and exports must meet keyboard and screen-reader expectations.

### AI-Driven Workflow Recommendation Engine

- Treat recommendations as suggestions with explanation, evidence, confidence, expected impact, owner, and expiry; users must be able to reject, correct, or defer them.
- Collect feedback only with appropriate notice, purpose limitation, access control, retention, and data minimization. Separate user identity from learning data where feasible.
- Feedback is not a direct training command. Route it through validation, deduplication, privacy/safety screening, data approval, versioned offline training, benchmark evaluation, bias checks, human release approval, canary deployment, and rollback.
- Measure recommendation acceptance, override rate, calibration, harm/incident rates, subgroup quality, distribution drift, and feedback poisoning indicators. Keep an auditable link from model version to approved training-data snapshot.

### CCaaS call summarization and GDPR controls

- Document controller/processor roles, purposes, Article 6 legal basis, transparency/recording notice, retention, recipients, international transfers, data-subject rights, and whether a DPIA is required.
- Minimize and redact personal data before sending transcripts to model providers where practicable; assess re-identification and residual sensitive content; keep raw transcript access more restricted than derived summaries.
- Use purpose-specific retention and deletion workflows, access logs, tenant separation, encryption in transit/at rest, provider contractual controls, and regional processing where required.
- Apply differential privacy only where its threat model and privacy budget are specified; do not imply that redaction, pseudonymization, aggregation, or a privacy-enhancing technology alone guarantees GDPR compliance.
- Do not use customer transcripts or generated summaries for model training by default. Any separate training purpose needs a lawful basis, notice, governance approval, and controls aligned with contractual and jurisdictional requirements.

## System security and integration architecture

Use this trust path:

1. **Presentation:** React UI, role-scoped routes, accessible controls, visible source/evidence status.
2. **Application/API:** authenticated session, authorization, schema validation, rate limits, request correlation and tenant scoping.
3. **Governance services:** policy decision service, model registry, RAG retrieval, fairness evaluation, drill orchestration, submission builder, recommendation service.
4. **Evidence services:** append-only event interface, evidence metadata database, immutable object storage/WORM retention, digest and signature verification, key management.
5. **Telemetry and operations:** OpenTelemetry-compatible traces/metrics/logs, alert routing, dashboard freshness, deployment and dependency inventory.

Important separation rules:
- Browser-only state is not an authoritative control state.
- OPA/Rego evaluation in the client is not an authorization boundary.
- A hash or Merkle root without verified signed inputs, key provenance, and a trusted timestamp does not establish who created an artifact or when.
- WORM retention does not prove that the input was correct before it was written.
- Hardware TEE/RTEE/vTPM status requires freshness, certificate-chain and revocation checks, verifier version, expected measurement/policy, and an independent evidence reference.
- zkML/zk-SNARK/STARK results require a bound statement, circuit/program version, public-input digest, verifier identity/version, security assumptions, and proof verification result. “Proof generated” is not “proof verified”.
- TLA+ results prove properties of a model under its assumptions and specification; they do not prove that a deployed system implements the model without a separate refinement/equivalence argument and deployment evidence.
- Kubernetes/GitOps posture requires evidence from deployed cluster state and admission/policy logs; a configured Git repository alone is not evidence of zero drift.
- Key management, signature generation and verification belong in approved cryptographic services; do not hand-roll primitives in browser code.

### Post-quantum terminology

Use the NIST standard names precisely:
- **FIPS 203 — ML-KEM:** key-encapsulation mechanism for establishing a shared secret; it is not a digital-signature standard.
- **FIPS 204 — ML-DSA:** digital-signature standard.
- **FIPS 205 — SLH-DSA:** stateless hash-based digital-signature standard.

Record the algorithm, parameter set, implementation/version, key identifier, validity period, crypto-agility plan, verifier result, and any applicable NIST errata. Do not treat algorithms such as Falcon as FIPS-approved merely because they appear in an architecture note.

## API patterns

Use versioned, typed APIs; illustrative endpoints:

- `GET /api/v1/telemetry?windowStart=...&windowEnd=...`
- `GET /api/v1/controls?framework=...`
- `GET /api/v1/evidence/{evidenceId}`
- `POST /api/v1/policy/evaluate` — authenticated service-to-service call with validated input and pinned bundle metadata
- `POST /api/v1/alerts/{alertId}/acknowledgements`
- `POST /api/v1/controls/emergency-stop` — privileged, audited and idempotent command; returns requested state and separately verified resulting state
- `POST /api/v1/submissions` — creates a draft package; external transmission is a separate operation with explicit approval and receipt
- `POST /api/v1/recommendation-feedback` — schema-validated feedback, never direct training
- `GET /api/v1/audit/events?cursor=...` — permissioned, paginated, append-only event read

Use Problem Details-style API errors or a similarly stable error schema. Never put tokens, transcripts, private data, prompts, secrets, or full document content into application logs. Apply request-size limits and idempotency to mutating operations.

## DevSecOps and testing

- Keep separate CI workflows for the frontend build/tests, Python/backend tests, governance-report/schema validation, and infrastructure workflows, but reconcile shared files before merging.
- Pin external GitHub Actions to reviewed immutable commit SHAs and document the upstream version. Grant least-privilege workflow permissions; use concurrency groups and timeouts; never expose publishing secrets to untrusted pull requests.
- For Node applications, use the repository's declared package manager and lockfile with `npm ci` (or equivalent deterministic installation), then typecheck, lint, unit-test, accessibility-test, build, and run a production-preview smoke test.
- Fail CI on TypeScript errors, invalid report tags, unexpected manifest entries, schema drift, unsafe dependencies, secret leaks, missing evidence labels, and broken SPA routes. Do not relax validators to make reports pass.
- Make workflow file paths, working directories and publish roots explicit. Add a SPA fallback for static hosting only where appropriate. Check the dev-server process/port, Vite configuration and dependency lockfile before diagnosing a startup failure.
- Interpret CI status by commit SHA. An old successful run is not proof of current-head success; queued, skipped, cancelled, startup-failure and failed checks are different states.
- Review tests, hosted logs, dependency alerts, SAST/DAST, SBOM and deployment previews. External analyzer summaries should be investigated, not ignored because the local build passes.
- Add regression tests for simulated-data labels, evidence freshness, metric threshold versioning, export consistency, cross-tenant RAG isolation, voice command allow-listing, emergency-stop confirmation/authorization, and policy default-deny behavior.

## Compliance crosswalk and current-reference handling

Always perform use-case and jurisdiction scoping before claiming a requirement applies. A framework matrix is a navigation and evidence map, not a legal opinion. Keep a source URL, retrieval date, source version, applicable article/section, mapping rationale, owner and review date for every externally sourced mapping.

- **EU AI Act:** As of 16 October 2026, the Commission's current implementation pages state that general-purpose AI and governance obligations began applying in 2025, the Act's enforcement/selected transparency provisions began on 2 August 2026, and high-risk Annex III use-case rules apply from 2 December 2027 while relevant Annex I product rules apply from 2 August 2028. Confirm the final AI Omnibus text and the exact provision before setting deadlines.
- **NIST AI RMF:** AI RMF 1.0 remains a reference version and NIST states that revision work is underway. NIST AI 600-1 is the Generative AI Profile published on 26 July 2024. Cite the version used and review changes before each compliance release.
- **ISO/IEC 42001:** map to the licensed/authoritative standard version actually adopted by the organization; do not claim certification from a crosswalk or dashboard.
- **U.S. model-risk guidance:** SR 26-2 dated 17 April 2026 supersedes SR 11-7 and SR 21-8. Treat SR 11-7 as a legacy reference when explaining historical mappings, not as the current governing letter.
- **OSCAL:** the requested 1.1.2 profile can be supported as a pinned compatibility target; upstream 1.2.3 was announced in August 2026. Record the deliberate version choice and migration decision.
- **GDPR, DORA, NIS2, FCRA/ECOA, SEC Rule 17a-4, Basel rules, MAS/HKMA guidance, and FCA requirements:** map only the provisions relevant to the actual entity, use case, record type, jurisdiction, and effective date. Obtain legal or compliance review where applicability is unclear.
- **Interstellar AI Governance Accord, Galactic Treaty Framework, CFE-1.0, Protocol SGR-028, ICGC/GASO, and GIEN-specific protocols:** identify any fictional or organization-defined construct explicitly as fictional/internal. Never place them in a “law” column.

## Role and decision ownership

Suggested RACI:
- Product/system owner: accountable for scope, intended use and release decisions.
- AI/model owner: responsible for model inventory, evaluations, monitoring and retraining records.
- Data protection/privacy lead: accountable for privacy analysis and data-subject process.
- Security/platform owner: responsible for identity, infrastructure, key management, incident response and supply chain.
- Legal/compliance: accountable for applicability and interpretation of regulatory obligations.
- Independent validation/assurance: responsible for independent review where commissioned; separate from implementation ownership.
- Human operator/supervisor: authorized for intervention, stop/resume decisions, and documented exceptions.

A role view changes presentation and access scope; it does not change the underlying evidence or permit self-approval of a control.

## Delivery sequence and release gates

1. **Foundation:** settle one canonical app PR/path; pin runtime and package versions; repair CI and report-manifest failures; add typed schemas and demo-data banner.
2. **Evidence and telemetry:** implement adapters, freshness state, source links, threshold registry, metric definitions and test fixtures.
3. **Compliance/RAG/fairness:** versioned crosswalk and OSCAL validation, server-side OPA, source provenance, injection resistance, fairness tests and evidence review.
4. **Operations and controls:** alert history, immutable audit events, authorized emergency stop, role-based views, observable control state and failure-safe recovery.
5. **Exports and recommendations:** submission manifest, PDF/CSV/JSON integrity, controlled workflow-feedback lifecycle, privacy-compliant CCaaS summarization.
6. **Release:** all required current-head checks pass; preview smoke test passes; evidence and report manifests agree; security review completed; known limitations and simulation status are visible; named owners approve.

A release must be blocked when a required check is red or unresolved, a manifest and report inventory disagree, a critical evidence source is stale, policy evaluation is unavailable, or the data classification/authorization scope is unknown. Do not automatically merge, transmit filings, resume operations, or promote a model solely because the build succeeds.

## Official reference links

Check official sources when updating mappings:
- EU AI Act implementation: https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai
- EU AI Act enforcement: https://digital-strategy.ec.europa.eu/en/policies/enforcement-ai-act
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 600-1: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- ISO/IEC 42001: https://www.iso.org/standard/42001
- Federal Reserve SR 26-2: https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm
- OSCAL 1.1.2 reference: https://pages.nist.gov/OSCAL-Reference/models/v1.1.2/
- OSCAL release notes: https://pages.nist.gov/OSCAL/about/news/
- NIST FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205: https://csrc.nist.gov/pubs/fips/205/final
- GDPR text: https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/
- NIS2 Directive: https://eur-lex.europa.eu/eli/dir/2022/2555/en

## Completion report template

When finishing an implementation task, report:
1. Files/commits/PR changed.
2. Tests actually run and their exact commit/ref.
3. Hosted checks still pending, failed, or not run.
4. Data sources connected versus demonstration fixtures.
5. Security/privacy decisions and known limitations.
6. Compliance mappings requiring legal review.
7. Next recommended action.

Never report a test, cryptographic proof, production connection, transmission, or legal review as successful unless it was actually performed and there is a reference to the evidence.
