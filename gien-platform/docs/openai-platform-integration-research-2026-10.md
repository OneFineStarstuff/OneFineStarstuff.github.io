# OpenAI Platform Integration Research for GIEN

**Research snapshot:** 12 October 2026  
**Repository:** OneFineStarstuff/OneFineStarstuff.github.io  
**Target application:** gien-platform/ — React, TypeScript, Vite, React Router and Tailwind  
**Classification:** Architecture proposal; not evidence of a production integration, compliance finding or assurance opinion

## Executive decision

Adopt the OpenAI Responses API through a server-side TypeScript service as the first integration seam. Keep the existing React application as a presentation client. Do not add an OpenAI API key to browser code or the static Vite bundle. Use the official OpenAI JavaScript SDK on the server, schema-constrained responses for machine-readable drafts, and an independently controlled evidence and authorization layer.

Do not begin with an autonomous multi-agent runtime or writable tools. Start with a narrow, human-reviewed “draft supervisory narrative from approved evidence” use case. Only consider the OpenAI Agents SDK after real requirements demonstrate a need for multi-step orchestration, tool handoffs, sessions or richer trace instrumentation. The official documentation distinguishes the code-owned Agents SDK runtime from hosted managed-agent approaches; that choice should follow the control and deployment boundary the institution needs, not a preference for agent complexity. See [Agents SDK](https://developers.openai.com/api/docs/guides/agents/sdk), [Responses API reference](https://developers.openai.com/api/reference/responses/overview) and the [official JavaScript SDK’s Responses documentation](https://github.com/openai/openai-node/blob/main/docs/responses.md).

**Important repository finding:** the current application is a React/Vite frontend with demonstration data. It does not presently contain a server-side OpenAI integration, authenticated evidence API, operational telemetry source, or verified OpenAI request path. Existing smoke tests validate the built frontend and SPA fallback; they do not exercise OpenAI credentials, model behavior or live data. Treat this document as a researched integration design until an independently configured backend is implemented and tested.

## 1. Research scope and product findings

### 1.1 Responses API — recommended first integration

The Responses API supports text and image inputs, stateful interaction options, built-in tools, and application-defined function calling. It is the recommended entry point for a constrained supervisory report-drafting function. See the [Responses overview](https://developers.openai.com/api/reference/responses/overview) and [Using tools](https://developers.openai.com/api/docs/guides/tools).

Recommended initial task:
- Accept a server-authenticated user request and a bounded set of evidence records already authorized for that user.
- Ask the model to draft a narrative summary, list evidence-backed observations, identify conflicts or missing inputs, and propose questions for a human reviewer.
- Return a typed result that is explicitly a draft and carries stable source identifiers.
- Store the application’s approved evidence records and final reviewer decisions in the institution’s evidence system, not in a model response or browser state.

The model must not calculate authoritative S_sys, G-SRI, C-SRI, CGR-I, CCR-I, G-SRI-VII, A-SRI, P-SRI, p(doom), p(doom)_kernel, Δ_drift or Δ_OSCAL values from prose. Those indicators require deterministic, versioned calculation rules, known inputs, data-quality checks, and reproducible test fixtures. The model may explain a verified result but must not fabricate a number when a source is absent.

### 1.2 Structured Outputs — use for bounded application contracts

OpenAI Structured Outputs can constrain an output to a supplied JSON Schema. OpenAI documents that it improves schema adherence over JSON mode, but refusals and incomplete responses still require explicit handling. See [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs).

Define and version the output schema in the application repository. Suggested minimum fields:

- schema_version
- report_status: draft_only, evidence_insufficient, refused, or needs_review
- summary
- observations: each with a claim, source_refs, evidence_status and limitations
- missing_evidence
- conflicting_evidence
- reviewer_questions
- model_metadata: model identifier, request identifier, generation timestamp and schema version

A schema guarantees structure, not truth, correct source interpretation, legal applicability or authorization. The server must verify every source reference against the supplied evidence manifest, reject invented identifiers, check that citations resolve to the approved snapshot, and reject unknown or disallowed status values. A response with a refusal, incomplete generation or failed validation must not be represented as a successful report.

### 1.3 Function calling and tools — begin read-only

Function calling connects model behavior to application-owned operations and data. It is not an authorization system. The server must validate every tool name, argument, tenant, permission and result, and should constrain the model to an allowlist rather than accept arbitrary tool names. See [Function calling](https://developers.openai.com/api/docs/guides/function-calling) and [Using tools](https://developers.openai.com/api/docs/guides/tools).

Safe phase-one tools, implemented on the server:
- read an already-authorized evidence snapshot by identifier;
- read the current, versioned control catalogue;
- read a deterministic risk-indicator result with calculation version and provenance;
- query approved policy and standards references from a curated corpus.

Exclude write capabilities such as transmitting supervisory submissions, changing thresholds, closing findings, rotating keys, invoking a kill switch, modifying a control, approving evidence, changing permissions or starting an operational remediation. If such actions are later required, expose them through separate application endpoints with explicit role authorization, object-level permission checks, a confirmation screen, an approval record, idempotency protection and immutable audit events. Do not let model-generated text trigger a privileged operation implicitly.

### 1.4 Agents SDK — a later option, not the initial dependency

The [OpenAI Agents SDK for TypeScript](https://github.com/openai/openai-agents-js) supports agents equipped with tools, guardrails, handoffs, human-in-the-loop patterns and tracing. Its documented runtime requires Node.js 22 or later; the GIEN workflow uses Node.js 24, so the runtime baseline is compatible. That does not mean the current frontend should be converted into an agent runtime.

Adopt the SDK only when the required flow needs multiple controlled steps or delegated specialists, and only after the single-request workflow has reliable evaluation, authorization, audit and cost controls. Prefer code-owned tool implementations and state handling. Review tracing configuration for personal, confidential and regulated data before enabling production traffic.

### 1.5 OpenAI-hosted tools and MCP

OpenAI documents built-in tools and remote MCP connections as ways to add search, retrieval or external-system capabilities. MCP can expand the model’s access to data and action surfaces, so each server’s identity, permissions, data flow, retention terms, tool list and failure modes must be assessed independently. OpenAI explicitly warns about prompt injection and recommends approval flows for sensitive actions. See [MCP servers](https://developers.openai.com/api/docs/guides/tools-connectors-mcp) and [Safety best practices](https://developers.openai.com/api/docs/guides/safety-best-practices).

For this repository, do not attach a remote MCP server to the production governance workflow until:
1. its owner, service identity, data recipients and operational boundary are documented;
2. only required tools are exposed;
3. read/write capabilities are separated;
4. sensitive actions use explicit human approval;
5. prompt-injection, data-exfiltration and cross-tenant authorization tests pass.

Retrieved documents and tool outputs are untrusted input, even when they are syntactically valid. Instructions inside a document must not override system policy or grant the model authority.

## 2. Recommended integration architecture

~~~
Browser / React UI
  │ authenticated request; no OpenAI credential
  ▼
GIEN application API / backend-for-frontend
  ├── Authenticate user and resolve server-side role / tenant
  ├── Validate request schema, payload size and rate limits
  ├── Load authorized evidence snapshot and provenance manifest
  ├── Redact or omit disallowed sensitive fields
  ├── Invoke OpenAI Responses API through official server SDK
  ├── Validate structured result and all evidence references
  ├── Apply response/refusal/error handling and output policy
  └── Emit minimal, redacted audit event and usage metadata
  │
  ├──► OpenAI Platform API (model, approved tools, configured project)
  │
  └──► Institution evidence/control services
        ├── Deterministic metric service
        ├── Approved policy / standards repository
        ├── Evidence store and immutable audit log
        └── Human approval and submission workflow
~~~

Keep the browser responsible for display, navigation and user interaction. Move credentials, authorization decisions, OpenAI requests, evidence lookups, tool execution and submission state transitions into the server. The model is a drafting and interpretation component, not the system of record.

Suggested repository structure when implementation is authorized:

~~~
gien-platform/
  src/                         # current React application
  server/
    api/                       # authenticated application routes
    openai/
      client.ts                # server-only SDK client
      draft-supervisory-report.ts
      output-schema.ts
      policy.ts                # server-side tool allowlist
      provenance.ts             # evidence reference validation
      redaction.ts
      telemetry.ts
  tests/
    openai-contract/
    prompt-injection/
    authorization/
    evidence-provenance/
  docs/
    openai-platform-integration-research-2026-10.md
~~~

This is a proposed structure, not a representation of files that already exist. Choose the backend deployment target explicitly before committing server files. The repository’s Vite frontend and existing deployment status do not by themselves establish that either current hosting target is configured to run a secured API service.

## 3. Credentials, identity and GitHub Actions

### 3.1 Runtime API access

OpenAI advises against exposing API keys in browsers, mobile applications, or source control. Use a server-only secret store, short-lived credentials where supported, separate identities for environments, permission scoping, rotation, and usage monitoring. See [API key safety](https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety).

Requirements:
- Never define an OpenAI secret with a Vite-prefixed public variable or embed one in React source, static assets, logs, build output, test fixtures or committed environment files.
- Use distinct OpenAI Projects and service identities for development, staging and production.
- Grant only the permissions required by the API routes that are enabled.
- Set spend alerts and hard limits for the relevant project; enforce a second set of quotas per application user or tenant.
- Store configuration such as the chosen model identifier in server-side environment configuration, then verify it against an approved allowlist.
- Never log bearer tokens, raw environment variables or secret-bearing headers.

### 3.2 GitHub Actions workload identity federation (WIF)

OpenAI now documents a GitHub Actions workload identity federation flow that exchanges a GitHub-issued OIDC token for a short-lived OpenAI access token, avoiding a long-lived API key in GitHub secrets. Setup requires an OpenAI Workload Identity Provider, a mapped service account and claim validation. See [Configuring workload identity federation for GitHub Actions](https://developers.openai.com/api/docs/guides/workload-identity-federation/github-actions).

Recommended controls if CI later needs to call the API:
- Use a separate protected workflow for a manual staging check or production deployment. Do not enable OIDC in the general pull-request build job.
- Give only the specific job the permission id-token: write; retain contents: read unless additional permissions are independently justified.
- Require a protected environment and, for privileged mappings, match the repository, exact main ref, workflow_ref and environment claims. Avoid broad owner-only trust mappings.
- Use separate service accounts and scoped permissions for test and production workflows.
- Do not allow fork-originated pull requests to access OpenAI identities.
- Keep raw GitHub OIDC tokens and exchanged OpenAI access tokens out of logs.

The current GIEN build/smoke workflow should remain credential-free. An API check should be opt-in, run only against sanitized test data and have a hard spending cap. Configure WIF only after an authorized OpenAI administrator establishes and reviews the provider and mapping; adding the workflow permission alone does not create a trust relationship.

## 4. Data handling, retention and privacy

OpenAI’s current API data-control documentation says API data is not used to train or improve models by default unless an organization opts in. That statement does not mean data is never retained. Abuse-monitoring retention, application-state retention, endpoint eligibility for Zero Data Retention (ZDR), and other controls vary by endpoint, feature and account configuration. Review the current [API data controls and retention table](https://developers.openai.com/api/docs/guides/your-data) before deciding what records to send.

Baseline rules for GIEN:
1. Classify each field before transmission; default to the minimum necessary content.
2. Redact personal data, client identifiers, secrets, raw credentials, restricted telemetry and unnecessary free-form logs.
3. Use store:false where compatible with the selected Responses API pattern, but do not equate that request setting with universal ZDR eligibility.
4. Do not enable API-side conversation state, file retention, vector stores, or persisted agent sessions without an explicit retention decision.
5. Confirm endpoint-specific storage behavior, account-level ZDR/MAM eligibility, applicable contract terms, residency requirements and deletion procedures with the responsible privacy/security owners.
6. Preserve required supervisory evidence in an institution-controlled system; make retention and legal-hold decisions there.
7. Treat regional routing or a security certification as one input to a control assessment, not as proof that the overall application satisfies a regulatory obligation.

OpenAI’s [security and privacy overview](https://openai.com/security-and-privacy/) summarizes platform-level security commitments and certifications. The GIEN implementation must still perform its own vendor, processing, data-flow and jurisdictional assessment. This document does not conclude that the proposed system is compliant with GDPR, DORA, the EU AI Act, banking supervisory rules or any other regime.

## 5. Model output, provenance and governance controls

A supervisory report draft should reference an immutable evidence snapshot. Each cited source should include, as available, a stable source identifier, source type, version or content hash, collection timestamp, applicable time window, source owner and verification status.

Server validation must:
- reject references that are not in the authorized evidence manifest for the request;
- identify unsupported claims, conflicting sources and stale data;
- distinguish observed values from computed indicators, interpretations, projections and hypothetical scenario outputs;
- fail closed when a required evidence field is missing or a schema/refusal/incomplete-response condition occurs;
- preserve model identifier, request identifier, prompt/schema version, evidence-snapshot identifier, timestamp, validation results and reviewer decision;
- keep human edits and approvals separate from model-generated content;
- show reviewers the underlying source record next to the drafted claim.

Risk indicator computation, threshold comparisons, OSCAL assessment outcomes, cryptographic signature verification, Merkle-root verification, TEE/PCR verification, and TLA+ model checking must execute in dedicated deterministic code or authoritative verification systems. An LLM must not mark an invariant “verified” merely because it produced a plausible explanation. The interface must continue to show UNVERIFIED or EVIDENCE-PENDING until a real verification procedure supplies a verifiable result.

## 6. Safety and tool-authority model

Use defense in depth rather than relying on a system prompt alone:

| Layer | Required control |
|---|---|
| Identity | Authenticate every request; derive role and tenant from server-side identity |
| Input | Size limits, request schema, content classification, injection-aware handling of retrieved text |
| Evidence | Allowlisted source IDs, timestamp and freshness policy, source hash/version |
| Model | Fixed server configuration, bounded instructions, structured output, limited context and output length |
| Tools | Least-privilege allowlist; read-only initially; schema and argument validation |
| Authorization | Server-enforced object and action permissions; model output never conveys authority |
| Human review | Required for formal findings, regulatory submissions, evidence seals and any write/action operation |
| Audit | Request correlation, model/schema versions, validated evidence references, result status and human approval event |
| Resilience | Explicit timeout, cancellation, bounded retry, rate-limit handling, per-user quotas and spend controls |
| Release | Deterministic contract tests, security tests, offline eval dataset, smoke test, controlled rollout and rollback |

Any future connector or MCP integration must be treated as an additional trust boundary. Review what user content can leave the organization, what data the connector can read, whether it can perform actions, what its identity is, and how failure or prompt injection is handled. Start with read-only tools; require human approval for sensitive actions.

## 7. Reliability, cost and observability

OpenAI documents request and token rate limits, retry guidance, and project/org spend controls. Review [Rate limits](https://developers.openai.com/api/docs/guides/rate-limits) and [Production best practices](https://developers.openai.com/api/docs/guides/production-best-practices) as part of deployment planning.

Implement:
- request and response timeouts with cancellation;
- bounded retries for transient errors, with exponential backoff and jitter and respect for Retry-After when valid;
- no automatic retry for errors that require user, permission or billing action;
- concurrency limits, request-size limits and per-user rate limits;
- cost estimation by task class and maximum output token bounds;
- a hard monthly/project spend limit plus an application-level circuit breaker;
- separate operational metrics for request volume, latency, token usage, errors, refusals, validation failures, evidence-reference failures and human rejection rate;
- redacted correlation IDs, OpenAI request IDs when available, and audit records that do not copy unnecessary prompt contents.

Do not represent model-reported confidence as a calibrated probability unless the organization has designed and validated a calibration method. Prefer categorical evidence states, explicit limitations and reviewer-visible source references over spurious numerical certainty.

## 8. Evaluations and product lifecycle risks

**Time-sensitive finding as of 12 October 2026:** OpenAI's deprecation notice says the Evals platform was announced for deprecation on 3 June 2026, existing evals become read-only on **31 October 2026**, and the Evals dashboard/API are scheduled to shut down on **30 November 2026**. The same notice says Agent Builder is scheduled to shut down on 30 November 2026. See [OpenAI API deprecations](https://developers.openai.com/api/docs/deprecations) and [Working with evals](https://developers.openai.com/api/docs/guides/evals).

Do not make a new GIEN release gate depend on the Evals dashboard/API or choose deprecated Agent Builder as the foundation for a new integration. Keep a repository-owned, versioned evaluation corpus that can execute without network access or API credentials in normal CI. The deprecation page lists a migration path from OpenAI Evals to Promptfoo; whichever harness is selected must be versioned and independently runnable in the project CI.

Suggested evaluation groups:
- correct use of evidence and refusal to fill evidence gaps;
- citation/source-reference fidelity and invented-source rejection;
- report schema conformance, refusal and incomplete-output paths;
- prompt injection in source documents and MCP output;
- data minimization and sensitive-field redaction;
- RBAC, tenant isolation and tool-allowlist boundary checks;
- stale, missing and conflicting telemetry;
- deterministic metric explanations and threshold boundary tests;
- human approval required for submission, closure, transition and cryptographic sealing;
- latency, errors, retry behavior, token costs and hard-budget stops.

Use synthetic records and fixed expected outcomes in required CI. An optional live-model evaluation may be triggered manually against sanitized samples, with explicit project identity, spend ceiling, result retention, and a non-blocking policy until quality thresholds have been reviewed. Do not allow stochastic model output to silently change hard regulatory or security gates.

## 9. Phased delivery plan

### Phase 0 — account, policy and threat-model decisions
Owners: platform architect, security, privacy, model risk.

- Confirm a business/API project exists and an accountable owner can manage RBAC and spend limits.
- Decide the backend runtime and deployment target; the frontend alone is not a secure API host.
- Approve permitted data classes, endpoint retention, ZDR/MAM eligibility, region/residency, logging, deletion, and vendor-review requirements.
- Approve a narrow use case, an explicit model allowlist, the JSON schema and evaluation criteria.
- Document a threat model and an exception path for unavailable, refused or invalid model output.

### Phase 1 — offline contracts and UI boundary
Owners: frontend and backend engineers.

- Add request/response contract types and an “AI-assisted draft” UI state without displaying fabricated live status.
- Implement server-side authentication, role/tenant authorization, evidence selection and redaction before model invocation.
- Implement the draft endpoint in a dedicated server runtime; do not ship the key with Vite.
- Validate all returned source references and display a traceable evidence panel beside every drafted observation.
- Add mock-provider tests so UI and error states can be tested without API access.

### Phase 2 — guarded OpenAI integration
Owners: platform engineering, security engineering.

- Add the official OpenAI JavaScript SDK to the server package only.
- Integrate the Responses API with Structured Outputs and a server-controlled model setting.
- Start with no tools or with a narrowly scoped read-only function allowlist.
- Handle refusals, incomplete output, schema mismatch, timeouts, 429/5xx responses, cancellations and spending limits.
- Record redacted audit metadata and human review state.

### Phase 3 — validation and supervised trial
Owners: QA, AI safety, model risk, supervisory users.

- Run offline evaluations and threat-driven tests against synthetic and approved de-identified samples.
- Require documented acceptance thresholds for source fidelity, invalid-output handling, role isolation, cost, latency and human override.
- Pilot in draft-only mode. Compare drafts to expert-authored reference reports; sample failure cases and document residual risks.
- Do not allow automated submission, evidence sealing, risk-score changes or regulatory determination.

### Phase 4 — optional tools and controlled operations
Only after Phase 3 is approved:
- Introduce approved read-only retrieval or MCP tools, each with a documented owner and separate authorization.
- If write actions are necessary, implement dedicated deterministic APIs with explicit human approval and replay-safe operations.
- Configure GitHub Actions WIF for an isolated, protected test or deployment workflow if needed; do not give OIDC permission to generic PR builds.
- Use canary rollout, monitored error/cost budgets, rollback and periodic reassessment of OpenAI model/API deprecations.

## 10. Release acceptance criteria

The first API-enabled draft feature is not ready for production until all applicable items pass:

- [ ] OpenAI credentials are server-only and absent from compiled assets, source, logs and artifacts.
- [ ] Backend identity and object permissions are enforced independently of the role selected in React.
- [ ] Input classification, redaction, data-flow documentation, retention and jurisdictional reviews are signed off.
- [ ] Structured output schema and schema version are checked server-side; refusals and incomplete responses are handled explicitly.
- [ ] Every output evidence reference resolves to an approved immutable snapshot; unsupported claims are marked as such.
- [ ] The deterministic risk-indicator and cryptographic-verification services remain independent of model output.
- [ ] All tool actions are allowlisted, validated and least-privileged; sensitive actions require human approval.
- [ ] Offline evaluations cover accuracy, provenance, prompt injection, redaction, RBAC, fail-closed behavior and cost boundaries.
- [ ] The production-preview smoke test and relevant unit/security tests pass.
- [ ] Monitoring, retention policy, spend ceilings, throttling, retries, support owner and rollback are in place.
- [ ] Reviewers can tell which text is model-generated, which evidence is verified, and who approved the final record.

## 11. Official reference register

All links below are primary OpenAI documentation or official OpenAI SDK repositories. Features and lifecycle dates can change; recheck the live docs before implementation and at each release.

1. [Responses API reference](https://developers.openai.com/api/reference/responses/overview) — API surface and interaction capabilities.
2. [Using tools](https://developers.openai.com/api/docs/guides/tools) — built-in, function and MCP tools.
3. [Function calling](https://developers.openai.com/api/docs/guides/function-calling) — application-owned capabilities.
4. [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs) — schema-constrained output and edge cases.
5. [OpenAI JavaScript SDK](https://github.com/openai/openai-node) — official server-side JavaScript SDK; [Responses example](https://github.com/openai/openai-node/blob/main/docs/responses.md).
6. [Agents SDK for TypeScript](https://github.com/openai/openai-agents-js) and [Agents SDK documentation](https://developers.openai.com/api/docs/guides/agents/sdk) — code-owned agent runtime.
7. [API data controls](https://developers.openai.com/api/docs/guides/your-data) — training and endpoint-specific retention.
8. [API key safety](https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety) — credentials and server-side storage.
9. [OpenAI API RBAC](https://developers.openai.com/api/docs/guides/rbac) — organization/project permissions.
10. [GitHub Actions workload identity federation](https://developers.openai.com/api/docs/guides/workload-identity-federation/github-actions) — OIDC-based short-lived access.
11. [MCP servers](https://developers.openai.com/api/docs/guides/tools-connectors-mcp) and [Safety best practices](https://developers.openai.com/api/docs/guides/safety-best-practices) — approval, prompt injection and human review.
12. [Rate limits](https://developers.openai.com/api/docs/guides/rate-limits) and [Production best practices](https://developers.openai.com/api/docs/guides/production-best-practices) — reliability and cost operations.
13. [API deprecations](https://developers.openai.com/api/docs/deprecations) and [Evals guide](https://developers.openai.com/api/docs/guides/evals) — product lifecycle and evaluation migration.
14. [OpenAI security and privacy](https://openai.com/security-and-privacy/) — vendor-level security information to evaluate alongside contracts, endpoint-specific data controls and application controls.

---

## Evidence boundary

This report is a researched implementation plan. It does not assert that the OpenAI API has been enabled for this repository, that OpenAI credentials have been configured, that any API request has been made, or that any risk metric, cryptographic control or regulator-facing assertion has been independently verified. No API secret or private credential is included in this commit.
