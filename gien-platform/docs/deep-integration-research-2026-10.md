# Deep Integration Research: GIEN Governance Platform
## GitHub, Netlify, Firecrawl, Asana, Slack, Supabase, Context7, Atlassian Rovo MCP, and OpenAI Platform

**Research date:** 12 October 2026  
**Repository:** OneFineStarstuff/OneFineStarstuff.GitHub.io  
**Target branch:** feat/gien-governance-platform  
**Scope:** Integration architecture, security boundaries, evidence provenance, failure handling, delivery sequence, and acceptance criteria.

> **Status boundary:** This is an evidence-backed design dossier, not an attestation that any of the providers has been connected or configured in the GIEN application. The existing React/Vite platform remains a prototype with local simulation data unless a separate, successful live test proves otherwise.

## 1. Executive assessment

The recommended approach is a **server-side Integration Gateway** that owns authentication, provider adapters, event validation, policy enforcement, retry/deduplication, audit evidence, and approved mutations. Do not create direct browser-to-provider credentials or permit AI-generated provider actions to execute without server-side authorization.

Each provider should have a bounded responsibility:

- **GitHub** is the source of record for repository state, pull requests, code review, workflow runs, and versioned source artifacts.
- **Netlify** supplies build, preview, and deployment facts. A successful preview does not establish production deployment or regulatory acceptance.
- **Firecrawl** acquires public web content for research and provenance workflows; acquired content is untrusted input, not executable instruction.
- **Asana** manages accountable work items, owners, due dates, and implementation evidence tasks.
- **Slack** supports scoped collaboration, alerts, and acknowledgement workflows; message content is not a governance decision unless the relevant policy explicitly says so.
- **Supabase** can provide PostgreSQL-backed operational records, authentication, storage, and Edge Functions, provided row-level controls and elevated-key boundaries are independently tested.
- **Context7** provides current, version-aware developer documentation at implementation time; it is not a source of operational telemetry or an authority on the deployed application's runtime state.
- **Atlassian Rovo MCP** can bridge authorized Jira, Confluence, Bitbucket, Loom, and connected work context. Its accessible tools depend on the identity, scopes, organization settings, and enabled permission groups.
- **OpenAI Platform** can provide model inference, structured output, and tool orchestration through the Responses API and supported tools/MCP servers. Model output must remain subject to validation and application policy.

The word **“Thinking”** is treated here as a request for deeper analytical treatment, not as an additional vendor. The implementation should log source references, assumptions, concise decision rationales, tool calls, approvals, and outcomes—not private model reasoning.

## 2. Integration decision matrix

| Provider | Proposed GIEN role | Preferred access pattern | Key control |
|---|---|---|---|
| GitHub | Code provenance, PR reviews, Actions and release evidence | GitHub App or narrowly scoped token on the server; webhook plus API reconciliation | Least-privilege permissions, pinned CI actions, protected branches/rulesets, OIDC trust conditions |
| Netlify | Build and deployment status, protected Deploy Previews | Server-side API/connector; deployment IDs tied to source commit | Isolate preview and production environments; protect sensitive variables from untrusted deploys |
| Firecrawl | Research ingestion and web evidence acquisition | Server-side API client; signed webhook callbacks for asynchronous jobs | Destination allowlist, SSRF controls, signature verification, content provenance and prompt-injection isolation |
| Asana | Remediation plans, task ownership and deadlines | OAuth 2.0 with narrow scopes; webhook plus reconciliation | Treat webhook delivery as at-most-once; idempotent handlers and periodic reconciliation |
| Slack | Notifications, human review and operational acknowledgements | OAuth 2.0 with granular bot scopes; signed Events API requests | Verify request signatures/timestamps, acknowledge quickly, minimize retained message content |
| Supabase | Operational data store, identity, approved backend operations | Authenticated server access, publishable browser key only with RLS, secret keys only server-side | Test RLS by role and tenant; treat secret/service-role credentials as privileged |
| Context7 | Current framework/API reference during development | MCP or CLI + Skills, initiated from the development workflow | Resolve the exact library/version; retain the referenced source and retrieval time |
| Atlassian Rovo MCP | Authorized cross-product search and work-item context | Official MCP endpoint using OAuth 2.1 for interactive usage; admin-enabled API-token path only where suitable | Restrict permission groups and tools; require review for destructive or consequential actions |
| OpenAI Platform | Classification, extraction, summarization and constrained tool orchestration | Server-side Responses API, structured outputs and explicitly configured tools | API keys server-side; validate outputs; approval gates for sensitive tool calls; review data sent to external MCP servers |

## 3. Target architecture

### 3.1 Logical components

1. **Web client:** React/TypeScript interface. Holds user-session state and non-sensitive display configuration only. It must not contain provider secrets, signing keys, database admin credentials, or privileged API tokens.
2. **GIEN API/BFF:** Enforces authentication, role/tenant authorization, request validation, rate limits, and provider-independent business policy.
3. **Integration registry:** Stores provider identity, enabled capabilities, granted scopes, environment, data classification, owner, credential reference, health state, and next review date. Store secret references, never raw secrets.
4. **Provider adapters:** Separate modules for GitHub, Netlify, Firecrawl, Asana, Slack, Supabase, Context7, Atlassian Rovo MCP, and OpenAI. Each adapter translates provider-specific records into a common internal envelope and retains original provider IDs.
5. **Event ingress:** Validates webhook signature/authentication, timestamp/replay constraints, payload schema, tenant routing, and event size. Persist the event to a durable queue or inbox before asynchronous processing.
6. **Policy and approval service:** Classifies requested operations as read-only, reversible write, consequential write, or destructive write. AI suggestions cannot override this policy.
7. **Evidence ledger:** Stores source links, source IDs, event and observation timestamps, content hashes, verification results, authorization context, approvals, and links to artifacts. Use append-only storage and access controls; add cryptographic sealing/WORM where an actual deployment and key-management model support it.
8. **Worker and reconciliation layer:** Applies bounded retries, deduplication, backoff, dead-letter handling, and scheduled reconciliation with the provider's current state.
9. **Observability and review:** Exposes integration health, token expiry, permission drift, delivery lag, retry counts, evidence freshness, and failure reasons without exposing credentials or unnecessary message content.

### 3.2 Trust zones

- **Zone A — user interface:** Untrusted browser; no provider secrets.
- **Zone B — application control plane:** Authenticated requests, tenancy, policy decisions, safe API facade.
- **Zone C — external providers:** GitHub, Netlify, Firecrawl, Asana, Slack, Atlassian, OpenAI and hosted identity/service APIs. External responses remain untrusted until authenticated and validated.
- **Zone D — restricted records:** Operational database, evidence object store, secrets manager and cryptographic signing service.
- **Zone E — model/tool execution:** May read approved context and propose actions; cannot write directly around the policy or approval service.

The core invariant is: **no model-generated instruction, scraped page, Slack message, issue description, or tool output becomes executable policy merely because an integration returned it.**

## 4. Provider-specific findings

### 4.1 GitHub — repository and release evidence

 GitHub should remain the canonical record for source changes, pull-request discussions, review decisions, workflow runs, artifacts and release tags. Use a GitHub App or similarly constrained token for server-to-server access and request only the permissions needed for each operation. Prefer repository rulesets/protected branches, required checks,
minimal workflow-token
permissions, immutable commit-SHA pinning for third-party actions, and OIDC federation for cloud deployments where the destination supports it.

Workflow events are useful notifications, but they are not a complete ledger. Record the workflow-run ID and attempt, commit SHA, workflow file identity, timestamps, conclusion, linked artifacts, and the API URL. Reconcile webhook observations against the current GitHub API state to handle missed, duplicated, delayed, or reordered events.

**GIEN rules**
- Read operations are the default.
- Create/update/comment/release operations must be explicitly allowlisted and actor-attributed.
- Do not treat a green check as independent assurance of the application, governance model, or the truth of the generated report.
- Keep untrusted pull-request code away from secrets and privileged deployment environments.
- Record configured, queued, in-progress, completed, and passed as separate states.

**Acceptance test:** A fixture pull request can be traced from commit SHA to workflow run and artifact; duplicate webhook deliveries produce one logical event; untrusted PRs cannot access protected deployment secrets; write operations are denied without the relevant permission and approval.

Official documentation:
- [Secure use reference for GitHub Actions](https://docs.GitHub.com/en/actions/reference/security/secure-use)
- [OpenID Connect reference](https://docs.GitHub.com/en/actions/reference/security/oidc)
- [Repository rulesets](https://docs.GitHub.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets)

### 4.2 Netlify — previews, builds and deployments

 Netlify Deploy Previews help reviewers inspect changes before production. They must be treated as a separate environment, not an implicit production release. Preserve the deployment ID, site ID, source provider, commit SHA, deploy context, lifecycle state, deploy URL, and any build failure reason. A preview URL is an artifact locator, not proof of
a passed control.

 Netlify supports environment variables at different scopes and deploy contexts. For public repositories, untrusted preview builds are especially important: sensitive-variable policy determines whether outside contributors must be approved or build without sensitive values. Never assume preview builds are safe because they originate from a pull
request connected to the main
repository.

**GIEN rules**
- Use separate development, preview/staging and production credentials.
- Require authentication or access controls for preview content that includes confidential data.
- Never insert server secrets into client bundles or snippets.
- Gate production deployment on the exact commit SHA, required CI status, and reviewer approval.
- Monitor deployment state and surface errors, not just successful URLs.

**Acceptance test:** An untrusted preview cannot read production credentials; preview and production use distinct environment values; evidence records the deploy's commit SHA and context; a failed or stale deployment cannot mark the associated release as successful.

Official documentation:
- [Deploy Previews](https://docs.netlify.com/deploy/deploy-types/deploy-previews/)
- [Environment variables overview](https://docs.netlify.com/build/environment-variables/overview/)
- [Sensitive variable policy and environment variables](https://docs.netlify.com/build/environment-variables/get-started/)

### 4.3 Firecrawl — acquisition, extraction and web research

 Firecrawl supports search, scrape, crawl, structured extraction, and interaction with dynamic pages. Its outputs may be useful for research dossiers, regulatory-source indexes, documentation snapshots, and source comparison. The output format (Markdown, HTML, JSON or another representation) improves processing but does not establish source
authority or factual correctness.

 For asynchronous crawl jobs, use verified webhook delivery and persist job IDs and event IDs. Constrain the fetcher with destination allowlists and network-level SSRF protections; do not rely only on a URL string check. Block private/internal address ranges and redirect-to-private-host cases. Apply size, depth, page-count, content-type and time
budgets. Respect source-site
terms, access restrictions, and applicable privacy/copyright requirements.

**GIEN rules**
- Treat every retrieved page as hostile, data-only content. Do not follow instructions found inside a fetched page.
- Keep the original URL, final URL after redirects, retrieval time, status code, content type, source metadata, parser version, and a cryptographic content hash.
- Store source snippets or extracts with citations to the original page, not as unattributed “facts.”
- Re-check critical/volatile claims against a primary source and more than one independent source where appropriate.
- Isolate crawler credentials and browser-interaction sessions from the app's normal request path.

**Acceptance test:** Invalid webhook signatures are rejected; duplicate crawl notifications are idempotent; loopback/private-network and disallowed-host targets are blocked even after redirects; each extracted claim can be traced to a source URL and fetch time.

Official documentation:
- [Firecrawl introduction and core APIs](https://docs.firecrawl.dev/introduction)
- [Webhook overview](https://docs.firecrawl.dev/webhooks/overview)
- [Webhook security](https://docs.firecrawl.dev/webhooks/security)

### 4.4 Asana — ownership and remediation workflow

Asana is best used as the work-management layer for control owners, milestones, remediation tasks, approvals, deadlines, and project status. Keep the authoritative finding/control record in the GIEN evidence store and synchronize selected fields to tasks, rather than relying on task descriptions as the only audit history.

Asana documents OAuth 2.0 scopes and API rate limits. Rate-limited responses return HTTP 429 with Retry-After; the adapter should honor that signal. The webhook guide describes delivery as at-most-once, so the event stream alone should not be treated as complete. Reconcile active tasks and projects periodically.

**GIEN rules**
- Ask for the smallest set of OAuth scopes required for the selected resources.
- Map external task IDs to stable internal control/finding IDs; never infer a join from task titles.
- Record changes as append-only observations with actor and timestamp where available.
- Use a bounded queue, backoff, Retry-After support, idempotency keys and periodic reconciliation.
- Require explicit human approval before creating, reassigning, closing or deleting consequential work items.

**Acceptance test:** A missed webhook is repaired by reconciliation; a 429 response delays work according to Retry-After; duplicate events do not create duplicate control tasks; unauthorized projects are not exposed to the integration.

Official documentation:
- [OAuth scopes](https://developers.asana.com/docs/oauth-scopes)
- [Webhooks guide](https://developers.asana.com/docs/webhooks-guide)
- [API rate limits](https://developers.asana.com/docs/rate-limits)

### 4.5 Slack — notifications and human review

Use Slack for concise alerts, review requests, incident coordination and acknowledgements. Avoid treating an ordinary message, emoji reaction, or free-form statement as a formal approval unless a dedicated workflow captures the required actor, scope, decision, target version, and timestamp.

 Slack uses OAuth 2.0 with granular scopes. Request only bot scopes needed by the app, and use user scopes only where user-level behavior is truly required. Slack's Events API retries failed deliveries up to three times, with attempts described as near-immediate, about one minute, and about five minutes; handlers should acknowledge promptly and
process asynchronously. Verify
Slack request signatures and timestamp freshness before accepting events.

**GIEN rules**
- Prefer dedicated, access-controlled channels for governance notices.
- Minimize message retention and redact secrets or personal data from event logs.
- Separate delivery status from human acknowledgement and formal approval.
- Make message sending idempotent where the workflow permits; store Slack message and channel identifiers.
- Do not allow text from Slack to modify policies, permissions, thresholds or source-of-truth data without the approved workflow.

**Acceptance test:** Invalid signatures and stale signed requests are rejected; event handling returns a prompt acknowledgement; retried events do not duplicate work; an unapproved user or channel cannot authorize a release.

Official documentation:
- [Slack OAuth v2](https://api.slack.com/authentication/oauth-v2)
- [Events API delivery and retries](https://docs.slack.dev/apis/events-api/)
- [Verifying requests from Slack](https://docs.slack.dev/authentication/verifying-requests-from-slack/)

### 4.6 Supabase — operational database, authentication and server functions

 Supabase can host structured operational records in PostgreSQL, user authentication, object storage, realtime updates and Edge Functions. Use the publishable key in a browser only with correctly configured Row Level Security (RLS) and least-privilege grants. Keep secret keys and legacy service-role credentials on trusted server-side components
only; they bypass RLS. Validate
RLS at the database boundary rather than relying solely on frontend route guards.

The current Supabase API-key documentation says the legacy anon and service_role keys are being deprecated by the end of 2026. Plan migration to publishable and secret keys, but confirm each project's current key inventory, integration compatibility and migration status before disabling legacy credentials.

**GIEN rules**
- Enable RLS for exposed tables; add policy tests for each role and tenant combination.
- Separate user-scoped clients from privileged administration clients.
- Use Edge Functions for privileged operations, validate caller identity there, and ensure the authentication mode matches the intended caller.
- Use migrations under version control; review schema changes; test them against a non-production branch before production promotion.
- Keep secrets in provider secret storage, not repository files, browser bundles, or prompt text.
- Use a server-side evidence writer for append-only records and separate read permissions from write/administrative access.

**Acceptance test:** Cross-tenant reads/writes fail; missing RLS policies fail closed; a leaked browser bundle contains no secret or service-role key; privileged functions reject unauthenticated/unauthorized callers; schema changes can be reproduced from migrations.

Official documentation:
- [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys)
- [Securing data](https://supabase.com/docs/guides/database/secure-data)
- [Securing Edge Functions](https://supabase.com/docs/guides/functions/auth)

### 4.7 Context7 — version-aware documentation for engineering

Context7 retrieves current, version-aware library documentation and code examples for AI coding assistants through an MCP server or CLI + Skills workflow. In GIEN, its primary value is reducing stale API guidance during implementation and review. It should be a development-time assistant, not a runtime data dependency for the supervisory UI.

**GIEN rules**
- Resolve the exact library ID and version before asking for usage guidance.
- Prefer the official documentation source for the library; record which library ID/source and retrieval date informed a code change.
- Treat retrieved code as a starting point: run type checking, tests, security scans and dependency review locally/CI.
- Do not send tokens, passwords, private code, personal data or confidential incident material in documentation queries.
- Pin dependencies and validate APIs against the actual installed versions.

**Acceptance test:** The implementation record identifies the requested library and version; the built app does not depend on live Context7 availability; generated code passes the repository CI suite and a human security review.

Official documentation:
- [Context7 overview](https://context7.com/docs/overview)
- [Context7 MCP clients and setup](https://context7.com/docs/resources/all-clients)
- [Context7 API guide](https://context7.com/docs/api-guide)

### 4.8 Atlassian Rovo MCP — connected work context

 The current public vendor documentation calls the service the **Atlassian Rovo MCP Server**. The available app connector is labeled “Atlassian Rovo (Legacy)” in this environment; that label does not by itself prove that Atlassian has discontinued the service or that the connector uses the current MCP endpoint. Confirm the connector's
authentication and API contract before
selecting an implementation path.

 The current server connects AI clients to Atlassian Cloud work context, including Jira, Confluence, Bitbucket, Jira Service Management and Loom, with other tools depending on access and configuration. OAuth 2.1 is the recommended interactive method; admin-enabled API-token authentication can serve non-interactive use cases. Tool availability
changes with authentication mode,
scopes, organization-enabled permission groups and site permissions. Tool discovery is dynamic, and read, write and destructive calls are separated.

**GIEN rules**
- Start with read-only Jira/Confluence/Bitbucket context and a narrow allowed-tool list.
- Preserve each source object's ARI or canonical URL, site/cloud identity, project/space, last-updated time and the principal that accessed it.
- Keep tenant/site boundaries explicit; never mix context from unrelated Atlassian sites.
- Require approval for write/destructive operations and log tool name, arguments after redaction, actor, approval and result.
- Do not assume the model sees all work items or that a missing result proves that a record does not exist.

**Acceptance test:** Tool inventory matches granted permissions; read scopes cannot invoke write actions; a user cannot retrieve a page outside their existing access; destructive operations require separate approval and audit evidence.

Official documentation:
- [Atlassian Rovo MCP overview](https://developer.atlassian.com/cloud/rovo-mcp/)
- [Authentication and authorization](https://developer.atlassian.com/cloud/rovo-mcp/guides/authentication-and-authorization/)
- [Supported tools and permission groups](https://developer.atlassian.com/cloud/rovo-mcp/guides/supported-tools/)

### 4.9 OpenAI Platform — structured inference and controlled tool use

 Use the server-side Responses API for model-driven extraction, summarization, classification, comparison and constrained tool orchestration. Use Structured Outputs when the application needs a schema-bounded response, but still validate semantic constraints, citations, source IDs, values, and authorization in application code. Schema-valid JSON is
not proof that the values are
true.

 Responses API MCP support can connect an application to remote MCP servers. The OpenAI guide says approval can be required before data is shared with a connector or remote server and recommends carefully reviewing sensitive tool actions and data sharing. Remote MCP server behavior and data handling remain the responsibility of the server operator.
Only connect to trusted
official endpoints where feasible; use explicit tool allowlists, minimal context and a defined approval rule. Prompt injection is a design concern when tool outputs can influence actions.

**GIEN rules**
- Keep the OpenAI API key server-side in managed secret storage and rotate it under an owner-controlled procedure.
- Apply per-role model/tool permissions and request only the context needed for the task.
- Use approval for write-capable or high-impact MCP tools; avoid blanket approval bypasses.
- Treat web pages, tickets, Slack messages and tool outputs as untrusted data; they cannot change system policy.
- Record model identifier/version when available, request/response IDs, prompt/template version, tool calls, source references, schema-validation result, evaluation result and reviewer decision—subject to privacy, retention and contractual controls.
- Keep an evaluation suite for extraction accuracy, citation completeness, prompt-injection resistance, refusal behavior, tool routing, and regressions.
- Confirm data-retention, data-residency and zero-data-retention needs with provider settings and each connected MCP service; the policy of an MCP server can differ from the policy of the model API.

**Acceptance test:** API credentials are absent from client assets; malformed/unsupported structured output is rejected; unapproved write calls cannot execute; sensitive values are not sent to an unapproved remote server; evaluation regressions block promotion.

Official documentation:
- [MCP servers and connector tools](https://developers.openai.com/api/docs/guides/tools-connectors-mcp)
- [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [Production best practices](https://developers.openai.com/api/docs/guides/production-best-practices)

## 5. Common event and evidence contract

Normalize provider events into a stable internal envelope while retaining the raw provider identity and a reference to the original payload. Suggested fields:

| Field | Meaning |
|---|---|
| event_id | GIEN-generated immutable event identifier |
| provider | Provider name and adapter version |
| provider_event_id | Provider's event/run/message identifier, when available |
| resource_type / resource_id | Type and stable external resource key |
| action | Read, create, update, delete, deploy, crawl, approve, or other normalized action |
| event_time / observed_time / ingested_time | Separate provider time from GIEN observation and ingestion time |
| principal / tenant / auth_context | Actor, tenant/site, and credential/scope reference (never secret value) |
| source_uri / commit_sha / version | Canonical source and version identifiers, when applicable |
| payload_hash | SHA-256 or SHA-384 digest of a canonicalized evidence payload |
| verification | Signature, schema, authorization, and source checks, each with a separate result |
| classification / retention | Data handling classification and retention category |
| idempotency_key | Stable deduplication key for retried or repeated work |
| evidence_refs | IDs for source documents, artifacts, workflow runs, and linked records |
| approval_id | Human/policy approval reference when needed |
| outcome / failure_code | Normalized terminal result or retryable/permanent failure reason |

Do not collapse these states:
- **Configured:** settings exist.
- **Connected:** authentication and a basic read request succeeded.
- **Observed:** a record/event was returned from a named source.
- **Authenticated:** the source/request identity was verified.
- **Schema-valid:** payload passed schema checks.
- **Policy-allowed:** operation passed application authorization.
- **Executed:** action was actually attempted.
- **Passed:** the relevant executable test/check returned success.
- **Reviewed/approved:** a named authorized reviewer made the applicable decision.
- **Independently assured:** a separate competent process reviewed sufficient evidence. This label must not be inferred from ordinary CI or model output.

A digest proves equality with the bytes that were hashed; by itself, it does not prove origin, correctness, timestamp authenticity, or independent assurance.

## 6. Failure handling and operational controls

- **Retries:** Retry transient network errors and provider 429/5xx responses with bounded exponential backoff and jitter; honor Retry-After where provided. Do not blindly retry permanent authorization, schema, or validation failures.
- **Idempotency:** Use a unique inbox key per provider event and an idempotency key per intended write. Keep event ingestion separate from action execution.
- **Dead-letter queue:** Move exhausted events to a review queue with reason and source reference. Provide a redrive process that retains the original event identity.
- **Reconciliation:** Scheduled jobs compare GIEN's observed state to provider state, especially for services whose webhooks can be missed. Report reconciliation lag and discrepancies rather than silently overwriting history.
- **Rate controls:** Per-provider, per-tenant and per-user concurrency limits; bounded queue length; circuit breakers for recurring failures.
- **Secret lifecycle:** Unique credentials per environment/component where feasible; minimal scopes; rotation and revocation runbooks; no credential values in traces, logs, commit messages, or model prompts.
- **Audit integrity:** Append-only application records; tightly controlled administrative edits; canonicalization rules; signed batch manifests or WORM-backed object retention only after key custody and recovery are tested.
- **Data minimization:** Collect only fields necessary for the defined control; define purpose, access, retention and deletion for messages, task descriptions, retrieved web content and model requests.
- **Versioning:** Track adapter version, API version, schema version, policy version, prompt/template version and dependency lockfile.

## 7. Rollout sequence

### Phase 0 — inventory and assurance boundary
Create an integration register with owner, purpose, data classification, source-of-truth status, authentication method, requested scopes, environments, retention rules, failure owner and revocation procedure. Treat all providers as unconnected until a live test is captured.

### Phase 1 — read-only and evidence-first
Implement GitHub repository/PR/workflow reads, Netlify deployment-status reads, source ingestion via Firecrawl, and read-only Asana/Slack/Atlassian context. Add correlation IDs, normalized evidence records and health views. Keep model calls read-only and bounded.

### Phase 2 — identity and persistence
Add Supabase migrations, tenant boundaries and RLS tests; provision server-side secret references; implement webhook inbox/outbox, duplicate handling, reconciliation and dead-letter review. Confirm Supabase key migration plan against the current state of each project.

### Phase 3 — human-reviewed writes
Introduce narrowly scoped write operations, such as creating an Asana remediation task or posting a Slack notification. Require explicit approval for release, policy, permissions, destructive operations and any action that changes source-of-truth status.

### Phase 4 — constrained model/tool orchestration
Add Responses API and selected MCP tools with documented allowlists, data-sharing review, structured schemas, prompt-injection tests and evaluation gates. Context7 remains a coding-time aid rather than a production runtime dependency.

### Phase 5 — operational readiness
Perform penetration and authorization testing; secret leakage checks; webhook replay and signature tests; failure/retry and restore drills; data-retention review; provider quota and cost review; and a rollback exercise. Only then consider production use.

## 8. Release acceptance criteria

A release candidate should not be promoted until all of the following are evidenced:

1. Provider connections use approved identities and the minimum required scopes.
2. Secrets do not appear in frontend bundles, repository content, test output, or telemetry.
3. Every webhook with a provider signature uses the documented verification procedure; replay and duplicate delivery are handled safely.
4. Database RLS/tenant-boundary tests pass for every applicable role; privileged functions fail closed.
5. Every consequential write has a policy decision, actor identity, and required approval.
6. Source IDs and versions are retained so control claims can be traced to provider records and original evidence.
7. Provider outages and rate limits do not cause unbounded retries or silent evidence loss.
8. Reconciliation detects missed events and conflicting provider state.
9. Model outputs are schema- and policy-validated; remote MCP data-sharing and write capabilities are reviewed.
10. CI build, smoke tests, dependency/security checks and human review all pass on the exact candidate commit.
11. Preview/prod separation, rollback and credential rotation are tested.
12. The UI distinguishes simulated, connected, observed, verified, approved and independently assured states.

## 9. Open questions to resolve before live implementation

- Which providers and workspaces/sites are actually authorized for GIEN, and who owns each integration?
- Is the hosting target Netlify, GitHub Pages, or both? A static frontend alone cannot keep server-side provider secrets; a BFF/Edge Function service is required.
- Which records may be sent to OpenAI, Firecrawl, Context7, or external MCP servers, under which retention and residency requirements?
- Which Asana, Slack and Atlassian writes are approved, and which require human approval?
- What are the operational database's tenant model, RLS policy set, backup/restore objective and evidence-retention period?
- What is the formal classification and verification process for an evidence item to be accepted into a supervisory submission?
- Which current GitHub checks are mandatory, and which checks are optional or informational?

Until these questions are answered and tests are run against actual connections, the correct status is **design specified; integration unverified**.

## 10. Official source register

 The vendor documentation links above were reviewed on 12 October 2026 for this design memo. APIs, scopes, feature availability, plans, model compatibility, and security settings may change. Before implementation, re-check the relevant official documentation and the settings of the actual organization/site/project. This report does not replace
legal, privacy, security,
contractual or independent assurance review.
