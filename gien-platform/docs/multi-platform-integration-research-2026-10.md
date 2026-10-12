# Multi-Platform Integration Research for the GIEN Governance Platform

**Research snapshot:** 12 October 2026  
**Repository:** OneFineStarstuff/OneFineStarstuff.GitHub.io  
**Target:** \`gien-platform/\` — React, TypeScript, Vite, React Router and Tailwind  
**Classification:** Architecture and vendor research; not evidence of deployed integrations, vendor endorsement, compliance, or independent assurance.

## 1. Executive assessment

The requested providers cover distinct integration classes. They should not be treated as 31 interchangeable APIs or connected as one broad agent with shared credentials. Several products expose documented APIs or MCP servers; some require enterprise or partner approval; others are best treated as user-mediated creation and export tools until a supported API and licence are
confirmed.

**Recommended design:** one server-side Integration Gateway/BFF with a registry of typed provider adapters, tenant-bound OAuth connections, per-action policy, source provenance, rate limits, redacted logs, and an approval queue for writes. The current GIEN application is a frontend prototype. This dossier does not claim that credentials, user authorizations, or production
service connections exist.

**Do not integrate everything into the core risk engine.** The governance application should keep risk and compliance calculations in deterministic services and authoritative records. External assistants can retrieve evidence, draft materials, and propose actions, but they must not set systemic-risk measurements, certify compliance, seal evidence, approve submissions, modify
constitutional invariants, or operate kill switches.

### Research findings that affect design decisions

1.  **Partner rights vary materially.** Coursera’s direct APIs target Business/Campus/Government customers and direct LMS/LXP integrations may require Coursera solution-architect engagement. Expedia’s Rapid APIs require an approved partner relationship. Zillow’s API terms apply to approved licensees and contain significant restrictions on use, caching, and redistribution.
   Thumbtack also distinguishes marketplace integrations from pro integrations and uses OAuth 2.0.
2. **A tool connector is not a production integration.** Availability of an app tool inside ChatGPT does not demonstrate that GIEN has an authorized service account, a durable API contract, a production secret store, or permission to operate on behalf of every GIEN tenant.
3. **Keep operational authority local.** The model may summarize an evidence record or draft a Jira/Asana/Slack update. The server must determine whether a caller may read or write, validate the payload, log the action, and obtain human approval for sensitive changes.
4. **Provider lifecycle matters.** OpenAI's current deprecation schedule lists 31 October 2026 as the date existing Evals become read-only and 30 November 2026 as the scheduled shutdown of the Evals dashboard/API and Agent Builder. Build and own the GIEN evaluation fixtures and harness rather than making the product depend on these legacy surfaces.
5. **Supabase has an approaching key migration.** Its current API-key documentation says legacy \`anon\` and \`service_role\` keys are being deprecated by the end of 2026. New work should use publishable and secret key types, with secret keys restricted to controlled server-side components.

### Connector catalog snapshot

At the time of this research, the current ChatGPT tool catalog exposed a dedicated app-tool namespace for every named provider in the registry except Firecrawl. OpenAI Platform was assessed as an API product, not as a separate third-party app connector. This is a snapshot of tools available to the current conversation, not proof that a user's account is authenticated, that a
specific workspace is authorized, or that any service is connected to the deployed GIEN application. The platform must re-check connection health, tenant authorization, and scopes at runtime.

## 2. Platform architecture recommendation

### 2.1 Control and data flow

- **GIEN web client:** role-based presentation, case/workflow UI, dashboards, and evidence previews. It never receives vendor secrets or unfiltered service credentials.
- **Integration Gateway/BFF:** server-side provider adapters, OAuth callbacks, token refresh and revocation, tenant-bound connections, request schemas, per-provider policy, quotas, timeouts, circuit breakers, idempotency, and audit events.
- **Policy and approval layer:** role + tenant + resource checks, operation risk tier, explicit approval for external writes or publication, two-person approval where required, and fail-closed behaviour.
- **Evidence and provenance layer:** source URL/record ID, provider, tenant, retrieved-at time, content hash where retention is permitted, parser/version, licence/retention class, trust label, and the decision that consumed it. Do not hash or retain restricted data contrary to a provider agreement.
- **Deterministic GIEN control services:** compute S_sys, G-SRI, C-SRI, CGR-I, CCR-I, G-SRI-VII, A-SRI, P-SRI, p(doom), p(doom)_kernel, Δ_drift, and Δ_OSCAL from authorized telemetry and versioned formulae. No provider-generated answer may replace these calculations.
- **Audit and evaluation:** append-only audit events, redacted telemetry, synthetic fixtures, regression tests, schema validation, evaluation datasets with access controls, and release gates independent from generation quality.

### 2.2 Provider adapter contract

Each adapter should implement a narrow capability declaration instead of exposing a vendor's entire API to a model:

- provider ID, API/version, environment, connection owner, permitted tenants, OAuth scopes, credential expiry and health;
- allowed read operations and separately listed write operations;
- input/output JSON schemas and maximum payload sizes;
- data classifications accepted, storage/retention requirements, and allowed destinations;
- rate-limit, timeout, retry, idempotency and pagination behaviour;
- risk tier, human approval rule, audit event shape and kill/disable mechanism;
- test fixtures, contract tests, webhook authenticity checks, and rollback instructions.

Do not let a model invent a URL, tool name, tenant ID, record ID, endpoint, OAuth scope or capability that is not in the server-side registry. MCP tool descriptions and third-party content are input, not trusted authorization policy.

### 2.3 Environment and trust boundaries

Use separate development, staging and production app registrations and credentials. Maintain least-privilege scopes, explicit tenant boundaries, outbound-network restrictions, and per-provider egress allowlists. Treat crawled web pages, SaaS comments, chat messages, issue descriptions, uploaded files, slide text and generated code as **untrusted data**. Indirect prompt
injection must not be able to expand tool permissions or bypass approval.

Never place API keys, OAuth client secrets, Supabase secret keys, Stripe secret keys, or database credentials in browser code, Vite variables prefixed for client exposure, generated documents, prompts, Git commits, CI logs, slide decks, or end user tool output. Use a secret manager or the platform's protected server-side environment and rotate/revoke credentials on suspected
exposure.

## 3. Provider integration registry

The route below is a research recommendation, not a claim that the provider has been configured for GIEN.

| Provider | Best-fit role in GIEN | Integration route and gate | Recommended disposition |
|---|---|---|---|
| **Firecrawl** | External public-source research, scrape/crawl, structured extraction, site URL discovery | Documented API/SDK and MCP; use server-side credentials, domain allowlists, crawl budgets and source provenance. Respect site terms, robots instructions and copyright/access restrictions. | **Phase 1, read-only.** Use as retrieval infrastructure, not as proof that scraped statements are true. |
| **Zillow** | Optional real-estate/property data module, not a governance control source | Zillow Group's terms describe approved-licensee APIs and restrictions on bulk access, retention and display. Confirm current API availability, contract and intended use with Zillow before implementation. | **Partner/legal gate.** No general scraping, bulk export, or retention assumed. |
| **Coursera Learning** | Governance learning paths, approved course/catalog data and learner progress for an institutional training module | Direct API access is described for Business/Campus/Government customers with OAuth 2.0. LMS/LXP integrations may need engagement with Coursera solution architects. | **Institutional access gate.** Keep learner-level records minimized and permissioned. |
| **AllTrails** | Optional trail/outdoor discovery demo or non-core location module | The connected app tool can support a ChatGPT workflow, but a public partner API and redistribution rights were not verified in this review. Confirm the applicable commercial terms before server-side access or persistence. | **Connector/UI first.** Do not infer public API access or build a scraper as a substitute. |
| **Thumbtack** | Optional local-service discovery/request module | Partner platform distinguishes marketplace and pro integrations; its docs specify OAuth 2.0 and webhooks. Request submission and pro-side lead/message handling are distinct privileges. | **Partner gate.** Search/read first; require user approval before submitting requests or sending messages. |
| **Netlify** | Hosting/deployment, deploy previews, site status and deploy logs | REST API supports sites, deploys and hooks; OAuth is the public-integration path, while personal access tokens are for controlled scripting. Code-agent docs provide deploy guidance. | **Choose as one production deploy authority, or use for preview only.** Protect production deploys with CI and approval. |
| **Replit** | Rapid prototyping and app-generation workflow | The available app tool exposes a project-building workflow. A generic, stable external API contract for all lifecycle actions was not established by this review; verify current supported API and account permissions before depending on it. | **Prototype/workbench.** Generated changes still require Git review, testing, security scan and standard release controls. |
| **Lovable** | Prompt-assisted implementation and scaffolding | Official docs support syncing projects to GitHub/GitLab/Bitbucket; Lovable documents Supabase integration and an MCP server. Keep the versioned repository as the reviewable source of truth. | **Prototype/workbench.** Never merge generated changes automatically into protected production branches. |
| **Airtable** | Human-maintained registers, intake queues and lightweight operational catalogues | Web API with paginated records and a documented 5-requests/second-per-base limit; current support docs state pages can return up to 100 records. OAuth/scopes and base permissions should be narrowed. | **Phase 2, bounded CRUD.** Not the authoritative database for critical invariants or high-volume telemetry. |
| **StubHub** | Optional event discovery/ticket data, unrelated to GIEN systemic-risk evidence | Official API docs describe HTTPS, OAuth 2.0 and event/listing operations. The API documentation surfaced in this review is older; confirm current availability, scopes, resale requirements and commercial terms before production use. | **Separate optional module.** Read-only event search first; no purchase/listing write without explicit user confirmation and current authorization. |
| **B12 site Generator** | Produce a separate public-facing site or non-production explainer | B12 documents a remote MCP server for MCP-compatible clients to generate an editable site and return a preview link. site publication is a real external side effect. | **Draft/preview only by default.** Human review for factual, legal, brand, privacy and accessibility checks before publishing. |
| **Outliner** | Turn source material into an outline or briefing structure | The current app connector exposes an outlining workflow; a supported public REST API was not verified in the official documentation reviewed. | **Drafting only.** Store the approved source references alongside the outline and verify claims before reuse. |
| **DataCamp** | Training catalogue and, where licensed, learner completion/progress ingestion | DataCamp describes a read-only Catalog API for course/project/assessment/practice/track content and learner events such as course completions; Enterprise SSO documentation describes SAML 2.0. | **Learning-module gate.** Confirm the plan and API entitlement; use aggregate progress where individual-level records are unnecessary. |
| **Speechify** | Accessible audio rendition of approved briefing text | Official TypeScript/JavaScript and Python SDKs expose text-to-speech functionality and require a Speechify API key. A ChatGPT playback tool is not equivalent to a production GIEN audio backend. | **Optional output adapter.** Send only approved/minimized text; validate generated audio, accessibility and voice rights. |
| **Genspark AI Slides** | Human-reviewed presentation drafting | The official help material documents its AI Slides workspace and export to PDF, PPTX or Google Slides. A stable public generation API was not verified in this review. | **User-mediated authoring.** Export reviewed decks; do not treat slides as signed evidence or automatically publish them. |
| **Agentic Slides by SlidesGPT** | Programmatic generation of first-draft presentations from an approved brief | SlidesGPT documents a presentation-generation endpoint authenticated with a bearer token. Treat its output as generated content requiring factual, source and confidentiality review. | **Optional output adapter.** Send redacted data; store request ID, template/version and reviewed export. |
| **Asana** | Work assignments, action plans and task status | Official API and webhooks; rate limits vary by plan, and 429 responses include Retry-After. Use OAuth, minimal scopes and webhook validation. | **Phase 2.** Create draft tasks only or place writes behind approval; Asana task status is not evidence that a control passed. |
| **Statsig** | Gradual rollout, feature flags, experiments and dynamic configuration | Official SDKs and HTTP API support gates, experiments, dynamic configs and event logging. | **Phase 2, non-authoritative.** Flags may control UI rollout but must not be the sole enforcement mechanism for security policies or constitutional invariants. |
| **Gamma** | Generate polished reports, briefings, presentations, documents, sites or social content | Gamma documents a generally available API; requests use an API key and API access is plan-gated (Pro, Ultra, Teams or Business per current docs). | **Optional output adapter.** Use approved summaries, cite source records, and require content/sign-off review. |
| **Slack** | Operational notifications, review requests and approved summaries | Web API, granular OAuth scopes and Events API. Access to messages/files depends on granted scopes; incoming events require signature and replay protection. | **Phase 2, least privilege.** Read only authorized channels. Do not ingest the whole workspace by default; human approval before externally visible or high-impact posts. |
| **Supabase** | Application database, authentication, storage and server-side functions | PostgreSQL/Auth/API/RLS stack. The current docs say publishable keys are for public components and secret keys bypass RLS and must remain server-side; legacy anon/service_role keys are due to deprecation by end-2026. | **Candidate primary backend.** Enforce RLS and tenant policies, use publishable/secret key types, and test database grants plus RLS independently. |
| **Neon** | Managed PostgreSQL with programmatic project/branch/database/role/compute management | Neon API docs describe management of projects, branches, databases, roles, compute endpoints and API keys. Use separate roles and branch protections; do not expose the management API to the browser/model. | **Alternative primary database.** Choose deliberately versus Supabase rather than adding two competing sources of truth. Pair with an explicitly selected identity/auth solution. |
| **Context7** | Version-specific software documentation lookup for implementation and debugging | Context7 exposes an MCP server with resolve-library-id/query-docs and a documented HTTP API. API-key/OAuth setup and rate limits apply. | **Phase 1.** Pin the library and version in research notes, but validate guidance against upstream docs and repository lockfiles. |
| **GitHub** | Code/review source of truth, issues, protected branches, CI/CD and release evidence | REST/API integrations should use GitHub Apps or fine-grained tokens with only the necessary permissions. GitHub Actions OIDC can avoid long-lived cloud deployment keys when configured with strict trust conditions. | **Core control plane.** Protected branches, mandatory CI, signed/reviewed changes, scoped workflow permissions, and independent release approvals. |
| **Figma** | UI/design-system source, design inspection and change notifications | Figma REST API supports OAuth apps; plan access tokens are available on Organization/Enterprise plans for organization-level automation; Webhooks V2 can notify file/team/folder changes. | **Design provenance only.** A design file does not establish runtime behaviour, accessibility compliance or evidence of control operation. |
| **Canva** | Reports, infographics and communications assets | Canva Connect REST APIs use OAuth 2.0 Authorization Code with PKCE; use user-consented scopes and approved templates. | **Optional output adapter.** Do not place confidential evidence in public templates; preserve source citations and review before distribution. |
| **Expedia** | Optional travel/lodging module, separate from GIEN governance | Expedia Group's Rapid API onboarding requires becoming an approved partner and meeting relevant launch requirements. Inventory access is not equivalent to an open public API entitlement. | **Partner gate.** No booking, cancellation or payment action without authorized partner integration and explicit user consent. |
| **Vercel** | Hosting, preview deployments and deployment metadata | Vercel provides project/deployment APIs and access tokens; constrain tokens to the proper team/project and use protected CI/OIDC where possible. | **Choose as one production deploy authority, or use for preview only.** Review preview data and protect production promotion. |
| **monday.com** | Portfolio/workstream boards and coordination state | GraphQL API supports board/item workflows and has complexity-based and daily call limits; hosted MCP/API operations consume that budget. | **Phase 2.** Treat board values as workflow metadata, not immutable audit evidence. Use narrow scopes and bounded queries. |
| **Stripe** | Optional paid product/subscription workflow; not required for GIEN control logic | Stripe provides API keys, webhooks and idempotency patterns. Secret keys stay server-side; webhook signatures and replay/idempotency protections are required. | **Only if payments are explicitly in scope.** Do not handle raw card data; keep financial events and approval/audit state distinct from GIEN risk calculations. |
| **Atlassian Rovo (Legacy)** | Atlassian issue/wiki/search workflow, subject to connector transition | The available ChatGPT namespace is labelled legacy. Current Atlassian docs describe the Rovo MCP Server using OAuth 2.1 and respecting existing Atlassian permissions, with read/write/destructive tool classes and discovery-based tool listing. These are not proof that the legacy connector is equivalent. | **Migration review before dependency.** Inventory actual supported tools, OAuth scopes and admin policy; start read-only, then approve writes by risk tier. |
| **OpenAI Platform** | Bounded reasoning, structured summarization and tool orchestration | Use the Responses API server-side with Structured Outputs, schema validation, limited tools, server authorization and provenance-bearing sources. Follow the current data controls and deprecation notices. | **Core AI adapter after security gate.** No browser key, no model authority over measurements or filings, and maintain a repository-owned evaluation harness. |

## 4. Detailed security and operational controls

### 4.1 Evidence retrieval and web data

For Firecrawl and Context7, preserve retrieval metadata and the originating URL/library identifier. Every retrieved page or snippet must be labelled untrusted. The model may propose an extraction, but a schema validator and provenance check must decide whether it is usable. Use domain allowlists where feasible, deny access to private/link-local/internal addresses, block
redirects into forbidden address ranges, constrain crawl depth and response size, and apply per-tenant budgets to prevent SSRF, data exfiltration, and uncontrolled spending.

Do not scrape a provider's consumer site when an authorized API or partner path is required. Do not use Firecrawl to bypass a login, paywall, anti-abuse control, or provider terms. For Zillow, the current terms surfaced in this review say access is for approved licensees and impose transactional display, no-bulk-access/no-retention requirements and a maximum of 20 individual
properties shown at a time for the Property Details API. These are contractual constraints, not implementation details to work around.

### 4.2 SaaS workspaces and human communications

Slack, Asana, Airtable, monday.com and Atlassian are collaborative systems. Messages and task descriptions can contain personal data, credentials, privileged information, malicious instructions or incorrect statements. Use explicit workspace/site/base/channel/project allowlists. Minimize content pulled into prompts and do not duplicate complete workspaces in a GIEN database
without a documented need and retention rule.

Separate operations by impact:

- **Read-only:** search/list/get metadata, with tenant and project checks.
- **Draft:** propose a task, message, page, design, comment or configuration without saving externally.
- **Reversible write:** create or update a low-impact object after user approval and server validation.
- **High-impact/destructive:** delete, publish, change permissions, trigger deploys, alter billing/experiments, or send broad external announcements. Require separate approval, review the exact payload, log the approver and result, and provide rollback where possible.

Never infer authority from a model response, tool description, a ticket's wording, or a Slack message. Use the authenticated principal and current API permissions.

### 4.3 Database, hosting and deployment

Select one primary production database and one production deployment authority before implementation. Supabase is the stronger integrated option when its Auth, RLS and storage features meet requirements; Neon is a PostgreSQL-first alternative with branches and a management API, typically paired with a separately selected identity stack. Use isolated preview databases and
synthetic data. Do not clone production personal data into preview environments by default.

Choose **Netlify or Vercel** as the canonical production deployment path, rather than letting multiple providers independently promote production builds. Replit and Lovable are useful generation/prototyping paths; GitHub review, CI checks, dependency scanning, secret scanning, immutable release artifacts and explicit production promotion should remain the governed delivery
process. B12, Gamma, Canva, SlidesGPT and Speechify are output channels, not authoritative record stores.

For every release, verify server-side secrets, auth and tenant isolation, API authorization, dependency health, accessibility, security headers, telemetry redaction, content security policy, rollback, and incident response. Apply signed webhooks, replay protection, idempotency keys where appropriate, bounded retries with jitter, dead-letter handling, and provider-specific
circuit breakers.

### 4.4 AI outputs and generated artifacts

Gamma, SlidesGPT, Genspark AI Slides, Outliner, B12, Canva and Speechify can improve packaging and accessibility. Generated prose, diagrams, audio or sites are not self-authenticating evidence. Every artifact that makes factual claims needs source references and a review status (draft, validated, approved, released). The content review must ensure sources are still accessible,
numbers match authoritative data, private fields are redacted, and no unpublished control/evidence details leak into an external generation service.

For external publication, deployment, payment, booking, ticket purchase/listing, service request submission, public message send, destructive deletion, or access-control modification, present a final human-readable confirmation with provider, destination, scope and exact intended side effect. If confirmation or authorization is missing, stop at draft/preview.

## 5. Recommended integration sequence

### Phase 0 — Inventory and threat model

Create a connection registry without storing secrets in the repository. For every provider record owner, business purpose, data categories, scopes, tenant binding, environment, API terms/licence, retention, incident contact, renewal date, and disable procedure. Mark unknown API rights as **unverified**, not implicitly approved.

### Phase 1 — Grounded research and engineering foundations

Start with the most directly relevant, low-side-effect adapters: GitHub (read/review/CI metadata), Context7 (versioned docs), and Firecrawl (public sources under allowed terms). Add source citations and a standard evidence schema. Build synthetic test datasets and an independent smoke/contract-test suite. Do not permit these providers to write to business systems.

### Phase 2 — Choose backend, identity and deploy topology

Select Supabase **or** Neon, and Netlify **or** Vercel, after threat modelling and a cost/operability review. Implement BFF, tenant-aware authorization, secret management, audit logging, database migrations, backup/restore tests, policy-as-code and protected release workflows.

### Phase 3 — Bounded operational workflow integrations

Pilot one coordination provider first (for example Asana or monday.com) and optionally Slack/Airtable. Implement read-only operations, explicit workspaces/project allowlists, draft creation, webhook validation and human-approved writes. Treat task completion as workflow metadata only.

### Phase 4 — Reviewed content outputs

Select one presentation API (Gamma or SlidesGPT) instead of wiring all content products into the first release. Add Canva/Figma assets if the design pipeline needs them; Speechify if accessibility requirements call for audio. Use B12/Replit/Lovable/Genspark/Outliner through a controlled authoring/export path unless their current supported integration contract specifically
justifies automation.

### Phase 5 — Partner-only and optional domain modules

Enable Coursera, DataCamp, Thumbtack, Expedia, Zillow, AllTrails and StubHub only where there is a confirmed product purpose, account entitlement, rights to the data, and a privacy/retention assessment. Keep travel, outdoor, ticketing, property and local services out of the core systemic-risk computation path. Do not ship placeholder API calls or scraped fallbacks for services
whose approved access is missing.

### Phase 6 — Production assurance

Require an adapter contract test, tenant-isolation test, negative authorization test, prompt-injection test, data-retention test, provider outage test, rate-limit/backoff test, secret scan, dependency scan, accessibility review, user acceptance review and rollback exercise before activating a provider. Record failures and exceptions; do not label the platform “compliant” or
“independently assured” without appropriate evidence.

## 6. Release acceptance criteria

An integration is not production-ready until all applicable items below are evidenced:

- [ ] Current official API/MCP/version and applicable terms have been reviewed; partner permissions and plan entitlements are recorded.
- [ ] Credentials are stored server-side; scopes are minimal; refresh/revocation/rotation and expiry alerts are tested.
- [ ] Tenant and resource authorization are enforced outside the model; negative tests prove inaccessible tenants cannot be queried.
- [ ] Data classification, retention, deletion, cross-border transfer, downstream processors and logging restrictions are documented.
- [ ] JSON schemas, provider error handling, rate limits, pagination, retries, idempotency and webhook verification are tested.
- [ ] Indirect prompt-injection tests prove source content cannot expand permissions, reveal secrets or cause unapproved side effects.
- [ ] Every write has an explicit operation policy, audit record, confirmation/approval and rollback or remediation path.
- [ ] CI, staging smoke tests, dependency/secret scans, observability redaction, cost caps and incident response are enabled.
- [ ] Generated content remains labelled as a draft until factual and human review is recorded.
- [ ] The specific provider integration is described accurately; no claims of production connection, vendor approval or regulatory assurance are made without evidence.

## 7. Official reference register

The following sources were consulted for the snapshot above. Vendor APIs, terms and product lifecycle dates can change; verify the exact plan, region, API version, permissions and contract again immediately before implementation.

### Retrieval and partner/data providers

- Firecrawl — [Introduction and API/SDK capabilities](<https://docs.firecrawl.dev/introduction)>
- Zillow Group — [Terms of Use: Data & APIs](<https://www.zillowgroup.com/developers/terms/)>
- Coursera — [Production API developer portal: Get started](<https://dev.coursera.com/get-started)>
- AllTrails — [Terms of Service](<https://www.alltrails.com/terms)>
- Thumbtack — [Partner Platform overview](<https://developers.thumbtack.com/docs/overview)>, [Getting started](<https://developers.thumbtack.com/docs/getting-started)>, and [OAuth 2.0 authentication](<https://developers.thumbtack.com/docs/getting-started/authentication)>
- StubHub — [API overview](<https://developer.stubhub.com/docs/overview/introduction/)>
- DataCamp — [Catalog API integration](<https://support.datacamp.com/hc/en-us/articles/14992652559255-Catalog-API-Integration)> and [Enterprise SSO](<https://support.datacamp.com/hc/en-us/articles/360009645713-Single-Sign-On-SSO-For-DataCamp-Enterprise-An-Overview)>
- Expedia Group — [Rapid API partner setup](<https://developers.expediagroup.com/rapid/setup)>

### Developer platforms, data and hosting

- Netlify — [REST API get started](<https://docs.netlify.com/api-and-cli-guides/api-guides/get-started-with-api/)> and [APIs for code agents](<https://docs.netlify.com/extend/building-code-agents/apis-for-code-agents/)>
- Replit — [Official documentation](<https://docs.replit.com/)>
- Lovable — [Official documentation](<https://docs.lovable.dev/introduction/welcome)> and [Supabase integration](<https://docs.lovable.dev/integrations/supabase)>
- Airtable — [Web API getting started](<https://support.airtable.com/articles/6292134965-getting-started-with-airtable-s-web-api)>
- Supabase — [API keys and key types](<https://supabase.com/docs/guides/getting-started/api-keys)> and [Postgres Row Level Security](<https://supabase.com/docs/guides/database/postgres/row-level-security)>
- Neon — [API reference](<https://neon.com/docs/reference/api)>
- Context7 — [API guide](<https://context7.com/docs/api-guide)> and [MCP client configuration](<https://context7.com/docs/resources/all-clients)>
- GitHub — [Fine-grained token permissions](<https://docs.GitHub.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=2026-03-10)> and [OIDC deployment hardening](<https://docs.GitHub.com/en/actions/security-for-GitHub-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)>
- Vercel — [REST API documentation](<https://vercel.com/docs/rest-api)>
- Replit and Lovable are treated as authoring/development workbenches here; deployment changes still use the versioned repository's governed release process.

### Operational SaaS

- Asana — [API rate limits](<https://developers.asana.com/docs/rate-limits)> and [webhooks](<https://developers.asana.com/docs/webhooks-guide)>
- Statsig — [HTTP API overview](<https://docs.statsig.com/http-api/overview)>
- Slack — [OAuth scopes](<https://docs.slack.dev/reference/scopes)> and [Events API](<https://docs.slack.dev/apis/events-api/)>
- monday.com — [API rate limits](<https://developer.monday.com/api-reference/docs/rate-limits)>
- Figma — [REST API authentication](<https://developers.figma.com/docs/rest-api/authentication/)> and [Webhooks V2](<https://developers.figma.com/docs/rest-api/webhooks/)>
- Canva — [Connect REST API authentication](<https://www.canva.dev/docs/apps/rest-apis/authentication/)>
- Stripe — [API keys](<https://docs.stripe.com/keys)>
- Atlassian — [Rovo MCP overview](<https://developer.atlassian.com/cloud/rovo-mcp/)>, [supported tools](<https://developer.atlassian.com/cloud/rovo-mcp/guides/supported-tools/)> and [authentication/authorization](<https://developer.atlassian.com/cloud/rovo-mcp/guides/authentication-and-authorization/)>

### Content and AI generation

- B12 — [Connecting an AI agent to B12's MCP server](<https://support.b12.io/en/v3/connecting-an-ai-agent-to-b12s-mcp-server)>
- Speechify — [Official TypeScript/JavaScript and Python SDKs](<https://docs.speechify.ai/build/guides/get-started/official-sdks)>
- Genspark — [AI Slides help center](<https://www.genspark.ai/helpcenter/ai-slides)>
- SlidesGPT — [Presentation generation API reference](<https://slidesgpt.com/docs/api-reference/endpoint/generate)>
- Gamma — [Developer documentation](<https://developers.gamma.app/)>
- Outliner — current ChatGPT app-tool workflow was reviewed; a public standalone API reference was not verified in the sources reviewed. Treat it as user-mediated drafting unless supported documentation is supplied.

### OpenAI Platform

- [Responses API overview](<https://developers.openai.com/api/reference/responses/overview)>
- [Function calling](<https://developers.openai.com/api/docs/guides/function-calling)>
- [Structured Outputs](<https://developers.openai.com/api/docs/guides/structured-outputs)>
- [API data controls](<https://developers.openai.com/api/docs/guides/your-data)>
- [API key safety](<https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety)>
- [OpenAI API deprecations](<https://developers.openai.com/api/docs/deprecations)>

## 8. Explicit limitations

This is a desk-research and architecture report dated 12 October 2026. It is not a security assessment of provider systems, legal advice, confirmation of subscription entitlements, or evidence that any provider has authorized GIEN. Public documentation may not reveal private/partner API conditions. “Not verified” means the reviewed sources did not establish a dependable
supported path; it does not prove that no such path exists. No API keys, personal tokens or customer records are included in this report.
