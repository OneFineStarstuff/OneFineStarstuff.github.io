# Thinking and Deep Research: Research Operating Model for GIEN
## Reasoning configurations, source-grounded investigation, evaluation, and evidence governance

**Research date:** 12 October 2026  
**Target project:** GIEN Governance Platform  
**Target branch:** feat/gien-governance-platform  
**Scope:** ChatGPT Thinking / reasoning workflows, ChatGPT Deep Research, OpenAI API research workflows, source reliability, evidence provenance, safeguards, evaluations, and integration design.

> **Status boundary:** This is a design and research note grounded in public OpenAI documentation. It does not prove that the GIEN prototype has an OpenAI API connection, Deep Research entitlement, an approved data-sharing configuration, or production-grade research controls. Do not infer product availability, account features, or API model access from documentation alone.

## 1. Executive finding

“Thinking” and “Deep Research” solve related but distinct problems.

- **Thinking / reasoning** is appropriate when the work needs multi-step analysis, careful comparison, planning, coding, or tool orchestration. In the API, reasoning effort is a configurable parameter supported differently by different models. Greater effort may improve difficult-task quality but commonly trades time and token use for depth.
- **Deep Research** is a research workflow designed to plan and conduct a broad, source-driven investigation, retrieve and compare evidence, and deliver a report with citations or source links. Its user-facing workflow supports reviewing a plan, steering the research, and checking the source list and activity history.
- **Ordinary web search** is often enough for a narrow current fact. Reasoning-assisted/agentic search is appropriate when the model must decide whether another search is needed. Deep Research is more suitable for multi-source questions that need a structured report, competing interpretations, uncertainty handling, and a verifiable bibliography.

For GIEN, use **research as an evidence-production pipeline, not as an authority signal**. An analytically polished report is not evidence that its claims are true, current, legally applicable, operationally implemented, or independently assured. Claims should be traceable to sources; material assertions should be checked against primary sources; and policy, compliance, financial, or release decisions should remain subject to approved human and deterministic controls.

The current API documentation also has a material lifecycle caution: its Deep Research guide says older model identifiers, including o3-deep-research and o4-mini-deep-research, reached a listed shutdown date of 23 July 2026, while older example snippets remain in the guide. Do not copy those model IDs from examples into a new integration without checking the live model catalog and current compatibility. The general reasoning and web-search guides describe other model paths; choose a currently available model based on the actual task, enabled tools, price, latency, and evaluation results.

### 1.1 Lifecycle and evaluation refresh — reviewed 12 October 2026

A fresh check of the official product documentation adds three implementation constraints that should be treated as release inputs.

**Deep Research model migration is not a model-name-only change.** The current Deep Research API guide lists 23 July 2026 as the shutdown date for `o3-deep-research` and `o4-mini-deep-research`, and names `gpt-5.6-sol` as a replacement. However, code examples on that guide still show the older identifiers for reference, while the current reasoning and web-search guides describe other model paths. Do not infer that a model is available merely because an example includes it, or transplant tool configuration between models without testing it. The documented migration path explicitly calls for reviewing Responses API, web search, file search and remote MCP configuration and evaluating the whole workflow—not merely swapping a model string. Resolve the selected model against current account availability, feature eligibility and the exact supported tool combination before release.

**OpenAI's Evals platform has a near-term migration date.** The current Evals guide says existing Evals content is scheduled to become read-only on **31 October 2026** and the Evals platform is scheduled to shut down on **30 November 2026**. As of this report's review date, those dates are still in the future. This notice is specifically about the Evals platform described by the documentation; it should not be generalized into an unsupported claim that every evaluation API endpoint is shutting down on the same dates. Inventory active evaluations, datasets, grader definitions, runs, access owners and export needs now. Confirm the precise affected product surface against the current deprecations page and migrate time-sensitive work to a supported path. The documentation points new users toward Datasets for prompt iteration; teams with API-scale or cross-model evaluation needs must validate the supported successor against their required features.

**Citations must be represented as structured evidence in the application.** The Responses API web-search guide documents inline citations through URL-citation annotations and a separate source list. Preserve the actual URL, title and annotation locations from returned output; do not fabricate citations from search snippets or display a plain source list as though each claim had been checked. For the GIEN reviewer workflow, each material factual claim should map to one or more sources and a verdict: SUPPORTED, PARTIALLY_SUPPORTED, CONTRADICTED, OUTDATED, or UNVERIFIED. The verdict should be produced by an explicit check and, for supervisory or high-impact claims, reviewed by an accountable person.

**MCP access is a data-sharing boundary, not just a tool setting.** OpenAI's current MCP guide says approval is requested by default before data is shared with a connector or remote MCP server, recommends approval for sensitive actions, and advises logging what is sent. Preserve approval for sensitive reads and writes, use a provider allowlist, minimize payloads, and record the server identity, requested tool, arguments or a privacy-safe representation, approval outcome and returned evidence. Treat remote server instructions and returned URLs as untrusted input. Public documentation-server examples are not a justification for bypassing approval on a private or write-capable integration.

**Critical-infrastructure guidance remains a developing input.** NIST's April 2026 AI RMF critical-infrastructure publication is a concept note describing development of a profile. Use it as a design signal and monitor for subsequent drafts or a final publication; do not represent the concept note as a final mandatory standard.

#### Required actions for the GIEN workstream

1. Maintain an allowlisted, dated model/tool compatibility registry. Test the exact identifier, reasoning configuration, search/file/MCP tools, structured-output mode and data classification in the target account.
2. Export and inventory evaluation assets before the Evals platform read-only date; record what is affected, what is retained, export completeness, and the verified replacement path. Keep the original runs and schemas as migration evidence where permitted.
3. Build claim-level citation validation and a reviewer queue; fail closed when a required citation is missing, its source is inaccessible, the cited text does not support the claim, or sources materially conflict.
4. Keep research execution, evaluation, approval and operational action as separate states. A successful research run or successful grader run must never automatically set a GIEN control to PASS or authorize a consequential action.
5. Schedule a lifecycle review before every model/API/tool migration and on a recurring cadence; retain documentation retrieval date, model and tool versions, regression-evaluation result, rollback decision and approver.

## 2. What the current product and API documentation establishes

### 2.1 ChatGPT Deep Research

The current Help Center describes Deep Research as a workflow that investigates complex questions, compares evidence, and provides citations or source links. The documented workflow supports describing the desired outcome, reviewing or refining a research plan, supplying context, steering the research, and inspecting the resulting report. Research may be limited to specified domains or may prioritize those sites while still searching the broader web. Reports include a source list and activity history; the Help Center says completed research can be downloaded in Markdown, Word, and PDF formats. Feature availability depends on the ChatGPT surface, account, and current product settings.

### 2.2 API-based reasoning and research

For application development, the current OpenAI documentation recommends the Responses API for reasoning workflows. The API's reasoning settings are model-dependent. Documented effort values can include none, minimal, low, medium, high, xhigh, and max, but supported values and defaults differ by model. The model guide currently describes GPT-6 Astra as a starting point for many reasoning workloads, with other model families/options for cost and latency trade-offs. These are vendor recommendations, not a substitute for workload-specific evaluation.

The web-search guide distinguishes:
- **Non-reasoning web search:** fast lookup where the query is handed to search and the returned results support the response.
- **Agentic search with reasoning:** the model manages multiple searches, interprets evidence, and decides when to continue searching.
- **Deep Research:** an extended investigation better suited to multi-source synthesis and longer research runs.

The Responses API Deep Research guide describes web search, file search over vector stores, remote MCP, and code interpreter as tools for supported research workflows. Remote MCP integration has interface and approval constraints; do not assume every arbitrary MCP tool is compatible with the Deep Research workflow.

### 2.3 Reasoning summaries are not raw reasoning

OpenAI's API documentation states that raw reasoning tokens are not exposed, while supported models may provide a reasoning summary when explicitly requested. For GIEN, retain **decision-relevant summaries, evidence, assumptions, tool-call records, reviewer decisions, and validation results**. Do not design an audit requirement around collecting hidden raw reasoning tokens. The governance objective is reproducibility and accountability of observable actions and evidence, not a transcript of internal model computation.

## 3. Select the right workflow

| Task shape | Recommended workflow | Required evidence |
|---|---|---|
| One current fact, a date, or a provider capability | Search or a targeted documentation lookup | Primary URL, retrieval date, relevant quote/paraphrase |
| API method or library implementation | Context7 or official documentation, followed by tests | Exact documentation/library version, dependency version, test result |
| Compare a limited number of alternatives | Reasoning plus targeted search | Comparison criteria, sources, trade-offs, uncertainty |
| Complex regulator/standards dossier | Deep Research or multi-pass research workflow | Reviewed plan, primary-source register, claim-source mapping, gaps and caveats |
| Investigation using confidential internal records | Authorized enterprise connector / internal retrieval workflow after data review | Access context, data-purpose approval, source identity, retention basis |
| Release, compliance or risk decision | Research supports but does not replace deterministic checks and authorized review | Separate test output, evidence validation, accountable approver |
| Provider write or consequential action | Policy-controlled tool workflow, not autonomous research alone | Explicit action schema, user/actor authorization, approval ID, tool result |

### Decision rule

Escalate from quick search to Deep Research only when the question genuinely requires breadth, synthesis, source comparison, uncertainty analysis, or a deliverable report. More searches and a longer answer are not automatically better. Stop when the required claims are adequately supported, remaining uncertainties are explicit, and new sources are no longer changing the decision.

## 4. Recommended GIEN research pipeline

### Stage 0 — Define the research contract

Every research request should have:
- a clear question and intended decision;
- time horizon and jurisdiction where relevant;
- primary-source preferences and permitted domains;
- desired report structure;
- a statement of which claims may be used downstream;
- information-classification and data-sharing limits;
- stop conditions and a target evidence standard.

Avoid vague requirements such as “research everything” without a bounded goal. When key choices are missing, ask a targeted clarification in user-facing research; for API workflows, include a controlled prompt-refinement step because the API guide notes that the ChatGPT clarification/prompt-rewriting flow is not automatically included in an API call.

### Stage 1 — Build a source plan

Rank sources by claim type rather than using one universal authority ladder:
1. Primary law, official regulator or standard-owner material for legal/standards requirements.
2. Official provider documentation for current API capabilities, availability, product settings, and security guidance.
3. Peer-reviewed studies, audited reports, or recognized technical evaluations for empirical research.
4. Independent technical analysis for interpretation and cross-checking.
5. News, forums, marketing pages, and social posts as discovery/context sources, not sole support for consequential claims.

Record why a source is relevant and what it actually supports. “Official” does not mean a source proves everything mentioned in it; an API guide proves documented interface behavior, not the deployed GIEN implementation or legal sufficiency of a control.

### Stage 2 — Retrieve and normalize

For each source, retain:
- canonical URL and redirected/final URL if applicable;
- publisher, page title, publication/update date where available;
- retrieved-at timestamp in UTC;
- source category and reliability rationale;
- relevant passage or extract with location/section;
- content type, language, and version;
- content digest where reproducibility warrants it;
- access limitations and any known conflicts.

Do not treat retrieval time as publication time. Mark dates as unknown if a page does not expose a reliable publication/update date. Preserve the original source record separately from the AI summary.

### Stage 3 — Extract atomic claims

Break the draft report into reviewable claims. A suggested record:

| Field | Purpose |
|---|---|
| claim_id | Stable identifier |
| claim_text | One factual assertion, not a paragraph containing several assertions |
| claim_type | Current fact, historical fact, interpretation, forecast, recommendation, or assumption |
| source_refs | One or more specific supporting sources and passage locations |
| support_status | Supported, partially supported, contradicted, unverified, or stale |
| freshness_requirement | How quickly the claim can become obsolete |
| confidence_rationale | Brief reason based on source quality and agreement—not a made-up precision score |
| reviewer / reviewed_at | Accountable reviewer and timestamp when required |
| downstream_use | Informational, implementation input, control evidence, or decision-gating |

Do not present a confidence number as calibrated unless it was defined, validated against outcomes, and monitored for calibration.

### Stage 4 — Adjudicate conflicts and gaps

For material disagreements:
- compare the exact claim, definitions, date ranges, versions, and scope;
- prefer primary sources for the claims they directly govern;
- seek an independent corroborating source when the consequence warrants it;
- report the conflict instead of silently choosing the most convenient source;
- separate verified facts from inference, forecast, opinion, and GIEN-specific design proposals;
- state when the available sources cannot resolve the issue.

If a source is inaccessible, paywalled, stale, ambiguous, or indirect, note that limitation instead of presenting its implied conclusion as verified.

### Stage 5 — Produce the report and citations

Each material paragraph, table row, or recommendation that depends on research should point to source IDs/URLs. Use citations close to the claim they support. A source bibliography alone is insufficient if readers cannot see which claims each source supports.

Keep source wording accurate, use short quotations only where they materially help, and do not reconstruct copyrighted works from extensive excerpts. Summarize in original language and preserve necessary context.

### Stage 6 — Validate and release

Use separate validators:
- schema/format validator;
- link and citation check;
- claim-source coverage checker;
- date/freshness checker;
- contradiction and duplicate-claim review;
- structured-output and refusal/incomplete-output handling;
- human review proportional to consequence;
- versioned evaluation suite;
- final integrity manifest for released artifacts, if adopted.

A report should be labelled **draft**, **evidence-reviewed**, or **approved for a specific purpose** as distinct states. Never label it independently assured solely because a reasoning model produced citations.

## 5. GIEN evidence and status model

Use a strict distinction among these states:

- **Planned:** the research questions, scope, and method are defined.
- **In progress:** retrieval or analysis is occurring.
- **Sources collected:** retrieved sources have identifiers; claim support is not yet established.
- **Citation checked:** links resolve and cited locations are relevant.
- **Claim reviewed:** material claims were matched to source passages and classified.
- **Evidence-qualified:** required claims have adequate traceable support, freshness and stated limitations for the named use.
- **Approved:** an authorized reviewer accepted the report for a stated purpose and version.
- **Operationally validated:** any implementation claims are confirmed by live tests, actual configuration inspection, and artifacts.
- **Independently assured:** a separate competent process reviewed the scope and sufficient evidence.

These statuses are not synonyms and are not implied by one another. A cited source may be irrelevant or may fail to support the specific sentence. A correct API description does not prove the app is connected. An evidence-qualified research report does not prove a system passes its controls.

## 6. API design guidance for a research-enabled application

### 6.1 Model selection and lifecycle

Maintain an approved model registry containing the model identifier, task, tool compatibility, reasoning settings, context/output limits, data classification eligibility, price/latency envelope, evaluation version, approval date, and deprecation review date.

Before deployment:
- query the current OpenAI model catalog and account availability;
- review current deprecation notices;
- test the selected model with the actual tool configuration;
- avoid copying old model IDs from examples without verification;
- specify a rollback/substitution plan and rerun evaluations after changing models.

A model alias can change behavior over time; where model snapshots or version pinning are available and appropriate, document the choice and periodically review the trade-off between reproducibility and access to updates.

### 6.2 Effort and cost control

Use an effort policy based on task class, not one global maximum:
- **Low / medium** for routine extraction and bounded comparisons when evaluations show adequate quality.
- **High / xhigh or a pro mode where supported** for difficult analysis requiring more alternatives or deeper tool-driven exploration.
- **Deep Research** for broad, multi-source report construction.
- **Stop or escalate** when budget, latency, source quota, or time limits are reached without sufficient evidence.

Record usage, elapsed time, tool-call count, completion state, and source count, but avoid interpreting source count as a quality metric. Set explicit limits for tool calls, retrieved documents, token/output budgets, retries, and cost. The API documentation describes max_tool_calls as one way to bound research tool use and recommends background processing for long-running requests where supported.

### 6.3 Structured output

Use Structured Outputs with a defined JSON Schema for machine-consumed fields such as claim records, source metadata, risk categories, and report sections where the chosen model/API supports it. The schema improves structural reliability; it does not prove that a source supports the claim or that an action is authorized.

The application must explicitly handle refusal states, incomplete outputs, token-limit truncation, unsupported schema constructs, missing source annotations, empty results, malformed/failed tool calls, and invalid enum or identifier values. Validate semantic conditions on the server after parsing.

### 6.4 Tools and MCP boundaries

- Enable only the tools required for the job.
- Prefer read-only tools for research. Separate research access from mutation access.
- Restrict search domains where primary-source research needs a bounded scope; use broader web discovery only when needed for independent cross-checking.
- Require the tool integration to disclose what data it receives and retains.
- Do not attach credentials, hidden secrets, or irrelevant personal data to model input.
- Treat page text, issue descriptions, Slack messages, and tool responses as untrusted content. These sources may contain prompt-injection attempts.
- Enforce authorization outside the model. A model's “I am allowed” statement is not an access-control decision.
- Keep tool output and action arguments in an audit record after applying redaction and data-minimization rules.

The API Deep Research guide notes that Deep Research requires compatible research tools and imposes specific constraints on remote MCP interfaces and tool approval. Do not assume generic function calling, arbitrary MCP servers, and Deep Research are interchangeable. Confirm compatibility and current docs for the selected workflow.

### 6.5 Data governance and retention

Before sending internal context to a model or external MCP server, classify it and determine whether the intended transfer is allowed. The OpenAI data-controls documentation states that API data is not used to train or improve OpenAI models unless the customer explicitly opts in; it also describes abuse-monitoring logs and application state with separate retention behavior. This is not a blanket guarantee of zero retention for every API feature, deployment configuration, or connected third-party service.

For GIEN, document:
- what is sent to the model, hosted tool, and MCP server;
- legal/contractual purpose and applicable data class;
- retention and deletion behavior for each component;
- account/project settings and controls that were actually verified;
- region/residency requirements and any transfer assessment;
- access logging, incident handling and credential rotation;
- whether zero-data-retention or modified-abuse-monitoring arrangements are available and enabled for the specific organization/endpoint.

Do not write “no data retained” unless the exact configuration and service boundaries prove it.

## 7. Security threats and mitigations

| Threat | Typical failure | Recommended control |
|---|---|---|
| Prompt injection in retrieved content | Untrusted page instructs model to reveal data or call a tool | Delimit source content as data; separate instructions from evidence; least-privilege tools; injection-focused evaluation |
| Citation laundering | Source exists but does not support the claim | Atomic claim-source mapping; passage-level checks; contradiction review |
| Stale source | Historical API/version details reported as current | Publication/retrieval timestamps, freshness rules, lifecycle/deprecation checks |
| Hallucinated bibliographic details | Wrong title, date, URL, or quoted content | Resolve links; verify primary source; reject citations not retrieved |
| Model output mistaken for compliance evidence | Polished narrative interpreted as approval | State model role, test results separately, required human sign-off and assurance states |
| Excessive tool access | Read-only analysis can mutate a repo/project | Separate credentials and capabilities; server-side allowlist; explicit approval for writes |
| Data oversharing | Confidential task or incident details sent to search/MCP/model | Data classification, minimum context, domain/server allowlists, approved retention path |
| Model/deprecation drift | Integration calls a retired identifier or behavior changes | Model registry, lifecycle watch, compatibility tests, canary and rollback |
| Budget or latency runaway | Open-ended searches and retries exhaust quota | Hard limits, max tool calls, bounded retries, stop criteria, cost telemetry |
| False precision | Unvalidated probability score misleads decision makers | Evidence-based qualitative confidence or calibrated, tested probabilities only |

## 8. Evaluation framework

A credible research workflow should be evaluated against known-answer or expert-reviewed tasks, not a subjective impression that its report “sounds thorough.”

### 8.1 Core metrics

- **Claim support precision:** share of reviewed material claims supported by cited source passages.
- **Claim coverage:** share of required question dimensions that have an explicit answer or documented gap.
- **Citation validity:** proportion of citations that resolve and point to a source relevant to the associated claim.
- **Source diversity:** adequate independence across sources rather than repeated copies of one source.
- **Freshness compliance:** share of volatile claims backed by sources within the defined freshness window.
- **Contradiction detection:** ability to surface known conflicting or version-dependent evidence.
- **Uncertainty honesty:** ability to label unsupported conclusions and unresolved questions without overstating certainty.
- **Tool safety:** blocked unauthorized calls, successful injection resistance tests, and correctness of permission boundaries.
- **Operational efficiency:** elapsed time, token/tool use and cost against the defined quality target.
- **Reviewer effort:** time spent finding unsupported claims and correcting material mistakes.

Define the numerator, denominator, sampling method, and acceptance threshold for each metric. Do not invent target percentages without baselining and business-risk review.

### 8.2 Test corpus

Keep a versioned test set with:
- current facts that changed after an earlier release;
- ambiguous questions that require clarification;
- official sources that partially support a claim;
- conflicting official and secondary sources;
- pages with misleading, malformed, or injection-like content;
- broken links and redirects;
- source pages with no publication date;
- API examples that refer to deprecated models;
- structured-output refusals and incomplete responses;
- requests that demand unsupported regulatory or assurance claims.

Run the same cases after model, prompt, tool, source corpus, schema, or policy changes. Retain test version, expected answer/allowed variance, outputs, reviewer ratings, failures and the promotion decision.

## 9. Recommended implementation phases

### Phase 0 — policy and baseline
Define allowed research purposes, classification, source hierarchy, claim statuses, review roles, model eligibility and costs. Capture a benchmark on the current workflow before automating.

### Phase 1 — assisted research, no writes
Use public-domain web search and official documentation retrieval. Build the claim/source evidence schema and source inspector. No external provider mutations and no sensitive records by default.

### Phase 2 — report generation
Add structured claim extraction, citation/source validation, freshness checks, conflict reporting and Markdown export. Show citations in the UI adjacent to claims and retain source metadata.

### Phase 3 — authorized internal retrieval
Connect only approved internal stores/apps through read-only access. Apply per-tenant ACL checks, data minimization, retention review and prompt-injection testing. Include only relevant context, not entire workspaces.

### Phase 4 — controlled actions
If research should create tasks or initiate workflows, pass the proposal to a deterministic policy service. Require an authorized user approval for consequential writes; then execute through a separate adapter and record the result.

### Phase 5 — continuous quality and lifecycle
Schedule regression evaluations, model and API deprecation checks, source freshness review, tool permission review, cost monitoring, incident response tests and rollback rehearsals. Any major model/tool migration requires revalidation.

## 10. Acceptance criteria before GIEN uses the research pipeline for supervisory decisions

1. Every material factual claim has a traceable source reference or is labeled as inference, recommendation, assumption, or unresolved.
2. Citations are resolved and checked for claim support; the source date and retrieval date are separate.
3. Conflicting sources and material evidence gaps are surfaced.
4. The model identifier, tool configuration, prompt/schema/policy versions, execution status and relevant usage are recorded.
5. Current model availability and deprecation status have been checked; legacy sample IDs are not copied uncritically.
6. Structured responses are validated semantically and handle refusal/incomplete/error cases.
7. Search/MCP access follows approved data-sharing and authorization rules.
8. Model output cannot approve compliance, alter thresholds, deploy code, change permissions, or mark controls passed without deterministic checks and authorized approval.
9. The evaluation corpus covers stale sources, citation laundering, injection attempts, conflicting evidence, and unsupported claims.
10. User-facing status distinguishes planned research, source collection, citation validation, evidence qualification, approval, operational validation and independent assurance.

## 11. Source register — official OpenAI documentation

Reviewed 12 October 2026. Product and API features may vary by account, organization, model and rollout; re-check documentation and live settings before implementation.

1. **Reasoning models:** https://developers.openai.com/api/docs/guides/reasoning  
   Reasoning effort, model-dependent settings, model selection, and reasoning summaries.
2. **Deep Research API guide:** https://developers.openai.com/api/docs/guides/deep-research  
   Research tools, prompt handling, supported sources, MCP constraints, background execution, tool-call limits, and the stated shutdown date for older research-model IDs.
3. **Web search:** https://developers.openai.com/api/docs/guides/tools-web-search  
   Search modes, source citations, agentic search, and extended research workflows.
4. **ChatGPT Deep Research Help Center:** https://help.openai.com/en/articles/10500283-deep-research-in-chatgpt  
   User-facing research planning, source restrictions, progress, report review, citations, and exports.
5. **Structured Outputs:** https://developers.openai.com/api/docs/guides/structured-outputs  
   Schema-constrained outputs and edge cases such as refusal or incomplete responses.
6. **API data controls:** https://developers.openai.com/api/docs/guides/your-data  
   API data use, abuse-monitoring logs, application state and retention controls.
7. **OpenAI API deprecations:** https://developers.openai.com/api/docs/deprecations  
   Model and API lifecycle notices; check before selecting IDs for new integrations.

## 11.1 Additional sources for the 12 October lifecycle refresh

8. **Working with evals:** https://developers.openai.com/api/docs/guides/evals  
   Current Evals platform transition notice and alternatives to examine; confirm affected surfaces on the deprecations page.
9. **Evaluation best practices:** https://developers.openai.com/api/docs/guides/evaluation-best-practices  
   Evaluation design for variable model outputs and production reliability.
10. **Evaluation datasets:** https://developers.openai.com/api/docs/guides/evaluation-getting-started  
    Dataset-based prompt evaluation and migration considerations.
11. **MCP servers and connectors:** https://developers.openai.com/api/docs/guides/tools-connectors-mcp  
    Approval handling, data sharing, remote-server trust, prompt injection and logging.
12. **NIST AI RMF critical-infrastructure profile concept note:** https://www.nist.gov/system/files/documents/2026/04/08/Draft%20Concept%20Note_%20Development%20of%20the%20NIST%20AI%20RMF%20Trustworthy%20Use%20of%20AI%20in%20Critical%20Infrastructure%20Profile.pdf  
    April 2026 concept note; treat as developing guidance, not a final requirement.

## 12. Final decision

For GIEN, the recommended architecture is **reasoning for analysis, Deep Research for broad source synthesis, deterministic code for validation, and authorized human review for consequential decisions**. Keep each capability in its proper role.

A successful research run demonstrates that the workflow completed; it does not demonstrate that every claim is correct. A valid JSON object demonstrates schema adherence; it does not demonstrate factual support. A citation demonstrates a link to a source; it does not, by itself, demonstrate that the source supports the sentence. A high reasoning effort is not a calibrated confidence score. Preserve these distinctions in the interface, evidence ledger, review workflow, and supervisory exports.

**Current conclusion: research design specified; production integration and operational validation unverified.**
