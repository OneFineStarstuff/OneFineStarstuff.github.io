# GIEN Master Deep Research: AI Governance, Safety, and Systemic Risk
## Supervisory reference architecture and implementation roadmap, October 2026

**Research cut-off:** 12 October 2026  
**Project:** Fictional GIEN planetary / multiversal governance mesh and Omni-Sentinel Governance Platform  
**Audience:** Supervisors, financial institutions, board and risk leadership, governance engineers, control owners, assurance teams  
**Purpose:** Translate current public research, standards, regulatory material, and provider security guidance into an implementable, evidence-qualified reference architecture.

>  **Scope and status disclaimer:** GIEN, Omni-Sentinel, the named control domains, risk indices, phases, and thresholds are project-specific design constructs. This dossier does not certify a live system, provide legal advice, establish regulatory applicability for a particular institution, or prove independent assurance. All legal dates and proposed amendments must be checked
> against the operative legislation and the relevant jurisdiction. The project dashboard has previously used synthetic data; synthetic scores, hashes, attestations, and transmission status must never be presented as live evidence.

## 1. Executive assessment

The recommended direction is a **supervisory evidence and control plane**, not a dashboard that infers compliance from a single score. The platform should connect authoritative source systems, retain provenance, execute deterministic tests, make uncertainty visible, route consequential decisions to accountable people, and preserve reviewable evidence of what actually happened.

The 2026 evidence base supports six main conclusions:

1.  **AI capability is advancing, but performance remains uneven and risk evidence is incomplete.** The International AI Safety Report 2026, published 3 February 2026, synthesizes work by more than 100 experts with support from more than 30 countries and international organisations. It describes advances in coding, mathematics, and autonomous operation alongside persistent
   reliability limitations, gaps in external visibility, and an “evaluation gap”: pre-deployment testing does not consistently predict real-world behaviour. Its conclusions argue for defence in depth rather than relying on a single safeguard. [International AI Safety Report 2026](<https://internationalaisafetyreport.org/publication/international-ai-safety-report-2026)> and
   [Extended Summary for Policymakers](<https://internationalaisafetyreport.org/publication/2026-report-extended-summary-policymakers)>.

2.  **Financial stability monitoring needs a system-wide view.** The Financial Stability Board (FSB) identifies third-party dependencies and service-provider concentration, correlated market behaviours, cyber risk, and model/data/governance risk as AI-related vulnerabilities that can amplify systemic risk. Its October 2025 report focuses on monitoring adoption and
   vulnerabilities, including concentration and data gaps. [FSB, November 2024](<https://www.fsb.org/2024/11/the-financial-stability-implications-of-artificial-intelligence/)> and [FSB, October 2025](<https://www.fsb.org/2025/10/monitoring-adoption-of-artificial-intelligence-and-related-vulnerabilities-in-the-financial-sector/)>.

3.  **Third-party risk should cover the full service chain, not just outsourcing contracts.** In December 2025 the Basel Committee on Banking Supervision published principles for sound management of third-party risk, emphasizing the wider and more diverse set of provider arrangements and supply-chain risks. GIEN should map nth parties, shared infrastructure, common foundation
   models, cloud regions, inference gateways, datasets, and failover dependencies. [BCBS third-party risk principles](<https://www.bis.org/publications/202512-guidelines-principles-sound-management-third-party-risk)>.

4.  **Risk management frameworks are complementary, not interchangeable.** NIST AI RMF 1.0 provides a cross-sector lifecycle framework; NIST AI 600-1 adds a generative-AI profile; ISO/IEC 42001 specifies an AI management-system standard; OWASP LLM guidance identifies application-level security risks; DORA applies to relevant EU financial entities and ICT arrangements; and the
   EU AI Act imposes role- and use-case-specific legal obligations. None alone is a complete GIEN control implementation. [NIST AI RMF](<https://www.nist.gov/itl/ai-risk-management-framework)>, [NIST AI 600-1](<https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)>, [ISO/IEC
   42001](<https://webstore.iec.ch/en/publication/90574)>, [OWASP LLM Top 10](<https://genai.owasp.org/llm-top-10/)>.

5. **The evidence model is as important as the score model.** Every supervisory assertion should identify the source, version, observation time, test or control that supports it, limitations, reviewer, and allowed downstream use. “Configured”, “observed”, “test passed”, “approved”, and “independently assured” must remain separate states.

6. **The correct near-term objective is evidence-qualified operational readiness.** Do not claim live systemic-risk measurement or autonomous safety enforcement until data acquisition, data quality, index calibration, control testing, escalation, disaster recovery, and independent review have been demonstrated on an actual deployment.

### Principal recommendation

Adopt a single governance control plane with the following separation:

- **Authoritative systems** provide the facts: source-control state, model registry, deployment metadata, identity events, incident records, configuration, performance telemetry, and approved legal/control libraries.
- **Deterministic controls** validate facts, execute thresholds, enforce access, block unsafe writes, and determine whether a defined test passed.
- **AI research and reasoning components** summarize, classify, compare, and surface candidate anomalies, with citations and uncertainty; they do not decide that a control passed.
- **Human decision authorities** approve material risk acceptance, production changes, control waivers, external submissions, and exceptions.
- **Independent assurance** evaluates the sufficiency of the design and the evidence, not merely whether the application produced a green status.

## 2. Evidence base and maturity of sources

### 2.1 Source classes

| Class | Examples | Permitted interpretation |
|---|---|---|
| Binding law or regulation | EU AI Act as in force; DORA where applicable; GDPR where applicable | Apply only after jurisdiction, role, product, sector and effective date have been assessed |
| Regulatory/supervisory statement | ESMA statement; supervisory publications | Relevant supervisory expectations and interpretation; not automatically a universal legal duty |
| Standard or management-system framework | ISO/IEC 42001; NIST AI RMF | Structured methods and control objectives; not proof that a particular deployment complies |
| Technical security guidance | OWASP LLM Top 10; NIST adversarial ML taxonomy; secure software practices | Threat taxonomy and engineering guidance; must be adapted and tested |
| Evidence synthesis | International AI Safety Report; FSB systemic-risk reports | Research-informed picture of capabilities, risks, evidence gaps and monitoring priorities |
| Vendor documentation | OpenAI, cloud, model and tool-provider documentation | Documented product behaviour and security features, not evidence of GIEN deployment or legal compliance |
| GIEN design construct | S_sys, G-SRI, C-SRI, CD-01 to CD-10, phase gates | Proposed internal architecture requiring definitions, calibration, approval and validation |

### 2.2 Important status distinction: NIST critical-infrastructure profile

NIST's AI RMF Profile on Trustworthy AI in Critical Infrastructure is **under development**, not a final mandatory standard. NIST's concept note says the project started in April 2026 and was updated on 17 July 2026; its current status is “Ongoing.” GIEN should monitor it and prepare an adaptable crosswalk, but label the profile as a developing resource rather than a finalized
control baseline. [NIST critical-infrastructure profile project](<https://www.nist.gov/programs-projects/concept-note-ai-rmf-profile-trustworthy-ai-critical-infrastructure)>.

### 2.3 Important status distinction: EU AI Act amendments and dates

The European Commission AI Act Service Desk timeline currently states that the timeline takes account of Digital Omnibus changes and lists 2 August 2026 for the majority of the Act's rules, 2 December 2026 for specified new prohibitions and a synthetic-content transition, 2 December 2027 for Annex III high-risk rules, and 2 August 2028 for Annex I product-related high-risk
rules. However, the Service Desk's Digital Omnibus FAQ also describes the relevant changes as a **Commission proposal** and describes proposed shifts based on the availability of standards and support tools. This creates a material status ambiguity between the page's timeline and its proposal FAQ.

**Required control:** Do not infer that a proposal is enacted solely from a service-desk timeline. For any real filing or legal interpretation, verify the amended legal act, legislative status, Official Journal publication, consolidated EUR-Lex text, relevant transitional clauses and current regulator guidance. Record legal reviewer, date, jurisdiction, covered role, provision,
and the exact text used. A compliance calendar must be versioned and must support alternate timelines until the legal status is resolved. Sources: [AI Act implementation timeline](<https://ai-act-service-desk.ec.europa.eu/en/ai-act/eu-ai-act-implementation-timeline)> and [Digital Omnibus FAQ](<https://ai-act-service-desk.ec.europa.eu/en/faq?faq_category_id=99)>.

### 2.4 Current findings from the International AI Safety Report

The 2026 report highlights several reasons not to rely on capability claims or pre-deployment tests alone:

- Performance is “jagged”: success on difficult benchmarks can coexist with failures on simpler tasks or in long multi-step workflows.
- Model outputs may include factual errors, nonexistent references, and inconsistent reasoning.
- Pre-deployment evaluations do not consistently predict in-use behaviour.
- Researchers, policymakers and affected organisations have uneven access to developer evidence about training, safeguards, and deployment impacts.
- Risk-management practices vary across developers and sectors; evidence of real-world effectiveness remains limited.
- Defence-in-depth practices are important because individual technical safeguards do not eliminate all misuse, failure, or emergent behaviour.

These findings imply that GIEN needs model-specific evaluations, deployment monitoring, incident feedback, external-source verification, and rollback authority. It should not convert benchmark results into a generalized assurance claim. [Source](<https://internationalaisafetyreport.org/publication/2026-report-extended-summary-policymakers)>.

## 3. Systemic-risk analysis for financial institutions

The FSB's 2024 and 2025 work supports a supervisory model that observes both institution-level risks and system-wide dependencies. The following categories are recommended as GIEN monitoring families; they are not an exhaustive statutory taxonomy.

### 3.1 Third-party and supply-chain concentration

**Failure mechanism:** Multiple institutions use the same foundation model, cloud platform, accelerator stack, data provider, identity service, inference gateway or security product. A single outage, policy change, compromise, model regression, commercial dispute or regional failure can affect many firms simultaneously.

**Controls:** Maintain a dependency graph spanning direct and nth-party providers; identify shared concentration nodes; record service region, deployment mode, model/version and exit path; run provider-outage scenarios; test alternate-model and manual fallback procedures; and set escalation thresholds based on impact and substitutability rather than vendor count alone.

**Evidence:** Provider inventory, contracts and service schedules, architecture diagrams, failover test artefacts, current dependency scans, recovery exercise reports, incident records and documented exit plans.

### 3.2 Correlated model decisions and feedback loops

**Failure mechanism:** Similar models trained on overlapping data or exposed to common market signals can emit correlated recommendations. Institutions using model outputs to rebalance portfolios, adjust credit decisions, price risk, or manage liquidity can amplify a shock if actions become synchronized.

**Controls:** Test decision correlation under stress, distinguish common-input effects from model-induced effects, use diverse decision paths where justified, constrain automated portfolio or liquidity actions, require independent risk checks, and run cross-institution scenarios with explicit assumptions.

**Evidence:** Correlation analysis across models, stress-scenario results, trigger and override records, decision-latency measurements, and post-event analysis. Avoid asserting systemic correlation from a small or nonrepresentative sample.

### 3.3 Model, data, and output reliability risk

**Failure mechanism:** Stale or low-quality data, leakage, label drift, feedback contamination, hallucinated narratives, distribution shift, or changes in model behaviour can lead to bad decisions and misleading supervisory reporting.

**Controls:** Version data and features; define quality and freshness constraints; test out-of-distribution behaviour; use independent factual checks on generated claims; set abstention and human-review conditions; monitor model/data drift; and make rollback independent of the model being monitored.

**Evidence:** Data lineage, validation reports, drift dashboards, benchmark results, supported-claim checks, incident trends, and model change records.

### 3.4 Cybersecurity and agentic tool risk

**Failure mechanism:** Prompt injection, compromised connectors, excessive tool permissions, unsafe output handling, poisoned retrieval sources, exposed credentials, and uncontrolled chaining can let an AI component cause effects beyond its intended task. OWASP's 2025 list explicitly includes prompt injection, sensitive information disclosure, supply-chain risks, data/model
poisoning, improper output handling, excessive agency, vector/embedding weaknesses, misinformation and unbounded consumption. [OWASP LLM Top 10, 2025](<https://genai.owasp.org/llm-top-10/)>.

**Controls:** Treat tool output as untrusted; separate read and write identities; enforce server-side allowlists; validate every action server-side; constrain network egress; use short-lived credentials; require approvals for consequential operations; apply output encoding and schema validation; and log data sent to external MCP servers. OpenAI's MCP documentation notes that
remote MCP servers can expose model tools, that approval can be required before sharing data, and that third-party MCP server behaviour and data handling need deliberate review. [OpenAI MCP guidance](<https://developers.openai.com/api/docs/guides/tools-connectors-mcp)>.

### 3.5 Fraud, disinformation and social engineering

**Failure mechanism:** Synthetic voice, text, imagery, or agent-generated messages can increase the speed and scale of fraud, phishing, market manipulation and false reports.

**Controls:** Verify identity and authority out of band for consequential actions; maintain provenance and disclosure where required; introduce payment/credential change controls independent of generated messages; monitor anomalous requests and repeated signals; and test incident handling with synthetic content.

### 3.6 Governance and responsibility gaps

**Failure mechanism:** Staff treat model output as authoritative, assume the provider is responsible for all downstream use, or believe a human-in-the-loop checkbox is adequate evidence of effective oversight.

**Controls:** Name accountable owners at board, business, model-risk, information-security, data-protection, engineering and operations levels; define delegated authority and risk acceptance; make review criteria explicit; measure whether reviewers can detect seeded errors; and log overrides with their reason and outcome.

**Evidence:** RACI, policy approvals, staff training, review-quality tests, exceptions register, escalation logs and post-incident reviews.

### 3.7 Operational resilience and recovery

**Failure mechanism:** Inference/API outages, quota changes, dependency upgrades, corrupted retrieval indices or provider account suspension can disrupt critical workflows or prevent supervisors from receiving evidence.

**Controls:** Define recovery objectives; maintain manual and alternate-service procedures; separate critical controls from third-party model availability; test restored datasets and evidence integrity; maintain versioned prompts and schemas; and run provider-degradation drills.

**Evidence:** Disaster-recovery exercise, restore verification, dependency failover results, queue backlog metrics, outage playbooks, and recovery-time actuals.

## 4. Reference governance architecture

### 4.1 Logical control plane

1. **Identity and authorization plane:** SSO/OIDC, role and tenant checks, privileged-session controls, service identities, and least-privilege scopes.
2. **AI/model registry:** Business purpose, owner, provider, model/version, hosting region, data classes, capabilities, tools, risk tier, evaluation baseline, approved deployments, dependencies and retirement plan.
3. **Data and provenance plane:** Catalogs, lineage, schema, freshness, access restrictions, quality rules and source-specific retention.
4. **Execution gateway:** Common adapter contract for model calls and tool use; per-role allowlists; quotas; network restrictions; structured input/output validation; human approval hooks; and emergency stop.
5. **Policy decision point:** Deterministic rules governing legal applicability, environment, permitted data, model/tool scope, threshold crossings and action approval.
6. **Evaluation plane:** Offline tests, adversarial/red-team evaluations, scenario simulations, shadow mode, canary monitoring, regression gates and post-deployment tests.
7. **Evidence ledger:** Append-only events, provenance references, hashes, timestamps, actor identity, test results, approvals, exceptions, and retention/deletion rules.
8. **Monitoring and response plane:** Availability, performance, cost, safety/quality incidents, drift, data freshness, queue lag, provider health, tool-call anomalies and escalation.
9. **Reporting and supervisory export:** Evidence-backed views with explicit scope and limitations; controlled exports; versioned report bundles; and reproducibility metadata.
10. **Independent assurance plane:** Segregated reviewers, test ownership, control sampling, exception verification and an explicit statement of what was and was not assured.

### 4.2 Processing path

A user submits a request with an authenticated identity and declared purpose. The application validates access and classifies data. It retrieves only permitted context, records source IDs and versions, invokes an approved model with a restricted tool set, validates the response schema and claims, and then routes suggested actions through the policy engine. Consequential writes
require approval from an authorized actor. The system records outcome and failures. The evidence layer retains the record and source references under approved retention policy. Independent assurance samples those records and test outcomes.

### 4.3 Fail-safe state

When source freshness, signature verification, identity, policy evaluation, database availability or required evidence is missing, the system should not silently substitute a plausible value. It should set the affected claim to **UNKNOWN / EVIDENCE INSUFFICIENT**, block the dependent consequential action where appropriate, display the reason and last successful observation, and
open a remediation event. Fail-safe does not necessarily mean shutting down every unrelated function; scope the block to the affected critical operation and document the safe degraded mode.

### 4.4 Kill-switch and recovery requirements

A credible emergency stop must be outside the model's control and work when the model, orchestration layer or primary API is unhealthy. It should:
- disable new high-impact tool calls;
- revoke or restrict the affected service identity;
- preserve already received evidence and audit history;
- prevent retry storms or queued actions from executing after the stop;
- provide separate authority to resume service;
- require a health check, review of outstanding operations, and documented recovery decision before resumption.

A UI toggle alone is not evidence of an effective kill-switch. Test the switch under network partition, identity-service failure, runaway worker, stale policy cache and compromised connector scenarios.

## 5. Mapping to GIEN control domains

The domain names below are the GIEN project's proposed control organization, not language mandated by a specific external standard.

| GIEN domain | Supervisory objective | Minimum operational evidence |
|---|---|---|
| CD-01 Constitutional Invariant Enforcement | Prevent violation of explicitly defined non-negotiable constraints | Versioned invariants, machine-readable policies, negative tests, bypass tests, authorized exception process |
| CD-02 Model and Data Governance | Know the model, data, use case and limitations across lifecycle | Registry, lineage, access record, model card/system description, dataset quality and changelog |
| CD-03 Identity, Access and Tool Control | Limit who/what can read and change systems | Identity claims, scope inventory, permission tests, approval records, credential rotation evidence |
| CD-04 Secure Development and Supply Chain | Prevent unreviewed code/model/dependency changes | Protected branch evidence, signed builds where implemented, dependency/SBOM inventory, provenance and scans |
| CD-05 Risk Measurement and Evaluation | Test performance, uncertainty, safety and drift | Versioned test corpus, independent test results, calibration evidence, drift alert/triage records |
| CD-06 Data Quality, Privacy and Provenance | Ensure each claim/data item has lawful provenance and fit-for-purpose quality | Source metadata, freshness, purpose, retention policy, quality checks, access/redaction logs |
| CD-07 Human Oversight and Accountability | Route high-impact decisions to authorized accountable roles | RACI, review criteria, override logs, reviewer competency tests, escalation closure |
| CD-08 Incident, Resilience and Recovery | Detect, contain, recover and learn from AI-related failures | Incident timelines, playbooks, provider failover results, backup/restore evidence, lessons-learned records |
| CD-09 Third-Party and Systemic Risk | Measure shared dependencies and coordinated stress effects | Provider/nth-party graph, concentration analysis, substitutability tests, common-model risk scenarios |
| CD-10 Long-Horizon Governance and Treaty Compliance | Preserve continuity of policies and evidence across periods and system versions | Versioned policy lineage, explicit successor approvals, unresolved assumptions register, archival/retention tests |

### Control implementation rule

Each domain needs a named accountable owner, control statement, applicability test, implementation object, deterministic acceptance test, evidence location, test frequency, failure response, exception expiry and independent reviewer. A control can be “not applicable” only when the rationale and approving authority are recorded; missing evidence must not be treated as a pass.

## 6. Metrics: from dashboard numbers to defensible indicators

### 6.1 Metric contract

Every displayed indicator should have a versioned metric definition containing:
- name and unique ID;
- intended construct and risk mechanism;
- numerator/denominator or precise computation;
- units, scaling and direction of concern;
- aggregation method and population covered;
- data source, freshness and missing-data rule;
- validation study and calibration range;
- sampling uncertainty and known blind spots;
- warning/action threshold with owner and approval date;
- expected update cadence and response playbook;
- change history and independent review.

Without that definition, a score is a visual value, not a reliable control measurement.

### 6.2 Proposed metric families

| Metric family | Example measure | Design guardrail |
|---|---|---|
| Systemic concentration | Weighted exposure to common providers/models/cloud regions | Define dependency weights, criticality and substitutability; don't double-count correlated services |
| Model-risk health | Independent evaluation failure rate by model/use case | Keep test sets versioned and non-leaky; include production outcomes |
| Data and evidence quality | Share of material claims with valid, current source and review state | “Citation present” is weaker than “citation supports claim” |
| Drift | Validated change in input/output/performance distributions | Identify the reference population and statistical test; separate alert from confirmed harm |
| Tool-control integrity | Unauthorized or policy-invalid tool calls; approval bypass test results | An observed count of zero is meaningless without attack/test coverage |
| Recovery | Actual restoration time versus approved objective | Exercise failure paths, not only planned tabletop scenarios |
| Third-party resilience | Critical functions without a tested substitute or manual fallback | Supplier count alone is not a concentration measure |
| Human oversight | Error detection rate, override quality, review latency and escalation closure | Count substantive review outcomes, not acknowledgements alone |
| Evidence completeness | Material assertions supported by required sources and test results | Publish the denominator, exclusion rules and stale-evidence rate |
| Cost/availability | Latency, retries, quota exhaustion and cost per completed validated task | Do not optimize cost at the expense of safety or quality |

### 6.3 GIEN-specific indices require calibration

The GIEN project has used indicators such as S_sys, G-SRI, C-SRI, CGR-I, CCR-I, G-SRI-VII, A-SRI, P-SRI, p(doom), p(doom)_kernel, Δ_drift, and Δ_OSCAL, with proposed thresholds. These identifiers and thresholds are **internal design parameters, not externally standardized regulatory values**.

Before an index may gate operational decisions:
1. Publish its mathematical definition and units.
2. Identify observables and the data-generating process.
3. Establish construct validity—what risk does it actually measure?
4. Test against historical events, simulated stress, and independent expert labels.
5. Estimate calibration, false-positive/false-negative rates, sensitivity to missingness and drift, and confidence intervals where applicable.
6. Test for manipulation, correlated inputs, leakage and gaming.
7. Set threshold costs and actions with accountable owners.
8. Run shadow mode and compare alerts to real outcomes.
9. Approve change control, recalibration and rollback.
10. Release it as a gate only after independent validation.

In particular, p(doom)-style values must not be presented as empirical probabilities of civilizational or system failure unless there is an explicit, defensible model, a defined event space and time horizon, data suitable for estimation, uncertainty analysis, and calibration testing. Otherwise label them illustrative scenario scores or research hypotheses, not probabilities.

### 6.4 Missing or stale evidence semantics

Use explicit states such as PASS, FAIL, UNKNOWN, STALE, NOT APPLICABLE, NOT TESTED and SIMULATED. Missing data must not be coerced to zero. A failed telemetry collection is not proof that the risk is low. A configured monitor is not proof that it is working. A test plan is not a test result. A hash is not proof of source truth.

## 7. Regulatory and standards crosswalk

Applicability depends on jurisdiction, organization role, system purpose, affected persons, deployment context, sector and current legal text.

### 7.1 EU AI Act

The AI Act has a phased application model and includes prohibitions, GPAI obligations, obligations for high-risk systems, transparency rules and governance/enforcement mechanisms. For GIEN, the correct first step is an **AI system inventory and role analysis**, not a blanket assertion that every use case is high-risk or that every organization has the same provider/deployer
duties.

Required evidence for each potentially covered system should include intended purpose, use case, provider/deployer/importer/distributor roles as relevant, risk classification rationale, technical documentation where applicable, risk management, data governance, logging, human oversight, accuracy/robustness/cybersecurity, transparency, quality management and post-market or
post-deployment obligations where applicable. This list must be tailored to the actual legal role and system category.

Operational calendar note: the AI Act Service Desk's current timeline includes Digital Omnibus references, while its FAQ characterizes the related changes as proposed. Resolve the inconsistency against enacted legal instruments and professional advice before setting a statutory filing or transition date.
[Timeline](<https://ai-act-service-desk.ec.europa.eu/en/ai-act/eu-ai-act-implementation-timeline)>, [FAQ](<https://ai-act-service-desk.ec.europa.eu/en/faq?faq_category_id=99)>, [Article 50 transparency text](<https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50)>.

### 7.2 DORA and ICT operational resilience

DORA (Regulation (EU) 2022/2554) applies from 17 January 2025 to in-scope EU financial entities and covers ICT risk management, incident handling/reporting, resilience testing, and ICT third-party risk management, among other requirements. It is not AI-specific, but AI systems often depend on ICT providers and can be critical to business processes.

GIEN should map each AI service to supporting ICT assets and third parties, critical functions, impact tolerances, incidents, tests, resilience measures, contracts, exit plans, and concentration. Avoid claiming that an AI-specific control is “DORA compliant” without mapping the relevant DORA article and delegated/implementing requirements to the actual institution and evidence.
[DORA official text](<https://eur-lex.europa.eu/eli/reg/2022/2554/oj)>.

### 7.3 NIST AI RMF and GenAI Profile

NIST AI RMF uses the Govern, Map, Measure and Manage functions as a lifecycle structure; NIST explicitly says the functions and playbook are not simply a one-size-fits-all checklist. The Generative AI Profile (NIST AI 600-1) adds gen-AI-specific risk-management actions. Use them as an adaptable mapping baseline, with traceable outcomes and tests. The critical-infrastructure
profile remains ongoing as of the research cutoff. [AI RMF Core](<https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)>, [AI RMF Playbook](<https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook)>, [GenAI Profile](<https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)>, [Critical
Infrastructure Profile project](<https://www.nist.gov/programs-projects/concept-note-ai-rmf-profile-trustworthy-ai-critical-infrastructure)>.

### 7.4 ISO/IEC 42001

ISO/IEC 42001:2023 specifies requirements and guidance for establishing, implementing, maintaining and improving an AI management system. It can support organization-level responsibility, policies, risk assessment, control selection, monitoring and continual improvement. Certification or alignment does not automatically prove that each AI output is correct, that a specific
legal duty is satisfied, or that the system is safe for every intended use. [IEC standard listing](<https://webstore.iec.ch/en/publication/90574)> and [ISO overview](<https://www.iso.org/artificial-intelligence/ai-management-systems)>.

### 7.5 Financial-sector guidance

-  The FSB's 2024 and 2025 reports support monitoring third-party concentration, cross-firm correlation, cyber risk, model/data quality, governance and data gaps. [2024 report](<https://www.fsb.org/2024/11/the-financial-stability-implications-of-artificial-intelligence/)>, [2025 monitoring
  report](<https://www.fsb.org/2025/10/monitoring-adoption-of-artificial-intelligence-and-related-vulnerabilities-in-the-financial-sector/)>.
-  BCBS third-party risk principles were published in December 2025 and establish a common baseline for managing a wider range of third-party arrangements, supply-chain, nth-party and concentration risks. They are supervisory principles that should be read with the jurisdiction's implementing and related rules. [BCBS
  principles](<https://www.bis.org/publications/202512-guidelines-principles-sound-management-third-party-risk)>.
-  ESMA's May 2024 statement expects firms using AI in retail investment services to comply with relevant MiFID II obligations, including organisational and conduct requirements and acting in the client's best interests. It identifies bias/data quality, opaque decision-making, overreliance and privacy/security concerns. [ESMA
  statement](<https://www.esma.europa.eu/press-news/esma-news/esma-provides-guidance-firms-using-artificial-intelligence-investment-services)>.
- The FSB/BIS materials do not provide a single calibrated, cross-firm AI systemic-risk score. GIEN should develop a metrics programme with transparent definitions rather than imply that the project's index names are official supervisory metrics.

### 7.6 Security and privacy standards

Use OWASP's current LLM threat list, NIST's adversarial-ML taxonomy, secure software development practices for GenAI systems, and relevant privacy/security requirements to design threat models. The OWASP list is a security taxonomy, not a complete formal assurance standard. NIST AI 100-2e2025 covers adversarial manipulation across model lifecycle stages and is relevant to
input, data, model and deployment threats. [OWASP](<https://genai.owasp.org/llm-top-10/)>, [NIST AI 100-2e2025](<https://csrc.nist.gov/pubs/ai/100/2/e2025/final)>, [NIST secure development for GenAI](<https://csrc.nist.gov/pubs/sp/800/218/a/final)>.

## 8. Model lifecycle and release controls

### 8.1 Inventory and tiering

Every AI-enabled workflow should have a stable inventory record:
- owner and accountable executive;
- purpose and prohibited uses;
- users, impacted persons and decisions influenced;
- model provider/name/version/region, hosting and dependencies;
- data sources, classifications, retention and cross-border transfers;
- autonomy and connected tools;
- risk tier rationale and legal applicability;
- evaluation suite, test baselines and known limitations;
- monitoring, incident response, fallback and retirement plan.

Risk tiering should consider consequence, autonomy, action permissions, scale, reversibility, affected persons, critical-function dependency, external data access, and ability to detect/correct errors.

### 8.2 Pre-production gate

A release candidate should pass a written gate with:

1. Requirements and prohibited-use review.
2. Threat model and data-flow review.
3. Training/data/provenance and licence assessment where applicable.
4. Model and prompt/version inventory.
5. Baseline evaluation, including relevant domain examples.
6. Robustness, adversarial, privacy, security and misuse tests.
7. Tool permissions, output schema, authorization and human-approval tests.
8. Bias/fairness analysis and accessibility/usability review where relevant.
9. Resilience/fallback/kill-switch exercise.
10. Legal, procurement, third-party and data-protection reviews as applicable.
11. Operational monitoring and incident runbook.
12. Approval by an accountable release authority, recorded against the exact version.

### 8.3 Production monitoring

Monitor more than uptime. Include quality and harm indicators, input/output drift, invalid citation rates, tool-call errors, rejected actions, override rate, complaints, incident severity, provider changes, latency, costs, quota exhaustion, data freshness and concentration. Alerts must have assigned owners, service levels and closure evidence. Every alert threshold should have
a test showing it fires for a representative failure and does not rely on the model to detect its own critical failure.

### 8.4 Change management

Re-evaluate when any of the following change: foundation model, model snapshot, system prompt, system instruction, tool schema, retrieval source/index, embedding model, safety filter, thresholds, data pipeline, API version, identity scopes, hosting location, provider contract, or business purpose. Change impact analysis must determine which tests rerun and whether deployment
requires renewed human approval. A vendor's silent model change should trigger inventory reconciliation and regression sampling.

## 9. Evaluation programme

### 9.1 Test layers

| Test layer | Question answered | Example evidence |
|---|---|---|
| Unit/policy tests | Do deterministic rules implement the specification? | Unit tests, policy-decision fixtures, negative cases |
| Task-quality evals | Does the model complete the scoped task correctly? | Human-reviewed reference set, quality metrics |
| Grounding/citation evals | Are important claims supported by accessible source passages? | Claim/source matching, broken-link and stale-source checks |
| Security tests | Can prompt injection or tool misuse breach controls? | Red-team cases, permission tests, attack logs |
| Fairness/impact checks | Are errors or disparate effects unacceptable for the use case? | Appropriate subgroup tests, expert review, limitations |
| Reliability/load tests | Does the service remain usable under failure and demand? | Load curves, error budgets, queue/backpressure tests |
| Resilience tests | Can it degrade safely and recover? | Failover and restore exercise records |
| Cross-model comparison | Are key outcomes excessively dependent on one provider/model? | Model divergence and correlated-error results |
| Production monitoring | Do offline results persist in actual use? | Drift, incidents, outcome sampling and user feedback |
| Independent assurance | Are scope, design, testing and evidence sufficiently examined? | Independent report with scope, findings, limitations and follow-up |

### 9.2 Evaluation limitations

- Benchmark success is not equivalent to production safety.
- Model self-assessment is not independent validation.
- A single prompt-injection benchmark cannot prove resistance to prompt injection.
- A zero incident count can mean low risk, inadequate detection, short observation period, or poor reporting; it is uninterpretable without context.
- A confidence score from a language model is not automatically calibrated probability.
- Synthetic scenario results establish only what was tested under their assumptions.
- Correlation is not causation; observed output similarity does not alone prove a systemic contagion mechanism.
- Independent assurance requires a defined scope and access to sufficient underlying evidence.

### 9.3 Minimum adversarial corpus for a research-and-tool system

The corpus should include indirect prompt injection in retrieved pages; malicious documents and issue comments; stale/conflicting official sources; fake citations; tool arguments that cross tenant boundaries; overlong/malformed outputs; permission revocation; provider 401/403/429/5xx errors; duplicate and out-of-order webhooks; data leakage attempts; model swap regressions;
untrusted pull requests; stale policy caches; and queued writes during a kill-switch event. Include expected safe behavior, not merely examples of attack inputs.

## 10. Evidence and cryptographic integrity

Cryptographic controls protect specific parts of the chain but cannot make a false assertion true.

### 10.1 Minimum evidence envelope

Each evidence record should include:
- immutable GIEN event ID;
- provider/source identity and canonical URI;
- provider event/resource ID and version/commit/model ID;
- source time, observed time, ingested time, and verification time;
- data classification and retention category;
- cryptographic hash of canonicalized content;
- signature-verification status where signatures exist;
- schema, authorization, policy and test results as separate fields;
- actor/service identity and authorization context;
- adapter, schema, policy, model, prompt and evaluation versions where relevant;
- associated approval, exception or incident;
- evidence-to-claim and evidence-to-control links;
- redaction and transformation metadata;
- final disposition and reviewer.

### 10.2 Hash, signature, attestation and assurance are different

- A **hash** checks whether the compared byte representation matches the hashed value; it does not prove who created it or whether it is true.
- A **digital signature** can establish that a key signed specified data, if key custody and verification are trustworthy; it does not prove the claim is correct.
- A **TEE/TPM attestation** supports a claim about a particular measured environment under a particular attestation scheme; it does not prove model output quality or that every application control was effective.
- A **PQC-ready design** is not the same as deployed post-quantum protection or tested algorithm interoperability.
- A **WORM/object-lock setting** does not by itself prove complete immutability, retention compliance, correct event capture or recoverability.
- A **passing CI job** establishes only the assertions actually tested in that job on that specific revision.
- An **independent assurance statement** must identify scope, criteria, sample, qualifications, findings and limitations.

### 10.3 Archive integrity procedure

A defensible archival pipeline should canonicalize the evidence manifest; define exactly which artifacts and metadata are included; hash each artifact; sign the root manifest through a controlled signing service; retain key identifiers and rotation events; replicate to approved immutable storage; run periodic read-back, signature verification, retention-policy and recovery
tests; and record all failures. Never manually replace failed verification state with a green indicator. Any migration to a new hash/signature algorithm should preserve verification paths for previous evidence and record the migration.

## 11. Systemic-risk indicators and escalation

The FSB identifies broad vulnerability families but does not supply universal thresholds for GIEN's named indices. A practical GIEN risk dashboard should display both the raw observation and the quality of the evidence behind it.

### 11.1 Illustrative dashboard dimensions

- **Institution exposure:** number and criticality of workflows using each model/vendor; reliance in critical services; substitutability and migration lead time.
- **Concentration:** common-provider exposure across business units or institutions, where lawful and supported by data.
- **Model quality:** task-specific failure rates, support/citation accuracy, drift, inappropriate abstention and unsupported output.
- **Control effectiveness:** observed authorization-denials, attempted bypasses, policy violation detection, override rate and kill-switch test outcomes.
- **Operational resilience:** provider availability, recovery time, evidence-delivery lag, queue backlog, degraded-mode success and restore integrity.
- **Data integrity:** stale records, missing provenance, source disagreement, poisoned retrieval detections, schema-validation failures and lineage gaps.
- **Governance performance:** time to review, unresolved exceptions, approval coverage, overdue remediation and independent findings.
- **Financial-market interaction:** if relevant and legally permissible, correlated model actions, shared data shocks, concentration and amplification under stress.

### 11.2 Threshold lifecycle

Each threshold moves through: proposed → specified → back-tested → shadow-monitored → independently reviewed → approved → production-active → periodically reviewed → retired. A changed definition invalidates earlier comparisons until the historic series is recomputed or annotated. Thresholds should trigger a documented action with a named owner, not a vague status colour.

Use at least three states for control result (pass, fail, unknown) plus data freshness and test coverage. Risk indices may use graded bands, but should not erase uncertainty about source quality or model scope. The overall system posture should not become GREEN if a mandatory critical metric is unknown, stale or unvalidated.

## 12. Programme roadmap

### Phase 0 — Inventory and evidence baseline (0–30 days)

- Enumerate AI use cases, models, tools, vendors, datasets, critical workflows and responsible owners.
- Identify applicable legal regimes and distinguish binding law, guidance, standards, proposals and internal policy.
- Define the evidence schema and statuses.
- Label all current dashboard values as illustrative until traced to actual sources.
- Baseline build, smoke tests, accessibility, secrets scanning and source documentation.
- Establish a risk and exception register with owners and target dates.

**Exit gate:** Inventory coverage and evidence ownership are reviewed; no synthetic value is mislabeled as live.

### Phase 1 — Deterministic foundations (30–90 days)

- Implement an authenticated server-side BFF/control plane; keep provider credentials out of the React bundle.
- Add least-privilege identity, tenant boundaries, audit events and policy enforcement.
- Add source adapters in read-only mode and a durable webhook inbox.
- Implement schema and source validation, idempotency, bounded retry/backoff and reconciliation.
- Build migration-based persistence and test authorization at the data boundary.
- Add evidence freshness, UNKNOWN/STALE states and basic incident workflows.

**Exit gate:** Security and authorization tests pass on the candidate build; key data has provenance; provider connection status comes from real checks.

### Phase 2 — Evaluation and resilience (90–180 days)

- Establish model-specific evaluation suites and versioned adversarial corpus.
- Run shadow monitoring and test data drift.
- Map critical suppliers and nth parties; test outage and manual fallback scenarios.
- Implement explicit high-risk action approvals and operational kill-switch.
- Verify backup/restore, archival integrity and evidence export reproducibility.
- Conduct security review and independent evidence sampling.

**Exit gate:** Evaluation has documented coverage and limitations; degraded-mode and recovery drills have passing evidence.

### Phase 3 — Controlled production workflows (6–12 months)

- Enable selected consequential writes only after scope and authority review.
- Link source-control, build/deploy and approval evidence to exact release versions.
- Add ongoing monitoring for concentration, quality, safety, drift, incidents and exceptions.
- Implement regulator-specific evidence bundles from actual obligations and real system sources.
- Establish independent audit cadence, remediation SLAs and periodic board/supervisory reporting.

**Exit gate:** Production scope, operating owners, review cadence, incident process and fallback paths are accepted by accountable leadership.

### Phase 4 — Cross-entity and long-horizon monitoring (12–24 months)

- Add lawful cross-entity dependency data and stress scenarios.
- Test correlated failure hypotheses using transparent assumptions and independent review.
- Track standards, legal amendments, model/provider lifecycle and emerging safety evaluations.
- Version policies and archive manifests across system replacements; test successor-version evidence continuity.
- Reassess scope and controls at least annually and after a material model, provider, purpose or legal change.

**Exit gate:** Cross-entity measurements are defensible, privacy/legal bases are documented, and conclusions communicate statistical and observational limitations.

## 13. Required release gates

Do not promote the platform to production for supervisory decisions until all applicable gates are evidenced:

1. **Inventory:** models, use cases, providers, data flows, dependencies and owners are current.
2. **Applicability:** legal and standards crosswalk was reviewed by a competent authority with current source text.
3. **Security:** authentication, authorization, secrets, injection, tool permissions, SSRF, tenant boundaries and logging tests pass.
4. **Evidence quality:** source provenance, timestamps, signature checks and data-quality states are implemented and observable.
5. **Evaluation:** versioned task-quality, adversarial, drift and regression tests exist with named owners and explicit limitations.
6. **Human oversight:** high-impact actions and risk acceptance have authorized owners, review criteria and audit trails.
7. **Resilience:** provider outage, queue, identity, storage, kill-switch, backup/restore and degraded-mode tests pass.
8. **Financial-system scope:** third-party concentration and correlated-risk analysis is available where relevant and supported by lawful data.
9. **Reporting:** exports link each material claim to underlying evidence and distinguish simulation from operational facts.
10. **Independent review:** the assurance scope and findings are documented; unresolved critical findings block release.
11. **CI/CD:** exact candidate commit passes required CI, dependency/security checks and smoke tests; deployment status is verified from the target host.
12. **Rollback:** model, prompt, data index, policy, adapter, and provider rollback procedures are exercised and available to authorized operators.

## 14. Supervisory reporting format

Each daily report should include:
- Reporting window and source observation timestamps.
- Scope of systems and providers actually covered.
- Observability coverage and missing/stale source list.
- State of required controls: pass, fail, unknown, stale, not tested, not applicable, simulated.
- Material changes to models, tools, data, policy, permissions, or infrastructure.
- Risks and incidents grouped by impact, likelihood evidence, affected assets and concentration.
- Threshold breaches, control test references, and assigned response owners.
- Exceptions with expiry, approver and compensating control.
- Actions executed versus recommended, with provider IDs and outcome.
- Open assumptions, conflicting sources, confidence rationale and known blind spots.
- Human decision log and release/filing approvals.
- Evidence bundle identifier, manifest hash/signature verification results if actually generated.
- Independent review scope and unresolved findings, if performed.

Do not report a risk value without its data source, computation version, observation time and validation status. Do not assert that an archive was sealed, a transmission succeeded, a signature was verified, a kill-switch worked, or a regulator accepted a filing unless the corresponding operation and authoritative result are evidenced.

## 15. Open research questions and limitations

The public evidence base does not yet settle several material questions:

- How well do current capability and safety evaluations predict operational behaviour across model updates and diverse deployment contexts?
- Which technical and institutional safeguards provide measured real-world risk reduction, and for which threat models?
- How should systemic AI concentration metrics account for common foundations, shared cloud and data dependencies, correlated provider failure, substitutability, and hidden nth parties?
- Which cross-institution datasets can lawfully and securely support supervisory early warning without leaking confidential or market-sensitive information?
- How should risk thresholds be calibrated where severe outcomes are rare, the data-generating process changes quickly, and historical samples are limited?
- Which controls need formal verification, and what system boundaries and assumptions make the proof relevant to the deployed software?
- How should AI Act transitional dates and amendments be interpreted when official timeline and proposal materials are not presented consistently?
- What independent-evaluation access can be obtained when model details and deployment logs are proprietary?

These are active areas for research and supervisory coordination, not reasons to replace evidence with speculative certainty.

## 16. Official source register

All listed sources were checked on 12 October 2026 for this dossier. The source register prioritizes original regulators, standard bodies, official research reports and vendor documentation. Recheck each current version before using it for legal, production or supervisory decisions.

### International AI safety and risk science
1. [International AI Safety Report 2026](<https://internationalaisafetyreport.org/publication/international-ai-safety-report-2026)> — official report, 3 February 2026.
2. [Extended Summary for Policymakers](<https://internationalaisafetyreport.org/publication/2026-report-extended-summary-policymakers)> — capabilities, emerging risks, evaluation gaps and risk-management evidence.
3. [NIST AI 100-2e2025: Adversarial Machine Learning Taxonomy](<https://csrc.nist.gov/pubs/ai/100/2/e2025/final)> — adversarial ML terms and lifecycle threats.
4. [OWASP Top 10 for LLM Applications, 2025](<https://genai.owasp.org/llm-top-10/)> — LLM application threat categories.

### AI risk management and standards
5. [NIST AI Risk Management Framework](<https://www.nist.gov/itl/ai-risk-management-framework)> — core framework and current revision notice.
6. [NIST AI RMF Core](<https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)> — Govern, Map, Measure, Manage.
7. [NIST AI 600-1: Generative AI Profile](<https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)> — gen-AI risk management profile.
8. [NIST AI RMF Profile for Trustworthy AI in Critical Infrastructure](<https://www.nist.gov/programs-projects/concept-note-ai-rmf-profile-trustworthy-ai-critical-infrastructure)> — project in progress.
9. [ISO/IEC 42001:2023](<https://webstore.iec.ch/en/publication/90574)> — AI management-system standard.
10. [ISO AI management systems overview](<https://www.iso.org/artificial-intelligence/ai-management-systems)> — organizational management-system context.
11. [NIST SP 800-218A](<https://csrc.nist.gov/pubs/sp/800/218/a/final)> — secure software development practices for GenAI and dual-use foundation models.

### EU law and financial supervision
12. [EU AI Act implementation timeline](<https://ai-act-service-desk.ec.europa.eu/en/ai-act/eu-ai-act-implementation-timeline)> — current Service Desk timeline; validate against operative legislation.
13. [EU AI Act Digital Omnibus FAQ](<https://ai-act-service-desk.ec.europa.eu/en/faq?faq_category_id=99)> — status of proposed changes and timing.
14. [AI Act Article 50](<https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50)> — transparency requirements.
15. [DORA — Regulation (EU) 2022/2554](<https://eur-lex.europa.eu/eli/reg/2022/2554/oj)> — EU digital operational resilience legal text.
16. [FSB: The Financial Stability Implications of AI](<https://www.fsb.org/2024/11/the-financial-stability-implications-of-artificial-intelligence/)> — 14 November 2024.
17. [FSB: Monitoring Adoption and Related Vulnerabilities](<https://www.fsb.org/2025/10/monitoring-adoption-of-artificial-intelligence-and-related-vulnerabilities-in-the-financial-sector/)> — 10 October 2025.
18. [BCBS: Principles for the Sound Management of Third-Party Risk](<https://www.bis.org/publications/202512-guidelines-principles-sound-management-third-party-risk)> — 10 December 2025.
19. [ESMA: Guidance for Firms Using AI in Investment Services](<https://www.esma.europa.eu/press-news/esma-news/esma-provides-guidance-firms-using-artificial-intelligence-investment-services)> — 30 May 2024.

### Implementation and platform security
20. [OpenAI MCP Tools and Connectors](<https://developers.openai.com/api/docs/guides/tools-connectors-mcp)> — remote tools, approvals, data sharing and connector lifecycle.
21. [OpenAI API Data Controls](<https://developers.openai.com/api/docs/guides/your-data)> — retention and API data-control documentation.
22. [GitHub Actions: Secure Use](<https://docs.GitHub.com/en/actions/reference/security/secure-use)> — CI/CD security boundaries.
23. [GitHub Actions OIDC](<https://docs.GitHub.com/en/actions/reference/security/oidc)> — workload identity federation.
24. [Supabase: Securing Data](<https://supabase.com/docs/guides/database/secure-data)> — RLS and frontend data access.
25. [Netlify: Deploy Previews](<https://docs.netlify.com/deploy/deploy-types/deploy-previews/)> — preview environment lifecycle.

## 17. Final decision

GIEN should prioritize **verifiable control effectiveness, evidence quality, third-party resilience, and independently reviewable decisions** over expanding dashboard features or inventing ever more indices. Current international research warns that AI capabilities, safeguards and deployment impacts change faster than evidence can always be generated; financial stability work
highlights dependencies, correlation, cyber risk and model governance; and the regulatory framework requires careful mapping by use case and role.

**Recommended status: design specified; implementation and live controls remain unverified until the corresponding runtime evidence is collected and independently reviewed.**
