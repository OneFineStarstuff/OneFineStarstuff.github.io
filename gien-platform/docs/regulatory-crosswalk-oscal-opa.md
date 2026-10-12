# GIEN Regulatory Crosswalk and OSCAL 1.1.2 Assessment Design

> **Purpose:** Starter crosswalk for the fictional GIEN governance architecture. Each row is a mapping hypothesis and assessment design—not a legal opinion, compliance certificate, or statement that the control is implemented.

## <title>Cross-Jurisdictional Regulatory Control Matrix</title>

## <abstract>
 This document defines a versioned method for connecting selected regulatory frameworks and governance standards to GIEN Control Domains CD-01 through CD-10, OSCAL-compatible assessment records, and OPA/Rego test evidence. Applicability must be decided per legal entity, jurisdiction, system, use case, record type and effective date. Fictional GIEN
treaties remain segregated from
public laws and standards.
</abstract>

## <content>1. Applicability and status semantics</content>

Use these assessment states consistently:
- **COMPLIANT:** applicable requirement assessed against approved criteria with sufficient evidence, including independent testing where required by policy.
- **PARTIAL:** material parts meet criteria but a documented gap remains.
- **NON-COMPLIANT:** applicable requirement fails its approved assessment criteria.
- **PENDING ASSESSMENT:** insufficient assessment work or evidence to reach a conclusion.
- **NOT APPLICABLE:** documented, reviewable rationale explains why the requirement does not apply.
- **UNVERIFIED:** evidence is stale, unauthenticated, incomplete, or integrity validation has failed. This is an evidence quality state, not a favorable result.
- **SIMULATED:** demo fixture only; excluded from live compliance aggregation.

Never default missing data to COMPLIANT. A regulatory mapping must carry source version, last reviewed date, applicability owner, legal-review state, and change-impact assessment.

## <content>2. Framework mapping starter</content>

| # | Framework / jurisdiction | Initial mapping focus | GIEN domains | Evidence candidates | Applicability cautions |
|---:|---|---|---|---|---|
| 1 | EU AI Act, including Annex IV and relevant provisions | System classification, risk management, data governance, logging, documentation, human oversight, robustness, quality management and applicable conformity/oversight obligations | CD-01, 02, 05, 06, 07, 08, 09 | Intended-purpose statement, classification rationale, technical documentation index, data governance, risk log, tests, oversight and incident records | Identify whether the system/use case is in scope and the specific obligations and dates. Annex IV concerns technical documentation. Do not apply Article 51 as a general high-risk-system article; it concerns GPAI-model classification with systemic risk. |
| 2 | NIST AI RMF 1.0 | GOVERN, MAP, MEASURE, MANAGE outcomes; profiles, accountability, context and risk treatment | CD-01, 02, 05, 06, 07, 08, 09 | AI system inventory, roles, impact analysis, evaluations, monitoring, incident/treatment plan | Voluntary framework unless adopted by contract/policy/regulatory expectation. Map outcomes rather than claiming a single certification. |
| 3 | NIST AI 600-1 Generative AI Profile | GenAI risks: confabulation, data privacy, information integrity, security, harmful bias, provenance, human-AI configuration and evaluation | CD-02, 04, 05, 07, 08, 09 | GenAI risk register, red-team results, retrieval/source evaluation, monitoring and human factors tests | Profile supplements risk management; applicability depends on GenAI use. |
| 4 | ISO/IEC 42001 AIMS | AI management-system scope, leadership, risk/opportunity processes, documented information, operational controls, internal audit, corrective action and continual improvement | CD-01, 02, 06, 07, 09, 10 | AIMS scope, policy, risk assessment, objectives, competence records, internal audit and corrective action | Do not imply certification from a crosswalk. Certification has its own audit and scope. |
| 5 | Basel III/IV and related prudential standards | Risk governance, capital/liquidity risk management, operational risk and relevant market/counterparty-risk treatment | CD-02, 05, 06, 08, 09 | Model inventory, approved methodology, exposure lineage, stress tests, independent validation, governance approvals | Map the specific rule, local implementation and use of model output; do not equate an AI proof with capital adequacy. Basel “IV” is often informal market terminology; identify actual applicable standards. |
| 6 | Federal Reserve SR 11-7 (legacy model-risk mapping) | Historical model development/use, validation, governance and documentation traceability | CD-02, 05, 06, 08 | Legacy model inventory, validation reports, issue logs and prior supervisory commitments | Maintain for historical audit trail and applicable legacy references; do not use it as the sole current US supervisory mapping after superseding guidance. |
| 7 | Federal Reserve SR 26-2 (current AI/model-risk mapping where applicable) | AI use by banking organizations, risk governance, model-risk expectations and proportional application of supervisory guidance | CD-01, 02, 05, 06, 07, 08, 09 | AI use inventory, materiality assessment, controls, model validation, changelogs and human oversight evidence | Verify the letter’s scope, effective implementation details and institution-specific applicability with current Federal Reserve sources/counsel. Keep transition traceability from SR 11-7. |
| 8 | DORA, EU financial entities | ICT risk governance, incident reporting, resilience testing, third-party risk, information sharing where in scope | CD-03, 04, 05, 06, 08, 09 | ICT asset map, incidents, recovery tests, TLPT records where required, third-party inventory and exit plans | Entity classification, proportionality, delegated acts and local supervisory procedures matter. |
| 9 | NIS2, EU essential/important entities | Cybersecurity risk-management measures, incident handling, business continuity, supply chain, access controls and reporting | CD-03, 04, 05, 06, 09 | Security policies, incident log, risk analysis, identity control tests, backup/recovery and supplier checks | Confirm transposition and national implementation, entity categorization and financial-sector interactions. |
| 10 | GDPR, EU/EEA personal data | Lawfulness, purpose limitation, minimization, accuracy, retention, rights, privacy by design, DPIA, automated decision-making where applicable | CD-01, 02, 04, 06, 07, 09 | Record of processing, lawful-basis and purpose register, DPIA, data-flow map, rights workflow, retention/deletion tests | Article 22 is not a blanket ban on all automated decisions. Assess its specific criteria and relevant exceptions/safeguards. |
| 11 | FCRA / ECOA, United States | Consumer-report use, accuracy/disputes, credit decision and adverse-action duties, fair lending and explanation requirements | CD-02, 05, 06, 07, 09 | Decision lineage, adverse-action reason mapping, dispute workflow, fair-lending tests, model version and consumer notice | Applicability depends on product, actor and decision. Legal and fair-lending review required; statistical fairness metrics alone do not establish legal compliance. |
| 12 | MAS FEAT Principles | Fairness, ethics, accountability and transparency in relevant financial AI/data analytics uses | CD-01, 02, 06, 07 | Accountability map, fairness methodology, explainability documentation, contestability and governance decisions | Check current MAS guidance and relevant sector/product context; FEAT principles should not be labelled a statutory certification. |
| 13 | MAS Guidelines on AI Risk Management for Financial Institutions (published 7 Oct 2026; effective 7 Oct 2027, per published announcement) | Board/senior management accountability, AI risk governance, lifecycle risk management, validation, monitoring and third-party risks as described by the current guideline | CD-01, 02, 04, 06, 07, 09 | AI inventory, policy, risk assessments, lifecycle gate evidence, oversight records and testing | Treat as readiness work until effective; re-check authoritative MAS publication, final text and applicability before asserting timing or obligations. |
| 14 | HKMA FEAT / AI governance publications | Responsible analytics, model governance, fairness, accountability and transparency relevant to the institution and use case | CD-01, 02, 06, 07 | Model approvals, fairness tests, explanation/complaint pathways, accountability and audit records | Use the current HKMA instrument and scope; do not assume Singapore MAS wording is identical. |
| 15 | FCA Senior Managers and Certification Regime (SMCR), UK | Individual accountability, responsibilities, governance, fitness/propriety and relevant certification/ conduct duties | CD-01, 06, 07, 09 | Responsibility maps, decision records, delegation limits, training/competence and escalation evidence | Map the actual regulated firm, role and duty. Avoid implying a dashboard substitutes for accountable human decisions. |
| 16 | FCA Consumer Duty, UK | Consumer outcomes, products/services, price/value, consumer understanding and consumer support, where applicable | CD-02, 05, 06, 07, 09 | Outcome metrics, customer research, communications tests, vulnerability/complaint analysis and remediation | The four outcome areas are not a single compliance percentage. Link evidence to target market and actual customer journey. |
| 17 | HKMA Fintech 2030 AI² (fictionalized label in the GIEN project) | Strategic AI adoption, innovation, governance and financial-sector readiness mapping | CD-01, 02, 06, 10 | Current HKMA source version, initiative-to-control map, approved pilots, governance gates and risk register | Verify exact official programme naming and current publication. Do not infer requirements from a shorthand or fictionalized label. |
| 18 | SEC Rule 17a-4, United States | Electronic records retention and permitted preservation/recordkeeping methods for covered broker-dealer records | CD-03, 06, 09 | Retention schedule, WORM configuration or qualifying audit-trail design, access/deletion tests, restore reports and record inventory | Scope is record/entity specific. WORM is one permitted option, not a universal sole method; obtain securities counsel review. |
| 19 | NIST FIPS 203 / 204 / 205 | PQC KEM/signature standards and controlled algorithm transitions | CD-03, 04 | Algorithm inventory, implementation/version, key lifecycle, interoperability tests, signed verification and migration plan | ML-KEM is KEM, ML-DSA and SLH-DSA are signature standards. Do not conflate predecessor names with distinct approved algorithms. |
| 20 | OPA/Rego and OSCAL | Policy-as-code tests and structured security/control assessment records | CD-01 through CD-10 | Versioned control/profile, component definitions, SSP where applicable, assessment plan/results, POA&M, policy tests and validation logs | Engineering formats are not regulators and do not certify compliance. Keep schema validity separate from effectiveness and legal conclusion. |
| 21 | ICGC/GASO Accords — fictional | Hypothetical multi-jurisdiction governance commitments and reciprocal audit | CD-01, 06, 10 | Fictional treaty version, signatory manifest, internal assessments, exception ledger and ratification records | Clearly label all names, legal effects and status as fictional GIEN constructs. |
| 22 | CFE-1.0 Constitutional Framework — fictional | Constitutional invariants, quorum, non-dissolution safeguards and phase-transition authorization | CD-01, 07, 10 | Formal specification, model checking, approval quorum and invariant exception log | Internal specification only; not public law or external regulator approval. |
| 23 | Protocol SGR-028 — fictional | Submission assembly, evidence sealing, transmission receipts and supervisory-cycle lifecycle | CD-03, 05, 06, 08, 09 | Package manifest, root/signature, verification, receipt and retention records | Filing IDs do not signify a real regulator filing unless a real recipient confirms receipt. |
| 24 | Interstellar AI Governance Accord — fictional | Beacon/corpus custody, successor handoff and continuity of fictional governance | CD-03, 06, 10 | Corpus manifest, independent channel tests, recovery drills and custodianship decision | Speculative and fictional; label as such in all regulator-facing material. |
| 25 | Galactic Treaty Framework — fictional | Long-horizon phase and dissolution constraints | CD-01, 06, 10 | Phase prerequisites, treaty-version history, succession gate and archive proof | Speculative and fictional; no terrestrial statutory authority is implied. |

## <content>3. Priority and version-control policy</content>

### Priority tiering
- **Tier 1 — current obligations:** actual legal duties for the institution, legal entity, product, data, model and jurisdiction. Examples may include applicable EU AI Act, GDPR, DORA, NIS2, US banking guidance, consumer-credit rules, prudential standards and recordkeeping requirements.
- **Tier 2 — supervisory expectations and adopted standards:** NIST AI RMF, ISO/IEC 42001, MAS/HKMA and FCA guidance, internal model-risk policy, contract obligations and required industry practices.
- **Tier 3 — fictional/internal:** GIEN CFE-1.0, SGR-028, ICGC/GASO and speculative treaty constructs. These can enrich internal governance but must not be represented as law.

Priority must be decided by compliance/legal teams using materiality and deadlines, not fixed globally for every institution. Keep distinct: binding legal duty, supervisory guidance, standard, contractual obligation, internal policy and simulated treaty.

### Change monitoring
 For every requirement store source URL, exact citation/version, publication date, effective date, last checked date, superseded-by reference, jurisdiction, scope and owner. A source change triggers impact analysis of controls, tests, training, documentation, model approvals, records retention and submission templates. Preserve the old mapping
version for historical reporting
rather than overwriting it.

## <content>4. OSCAL 1.1.2 implementation pattern</content>

OSCAL artefacts should be selected according to the assessment workflow. A typical package can include:
- Catalog/profile or profile resolution output to establish the defined control set.
- Component definitions to describe relevant implemented components and control implementations.
- System Security Plan (SSP) where required by the target workflow.
- Assessment Plan to define objectives, methods, scope and test schedule.
- Assessment Results to record observations, results, findings and evidence references.
- Plan of Action and Milestones (POA&M) to track remediation where applicable.
- Schema/profile validation logs, package index and signed manifest.

Exact OSCAL models and required fields depend on chosen version and authoring workflow. Pin schema and profile versions; validate input and output; do not use hand-authored JSON as proof of OSCAL conformance without running a validator.

### Control mapping data contract
Every mapping record should include:

~~~json
{
  "mapping_id": "MAP-CD04-TEE-001",
  "framework": "Illustrative framework name and version",
  "jurisdiction": "jurisdiction or internal",
  "source_reference": "official provision / control reference",
  "applicability": "PENDING_ASSESSMENT",
  "gien_domain": "CD-04",
  "internal_control_id": "GIEN-CD04-CTRL-001",
  "oscal_version": "1.1.2",
  "oscal_control_id": "approved control ID",
  "assessment_method": "EXAMINE_AND_TEST",
  "policy_revision": "sha256 digest / version reference",
  "evidence_reference": "artefact URI plus digest",
  "assessment_result": "PENDING_ASSESSMENT",
  "finding_id": null,
  "owner": "role or accountable team",
  "last_reviewed_at": "2026-10-12T00:00:00Z",
  "independent_assurance": "NOT_PERFORMED"
}
~~~

Values above are structure examples only. The mapping ID, control ID and timestamp are demonstration placeholders and must be replaced with authoritative values from the consuming system.

### Sample Rego policy pattern
~~~rego
package gien.control_evidence

default allow := false

allow if {
  input.evidence.present == true
  input.evidence.provenance == "verified"
  input.evidence.fresh == true
  input.assessment.status == "pass"
  input.policy.version == input.expected_policy_version
}

deny_reason := "missing, stale, unverified, or failed evidence" if {
  not allow
}
~~~

This is a teaching snippet, not a production policy. Add strict input schemas, typing, error handling, policy tests for missing/stale/tampered values, peer review, signed policy releases and rollback. The output should record rule version, test suite version and input digest.

## <content>5. Evidence requirements by control family</content>

| Control family | Minimum evidence | Common false assurance to avoid |
|---|---|---|
| Identity and zero trust | Identity policy, access logs, least-privilege review, failed-auth tests, short-lived token evidence | A policy document alone proves enforcement |
| AI/model risk | Inventory, intended use, evaluation dataset lineage, validation, limitations, approvals, drift and rollback tests | Passing benchmark guarantees acceptable deployment |
| Fairness and consumer outcomes | Defined population, metric, sampling, confidence/uncertainty, relevant legal analysis, complaint/appeal pathway | Demographic parity alone establishes legal fairness |
| TEE and confidential compute | Fresh quote, verifier/trust chain, revocation check, workload measurement and policy decision | TEE label proves the whole application is safe |
| PQC / WORM / Merkle | Algorithm/key IDs, manifest/root, signature verification, retention and independent restore tests | Hash/root proves source truth or compliance |
| zkML | Circuit/model digest, public input provenance, proof verification, circuit audit and negative tests | Proof generation success proves real-world input correctness |
| Incident response | Timeline, severity, scope, containment, notification decision, remediation and retest | Closing a ticket equals reducing systemic risk |
| Digital twin | Input/config digest, pinned simulator, rerun, validation, sensitivity, limits and reviewer | Deterministic replay proves scenario validity |
| Compliance assessment | Applicability, version, control test, artefact digest, finding and remediation | Control crosswalk equals compliance certification |
| Long-horizon governance | Authority, succession, independent replicas, format portability, restore and quorum proof | A sealed codex proves lawful successor activation |

## <content>6. Reporting outputs and supervisor review checklist</content>

Each daily submission should answer:
1. What changed during the evaluation window, and which evidence sources support the statement?
2. Which metrics crossed approved thresholds, which sources were stale, and what uncertainties exist?
3. What changed in models, dependencies, policies, keys, firmware, control mappings or legal obligations?
4. Which controls failed, were not tested, are not applicable, or are only simulated?
5. Were interventions/kill-switches exercised; what exactly was observed; what negative tests failed?
6. Did cryptographic verification and storage-retention tests pass with independent evidence?
7. Which framework obligations remain unmapped or have overdue remediation?
8. What decisions require executive, risk, legal, privacy, model-risk or supervisory approval?
9. What was transmitted, to whom, under what identity, and which authenticated receipt confirms delivery?
10. What remains explicitly unknown and which owner/date is assigned to resolve it?

### Executive disposition states
- **No decision:** evidence is inadequate or review incomplete.
- **Continue with conditions:** explicitly enumerated temporary controls, owners and due dates.
- **Restrict / suspend:** control failures require limiting scope or operations.
- **Escalate / notify:** according to applicable legal/regulatory requirements and counsel.
- **Close finding:** only after remediation and retest evidence, with independent challenge where required.

No disposition should be inferred from a fictional GIEN aggregate score alone.

## <content>7. Official source index</content>

Use primary sources and re-confirm the current text at time of filing:
- EU AI Act implementation and timeline: <https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai>
- EU AI Act, Regulation (EU) 2024/1689: <https://eur-lex.europa.eu/eli/reg/2024/1689/oj>
- NIST AI RMF: <https://www.nist.gov/itl/ai-risk-management-framework>
- NIST AI 600-1: <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>
- NIST OSCAL: <https://pages.nist.gov/OSCAL/>
- ISO/IEC 42001: <https://www.iso.org/standard/81230.html>
- Federal Reserve SR 26-2: <https://www.federalreserve.gov/supervisionreg/srletters/SR2602.htm>
- DORA: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>
- NIS2: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>
- GDPR: <https://eur-lex.europa.eu/eli/reg/2016/679/oj>
- NIST FIPS 203: <https://csrc.nist.gov/pubs/fips/203/final>
- NIST FIPS 204: <https://csrc.nist.gov/pubs/fips/204/final>
- NIST FIPS 205: <https://csrc.nist.gov/pubs/fips/205/final>
- SEC electronic recordkeeping rule resources: <https://www.sec.gov/rules-regulations/2003/05/electronic-storage-broker-dealer-records>

**Disclaimer:** The crosswalk is a starting point for professional applicability review. It is not legal advice, certification, proof of implementation, regulatory approval, or independent assurance.
