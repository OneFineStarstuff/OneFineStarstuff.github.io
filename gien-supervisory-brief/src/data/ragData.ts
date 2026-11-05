import { fakeHash, series, truncateHash } from './helpers';

export interface RagIndexHealth {
  id: string;
  name: string;
  docsCount: number;
  lastIngest: string;
  embeddingDrift: number;
  status: 'NOMINAL' | 'ELEVATED' | 'CRITICAL';
  p50Ms: number;
  p95Ms: number;
}

export const RAG_INDEXES: RagIndexHealth[] = [
  {
    id: 'policy-corpus',
    name: 'Policy Corpus',
    docsCount: 14280,
    lastIngest: '12m ago',
    embeddingDrift: 0.014,
    status: 'NOMINAL',
    p50Ms: 18,
    p95Ms: 42,
  },
  {
    id: 'control-library',
    name: 'Control Library',
    docsCount: 8640,
    lastIngest: '25m ago',
    embeddingDrift: 0.021,
    status: 'NOMINAL',
    p50Ms: 22,
    p95Ms: 58,
  },
  {
    id: 'oscal-catalog',
    name: 'OSCAL Catalog',
    docsCount: 3120,
    lastIngest: '1h ago',
    embeddingDrift: 0.038,
    status: 'NOMINAL',
    p50Ms: 31,
    p95Ms: 78,
  },
  {
    id: 'treaty-registry',
    name: 'Treaty Registry',
    docsCount: 1850,
    lastIngest: '3h ago',
    embeddingDrift: 0.012,
    status: 'NOMINAL',
    p50Ms: 25,
    p95Ms: 64,
  },
  {
    id: 'incident-archive',
    name: 'Incident Archive',
    docsCount: 640,
    lastIngest: '4h ago',
    embeddingDrift: 0.082,
    status: 'ELEVATED',
    p50Ms: 45,
    p95Ms: 110,
  },
  {
    id: 'model-cards',
    name: 'Model Cards',
    docsCount: 420,
    lastIngest: '6h ago',
    embeddingDrift: 0.029,
    status: 'NOMINAL',
    p50Ms: 20,
    p95Ms: 48,
  },
];

export interface RagasMetric {
  name: string;
  score: number;
  threshold: number;
  status: 'PASS' | 'WARN' | 'FAIL';
  description: string;
}

export const RAGAS_METRICS: RagasMetric[] = [
  {
    name: 'Faithfulness',
    score: 0.94,
    threshold: 0.9,
    status: 'PASS',
    description: 'Factual consistency of generated response relative to retrieved context chunks.',
  },
  {
    name: 'Answer Relevance',
    score: 0.89,
    threshold: 0.85,
    status: 'PASS',
    description: 'Alignment between retrieved answer content and query intent.',
  },
  {
    name: 'Context Precision',
    score: 0.91,
    threshold: 0.88,
    status: 'PASS',
    description: 'Signal-to-noise ratio of relevant chunks in top-k retrieval results.',
  },
  {
    name: 'Context Recall',
    score: 0.93,
    threshold: 0.85,
    status: 'PASS',
    description: 'Proportion of required regulatory ground-truth evidence successfully retrieved.',
  },
];

export interface RagFailureMode {
  id: string;
  mode: string;
  count: number;
  mitigation: string;
  severity: 'NOMINAL' | 'ELEVATED' | 'CRITICAL';
}

export const RAG_FAILURE_MODES: RagFailureMode[] = [
  {
    id: 'fm-1',
    mode: 'Stale chunk',
    count: 14,
    mitigation: 'Automated ingestion pipeline re-indexing trigger enabled upon document hash change.',
    severity: 'NOMINAL',
  },
  {
    id: 'fm-2',
    mode: 'Retrieval miss',
    count: 8,
    mitigation: 'Hybrid sparse-dense retriever re-weighting with Reciprocal Rank Fusion (RRF).',
    severity: 'ELEVATED',
  },
  {
    id: 'fm-3',
    mode: 'Citation gap',
    count: 3,
    mitigation: 'Strict-mode post-generation citation verifier with sentence-level grounding check.',
    severity: 'NOMINAL',
  },
  {
    id: 'fm-4',
    mode: 'Prompt injection attempt blocked',
    count: 19,
    mitigation: 'Input guardrail classifier with quarantine vector logging and tenant isolation.',
    severity: 'ELEVATED',
  },
  {
    id: 'fm-5',
    mode: 'Low-confidence abstention',
    count: 12,
    mitigation: 'Fallback routing to human-in-the-loop Compliance Officer review queue.',
    severity: 'NOMINAL',
  },
];

export interface RagRemediationItem {
  id: string;
  task: string;
  owner: string;
  eta: string;
  status: 'IN_PROGRESS' | 'PENDING' | 'SCHEDULED' | 'PLANNED';
}

export const RAG_REMEDIATION_QUEUE: RagRemediationItem[] = [
  {
    id: 'rem-1',
    task: 'Re-index Incident Archive embeddings with v3 high-density embedding model',
    owner: 'Data Engineering',
    eta: '2026-11-03',
    status: 'IN_PROGRESS',
  },
  {
    id: 'rem-2',
    task: 'Update OSCAL Catalog XML parsing rules for NIST SP 800-53 Rev 5 compliance',
    owner: 'Security Ops',
    eta: '2026-11-04',
    status: 'PENDING',
  },
  {
    id: 'rem-3',
    task: 'Tune BM25 sparse weighting parameter (alpha = 0.65) on treaty registry',
    owner: 'AI Systems Group',
    eta: '2026-11-05',
    status: 'SCHEDULED',
  },
  {
    id: 'rem-4',
    task: 'Audit low-confidence abstention logs for supervisory query false positives',
    owner: 'Legal Compliance',
    eta: '2026-11-06',
    status: 'PLANNED',
  },
];

// Provenance Data for RagAudit
export interface ProvenanceRecord {
  doc_id: string;
  sourceSystem: string;
  classification: 'PUBLIC' | 'RESTRICTED' | 'CONFIDENTIAL' | 'SECRET' | 'REGULATORY_ONLY';
  ingested_at: string;
  chunk_count: number;
  pii_scan: 'CLEARED' | 'MASKED' | 'NONE_DETECTED';
  license: string;
  merkleHash: string;
}

export const PROVENANCE_RECORDS: ProvenanceRecord[] = Array.from({ length: 18 }, (_, i) => {
  const sources = ['PolicyEngine', 'ControlDB', 'OSCAL-Hub', 'TreatyNet', 'IncidentLog', 'ModelRegistry'];
  const classifications: ProvenanceRecord['classification'][] = [
    'PUBLIC',
    'RESTRICTED',
    'CONFIDENTIAL',
    'SECRET',
    'REGULATORY_ONLY',
  ];
  const piiStatuses: ProvenanceRecord['pii_scan'][] = ['CLEARED', 'MASKED', 'NONE_DETECTED'];
  const licenses = ['Apache-2.0', 'MIT', 'CC-BY-4.0', 'Proprietary-GIEN', 'Open-Gov-1.0'];

  const seed = `rag-audit-doc-${i + 1}`;
  const rawHash = fakeHash(seed);

  return {
    doc_id: `DOC-2026-${String(i + 101).padStart(4, '0')}`,
    sourceSystem: sources[i % sources.length],
    classification: classifications[i % classifications.length],
    ingested_at: `2026-11-0${(i % 2) + 1} T${String(8 + (i % 10)).padStart(2, '0')}:15:00Z`,
    chunk_count: 12 + (i * 7) % 45,
    pii_scan: piiStatuses[i % piiStatuses.length],
    license: licenses[i % licenses.length],
    merkleHash: truncateHash(rawHash, 10, 6),
  };
});

export interface PiiFinding {
  id: string;
  title: string;
  severity: 'ELEVATED' | 'NOMINAL' | 'CRITICAL';
  sourceSystem: string;
  status: string;
  description: string;
}

export const PII_FINDINGS: PiiFinding[] = [
  {
    id: 'PII-001',
    title: 'Unmasked PII pattern in legacy 2024 incident report chunk #412',
    severity: 'ELEVATED',
    sourceSystem: 'IncidentLog',
    status: 'REMEDIATED',
    description: 'Anonymization regex missed synthetic engineer email addresses in raw log export.',
  },
  {
    id: 'PII-002',
    title: 'GPL-3.0 copyleft code snippet detected in control-library docs',
    severity: 'ELEVATED',
    sourceSystem: 'ControlDB',
    status: 'IN_REVIEW',
    description: 'License scanner flagged 14 lines of sample code carrying GPL-3.0 header.',
  },
  {
    id: 'PII-003',
    title: 'Missing classification header on treaty supplement filing SGR-028-A',
    severity: 'NOMINAL',
    sourceSystem: 'TreatyNet',
    status: 'RESOLVED',
    description: 'Document metadata lacked explicit REGULATORY_ONLY tag during ingest batch #9.',
  },
  {
    id: 'PII-004',
    title: 'Stale PII scanner pattern definition file (>30 days old)',
    severity: 'ELEVATED',
    sourceSystem: 'PolicyEngine',
    status: 'SCHEDULED',
    description: 'Regex ruleset updated to v4.2 in staging; pending production deployment.',
  },
];

// Prompt Architect Prompt Variables
export interface PromptVariable {
  name: string;
  description: string;
  defaultValue: string;
}

export const PROMPT_VARIABLES: PromptVariable[] = [
  {
    name: '{{filing_reference}}',
    description: 'Current regulatory filing identifier',
    defaultValue: 'SGR-028-CFE-2026-07-001',
  },
  {
    name: '{{evaluation_window}}',
    description: 'Telemetry time window scope',
    defaultValue: '2026-11-01T09:00:00Z → 2026-11-02T09:00:00Z',
  },
  {
    name: '{{risk_index}}',
    description: 'Target systemic risk metric identifier',
    defaultValue: 'C-SRI (0.33)',
  },
  {
    name: '{{framework}}',
    description: 'Governance & compliance framework',
    defaultValue: 'GIEN Protocol SGR-028 / DORA / EU AI Act',
  },
  {
    name: '{{control_domain}}',
    description: 'Supervisory control domain',
    defaultValue: 'Autonomous Agent Safety & Containment',
  },
  {
    name: '{{audience}}',
    description: 'Recipient authority or stakeholder tier',
    defaultValue: 'Supervisory Board / Regulator Authority',
  },
];

export const DEFAULT_SYSTEM_PROMPT = `You are an AI Governance Assistant operating under GIEN Protocol SGR-028.
Analyze regulatory filings and output structured supervisory reports.

Filing Reference: {{filing_reference}}
Evaluation Window: {{evaluation_window}}
Risk Index Telemetry: {{risk_index}}
Governance Framework: {{framework}}
Control Domain: {{control_domain}}
Target Audience: {{audience}}

Instructions:
1. Cross-reference retrieved policy chunks against NIST SP 800-53 and EU AI Act requirements.
2. Verify all cryptographic attestation hashes before asserting compliance status.
3. Cite exact chunk IDs and document source references for every supervisory finding.
4. Maintain strict neutral tone with zero unverified predictions or claims.`;

// Templates Library Data
export interface PromptTemplate {
  id: string;
  name: string;
  category: 'Supervisory' | 'Executive' | 'Compliance' | 'Incident' | 'Treaty' | 'Governance' | 'Operations' | 'Cryptographic';
  description: string;
  variables: string[];
  version: string;
  lastUpdated: string;
  body: string;
}

export const GOVERNANCE_TEMPLATES: PromptTemplate[] = [
  {
    id: 'tpl-1',
    name: 'Daily Supervisory Brief',
    category: 'Supervisory',
    description: 'Daily executive summary of systemic risk telemetry, active alerts, and containment status.',
    variables: ['{{filing_reference}}', '{{evaluation_window}}', '{{risk_index}}'],
    version: 'v1.4',
    lastUpdated: '2026-10-28',
    body: `Systemic Risk Telemetry Daily Brief — Filing {{filing_reference}}
Window: {{evaluation_window}}
Primary Metric: {{risk_index}}

Summary of Observations:
- Systemic Risk Indices: 10 Nominal, 2 Elevated Watch (C-SRI & A-SRI).
- Autonomous Agent Drift: All 8 supervisory agents within containment parameters.
- Cryptographic Enclaves: 8,020 TEE nodes attested with 99.0% coherence score.

Action Required:
Review contagion risk in G-SIFI cluster 3 before 17:00 UTC. Cite all relevant policy references.`,
  },
  {
    id: 'tpl-2',
    name: 'Executive One-Pager',
    category: 'Executive',
    description: 'Concise high-level overview for C-suite and Board members regarding AI model alignment.',
    variables: ['{{filing_reference}}', '{{audience}}', '{{framework}}'],
    version: 'v2.1',
    lastUpdated: '2026-10-30',
    body: `Executive Governance Briefing — {{audience}}
Ref: {{filing_reference}} | Framework: {{framework}}

Key Takeaways:
1. Overall Compliance Grade: 98.4% across all 12 control domains.
2. Risk Posture: Low systemic contagion risk; p(doom) kernel modeled at < 0.000001.
3. Audit Readiness: Zero critical compliance gaps identified in current window.

Recommendation: Maintain current supervisory containment bounds and proceed with Q4 filings.`,
  },
  {
    id: 'tpl-3',
    name: 'Compliance Gap Memo',
    category: 'Compliance',
    description: 'Detailed gap analysis memorandum linking missing controls to regulatory articles.',
    variables: ['{{filing_reference}}', '{{control_domain}}', '{{framework}}'],
    version: 'v1.1',
    lastUpdated: '2026-10-25',
    body: `Regulatory Compliance Gap Analysis Memo
Filing Reference: {{filing_reference}}
Control Domain: {{control_domain}}
Framework: {{framework}}

Identified Items:
- Control CD-04 (Automated Kill-Switch Verification): Partial implementation in secondary cluster.
- Remediation Plan: Deploy hardware-enforced circuit breakers by 2026-11-15.
- Citation: EU AI Act Article 14 (Human Oversight) & DORA Article 9.`,
  },
  {
    id: 'tpl-4',
    name: 'Incident Notification (DORA)',
    category: 'Incident',
    description: 'Standardized operational disruption and AI agent boundary excursion notification.',
    variables: ['{{filing_reference}}', '{{evaluation_window}}', '{{risk_index}}'],
    version: 'v3.0',
    lastUpdated: '2026-11-01',
    body: `Major ICT / AI Incident Notification — DORA Article 19
Ref: {{filing_reference}} | Time Window: {{evaluation_window}}
Trigger Metric: {{risk_index}}

Incident Details:
- Type: Autonomous Agent Boundary Excursion Watch
- Root Cause: Prompt drift in telemetry summarizer agent ASA-02
- Mitigation Applied: Automatic fallback to deterministic baseline model; zero data leak.`,
  },
  {
    id: 'tpl-5',
    name: 'Treaty Audit Cover Note',
    category: 'Treaty',
    description: 'Formal cover memorandum accompanying multi-jurisdictional AI governance treaty submission.',
    variables: ['{{filing_reference}}', '{{framework}}', '{{audience}}'],
    version: 'v1.0',
    lastUpdated: '2026-10-18',
    body: `Multi-Lateral AI Governance Treaty Submission Cover Note
Filing Reference: {{filing_reference}}
Jurisdictional Framework: {{framework}}
Addressed To: {{audience}}

Attestation Statement:
We hereby submit verified cryptographic proofs and audit logs demonstrating full adherence to international AI safety standards and Protocol SGR-028 obligations.`,
  },
  {
    id: 'tpl-6',
    name: 'Model Card',
    category: 'Governance',
    description: 'Standardized transparency model card detailing architecture, training provenance, and safety limits.',
    variables: ['{{filing_reference}}', '{{control_domain}}', '{{risk_index}}'],
    version: 'v2.0',
    lastUpdated: '2026-10-29',
    body: `Supervisory LLM Model Card — GIEN Governance Core v4
Model Reference: {{filing_reference}}
Domain: {{control_domain}} | Risk Telemetry Baseline: {{risk_index}}

Safety Characteristics:
- Parameter Count: 70B Dense Transformer
- Alignment Method: RLAIF with Constitutional AI Ruleset v6
- Context Window: 128k Tokens with strict citation verification layer.`,
  },
  {
    id: 'tpl-7',
    name: 'Agent Containment Runbook',
    category: 'Operations',
    description: 'Emergency response protocol and containment step-by-step procedures for rogue agent drift.',
    variables: ['{{risk_index}}', '{{control_domain}}', '{{evaluation_window}}'],
    version: 'v1.3',
    lastUpdated: '2026-11-02',
    body: `Emergency Agent Containment & Circuit Breaker Runbook
Alert Trigger: {{risk_index}} exceeding threshold during {{evaluation_window}}
Domain: {{control_domain}}

Procedure:
1. Execute soft quarantine on target agent process ID.
2. Verify state hash in TEE enclave.
3. If drift > 0.15 within 10s, trip hardware-level e-stop.
4. Notify Lead Governance Engineer and log incident hash.`,
  },
  {
    id: 'tpl-8',
    name: 'ZK Proof Attestation Summary',
    category: 'Cryptographic',
    description: 'Summary of zero-knowledge compliance proofs and Merkle root verification state.',
    variables: ['{{filing_reference}}', '{{evaluation_window}}', '{{framework}}'],
    version: 'v1.5',
    lastUpdated: '2026-10-31',
    body: `Zero-Knowledge Compliance Attestation Summary
Filing: {{filing_reference}} | Window: {{evaluation_window}}
Compliance Standard: {{framework}}

ZK Proof Telemetry:
- Total Circuit Proofs Generated: 1,420 / 1,420 (100% PROVED)
- Verification Key Digest: 0x7f8a...c912
- Verifier Delay: 4.2ms avg per batch proof.
- Merkle Root State: Sealed and immutable.`,
  },
];
