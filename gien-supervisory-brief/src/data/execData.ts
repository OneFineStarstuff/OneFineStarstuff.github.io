export interface ExecutiveDecision {
  id: string;
  title: string;
  description: string;
  owner: string;
  dueDate: string;
  status: 'PENDING' | 'UNDER_REVIEW' | 'PREPARED';
  impact: 'HIGH' | 'CRITICAL' | 'MEDIUM';
}

export interface RoadmapMilestone {
  id: string;
  title: string;
  description: string;
  targetDate: string;
  quarter: 'Q4 2026' | 'Q1 2027' | 'Q2 2027' | 'Q3 2027';
  frameworks: string[];
  owner: string;
  status: 'DONE' | 'IN_PROGRESS' | 'AT_RISK' | 'PLANNED';
  badgeVariant: 'NOMINAL' | 'ACTIVE' | 'ELEVATED' | 'PENDING';
  dependencyNote: string;
}

export interface GovernanceAlertRecord {
  id: string;
  timestamp: string;
  severity: 'INFO' | 'ELEVATED' | 'CRITICAL';
  source: 'SystemicRiskTelemetry' | 'PQC Ledger' | 'Attestation' | 'Agent Drift' | 'Compliance';
  message: string;
  acknowledged: boolean;
}

export interface VoiceCommandDef {
  id: string;
  name: string;
  utterance: string;
  route: string;
  description: string;
}

export const EXECUTIVE_DECISIONS: ExecutiveDecision[] = [
  {
    id: 'DEC-2026-01',
    title: 'Approve C-SRI Contagion Buffer Allocation for G-SIFI Cluster 3',
    description: 'Reallocate 15% collateral reserve buffer to mitigate contagion spillover in interbank settlement network.',
    owner: 'Chief Risk Officer (CRO)',
    dueDate: '2026-11-15',
    status: 'PENDING',
    impact: 'CRITICAL',
  },
  {
    id: 'DEC-2026-02',
    title: 'Ratify VKFM v3 Key Rotation Schedule & PQC Migration Plan',
    description: 'Authorize deployment of ML-DSA-65 post-quantum signature suite across primary ledger validators.',
    owner: 'Chief Information Security Officer (CISO)',
    dueDate: '2026-12-01',
    status: 'UNDER_REVIEW',
    impact: 'HIGH',
  },
  {
    id: 'DEC-2026-03',
    title: 'Authorize EU AI Act Art. 35 DPIA Evidence Submission Package',
    description: 'Formal board sign-off on machine-readable OSCAL 1.1.2 conformity assessment package.',
    owner: 'Head of Regulatory Compliance',
    dueDate: '2026-12-15',
    status: 'PREPARED',
    impact: 'HIGH',
  },
];

export const ROADMAP_MILESTONES: RoadmapMilestone[] = [
  {
    id: 'MS-2026-01',
    title: 'EU AI Act Art. 35 DPIA Evidence Pack Submission',
    description: 'Formal compilation and submission of machine-readable OSCAL 1.1.2 compliance evidence pack for high-risk AI supervisory models.',
    targetDate: '2026-11-20',
    quarter: 'Q4 2026',
    frameworks: ['EU AI Act Art. 35', 'ISO/IEC 42001'],
    owner: 'Head of Regulatory Compliance',
    status: 'IN_PROGRESS',
    badgeVariant: 'ACTIVE',
    dependencyNote: 'Requires Sentinel-4 model risk dossier signoff & OSCAL validation.',
  },
  {
    id: 'MS-2026-02',
    title: 'Solvency-Style Macro Stress Test Execution',
    description: 'Simulate severe multi-node contagion cascade and evaluate buffer adequacy under Protocol SGR-028.',
    targetDate: '2026-12-05',
    quarter: 'Q4 2026',
    frameworks: ['Solvency II', 'Basel III/IV SA-CCR'],
    owner: 'Chief Risk Officer',
    status: 'PLANNED',
    badgeVariant: 'PENDING',
    dependencyNote: 'S_sys telemetry pipeline stabilization and EWMA model calibration.',
  },
  {
    id: 'MS-2026-03',
    title: 'Q4 2026 Board Governance Attestation',
    description: 'Annual board attestation filing confirming 100% TLA+ proof coverage across constitutional invariants CI-001 through CI-024.',
    targetDate: '2026-12-20',
    quarter: 'Q4 2026',
    frameworks: ['Protocol SGR-028', 'CFE-1.0 §7'],
    owner: 'Executive Governance Committee',
    status: 'PLANNED',
    badgeVariant: 'PENDING',
    dependencyNote: 'Requires zero open high-severity findings in invariant verification suite.',
  },
  {
    id: 'MS-2027-01',
    title: 'FIPS 205 Stateless Hash-Based Signatures Migration',
    description: 'Transition audit log attestation pipeline to full FIPS 205 (SLH-DSA) post-quantum signature verification.',
    targetDate: '2027-01-15',
    quarter: 'Q1 2027',
    frameworks: ['NIST FIPS 205', 'DORA Art. 12'],
    owner: 'Lead Cryptographic Architect',
    status: 'IN_PROGRESS',
    badgeVariant: 'ACTIVE',
    dependencyNote: 'ML-DSA-65 signature chain validation across all secondary nodes.',
  },
  {
    id: 'MS-2027-02',
    title: 'vkFMv3 Key Rotation & Validator Re-keying',
    description: 'Perform scheduled cryptographic epoch transition and rotate key-encrypting keys across all TEE enclaves.',
    targetDate: '2027-02-10',
    quarter: 'Q1 2027',
    frameworks: ['Protocol SGR-028 §4.1', 'ISO/IEC 42001 §9'],
    owner: 'Security Operations Center',
    status: 'PLANNED',
    badgeVariant: 'PENDING',
    dependencyNote: 'Hardware HSM firmware patch 3.1 deployment across core cluster.',
  },
  {
    id: 'MS-2027-03',
    title: 'SR 26-2 Model Inventory Reconciliation',
    description: 'Comprehensive inventory audit and drift reconciliation for all active Autonomous Supervisory Agents.',
    targetDate: '2027-03-25',
    quarter: 'Q1 2027',
    frameworks: ['Fed SR 26-2', 'SR 11-7', 'EU AI Act Art. 14'],
    owner: 'Model Risk Governance Lead',
    status: 'AT_RISK',
    badgeVariant: 'ELEVATED',
    dependencyNote: 'Autonomous Agent drift delta must remain below 0.03 threshold.',
  },
  {
    id: 'MS-2027-04',
    title: 'DORA TLPT Threat-Led Penetration Testing',
    description: 'Conduct mandatory threat-led penetration testing cycle on cross-chain governance settlement ledgers.',
    targetDate: '2027-04-18',
    quarter: 'Q2 2027',
    frameworks: ['DORA Art. 26', 'NIS2 Art. 21'],
    owner: 'Red Team & Threat Intelligence',
    status: 'PLANNED',
    badgeVariant: 'PENDING',
    dependencyNote: 'RTEE attestation quote freshness verification & scope approval.',
  },
  {
    id: 'MS-2027-05',
    title: 'ISO 42001 Surveillance Audit',
    description: 'External surveillance audit covering AI Management System (AIMS) operational controls and drift telemetry.',
    targetDate: '2027-05-30',
    quarter: 'Q2 2027',
    frameworks: ['ISO/IEC 42001 §9.1', 'NIST AI RMF'],
    owner: 'Internal Quality & Audit Lead',
    status: 'PLANNED',
    badgeVariant: 'PENDING',
    dependencyNote: 'OSCAL 1.1.2 SSP catalog published and signed in audit repository.',
  },
  {
    id: 'MS-2027-06',
    title: 'NIS2 Cyber Incident Resilience Drill',
    description: 'Simulate critical infrastructure incident response drill (DRILL-042) with multi-jurisdictional notification.',
    targetDate: '2027-06-22',
    quarter: 'Q2 2027',
    frameworks: ['NIS2 Art. 21', 'Protocol SGR-028'],
    owner: 'Incident Response Director',
    status: 'PLANNED',
    badgeVariant: 'PENDING',
    dependencyNote: 'Automated notification hook testing across supervisory portals.',
  },
  {
    id: 'MS-2027-07',
    title: 'Interstellar Governance Accord Annual Sync',
    description: 'Cross-jurisdictional synchronization of planetary systemic risk baselines and long-horizon invariants.',
    targetDate: '2027-09-15',
    quarter: 'Q3 2027',
    frameworks: ['Interstellar AI Accord', 'CFE-1.0 §2'],
    owner: 'Supervisory Board Council',
    status: 'PLANNED',
    badgeVariant: 'PENDING',
    dependencyNote: 'Cross-chain coherence risk index CCR-I < 0.20 for 30 consecutive days.',
  },
];

export const ALERT_HISTORY_SEED: GovernanceAlertRecord[] = [
  {
    id: 'ALR-2026-11-02-001',
    timestamp: '2026-11-02T08:45:12Z',
    severity: 'ELEVATED',
    source: 'SystemicRiskTelemetry',
    message: 'C-SRI at 0.33 (threshold 0.30) — contagion channel stress persists in G-SIFI cluster 3',
    acknowledged: false,
  },
  {
    id: 'ALR-2026-11-02-002',
    timestamp: '2026-11-02T08:12:04Z',
    severity: 'ELEVATED',
    source: 'Agent Drift',
    message: 'A-SRI at 0.48 (threshold 0.45) — Autonomous Supervisory Agent drift watch in effect for Agent fleet Delta',
    acknowledged: false,
  },
  {
    id: 'ALR-2026-11-02-003',
    timestamp: '2026-11-02T07:30:00Z',
    severity: 'INFO',
    source: 'PQC Ledger',
    message: 'Scheduled ML-DSA-65 key pair rotation completed successfully for secondary validator node 04',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-02-004',
    timestamp: '2026-11-02T06:15:44Z',
    severity: 'CRITICAL',
    source: 'Attestation',
    message: 'RTEE Quote staleness warning: TEE node node-alpha-09quote refresh delayed by 180 seconds',
    acknowledged: false,
  },
  {
    id: 'ALR-2026-11-02-005',
    timestamp: '2026-11-02T05:00:22Z',
    severity: 'INFO',
    source: 'Compliance',
    message: 'OSCAL 1.1.2 machine-readable SSP catalog re-indexed against EU AI Act Art. 35 requirements',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-006',
    timestamp: '2026-11-01T23:40:10Z',
    severity: 'ELEVATED',
    source: 'SystemicRiskTelemetry',
    message: 'G-SRI short-term spike detected (0.354 vs threshold 0.400) following liquidity dispersion event',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-007',
    timestamp: '2026-11-01T21:10:00Z',
    severity: 'INFO',
    source: 'Agent Drift',
    message: 'Supervisory Agent SA-03 soft-containment routine executed nominal policy adjustment',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-008',
    timestamp: '2026-11-01T19:25:30Z',
    severity: 'CRITICAL',
    source: 'SystemicRiskTelemetry',
    message: 'Constitutional Invariant CI-003 quorum proximity threshold approached during stress simulation',
    acknowledged: false,
  },
  {
    id: 'ALR-2026-11-01-009',
    timestamp: '2026-11-01T17:05:18Z',
    severity: 'INFO',
    source: 'PQC Ledger',
    message: 'WORM Merkle-DAG epoch boundary sealed: Root hash 0x7a9f...b12e verified',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-010',
    timestamp: '2026-11-01T15:50:00Z',
    severity: 'ELEVATED',
    source: 'Compliance',
    message: 'Fed SR 26-2 model inventory reconciliation gap flagged on automated agent policy classifier',
    acknowledged: false,
  },
  {
    id: 'ALR-2026-11-01-011',
    timestamp: '2026-11-01T14:12:09Z',
    severity: 'INFO',
    source: 'Attestation',
    message: 'vTPM PCR summary verified clean across 12 active enclaves',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-012',
    timestamp: '2026-11-01T12:00:00Z',
    severity: 'INFO',
    source: 'SystemicRiskTelemetry',
    message: 'p(doom) existential probability metric updated: 0.00042 (nominal, threshold 0.001)',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-013',
    timestamp: '2026-11-01T10:35:40Z',
    severity: 'ELEVATED',
    source: 'Agent Drift',
    message: 'Delta_drift fleet-mean reached 0.031 (threshold 0.050) — StaR-MoE routing load rebalanced',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-014',
    timestamp: '2026-11-01T08:20:15Z',
    severity: 'INFO',
    source: 'Compliance',
    message: 'DORA Art. 26 digital operational resilience testing schedule approved for Q2 2027',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-015',
    timestamp: '2026-11-01T06:10:00Z',
    severity: 'CRITICAL',
    source: 'PQC Ledger',
    message: 'Legacy RSA-4096 key usage attempt intercepted and blocked by PQC enforcement filter',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-016',
    timestamp: '2026-11-01T04:45:22Z',
    severity: 'INFO',
    source: 'Attestation',
    message: 'Hardware Root of Trust quote re-signed with ML-DSA-65 post-quantum signature',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-017',
    timestamp: '2026-11-01T02:30:11Z',
    severity: 'ELEVATED',
    source: 'SystemicRiskTelemetry',
    message: 'Cross-chain Coherence Risk Index CCR-I experienced minor divergence spike (0.152 vs 0.200)',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-11-01-018',
    timestamp: '2026-11-01T01:15:00Z',
    severity: 'INFO',
    source: 'Compliance',
    message: 'ISO 42001 AIMS internal review completed with 98% control adherence',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-10-31-019',
    timestamp: '2026-10-31T23:00:00Z',
    severity: 'INFO',
    source: 'Agent Drift',
    message: 'Supervisory Agent SA-01 containment health check passed nominal parameters',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-10-31-020',
    timestamp: '2026-10-31T20:15:55Z',
    severity: 'INFO',
    source: 'SystemicRiskTelemetry',
    message: 'Kernel-level doom probability p(doom)_kernel calculated at 0.000038 (threshold 0.0001)',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-10-31-021',
    timestamp: '2026-10-31T18:40:12Z',
    severity: 'ELEVATED',
    source: 'Attestation',
    message: 'TPM 2.0 quote latency exceeded 500ms on secondary satellite node cluster',
    acknowledged: true,
  },
  {
    id: 'ALR-2026-10-31-022',
    timestamp: '2026-10-31T15:20:00Z',
    severity: 'INFO',
    source: 'Compliance',
    message: 'OSCAL Compliance Delta (Delta_OSCAL) measured at 0.014 (threshold 0.020)',
    acknowledged: true,
  },
];

export const VOICE_COMMANDS: VoiceCommandDef[] = [
  {
    id: 'cmd-01',
    name: 'open risk indices',
    utterance: '"open risk indices" or "take me to systemic risk"',
    route: '/risk-indices',
    description: 'Navigate to Systemic Risk Telemetry Index dashboard',
  },
  {
    id: 'cmd-02',
    name: 'show compliance gaps',
    utterance: '"show compliance gaps" or "view compliance matrix"',
    route: '/compliance',
    description: 'Navigate to Cross-Jurisdictional Compliance Matrix',
  },
  {
    id: 'cmd-03',
    name: 'read executive summary',
    utterance: '"read executive summary" or "open executive summary"',
    route: '/executive-summary',
    description: 'Navigate to Board-Level Executive Summary',
  },
  {
    id: 'cmd-04',
    name: 'engage emergency stop',
    utterance: '"engage emergency stop" or "trigger emergency containment"',
    route: '/voice',
    description: 'Simulate supervisory emergency stop and containment modal',
  },
  {
    id: 'cmd-05',
    name: 'export submission package',
    utterance: '"export submission package" or "go to submission packages"',
    route: '/submission-packages',
    description: 'Navigate to Regulatory Submission Packages area',
  },
  {
    id: 'cmd-06',
    name: 'reset drill state',
    utterance: '"reset drill state" or "open scenario planner"',
    route: '/scenario-planner',
    description: 'Navigate to Scenario Planner and reset active drill state',
  },
];
