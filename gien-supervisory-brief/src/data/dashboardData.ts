export interface TransmissionCheckpoint {
  time: string;
  title: string;
  status: 'COMPLETED' | 'PENDING';
  detail: string;
}

export const SUPERVISORY_CHECKPOINTS: TransmissionCheckpoint[] = [
  {
    time: '08:00 UTC',
    title: 'Archive Transmission',
    status: 'COMPLETED',
    detail: 'WORM audit log bundle transmitted to multi-region cold archive vault.',
  },
  {
    time: '08:15 UTC',
    title: 'Merkle Root Validation',
    status: 'COMPLETED',
    detail: 'Cross-node consensus on root hash verified across 512 nodes.',
  },
  {
    time: '08:20 UTC',
    title: 'PQC Signature Verification',
    status: 'COMPLETED',
    detail: 'ML-DSA-65 post-quantum signature validated against protocol public keys.',
  },
  {
    time: '08:30 UTC',
    title: 'Cross-Jurisdictional Bundle Derivation',
    status: 'COMPLETED',
    detail: 'Sub-bundles compiled for EU, US, UK, and APAC supervisory college endpoints.',
  },
  {
    time: '23:59 UTC',
    title: 'Cycle Closure',
    status: 'PENDING',
    detail: 'Awaiting daily UTC epoch boundary wrap and final state seal.',
  },
];

export interface StaRExpert {
  id: string;
  name: string;
  loadPercent: number;
  status: 'NOMINAL' | 'ELEVATED';
  taskCategory: string;
}

export const STAR_MOE_EXPERTS: StaRExpert[] = [
  { id: 'EXP-01', name: 'Macro-Prudential Stress', loadPercent: 42, status: 'NOMINAL', taskCategory: 'Risk Modeling' },
  { id: 'EXP-02', name: 'Liquidity Spillover', loadPercent: 78, status: 'NOMINAL', taskCategory: 'Market Analysis' },
  { id: 'EXP-03', name: 'Contagion Propagation', loadPercent: 88, status: 'ELEVATED', taskCategory: 'Graph Neural Net' },
  { id: 'EXP-04', name: 'Invariant Proof Assistant', loadPercent: 35, status: 'NOMINAL', taskCategory: 'TLA+ Verification' },
  { id: 'EXP-05', name: 'Agent Policy Audit', loadPercent: 91, status: 'ELEVATED', taskCategory: 'RL Alignment' },
  { id: 'EXP-06', name: 'PQC Key Migration', loadPercent: 22, status: 'NOMINAL', taskCategory: 'Crypto Operations' },
  { id: 'EXP-07', name: 'OSCAL Spec Mapping', loadPercent: 64, status: 'NOMINAL', taskCategory: 'Compliance Translation' },
  { id: 'EXP-08', name: 'TEE Attestation Monitor', loadPercent: 51, status: 'NOMINAL', taskCategory: 'Enclave Security' },
];

export interface DashboardQuickLink {
  to: string;
  title: string;
  description: string;
  category: string;
}

export const DASHBOARD_QUICK_LINKS: DashboardQuickLink[] = [
  {
    to: '/risk-indices',
    title: 'Risk Telemetry',
    description: '12 Systemic risk indices, sparklines & agent drift panel',
    category: 'Systemic Risk',
  },
  {
    to: '/compliance',
    title: 'Compliance Frameworks',
    description: '20 Regulatory frameworks gap analysis & OSCAL mapping',
    category: 'Regulatory',
  },
  {
    to: '/cryptographic-integrity',
    title: 'Cryptographic Integrity',
    description: 'PQC algorithm suite, WORM Merkle-DAG & attestation logs',
    category: 'Security',
  },
  {
    to: '/digital-twin',
    title: 'Digital Twin Mesh',
    description: 'Live 512-node topology & RTEE enclave status',
    category: 'Infrastructure',
  },
  {
    to: '/control-domains',
    title: 'Control Domains',
    description: 'CD-01 to CD-10 control matrix & active findings',
    category: 'Governance',
  },
  {
    to: '/constitutional',
    title: 'Constitutional Invariants',
    description: '24 TLA+ verified invariant proofs & epoch mappings',
    category: 'Constitutional',
  },
  {
    to: '/scenario-planner',
    title: 'Scenario Planner',
    description: 'Stress test simulations & contagion cascade modeling',
    category: 'Simulation',
  },
  {
    to: '/submission-packages',
    title: 'Submission Packages',
    description: 'SGR-028 filing bundles, replay proofs & XML manifests',
    category: 'Filings',
  },
];

export const EXECUTIVE_RECOMMENDATIONS: string[] = [
  'Authorize soft-containment drills for Mesh Topologist (ASA-005) following sustained Δ_drift telemetry.',
  'Accelerate remediation for GIEN-ZTAI-02 TEE sandbox-escape vulnerability prior to the 2026-10-24 SLA deadline.',
  'Maintain elevated supervisory monitoring on Contagion Index C-SRI (0.327) within G-SIFI Cluster 3.',
];
