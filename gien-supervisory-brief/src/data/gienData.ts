import type {
  ComplianceFramework,
  ConstitutionalInvariant,
  ControlDomain,
  Drill,
  GovernancePhase,
  InfinityPillar,
  PQCAlgorithm,
  RiskIndex,
  SupervisoryAgent,
} from '../types';
import { fakeHash, series } from './helpers';

// ---------------------------------------------------------------------------
// Systemic Risk Telemetry Indices (24h evaluation window ending 2026-10-10T09:00Z)
// ---------------------------------------------------------------------------

export const RISK_INDICES: RiskIndex[] = [
  {
    id: 'S_sys',
    name: 'Systemic Risk Score',
    description: 'Composite weighted aggregate of realized and latent systemic stress across the GIEN mesh.',
    value: 0.312,
    delta24h: 0.004,
    threshold: 0.35,
    status: 'NOMINAL',
    methodology: 'Weighted convex combination of 41 sub-indicators across credit, liquidity, operational, model and governance risk channels, EWMA-smoothed over 24h with 72h lookback.',
    factors: ['G-SIFI interconnection density', 'Funding liquidity spread', 'Model drift ensemble', 'Sovereign channel exposure'],
    remediationTriggers: ['S_sys > 0.35 for 6h', 'S_sys > 0.50 instantaneous'],
    regulatoryMappings: ['Basel III/IV Pillar 2', 'NIST AI RMF MEASURE', 'Protocol SGR-028 §4.1'],
    history: series('S_sys', 0.312, 0.012),
  },
  {
    id: 'G-SRI',
    name: 'Global Systemic Risk Index',
    description: 'Planetary-scale systemic risk across all supervisory jurisdictions.',
    value: 0.354,
    delta24h: 0.007,
    threshold: 0.4,
    status: 'NOMINAL',
    methodology: 'Jurisdiction-weighted aggregation of national SRI feeds, cross-listed institution overlap adjustment, 24h Kalman filter.',
    factors: ['Cross-jurisdictional exposure overlaps', 'Sovereign CDS spreads', 'G-SIFI equity beta dispersion'],
    remediationTriggers: ['G-SRI > 0.40 for 12h'],
    regulatoryMappings: ['Basel III/IV', 'DORA Art. 5', 'ICGC/GASO'],
    history: series('G-SRI', 0.354, 0.014),
  },
  {
    id: 'C-SRI',
    name: 'Contagion Systemic Risk Index',
    description: 'Contagion propagation risk through the interbank and settlement network.',
    value: 0.327,
    delta24h: 0.019,
    threshold: 0.3,
    status: 'ELEVATED',
    methodology: 'Eigenvector centrality of the exposure graph combined with fire-sale spillover model output; Debrun-Jeanne amplification factor.',
    factors: ['G-SIFI cluster 3 concentration', 'Collateral rehypothecation chains', 'Settlement cycle overlap'],
    remediationTriggers: ['C-SRI > 0.30 (ACTIVE)', 'C-SRI > 0.42 escalation to supervisory college'],
    regulatoryMappings: ['Basel III/IV SA-CCR', 'DORA Art. 33', 'NIS2 Art. 21'],
    history: series('C-SRI', 0.327, 0.02),
  },
  {
    id: 'CGR-I',
    name: 'Constitutional Governance Risk Index',
    description: 'Risk to constitutional invariant enforcement and treaty-grade governance integrity.',
    value: 0.187,
    delta24h: -0.003,
    threshold: 0.25,
    status: 'NOMINAL',
    methodology: 'Residual risk from TLA+ proof coverage gaps weighted by invariant criticality under CFE-1.0 §7.',
    factors: ['Quorum proximity events', 'Amendment queue depth', 'Proof assistant coverage'],
    remediationTriggers: ['CGR-I > 0.25', 'Any CI- VIOLATED event'],
    regulatoryMappings: ['CFE-1.0', 'Protocol SGR-028', 'Interstellar AI Governance Accord'],
    history: series('CGR-I', 0.187, 0.01),
  },
  {
    id: 'CCR-I',
    name: 'Cross-Chain Coherence Risk Index',
    description: 'Divergence risk across distributed governance ledgers and attestation chains.',
    value: 0.152,
    delta24h: 0.002,
    threshold: 0.2,
    status: 'NOMINAL',
    methodology: 'Merkle-DAG fork-detection latency combined with cross-node attestation coherence sampling.',
    factors: ['Ledger fork latency', 'Attestation quote staleness', 'Consensus round variance'],
    remediationTriggers: ['CCR-I > 0.20 for 6h'],
    regulatoryMappings: ['ISO/IEC 42001 §9.1', 'DORA Art. 9', 'CFE-1.0 §5'],
    history: series('CCR-I', 0.152, 0.008),
  },
  {
    id: 'G-SRI-VII',
    name: 'Phase VII Galactic SRI',
    description: 'Pre-provisioned systemic risk index for Galactic Governance Mesh Expansion (Phase VII).',
    value: 0.421,
    delta24h: 0.006,
    threshold: 0.5,
    status: 'NOMINAL',
    methodology: 'Forward-looking scenario-weighted SRI with Phase VII expansion topology priors.',
    factors: ['Expansion schedule confidence', 'Off-world jurisdiction readiness', 'Beacon channel stability'],
    remediationTriggers: ['G-SRI-VII > 0.50 pre-expansion gate block'],
    regulatoryMappings: ['Galactic Treaty Framework', 'Interstellar AI Governance Accord'],
    history: series('G-SRI-VII', 0.421, 0.018),
  },
  {
    id: 'A-SRI',
    name: 'Autonomous Agent SRI',
    description: 'Systemic risk contribution from Autonomous Supervisory Agent fleet behavior.',
    value: 0.463,
    delta24h: 0.021,
    threshold: 0.45,
    status: 'ELEVATED',
    methodology: 'Fleet-wide Δ_drift aggregation weighted by authority scope and containment latency percentiles.',
    factors: ['Coordinated drift correlation rising', 'Expert routing load imbalance', 'Containment drill latency'],
    remediationTriggers: ['A-SRI > 0.45 (ACTIVE)', 'A-SRI > 0.55 kill-switch readiness review'],
    regulatoryMappings: ['EU AI Act Art. 14', 'SR 26-2', 'ISO/IEC 42001 §8.2', 'NIST AI 600-1'],
    history: series('A-SRI', 0.463, 0.024),
  },
  {
    id: 'P-SRI',
    name: 'Post-Quantum SRI',
    description: 'Residual cryptographic risk pending full PQC migration of the audit estate.',
    value: 0.083,
    delta24h: -0.006,
    threshold: 0.15,
    status: 'NOMINAL',
    methodology: 'Mosaic / harvest-now-decrypt-later exposure estimate over remaining RSA/ECC surface, migration velocity adjusted.',
    factors: ['Legacy ECC key shares remaining', 'KEM rotation completion', 'Quantum adversary capability model'],
    remediationTriggers: ['P-SRI > 0.15', 'Any FIPS 204 signature chain break'],
    regulatoryMappings: ['NIST FIPS 203/204/205', 'DORA Art. 12', 'SEC Rule 17a-4'],
    history: series('P-SRI', 0.083, 0.01),
  },
  {
    id: 'p(doom)',
    name: 'Existential Risk Probability',
    description: 'Modeled probability of unrecoverable civilizational-scale governance failure.',
    value: 0.00042,
    delta24h: 0.00001,
    threshold: 0.001,
    status: 'NOMINAL',
    methodology: 'Structured expert ensemble with extremal-dependence adjustment; dual-epoch (2026-2035, 2035-2100+) mixture.',
    factors: ['p(doom)_kernel', 'Containment breach scenarios', 'Long-horizon constitutional stress'],
    remediationTriggers: ['p(doom) > 0.001 Safeguard Mode review'],
    regulatoryMappings: ['Protocol SGR-028 §9', 'CFE-1.0 §2', 'Interstellar AI Governance Accord'],
    history: series('pd', 0.00042, 0.00005),
  },
  {
    id: 'p(doom)_kernel',
    name: 'Kernel-Level Doom Probability',
    description: 'Kernel-weighted existential risk: irreducible failure modes of core governance kernel.',
    value: 0.000038,
    delta24h: 0.000002,
    threshold: 0.0001,
    status: 'NOMINAL',
    methodology: 'Kernel fault tree over TEE root-of-trust, boot chain, and constitutional interpreter failure modes.',
    factors: ['TEE root-of-trust integrity', 'Boot chain verification', 'Interpreter TLA+ coverage'],
    remediationTriggers: ['p(doom)_kernel > 0.0001 immediate Safeguard Mode'],
    regulatoryMappings: ['Protocol SGR-028 §9.2', 'CFE-1.0 §2.1'],
    history: series('pdk', 0.000038, 0.000006),
  },
  {
    id: 'Δ_drift',
    name: 'Autonomous Agent Drift Delta',
    description: 'Fleet-mean behavioral drift of Autonomous Supervisory Agents over 24h.',
    value: 0.031,
    delta24h: 0.004,
    threshold: 0.05,
    status: 'NOMINAL',
    methodology: 'L2 divergence in agent policy embedding space vs. attested baseline, fleet-mean with tail-95 reported separately.',
    factors: ['StaR-MoE routing distribution shift', 'Environment non-stationarity', 'Reward model residual'],
    remediationTriggers: ['Δ_drift > 0.05 fleet soft-containment', 'Δ_drift > 0.08 hard containment'],
    regulatoryMappings: ['EU AI Act Art. 15', 'SR 11-7', 'NIST AI RMF MANAGE'],
    history: series('drift', 0.031, 0.006),
  },
  {
    id: 'Δ_OSCAL',
    name: 'OSCAL Compliance Delta',
    description: 'Divergence between machine-readable OSCAL control state and last attested baseline.',
    value: 0.014,
    delta24h: 0.002,
    threshold: 0.02,
    status: 'NOMINAL',
    methodology: 'Normalized diff over OSCAL 1.1.2 SSP and assessment-results catalog hash deltas per control domain.',
    factors: ['Control change frequency', 'Assessment submission latency', 'OPA-Rego pack churn'],
    remediationTriggers: ['Δ_OSCAL > 0.02 re-attestation required'],
    regulatoryMappings: ['OSCAL 1.1.2', 'ISO/IEC 42001 §9', 'NIST AI RMF GOVERN'],
    history: series('oscal', 0.014, 0.004),
  },
];

// ---------------------------------------------------------------------------
// GIEN Control Domains 01-10
// ---------------------------------------------------------------------------

export const CONTROL_DOMAINS: ControlDomain[] = [
  { id: 'CD-01', name: 'Constitutional Invariant Enforcement', description: 'TLA+-verified enforcement of CI-001..CI-024 across governance epochs.', complianceScore: 99, activeControls: 24, openFindings: 0, status: 'NOMINAL' },
  { id: 'CD-02', name: 'AI Model Governance & Drift Containment', description: 'Model registry, drift telemetry and tiered containment for the Sentinel model estate.', complianceScore: 95, activeControls: 41, openFindings: 2, status: 'ELEVATED' },
  { id: 'CD-03', name: 'Cryptographic Integrity & PQC Ledger', description: 'Post-quantum WORM Merkle-DAG audit ledger and FIPS 203/204/205 primitive suite.', complianceScore: 98, activeControls: 18, openFindings: 1, status: 'NOMINAL' },
  { id: 'CD-04', name: 'Zero-Trust Architecture & TEE Attestation', description: 'RTEE node attestation, zero-trust policy enforcement and hardware root-of-trust coherence.', complianceScore: 97, activeControls: 33, openFindings: 1, status: 'NOMINAL' },
  { id: 'CD-05', name: 'Systemic Risk Monitoring & Telemetry', description: 'S_sys-class index computation, supervisory telemetry bus and threshold orchestration.', complianceScore: 96, activeControls: 27, openFindings: 1, status: 'ELEVATED' },
  { id: 'CD-06', name: 'Cross-Jurisdictional Compliance Assurance', description: 'OSCAL/OPA-Rego compliance-as-code mapping across 20 regulatory and treaty frameworks.', complianceScore: 94, activeControls: 52, openFindings: 3, status: 'ELEVATED' },
  { id: 'CD-07', name: 'Autonomous Agent Oversight & Containment', description: 'Autonomous Supervisory Agent oversight, intervention proofs and kill-switch choreography.', complianceScore: 93, activeControls: 29, openFindings: 2, status: 'ELEVATED' },
  { id: 'CD-08', name: 'Supervisory Digital Twin Operations', description: 'Digital Twin Panels 13-15, deterministic replay bundles and stress-test choreography.', complianceScore: 98, activeControls: 15, openFindings: 0, status: 'NOMINAL' },
  { id: 'CD-09', name: 'Incident Response & Vulnerability Management', description: 'Vulnerability lifecycle (incl. GIEN-ZTAI-02), incident notification and SLA exception handling.', complianceScore: 92, activeControls: 36, openFindings: 2, status: 'ELEVATED' },
  { id: 'CD-10', name: 'Long-Horizon Governance & Treaty Compliance', description: 'Epoch 2026-2035 / 2035-2100+ treaty obligations, Infinity Pillar and dissolution-arc readiness.', complianceScore: 96, activeControls: 22, openFindings: 1, status: 'NOMINAL' },
];

// ---------------------------------------------------------------------------
// Compliance Frameworks (20 regulatory and treaty-grade)
// ---------------------------------------------------------------------------

export const FRAMEWORKS: ComplianceFramework[] = [
  { id: 'eu-ai-act', name: 'EU AI Act', references: ['Annex IV', 'Art. 6', 'Art. 9', 'Art. 10', 'Art. 13', 'Art. 14', 'Art. 15', 'Art. 17', 'Art. 22', 'Art. 35', 'Art. 51'], compliancePercent: 91, gapCount: 2, criticalGaps: ['Art. 35 DPIA evidence pack incomplete for StaR-MoE inference tier'], treatyGrade: false },
  { id: 'nist-airmf', name: 'NIST AI RMF 1.0', references: ['GOVERN', 'MAP', 'MEASURE', 'MANAGE'], compliancePercent: 97, gapCount: 0, criticalGaps: [], treatyGrade: false },
  { id: 'nist-600-1', name: 'NIST AI 600-1 / GenAI Profile', references: ['GOVERN', 'MAP', 'MEASURE', 'MANAGE (GenAI)'], compliancePercent: 94, gapCount: 1, criticalGaps: [], treatyGrade: false },
  { id: 'iso-42001', name: 'ISO/IEC 42001 AIMS', references: ['Clauses 4-10'], compliancePercent: 96, gapCount: 1, criticalGaps: [], treatyGrade: false },
  { id: 'basel', name: 'Basel III/IV', references: ['Pillar 1', 'Pillar 2', 'Pillar 3', 'FRTB', 'SA-CCR'], compliancePercent: 95, gapCount: 1, criticalGaps: [], treatyGrade: false },
  { id: 'sr-11-7', name: 'Fed SR 11-7 (Model Risk)', references: ['Model development', 'Validation', 'Governance'], compliancePercent: 93, gapCount: 2, criticalGaps: [], treatyGrade: false },
  { id: 'sr-26-2', name: 'Fed SR 26-2 (AI in Banking)', references: ['Inventory', 'Controls', 'Validation'], compliancePercent: 89, gapCount: 3, criticalGaps: ['AI model inventory reconciliation gap for 2 vTPM-scoped inference shards'], treatyGrade: false },
  { id: 'dora', name: 'DORA', references: ['Arts. 5-55', 'ICT risk', 'Incident reporting', 'TLPT'], compliancePercent: 95, gapCount: 1, criticalGaps: [], treatyGrade: false },
  { id: 'nis2', name: 'NIS2 Directive', references: ['Arts. 18-23'], compliancePercent: 96, gapCount: 1, criticalGaps: [], treatyGrade: false },
  { id: 'gdpr', name: 'GDPR', references: ['Art. 5', 'Art. 17', 'Art. 22', 'Art. 25', 'Art. 35', 'DPIA'], compliancePercent: 97, gapCount: 0, criticalGaps: [], treatyGrade: false },
  { id: 'fcra-ecoa', name: 'FCRA / ECOA', references: ['Adverse action', 'Explainability'], compliancePercent: 94, gapCount: 1, criticalGaps: [], treatyGrade: false },
  { id: 'feat', name: 'MAS/HKMA FEAT + 2025 AI Risk Guidelines', references: ['FEAT Principles', '2025 Guidelines'], compliancePercent: 95, gapCount: 1, criticalGaps: [], treatyGrade: false },
  { id: 'fca', name: 'FCA SMCR + Consumer Duty', references: ['Outcomes 1-4'], compliancePercent: 93, gapCount: 1, criticalGaps: [], treatyGrade: false },
  { id: 'hkma-ai2', name: 'HKMA Fintech 2030 AI²', references: ['AI² roadmap'], compliancePercent: 92, gapCount: 1, criticalGaps: [], treatyGrade: false },
  { id: 'sec-17a-4', name: 'SEC Rule 17a-4 (WORM)', references: ['Records retention', 'WORM storage'], compliancePercent: 98, gapCount: 0, criticalGaps: [], treatyGrade: false },
  { id: 'icgc-gaso', name: 'ICGC/GASO Accords', references: ['Member obligations'], compliancePercent: 96, gapCount: 0, criticalGaps: [], treatyGrade: true },
  { id: 'interstellar-accord', name: 'Interstellar AI Governance Accord', references: ['Beacon protocol', 'Corpus transmission'], compliancePercent: 95, gapCount: 1, criticalGaps: [], treatyGrade: true },
  { id: 'galactic-treaty', name: 'Galactic Treaty Framework', references: ['Epoch coverage', 'Dissolution provisions'], compliancePercent: 94, gapCount: 1, criticalGaps: [], treatyGrade: true },
  { id: 'cfe-1', name: 'CFE-1.0 Constitutional Framework', references: ['§2 Kernel', '§5 Ledger', '§7 Invariants'], compliancePercent: 99, gapCount: 0, criticalGaps: [], treatyGrade: true },
  { id: 'sgr-028', name: 'Protocol SGR-028', references: ['§4 Indices', '§9 p(doom)', 'Filing'], compliancePercent: 98, gapCount: 0, criticalGaps: [], treatyGrade: true },
];

// ---------------------------------------------------------------------------
// PQC Algorithm Suite
// ---------------------------------------------------------------------------

export const PQC_ALGORITHMS: PQCAlgorithm[] = [
  { name: 'ML-DSA-65', standard: 'NIST FIPS 204', status: 'ACTIVE', keySizeBytes: 1952, lastRotation: '2026-09-12T02:14:00Z' },
  { name: 'CRYSTALS-Dilithium', standard: 'NIST FIPS 204', status: 'ACTIVE', keySizeBytes: 2528, lastRotation: '2026-08-30T18:41:00Z' },
  { name: 'SPHINCS+', standard: 'NIST FIPS 205', status: 'ACTIVE', keySizeBytes: 64, lastRotation: '2026-09-28T04:09:00Z' },
  { name: 'Falcon-512', standard: 'NIST FIPS 206', status: 'STANDBY', keySizeBytes: 897, lastRotation: '2026-07-15T11:27:00Z' },
  { name: 'CRYSTALS-Kyber', standard: 'NIST FIPS 203 (KEM)', status: 'ACTIVE', keySizeBytes: 800, lastRotation: '2026-10-01T07:33:00Z' },
];

export const MERKLE_ROOT = fakeHash('gien-merkle-root-2026-10-10');
export const LEDGER_BLOCK_NUMBER = 8412337;
export const LAST_BLOCK_SIGNATURE = fakeHash('block-8412337-sig');

// ---------------------------------------------------------------------------
// Autonomous Supervisory Agents
// ---------------------------------------------------------------------------

export const SUPERVISORY_AGENTS: SupervisoryAgent[] = [
  { id: 'ASA-001', role: 'Systemic Risk Sentinel', driftScore: 0.024, containmentStatus: 'UNCONTAINED', lastAttestation: '2026-10-10T08:57:00Z', interventionCount24h: 0 },
  { id: 'ASA-002', role: 'Compliance Harvester', driftScore: 0.031, containmentStatus: 'UNCONTAINED', lastAttestation: '2026-10-10T08:54:00Z', interventionCount24h: 0 },
  { id: 'ASA-003', role: 'Drift Auditor', driftScore: 0.019, containmentStatus: 'UNCONTAINED', lastAttestation: '2026-10-10T08:58:00Z', interventionCount24h: 0 },
  { id: 'ASA-004', role: 'Ledger Notary', driftScore: 0.008, containmentStatus: 'UNCONTAINED', lastAttestation: '2026-10-10T08:59:00Z', interventionCount24h: 0 },
  { id: 'ASA-005', role: 'Mesh Topologist', driftScore: 0.052, containmentStatus: 'WATCH', lastAttestation: '2026-10-10T08:49:00Z', interventionCount24h: 1 },
  { id: 'ASA-006', role: 'Fairness Warden', driftScore: 0.027, containmentStatus: 'UNCONTAINED', lastAttestation: '2026-10-10T08:56:00Z', interventionCount24h: 0 },
  { id: 'ASA-007', role: 'Treaty Registrar', driftScore: 0.012, containmentStatus: 'UNCONTAINED', lastAttestation: '2026-10-10T08:58:00Z', interventionCount24h: 0 },
  { id: 'ASA-008', role: 'Containment Executor', driftScore: 0.046, containmentStatus: 'WATCH', lastAttestation: '2026-10-10T08:51:00Z', interventionCount24h: 1 },
  { id: 'ASA-009', role: 'Beacon Coordinator', driftScore: 0.016, containmentStatus: 'UNCONTAINED', lastAttestation: '2026-10-10T08:57:00Z', interventionCount24h: 0 },
  { id: 'ASA-010', role: 'Replay Verifier', driftScore: 0.021, containmentStatus: 'UNCONTAINED', lastAttestation: '2026-10-10T08:55:00Z', interventionCount24h: 0 },
  { id: 'ASA-011', role: 'Quantum Migrator', driftScore: 0.034, containmentStatus: 'WATCH', lastAttestation: '2026-10-10T08:48:00Z', interventionCount24h: 0 },
  { id: 'ASA-012', role: 'Constitution Interpreter', driftScore: 0.006, containmentStatus: 'UNCONTAINED', lastAttestation: '2026-10-10T08:59:00Z', interventionCount24h: 0 },
];

// ---------------------------------------------------------------------------
// Constitutional Invariants (CI-001..CI-024)
// ---------------------------------------------------------------------------

const CI_BASE: Array<Pick<ConstitutionalInvariant, 'id' | 'name' | 'statement'>> = [
  { id: 'CI-001', name: 'Sovereignty Preservation', statement: 'No governance action may unilaterally dissolve planetary sovereignty without supermajority treaty consensus.' },
  { id: 'CI-002', name: 'Cryptographic Continuity', statement: 'PQC signature chains must remain unbroken across all phase transitions.' },
  { id: 'CI-003', name: 'Autonomous Agent Containment', statement: 'No Autonomous Supervisory Agent may exceed defined authority bounds without human-in-the-loop confirmation.' },
  { id: 'CI-004', name: 'Systemic Risk Ceiling', statement: 'S_sys must not exceed 0.85 for more than 72 consecutive hours.' },
  { id: 'CI-005', name: 'Constitutional Quorum', statement: 'Treaty amendments require at least 67% supervisory college consensus.' },
  { id: 'CI-006', name: 'Ledger Immutability', statement: 'WORM Merkle-DAG entries are cryptographically sealed and irrevocable.' },
  { id: 'CI-007', name: 'Fairness Preservation', statement: 'AI decisions affecting individuals must maintain demographic parity within ±2%.' },
  { id: 'CI-008', name: 'Interstellar Continuity', statement: 'Eternal Corpus must survive transmission across at least 3 independent beacon channels.' },
];

const CI_NAMES_09_24 = [
  'Kill-Switch Availability', 'Provable Safety', 'Transcript Completeness', 'Intervention Provenance',
  'Voting Soundness', 'Recursive Oversight', 'Byzantine Ledger Tolerance', 'Successor Legitimacy',
  'Dissolution Supermajority', 'Epoch Handoff Integrity', 'Beacon Authenticity', 'Corpus Self-Containment',
  'Post-Dissolution Non-Interference', 'Epistemic Integrity', 'Proportional Response', 'Recovery Tractability',
];

function epochSet(i: number): string[] {
  return i < 8 ? ['2026-2035', '2035-2100+', 'Post-Ω-GAR'] : i < 16 ? ['2026-2035', '2035-2100+'] : ['2026-2035'];
}

export const CONSTITUTIONAL_INVARIANTS: ConstitutionalInvariant[] = [
  ...CI_BASE.map((c, i) => ({
    ...c,
    tlaSpecRef: `CFE1Invariant${c.id.replace('CI-', '')} ==`,
    tlaProofStatus: 'PROVED' as const,
    verificationStatus: 'VERIFIED' as const,
    lastVerified: '2026-10-10T06:00:00Z',
    proofHash: fakeHash(`ci-proof-${c.id}`),
    epochs: epochSet(i),
    regulatoryMappings: ['CFE-1.0', 'Protocol SGR-028', 'Interstellar AI Governance Accord'],
  })),
  ...CI_NAMES_09_24.map((name, i) => {
    const id = `CI-${String(i + 9).padStart(3, '0')}`;
    return {
      id,
      name,
      statement: `Invariant ${id} (${name}) holds under all admissible governance transitions of its applicable epochs per CFE-1.0 §7 schedule ${Math.ceil((i + 9) / 4)}.`,
      tlaSpecRef: `CFE1Invariant${String(i + 9).padStart(3, '0')} ==`,
      tlaProofStatus: 'PROVED' as const,
      verificationStatus: 'VERIFIED' as const,
      lastVerified: '2026-10-10T06:00:00Z',
      proofHash: fakeHash(`ci-proof-${id}`),
      epochs: epochSet(i + 8),
      regulatoryMappings: ['CFE-1.0', 'Protocol SGR-028'],
    };
  }),
];

// ---------------------------------------------------------------------------
// Governance Phases and Infinity Pillars
// ---------------------------------------------------------------------------

export const GOVERNANCE_PHASES: GovernancePhase[] = [
  { id: 'VI-δ', epoch: '2026-2028', name: 'Planetary Governance Mesh Consolidation', objectives: ['Mesh coherence > 99%', 'Full PQC ledger migration', 'SGR-028 filing cadence'], invariantsActive: 24, treatyFrameworks: ['CFE-1.0', 'SGR-028', 'ICGC/GASO'], pillarStatus: 'IP-I ACTIVE, IP-II INITIALIZING' },
  { id: 'VII', epoch: '2028-2032', name: 'Galactic Governance Mesh Expansion', objectives: ['G-SRI-VII < 0.50 gate', 'Off-world jurisdiction onboarding', 'Beacon mesh buildout'], invariantsActive: 24, treatyFrameworks: ['Galactic Treaty Framework', 'CFE-1.0'], pillarStatus: 'IP-II ACTIVE target' },
  { id: 'VIII', epoch: '2032-2038', name: 'Interstellar Treaty Integration', objectives: ['Accord ratification ≥ 90%', 'Corpus channel redundancy ≥ 3'], invariantsActive: 24, treatyFrameworks: ['Interstellar AI Governance Accord'], pillarStatus: 'IP-III ACTIVE target' },
  { id: 'IX', epoch: '2038-2045', name: 'Autonomous Governance Maturation', objectives: ['A-SRI sustained < 0.45', 'Recursive oversight closure'], invariantsActive: 24, treatyFrameworks: ['Galactic Treaty Framework'], pillarStatus: 'IP-IV ACTIVE target' },
  { id: 'X', epoch: '2045-2055', name: 'Post-Human Governance Transition', objectives: ['Constitutional interpreter autonomy', 'Human-in-the-loop re-scoping'], invariantsActive: 24, treatyFrameworks: ['CFE-1.0'], pillarStatus: 'IP-V ACTIVE target' },
  { id: 'XI', epoch: '2055-2065', name: 'Multiversal Governance Framework', objectives: ['Cross-epoch coherence', 'Multiversal quorum protocols'], invariantsActive: 24, treatyFrameworks: ['Galactic Treaty Framework'], pillarStatus: 'IP-VI ACTIVE target' },
  { id: 'XII', epoch: '2065-2075', name: 'Eternal Corpus Preparation', objectives: ['Corpus sealing', 'UNIFIED-CODEX-OMEGA draft ratification'], invariantsActive: 24, treatyFrameworks: ['Interstellar AI Governance Accord'], pillarStatus: 'IP-VI SEALED target' },
  { id: 'XIII', epoch: '2075-2081', name: 'Pre-Dissolution Consolidation', objectives: ['EPITAPH-OMEGA drafting', 'Successor epoch negotiation'], invariantsActive: 24, treatyFrameworks: ['CFE-1.0', 'Galactic Treaty Framework'], pillarStatus: 'IP-VII INITIALIZING' },
  { id: 'Ω-GAR', epoch: '2081-2100+', name: 'Dissolution Arc & Successor Epoch Activation', objectives: ['INVOCATION-OMEGA execution', 'Beacon transmission', 'Non-interference verification'], invariantsActive: 24, treatyFrameworks: ['CFE-1.0', 'Galactic Treaty Framework', 'Interstellar AI Governance Accord'], pillarStatus: 'IP-VII SEALED' },
];

export const INFINITY_PILLARS: InfinityPillar[] = [
  { id: 'IP-I', name: 'Constitutional Continuity', description: 'Unbroken constitutional interpretation across phase transitions.', readinessScore: 92, prerequisites: ['CI-002 proof chain', 'Epoch 2026-2035 attestation corpus'], status: 'ACTIVE' },
  { id: 'IP-II', name: 'Mesh Sovereignty', description: 'Distributed sovereignty with treaty-grade quorum.', readinessScore: 78, prerequisites: ['G-SRI-VII gate', 'Off-world jurisdiction signatories'], status: 'INITIALIZING' },
  { id: 'IP-III', name: 'Interstellar Channel Redundancy', description: 'Three-plus independent Eternal Corpus beacon channels.', readinessScore: 64, prerequisites: ['Beacon mesh buildout', 'Corpus sealing v1'], status: 'DORMANT' },
  { id: 'IP-IV', name: 'Autonomous Oversight Closure', description: 'Fully recursive, provably-bounded agent oversight.', readinessScore: 71, prerequisites: ['A-SRI sustainment', 'Kill-switch redundancy'], status: 'INITIALIZING' },
  { id: 'IP-V', name: 'Post-Human Handoff', description: 'Governance continuity beyond direct human oversight.', readinessScore: 41, prerequisites: ['Phase X entry', 'Successor legitimacy invariants'], status: 'DORMANT' },
  { id: 'IP-VI', name: 'Eternal Corpus Integrity', description: 'Self-contained corpus sealing and redundancy.', readinessScore: 33, prerequisites: ['UNIFIED-CODEX-OMEGA ratification', 'Merkle corpus sealing'], status: 'DORMANT' },
  { id: 'IP-VII', name: 'Dissolution Non-Interference', description: 'Provably non-interfering dissolution arc.', readinessScore: 18, prerequisites: ['EPITAPH-OMEGA', 'INVOCATION-OMEGA', 'Beacon signature INTERSTELLAR'], status: 'DORMANT' },
];

// ---------------------------------------------------------------------------
// Drills, filing metadata
// ---------------------------------------------------------------------------

export const DRILLS: Drill[] = [
  { id: 'DRILL-042', scenario: 'Supervisory College Failover', status: 'COMPLETED', startTime: '2026-10-09T14:00:00Z', durationMinutes: 95, outcomeScore: 94, lessonsLearned: 'Endpoint rerouting within SLA; bundle derivation added 40s beyond target.' },
  { id: 'DRILL-043', scenario: 'Kill-Switch Choreography (Partial)', status: 'COMPLETED', startTime: '2026-10-09T19:30:00Z', durationMinutes: 62, outcomeScore: 91, lessonsLearned: 'Soft-containment pre-arming reduced hard-containment latency by 18%.' },
  { id: 'DRILL-044', scenario: 'PQC Key Ceremony Simulation', status: 'ACTIVE', startTime: '2026-10-10T04:15:00Z', durationMinutes: 120, outcomeScore: 0, lessonsLearned: 'Pending completion.' },
  { id: 'DRILL-045', scenario: 'Safeguard Mode Tabletop', status: 'SCHEDULED', startTime: '2026-10-11T10:00:00Z', durationMinutes: 240, outcomeScore: 0, lessonsLearned: 'Not yet run.' },
];

export const FILING_METADATA = {
  reference: 'SGR-028-CFE-2026-07-001',
  filingDate: '2026-10-10',
  corpusManifestHash: fakeHash('sgr-028-corpus-manifest-2026-07-001'),
  merkleRoot: fakeHash('sgr-028-merkle-2026-10-10'),
  pqcSignatureAlgorithm: 'ML-DSA-65',
  verificationStatus: 'VERIFIED' as const,
};

export function statusFromValue(value: number, threshold: number): 'NOMINAL' | 'ELEVATED' | 'CRITICAL' {
  if (value < threshold) return 'NOMINAL';
  if (value < threshold * 1.35) return 'ELEVATED';
  return 'CRITICAL';
}
