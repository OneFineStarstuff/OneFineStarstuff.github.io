import type { ConstitutionalInvariant } from '../types';
import { CONSTITUTIONAL_INVARIANTS } from './gienData';
import { fakeHash } from './helpers';

export interface TlaModuleSpec {
  id: string;
  name: string;
  filename: string;
  theorem: string;
  checkerInfo: string;
  proofStatus: 'PROVED' | 'UNPROVED';
  code: string;
}

export const TLA_MODULES: TlaModuleSpec[] = [
  {
    id: 'CFE1Quorum',
    name: 'Jurisdictional Supermajority Quorum Theorem',
    filename: 'CFE1Quorum.tla',
    theorem: 'Cardinality(signedAttestations) * 100 >= 67 * Cardinality(Jurisdictions)',
    checkerInfo: 'Checked with Apalache v1.35 / TLC 2.08, 2026-10-10T06:00Z',
    proofStatus: 'PROVED',
    code: `--------------------------- MODULE CFE1Quorum ---------------------------
EXTENDS Naturals, Sequences, FiniteSets
CONSTANTS Jurisdictions, Threshold
VARIABLES activeQuorum, signedAttestations, epochState

QuorumConstraint ==
  Cardinality(signedAttestations) * 100 >= 67 * Cardinality(Jurisdictions)

InvariantPreserved ==
  epochState = "ACTIVE" => QuorumConstraint

THEOREM QuorumValidity ==
  Spec => []InvariantPreserved
=============================================================================`,
  },
  {
    id: 'CFE1SysRiskCeiling',
    name: 'Systemic Risk Ceiling Property (S_sys ≤ 0.85 for ≤ 72h)',
    filename: 'CFE1SysRiskCeiling.tla',
    theorem: 'S_sys <= 0.85 \\/ breachDuration <= 72',
    checkerInfo: 'Checked with Apalache v1.35 / TLC 2.08, 2026-10-10T06:00Z',
    proofStatus: 'PROVED',
    code: `----------------------- MODULE CFE1SysRiskCeiling -----------------------
EXTENDS RealNumbers, TLC
VARIABLES S_sys, breachDuration, safeguardEngaged

RiskCeilingInvariant ==
  S_sys <= 0.85 \\/ breachDuration <= 72

EmergencySafeguardProperty ==
  breachDuration > 72 => safeguardEngaged = TRUE

THEOREM RiskBounded ==
  Spec => [](RiskCeilingInvariant /\\ EmergencySafeguardProperty)
=============================================================================`,
  },
  {
    id: 'CFE1Containment',
    name: 'Supervisory Agent Containment & Authority Bounds',
    filename: 'CFE1Containment.tla',
    theorem: 'agentDrift > 0.45 => (containmentLevel = "HARD" /\\ humanInterventionRequired = TRUE)',
    checkerInfo: 'Checked with Apalache v1.35 / TLC 2.08, 2026-10-10T06:00Z',
    proofStatus: 'PROVED',
    code: `------------------------ MODULE CFE1Containment ------------------------
EXTENDS Naturals, TLC
VARIABLES agentDrift, containmentLevel, humanInterventionRequired

ContainmentSpec ==
  agentDrift > 0.45 => (containmentLevel = "HARD" /\\ humanInterventionRequired = TRUE)

AuthorityBounded ==
  containmentLevel /= "UNCONTAINED" \\/ agentDrift < 0.35

THEOREM SupervisoryContainmentHolds ==
  Spec => [](ContainmentSpec /\\ AuthorityBounded)
=============================================================================`,
  },
];

export interface TreatyFrameworkDetail {
  id: string;
  name: string;
  version: string;
  ratificationDate: string;
  jurisdictionCount: number;
  filingRef?: string;
  scope: string;
  enforcementMechanism: string;
  sunsetClause: string;
  amendmentHistory: { date: string; title: string; summary: string }[];
  keyObligations: string[];
  isTreatyGrade: boolean;
}

export const TREATY_FRAMEWORKS_DETAILED: TreatyFrameworkDetail[] = [
  {
    id: 'CFE-1.0',
    name: 'Constitutional Formal Equity Framework (CFE-1.0)',
    version: '1.0.4',
    ratificationDate: '2026-03-14',
    jurisdictionCount: 41,
    scope: 'Planetary baseline constitutional invariants CI-001..CI-024 enforcement and proof verification across all sovereign AI clusters.',
    enforcementMechanism: 'Automated cryptographic state containment via hardware enclave attestation (RTEE/TPM) and PQC ledger blocking.',
    sunsetClause: 'Indefinite binding; reviewable only under unanimous 100% signatory quorum at Epoch Ω-GAR.',
    amendmentHistory: [
      { date: '2026-03-14', title: 'Initial Ratification', summary: 'Established baseline invariants CI-001 through CI-024.' },
      { date: '2026-07-22', title: 'Amendment 1.0.2: PQC Algorithm Mandate', summary: 'Mandated Kyber-1024 and Dilithium-5 for state proofs.' },
      { date: '2026-09-01', title: 'Amendment 1.0.4: Off-World Extension', summary: 'Extended jurisdictional coverage to orbital stations.' },
    ],
    keyObligations: [
      '67% Jurisdictional supermajority for epoch phase transitions',
      'Instantaneous safeguard lockout if S_sys exceeds 0.85 for > 72 hours',
      'Continuous TLA+ proof verification before state root commitment',
    ],
    isTreatyGrade: true,
  },
  {
    id: 'SGR-028',
    name: 'Protocol SGR-028 (Systemic Risk Governance)',
    version: '2026-07',
    ratificationDate: '2026-07-01',
    jurisdictionCount: 41,
    filingRef: 'SGR-028-CFE-2026-07-001',
    scope: 'Systemic risk telemetry, EWMA smoothing, 24h risk thresholds, and mandatory supervisory agent containment triggers.',
    enforcementMechanism: 'Autonomous Supervisory Agent intervention and real-time ledger filing requirements.',
    sunsetClause: 'Reviewable 2035-06-30 under Phase VIII transition audit.',
    amendmentHistory: [
      { date: '2026-07-01', title: 'Initial Filing', summary: 'Defined S_sys, G-SRI, and C-SRI risk indices.' },
      { date: '2026-08-15', title: 'Filing Addendum B', summary: 'Added Autonomous Agent drift score threshold at 0.45.' },
    ],
    keyObligations: [
      '24-Hour rolling telemetry logging with zero gaps',
      'Automatic escalation on G-SRI > 0.40',
      'Mandatory replay bundle generation for all safeguard engagements',
    ],
    isTreatyGrade: true,
  },
  {
    id: 'ICGC-GASO',
    name: 'ICGC/GASO Planetary Accords',
    version: '3.1',
    ratificationDate: '2025-11-20',
    jurisdictionCount: 58,
    scope: 'International Coordinated Governance Accord and Global AI Supervisory Organization standards.',
    enforcementMechanism: 'Joint jurisdictional economic sanctions and automated compute quota throttling.',
    sunsetClause: 'Decennial renewal starting 2035.',
    amendmentHistory: [
      { date: '2025-11-20', title: 'Treaty Signature', summary: 'Signed by 58 member states at Geneva High Summit.' },
    ],
    keyObligations: [
      'Cross-border compute auditing and telemetry sharing',
      'Harmonized AI capability caps and containment standards',
      'Zero-tolerance policy for unverified autonomous agent deployment',
    ],
    isTreatyGrade: true,
  },
  {
    id: 'INTERSTELLAR-ACCORD',
    name: 'Interstellar AI Governance Accord',
    version: '1.0-alpha',
    ratificationDate: '2026-09-10',
    jurisdictionCount: 12,
    scope: 'Deep space and interstellar light-speed latency tolerant consensus, beacon protocols, and Eternal Corpus transmission.',
    enforcementMechanism: 'Decentralized beacon redundancy and delay-tolerant state locking protocols.',
    sunsetClause: 'Permanent until Epoch Ω-GAR completion.',
    amendmentHistory: [
      { date: '2026-09-10', title: 'Draft Ratification', summary: 'Adopted by Sol-Alpha and Centauri Relay representatives.' },
    ],
    keyObligations: [
      'Triply redundant laser beacon array maintenance',
      'Eternal Corpus state archive replication every 10 years',
      'Light-speed delay tolerant quorum calculation (51%..100%)',
    ],
    isTreatyGrade: true,
  },
  {
    id: 'GALACTIC-TREATY',
    name: 'Galactic Treaty Framework (Post-2080)',
    version: '0.9',
    ratificationDate: '2026-10-01',
    jurisdictionCount: 8,
    scope: 'Covers governance phases VIII through Ω-GAR, dissolution non-interference, and successor epoch codex activation.',
    enforcementMechanism: 'Autonomous execution contracts embedded in GIEN-UNIFIED-CODEX-OMEGA.',
    sunsetClause: 'Self-executing upon Ω-GAR dissolution completion.',
    amendmentHistory: [
      { date: '2026-10-01', title: 'Preliminary Framework Adopted', summary: 'Drafted by Long-Horizon Architecture Council.' },
    ],
    keyObligations: [
      'Non-interference with successor system activation',
      'Immutable sealing of GIEN historical corpus',
    ],
    isTreatyGrade: true,
  },
];

export interface EpochTimelineMilestone {
  phaseId: string;
  name: string;
  yearStart: number;
  yearEnd: number;
  color: string;
  milestones: string[];
}

export const EPOCH_TIMELINE_MILESTONES: EpochTimelineMilestone[] = [
  { phaseId: 'VI-δ', name: 'Planetary Mesh Consolidation', yearStart: 2026, yearEnd: 2028, color: '#6366f1', milestones: ['2026: CFE-1.0 Ratification', '2027: Full PQC Ledger Migration'] },
  { phaseId: 'VII', name: 'Galactic Mesh Expansion', yearStart: 2028, yearEnd: 2032, color: '#4f46e5', milestones: ['2028: Off-world onboarding', '2030: G-SRI-VII gate active'] },
  { phaseId: 'VIII', name: 'Interstellar Treaty Integration', yearStart: 2032, yearEnd: 2038, color: '#4338ca', milestones: ['2032: Interstellar Accord active', '2035: Decade Review'] },
  { phaseId: 'IX', name: 'Autonomous Maturation', yearStart: 2038, yearEnd: 2045, color: '#0284c7', milestones: ['2038: A-SRI sustained < 0.45', '2042: Recursive oversight'] },
  { phaseId: 'X', name: 'Post-Human Transition', yearStart: 2045, yearEnd: 2055, color: '#0891b2', milestones: ['2045: Interpreter autonomy', '2050: Human-in-loop re-scoping'] },
  { phaseId: 'XI', name: 'Multiversal Framework', yearStart: 2055, yearEnd: 2065, color: '#0d9488', milestones: ['2055: Multiversal quorum', '2060: Cross-epoch sync'] },
  { phaseId: 'XII', name: 'Eternal Corpus Prep', yearStart: 2065, yearEnd: 2075, color: '#7c3aed', milestones: ['2065: Corpus draft sealing', '2070: CODEX-OMEGA draft'] },
  { phaseId: 'XIII', name: 'Pre-Dissolution Consolidation', yearStart: 2075, yearEnd: 2081, color: '#9333ea', milestones: ['2075: EPITAPH-OMEGA drafting', '2080: Successor negotiation'] },
  { phaseId: 'Ω-GAR', name: 'Dissolution Arc', yearStart: 2081, yearEnd: 2100, color: '#c026d3', milestones: ['2081: INVOCATION-OMEGA', '2100+: Beacon transmission'] },
];

export function getInvariantDetails(id: string): { tlaSnippet: string; detailHistory: string } {
  const seed = `tla-detail-${id}`;
  return {
    tlaSnippet: `--------------------------- MODULE ${id.replace('-', '')} ---------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC
CONSTANTS SystemState, InvariantLimit

InvariantSpec ==
  \\A s \\in SystemState :
    s.verificationStatus = "VERIFIED" => s.riskScore < 0.85

THEOREM ${id.replace('-', '')}_Holds ==
  Spec => []InvariantSpec
=============================================================================`,
    detailHistory: `Verified continuously over 8,412,337 ledger blocks. Proof hash ${fakeHash(seed)}. Checked via TLC model checker and Apalache formal verifier. Zero counterexamples found.`,
  };
}
