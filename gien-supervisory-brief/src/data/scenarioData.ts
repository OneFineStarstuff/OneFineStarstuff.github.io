import type { GovernancePhase, InfinityPillar } from '../types';
import { fakeHash, truncateHash } from './helpers';

export type ScenarioTypeId =
  | 'phase_transition'
  | 'omega_gar_dissolution'
  | 'successor_codex'
  | 'invariant_stress_test'
  | 'regulatory_shift'
  | 'interstellar_handoff';

export interface ScenarioTypeInfo {
  id: ScenarioTypeId;
  title: string;
  category: string;
  description: string;
  badge: string;
  iconName: string;
}

export const SCENARIO_TYPES: ScenarioTypeInfo[] = [
  {
    id: 'phase_transition',
    title: 'Governance Phase Transition',
    category: 'Epoch Transition',
    description: 'Simulate structural shifts between GIEN governance phases (VI-δ through XIII).',
    badge: 'CORE ARC',
    iconName: 'Sliders',
  },
  {
    id: 'omega_gar_dissolution',
    title: 'Ω-GAR Dissolution Arc',
    category: 'Terminal Horizon',
    description: 'Model controlled dissolution, beacon sealing, and successor system handoff.',
    badge: 'TERMINAL',
    iconName: 'Zap',
  },
  {
    id: 'successor_codex',
    title: 'Successor Epoch Codex Activation',
    category: 'Codex Migration',
    description: 'Evaluate structural migration to post-GIEN autonomous successor codices.',
    badge: 'SPECULATIVE',
    iconName: 'FileText',
  },
  {
    id: 'invariant_stress_test',
    title: 'Constitutional Invariant Stress Test',
    category: 'Resilience',
    description: 'Subject invariants CI-001..CI-024 to high-stress adversarial loading.',
    badge: 'SECURITY',
    iconName: 'ShieldAlert',
  },
  {
    id: 'regulatory_shift',
    title: 'Regulatory Regime Shift',
    category: 'Compliance',
    description: 'Assess cross-border harmonizations under new supranational treaties.',
    badge: 'TREATY-GRADE',
    iconName: 'Globe',
  },
  {
    id: 'interstellar_handoff',
    title: 'Interstellar Governance Handoff',
    category: 'Deep Space',
    description: 'Model delay-tolerant quorum and consensus across interstellar communication links.',
    badge: 'HORIZON',
    iconName: 'Radio',
  },
];

export const MAJOR_FRAMEWORKS = [
  'Basel III/IV',
  'Protocol SGR-028',
  'CFE-1.0',
  'ICGC/GASO Accords',
  'DORA',
  'NIST AI RMF',
  'EU AI Act',
  'Interstellar Accord',
];

export interface PhaseTransitionConfig {
  sourcePhase: string;
  targetPhase: string;
  invariantMode: 'STRICT' | 'ADAPTIVE' | 'EMERGENCY';
  cryptoContinuity: 'FULL' | 'PARTIAL' | 'RESET';
  frameworks: string[];
  timelineMode: 'IMMEDIATE' | 'PHASED';
  timelineMonths: number;
  pillars: string[];
}

export interface OmegaGarDissolutionConfig {
  trigger: 'SCHEDULED' | 'EMERGENCY' | 'TREATY-MANDATED';
  targetEpoch: '2081' | '2085' | '2090' | '2095' | '2100+';
  epitaphOmegaActive: boolean;
  invocationOmegaActive: boolean;
  unifiedCodexSealed: boolean;
  successorSystem: string;
  eternalCorpusProtocol: 'ACTIVE' | 'STANDBY';
  beaconSignature: 'STANDARD' | 'ENHANCED' | 'INTERSTELLAR';
}

export interface SuccessorCodexConfig {
  targetCodexVersion: 'Codex v2.0' | 'Codex v3.0' | 'Codex v4.0' | 'Codex v5.0';
  migrationWindowMonths: number;
  fallbackThreshold: number;
  verificationMode: 'FORMAL' | 'HYBRID' | 'EMPIRICAL';
  autoSealInvariants: boolean;
  legacyQuarantine: boolean;
}

export interface InvariantStressConfig {
  targetScope: 'ALL' | 'CRITICAL' | 'CORE_PQC';
  stressLoadMultiplier: number;
  attackVector: 'QUANTUM_SPOOFING' | 'CONCURRENCY_FLAW' | 'BYZANTINE_SPLIT';
  durationHours: number;
  autoSafeguard: boolean;
}

export interface RegulatoryShiftConfig {
  targetRegime: 'EU-AI-ACT-V2' | 'US-FEDERAL-AI-ACCORD' | 'UN-GLOBAL-AI-TREATY' | 'SINGAPORE-FEAT-V3';
  gracePeriodMonths: number;
  crossBorderMode: 'STRICT' | 'HARMONIZED';
  penalizeGaps: boolean;
  agentRecalibration: 'AUTOMATIC' | 'MANUAL';
}

export interface InterstellarHandoffConfig {
  targetConstellation: 'CENTAURI-ALPHA' | 'SOL-OUTER-COLONIES' | 'DEEP-SPACE-RELAY';
  signalLatencyHours: number;
  quorumRatio: '51%' | '67%' | '75%' | '100%';
  lockoutYears: number;
  redundancyLevel: 'DUAL' | 'TRIPLE' | 'HEX';
}

export type ScenarioConfig =
  | { type: 'phase_transition'; config: PhaseTransitionConfig }
  | { type: 'omega_gar_dissolution'; config: OmegaGarDissolutionConfig }
  | { type: 'successor_codex'; config: SuccessorCodexConfig }
  | { type: 'invariant_stress_test'; config: InvariantStressConfig }
  | { type: 'regulatory_shift'; config: RegulatoryShiftConfig }
  | { type: 'interstellar_handoff'; config: InterstellarHandoffConfig };

export interface SimulationEvent {
  step: number;
  at: string;
  label: string;
  state: 'DONE' | 'PENDING' | 'ACTIVE' | 'FAILED';
  description: string;
}

export interface RiskTrajectoryStep {
  step: number;
  month: number;
  label: string;
  S_sys: number;
  G_SRI: number;
  C_SRI: number;
  p_doom: number;
}

export interface InvariantStepStatus {
  step: number;
  stepLabel: string;
  invariants: {
    id: string;
    name: string;
    status: 'VERIFIED' | 'ELEVATED' | 'SAFEGUARD' | 'DEGRADED' | 'VIOLATED';
  }[];
}

export interface ComplianceImpact {
  framework: string;
  prevScore: number;
  newScore: number;
  status: 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT' | 'DEGRADED';
  notes: string;
}

export interface SimulationResult {
  scenarioType: ScenarioTypeId;
  scenarioTitle: string;
  runTimestamp: string;
  outcomeScore: number;
  overallStatus: 'NOMINAL' | 'ELEVATED' | 'CRITICAL' | 'SAFEGUARD';
  summary: string;
  events: SimulationEvent[];
  riskTrajectories: RiskTrajectoryStep[];
  invariantStepStatuses: InvariantStepStatus[];
  complianceImpacts: ComplianceImpact[];
  recommendations: string[];
  reportTitle: string;
  reportAbstract: string;
  reportContent: string;
}

export interface ScenarioHistoryRun {
  id: string;
  scenarioType: ScenarioTypeId;
  scenarioTitle: string;
  paramsSummary: string;
  outcomeScore: number;
  overallStatus: 'NOMINAL' | 'ELEVATED' | 'CRITICAL' | 'SAFEGUARD';
  timestamp: string;
  config: ScenarioConfig;
  result: SimulationResult;
}

// Default initial configurations for each scenario
export const DEFAULT_PHASE_TRANSITION_CONFIG: PhaseTransitionConfig = {
  sourcePhase: 'VI-δ',
  targetPhase: 'VII',
  invariantMode: 'STRICT',
  cryptoContinuity: 'FULL',
  frameworks: ['Basel III/IV', 'Protocol SGR-028', 'CFE-1.0', 'ICGC/GASO Accords'],
  timelineMode: 'PHASED',
  timelineMonths: 24,
  pillars: ['IP-I', 'IP-II'],
};

export const DEFAULT_OMEGA_GAR_CONFIG: OmegaGarDissolutionConfig = {
  trigger: 'SCHEDULED',
  targetEpoch: '2081',
  epitaphOmegaActive: true,
  invocationOmegaActive: true,
  unifiedCodexSealed: true,
  successorSystem: 'Autonomous Post-Planetary Synthesis Mesh (APPS-01)',
  eternalCorpusProtocol: 'ACTIVE',
  beaconSignature: 'INTERSTELLAR',
};

export const DEFAULT_SUCCESSOR_CODEX_CONFIG: SuccessorCodexConfig = {
  targetCodexVersion: 'Codex v3.0',
  migrationWindowMonths: 18,
  fallbackThreshold: 0.25,
  verificationMode: 'FORMAL',
  autoSealInvariants: true,
  legacyQuarantine: true,
};

export const DEFAULT_INVARIANT_STRESS_CONFIG: InvariantStressConfig = {
  targetScope: 'ALL',
  stressLoadMultiplier: 2.5,
  attackVector: 'QUANTUM_SPOOFING',
  durationHours: 24,
  autoSafeguard: true,
};

export const DEFAULT_REGULATORY_SHIFT_CONFIG: RegulatoryShiftConfig = {
  targetRegime: 'UN-GLOBAL-AI-TREATY',
  gracePeriodMonths: 12,
  crossBorderMode: 'HARMONIZED',
  penalizeGaps: true,
  agentRecalibration: 'AUTOMATIC',
};

export const DEFAULT_INTERSTELLAR_HANDOFF_CONFIG: InterstellarHandoffConfig = {
  targetConstellation: 'CENTAURI-ALPHA',
  signalLatencyHours: 4.5,
  quorumRatio: '67%',
  lockoutYears: 25,
  redundancyLevel: 'TRIPLE',
};

// Pure Deterministic Simulator
export function runSimulation(scenarioConfig: ScenarioConfig): SimulationResult {
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

  if (scenarioConfig.type === 'phase_transition') {
    return simulatePhaseTransition(scenarioConfig.config, timestamp);
  } else if (scenarioConfig.type === 'omega_gar_dissolution') {
    return simulateOmegaGarDissolution(scenarioConfig.config, timestamp);
  } else if (scenarioConfig.type === 'successor_codex') {
    return simulateSuccessorCodex(scenarioConfig.config, timestamp);
  } else if (scenarioConfig.type === 'invariant_stress_test') {
    return simulateInvariantStressTest(scenarioConfig.config, timestamp);
  } else if (scenarioConfig.type === 'regulatory_shift') {
    return simulateRegulatoryShift(scenarioConfig.config, timestamp);
  } else {
    return simulateInterstellarHandoff(scenarioConfig.config, timestamp);
  }
}

function simulatePhaseTransition(cfg: PhaseTransitionConfig, timestamp: string): SimulationResult {
  let score = 82;
  if (cfg.invariantMode === 'STRICT') score += 10;
  else if (cfg.invariantMode === 'EMERGENCY') score -= 18;

  if (cfg.cryptoContinuity === 'FULL') score += 8;
  else if (cfg.cryptoContinuity === 'RESET') score -= 22;

  score += Math.min(10, cfg.frameworks.length * 1.5);
  score += Math.min(10, cfg.pillars.length * 1.5);

  if (cfg.timelineMode === 'IMMEDIATE' || cfg.timelineMonths < 6) score -= 12;

  score = Math.max(10, Math.min(99, Math.round(score)));

  const overallStatus: 'NOMINAL' | 'ELEVATED' | 'CRITICAL' | 'SAFEGUARD' =
    score >= 85 ? 'NOMINAL' : score >= 70 ? 'ELEVATED' : score >= 50 ? 'SAFEGUARD' : 'CRITICAL';

  const stepsCount = 10;
  const riskTrajectories: RiskTrajectoryStep[] = [];
  const totalMonths = cfg.timelineMonths;

  for (let i = 0; i < stepsCount; i++) {
    const month = Math.round((i / (stepsCount - 1)) * totalMonths);
    const progress = i / (stepsCount - 1);
    // Peak stress mid-transition
    const stressPeak = Math.sin(progress * Math.PI);
    const baseS = 0.31;
    const sDelta = cfg.invariantMode === 'EMERGENCY' ? 0.28 : cfg.invariantMode === 'ADAPTIVE' ? 0.12 : 0.05;
    const contMult = cfg.cryptoContinuity === 'RESET' ? 1.8 : cfg.cryptoContinuity === 'PARTIAL' ? 1.3 : 1.0;

    const sSys = +(baseS + stressPeak * sDelta * contMult).toFixed(3);
    const gSri = +(0.35 + stressPeak * 0.08 * contMult).toFixed(3);
    const cSri = +(0.32 + stressPeak * 0.11 * contMult).toFixed(3);
    const pDoom = +(0.02 + stressPeak * (cfg.invariantMode === 'EMERGENCY' ? 0.12 : 0.03)).toFixed(3);

    riskTrajectories.push({
      step: i + 1,
      month,
      label: `M${month}`,
      S_sys: Math.min(0.99, Math.max(0.05, sSys)),
      G_SRI: Math.min(0.99, Math.max(0.05, gSri)),
      C_SRI: Math.min(0.99, Math.max(0.05, cSri)),
      p_doom: Math.min(0.99, Math.max(0.001, pDoom)),
    });
  }

  const sampleInvariants = ['CI-001', 'CI-002', 'CI-003', 'CI-004', 'CI-005', 'CI-006', 'CI-012', 'CI-024'];
  const invariantStepStatuses: InvariantStepStatus[] = [];

  for (let i = 0; i < stepsCount; i++) {
    const month = Math.round((i / (stepsCount - 1)) * totalMonths);
    const progress = i / (stepsCount - 1);
    const isMid = progress > 0.2 && progress < 0.8;

    const stepInvs = sampleInvariants.map((id) => {
      let st: 'VERIFIED' | 'ELEVATED' | 'SAFEGUARD' | 'DEGRADED' | 'VIOLATED' = 'VERIFIED';
      if (isMid && cfg.invariantMode === 'EMERGENCY') {
        st = id === 'CI-002' || id === 'CI-004' ? 'SAFEGUARD' : 'ELEVATED';
      } else if (isMid && cfg.cryptoContinuity === 'RESET') {
        st = id === 'CI-001' || id === 'CI-003' ? 'DEGRADED' : 'ELEVATED';
      } else if (isMid && cfg.invariantMode === 'ADAPTIVE') {
        st = id === 'CI-005' ? 'ELEVATED' : 'VERIFIED';
      }
      return {
        id,
        name: `Invariant ${id}`,
        status: st,
      };
    });

    invariantStepStatuses.push({
      step: i + 1,
      stepLabel: `Step ${i + 1} (M${month})`,
      invariants: stepInvs,
    });
  }

  const events: SimulationEvent[] = [
    {
      step: 1,
      at: 'M0',
      label: `Initiate Phase Transition (${cfg.sourcePhase} → ${cfg.targetPhase})`,
      state: 'DONE',
      description: `Formal declaration of transition intent under ${cfg.invariantMode} preservation.`,
    },
    {
      step: 2,
      at: `M${Math.round(totalMonths * 0.2)}`,
      label: 'Cryptographic Ledger Mirroring',
      state: 'DONE',
      description: `State mirroring executed with ${cfg.cryptoContinuity} cryptographic continuity.`,
    },
    {
      step: 3,
      at: `M${Math.round(totalMonths * 0.5)}`,
      label: 'Mid-Transition Invariant Audit',
      state: overallStatus === 'CRITICAL' ? 'FAILED' : 'ACTIVE',
      description: `Subsystem verification across selected ${cfg.frameworks.length} compliance frameworks.`,
    },
    {
      step: 4,
      at: `M${Math.round(totalMonths * 0.8)}`,
      label: 'Pillar Alignment Verification',
      state: 'PENDING',
      description: `Readiness verification for pillars: ${cfg.pillars.join(', ')}.`,
    },
    {
      step: 5,
      at: `M${totalMonths}`,
      label: `Phase ${cfg.targetPhase} Activation Seal`,
      state: 'PENDING',
      description: `Final sealing of the new governance phase state root.`,
    },
  ];

  const complianceImpacts: ComplianceImpact[] = cfg.frameworks.map((fw) => {
    const baseScore = fw.includes('SGR-028') || fw.includes('CFE-1.0') ? 95 : 88;
    const delta =
      cfg.invariantMode === 'STRICT' && cfg.cryptoContinuity === 'FULL'
        ? +3
        : cfg.cryptoContinuity === 'RESET'
          ? -18
          : -5;
    const newScore = Math.max(40, Math.min(100, baseScore + delta));
    return {
      framework: fw,
      prevScore: baseScore,
      newScore,
      status: newScore >= 90 ? 'COMPLIANT' : newScore >= 75 ? 'PARTIAL' : 'DEGRADED',
      notes:
        newScore >= 90
          ? 'Full mapping preserved across phase boundary.'
          : 'Requires secondary attestation filing under SGR-028 §4.2.',
    };
  });

  const recommendations: string[] = [];
  if (cfg.invariantMode === 'STRICT' && cfg.cryptoContinuity === 'FULL') {
    recommendations.push('PROCEED: High-assurance transition path verified with strict invariant preservation.');
    recommendations.push('Maintain 24h PQC key rotation cadence during months 6-12 of transition.');
  } else {
    if (cfg.cryptoContinuity === 'RESET') {
      recommendations.push('CRITICAL: Cryptographic RESET will break cross-border historical attestation chains. Recommend Full state carryover.');
    }
    if (cfg.invariantMode === 'EMERGENCY') {
      recommendations.push('WARNING: Emergency mode relaxes invariant bounds. Trigger mandatory 72h supervisory board review.');
    }
    if (cfg.pillars.length < 3) {
      recommendations.push('RECOMMENDATION: Enable additional Infinity Pillars to buffer against systemic risk spikes.');
    }
  }

  const reportTitle = `REGULATOR REPORT: Governance Transition Arc ${cfg.sourcePhase} → ${cfg.targetPhase}`;
  const reportAbstract = `Simulation analysis for GIEN transition from Phase ${cfg.sourcePhase} to Phase ${cfg.targetPhase} over a ${cfg.timelineMonths}-month horizon under ${cfg.invariantMode} invariant mode and ${cfg.cryptoContinuity} cryptographic continuity. Overall calculated outcome score is ${score}/100 (${overallStatus}).`;
  const reportContent = `1. EXECUTIVE SUMMARY: Transition arc evaluation indicates a composite systemic risk trajectory peaking at S_sys=${Math.max(...riskTrajectories.map((r) => r.S_sys))} during mid-transition.
2. INVARIANT INTEGRITY: Strict verification was simulated for 24 constitutional invariants. Invariant mode set to ${cfg.invariantMode} with ${cfg.cryptoContinuity} crypto state carryover.
3. COMPLIANCE ASSESSMENT: Framework compliance spans ${cfg.frameworks.join(', ')}. Average post-transition framework compliance is ${Math.round(complianceImpacts.reduce((acc, c) => acc + c.newScore, 0) / (complianceImpacts.length || 1))}%.
4. REGULATORY ACTION ITEM: File formal transition notice under Protocol SGR-028 prior to M0 execution.`;

  return {
    scenarioType: 'phase_transition',
    scenarioTitle: 'Governance Phase Transition',
    runTimestamp: timestamp,
    outcomeScore: score,
    overallStatus,
    summary: `Transition from ${cfg.sourcePhase} to ${cfg.targetPhase} (${cfg.timelineMonths} months, ${cfg.invariantMode} mode, ${cfg.cryptoContinuity} continuity). Calculated risk score: ${score}/100.`,
    events,
    riskTrajectories,
    invariantStepStatuses,
    complianceImpacts,
    recommendations,
    reportTitle,
    reportAbstract,
    reportContent,
  };
}

function simulateOmegaGarDissolution(cfg: OmegaGarDissolutionConfig, timestamp: string): SimulationResult {
  let score = 90;
  if (cfg.trigger === 'EMERGENCY') score -= 25;
  if (!cfg.epitaphOmegaActive) score -= 15;
  if (!cfg.invocationOmegaActive) score -= 15;
  if (!cfg.unifiedCodexSealed) score -= 10;
  if (cfg.beaconSignature === 'STANDARD') score -= 10;
  if (cfg.eternalCorpusProtocol === 'STANDBY') score -= 12;

  score = Math.max(15, Math.min(99, Math.round(score)));

  const overallStatus: 'NOMINAL' | 'ELEVATED' | 'CRITICAL' | 'SAFEGUARD' =
    score >= 85 ? 'NOMINAL' : score >= 70 ? 'ELEVATED' : score >= 50 ? 'SAFEGUARD' : 'CRITICAL';

  const riskTrajectories: RiskTrajectoryStep[] = Array.from({ length: 10 }).map((_, i) => {
    const year = 2081 + i * 2;
    const progress = i / 9;
    const sSys = +(0.25 + progress * (cfg.trigger === 'EMERGENCY' ? 0.45 : 0.08)).toFixed(3);
    const gSri = +(0.28 + progress * (cfg.trigger === 'EMERGENCY' ? 0.35 : 0.06)).toFixed(3);
    const cSri = +(0.22 + progress * 0.05).toFixed(3);
    const pDoom = +(0.01 + progress * (cfg.trigger === 'EMERGENCY' ? 0.15 : 0.01)).toFixed(3);
    return {
      step: i + 1,
      month: i * 24,
      label: `${year}`,
      S_sys: Math.min(0.99, sSys),
      G_SRI: Math.min(0.99, gSri),
      C_SRI: Math.min(0.99, cSri),
      p_doom: Math.min(0.99, pDoom),
    };
  });

  const sampleInvariants = ['CI-001', 'CI-002', 'CI-018', 'CI-022', 'CI-023', 'CI-024'];
  const invariantStepStatuses: InvariantStepStatus[] = Array.from({ length: 10 }).map((_, i) => {
    const year = 2081 + i * 2;
    const invs = sampleInvariants.map((id) => ({
      id,
      name: `Invariant ${id}`,
      status: id === 'CI-024' ? ('SEALED' as any) : cfg.trigger === 'EMERGENCY' ? 'ELEVATED' : 'VERIFIED',
    }));
    return {
      step: i + 1,
      stepLabel: `Epoch ${year}`,
      invariants: invs as any,
    };
  });

  const events: SimulationEvent[] = [
    { step: 1, at: '2081-Q1', label: 'GIEN-EPITAPH-OMEGA Activation', state: 'DONE', description: 'Initiation of controlled dissolution arc.' },
    { step: 2, at: '2081-Q3', label: 'UNIFIED-CODEX-OMEGA Sealing', state: cfg.unifiedCodexSealed ? 'DONE' : 'FAILED', description: 'Immutable state archive sealed.' },
    { step: 3, at: '2082-Q2', label: 'GIEN-INVOCATION-OMEGA Execution', state: cfg.invocationOmegaActive ? 'DONE' : 'PENDING', description: 'Orderly transfer of governance authority.' },
    { step: 4, at: '2083-Q1', label: `Handoff to ${cfg.successorSystem}`, state: 'ACTIVE', description: 'Successor system validation and boot.' },
    { step: 5, at: '2085-Q4', label: 'Eternal Corpus Interstellar Beacon Emission', state: 'PENDING', description: `Beacon broadcast with ${cfg.beaconSignature} signature.` },
  ];

  const complianceImpacts: ComplianceImpact[] = [
    { framework: 'CFE-1.0', prevScore: 98, newScore: cfg.unifiedCodexSealed ? 100 : 70, status: cfg.unifiedCodexSealed ? 'COMPLIANT' : 'PARTIAL', notes: 'Final dissolution article §12 fulfilled.' },
    { framework: 'Interstellar Accord', prevScore: 90, newScore: cfg.beaconSignature === 'INTERSTELLAR' ? 98 : 82, status: 'COMPLIANT', notes: 'Beacon transmission parameters verified.' },
  ];

  const recommendations = [
    cfg.trigger === 'SCHEDULED'
      ? 'PROCEED: Orderly Ω-GAR dissolution arc parameters validated.'
      : 'WARNING: Emergency trigger bypasses standard 10-year dissolution buffer.',
    `Ensure Eternal Corpus Transmission Protocol (${cfg.eternalCorpusProtocol}) has triply redundant space relays active.`,
  ];

  return {
    scenarioType: 'omega_gar_dissolution',
    scenarioTitle: 'Ω-GAR Dissolution Arc',
    runTimestamp: timestamp,
    outcomeScore: score,
    overallStatus,
    summary: `Ω-GAR Dissolution Arc under ${cfg.trigger} trigger into target epoch ${cfg.targetEpoch}. Handoff to: ${cfg.successorSystem}. Calculated outcome score: ${score}/100.`,
    events,
    riskTrajectories,
    invariantStepStatuses,
    complianceImpacts,
    recommendations,
    reportTitle: `REGULATOR REPORT: Terminal Horizon Ω-GAR Dissolution Arc (${cfg.targetEpoch})`,
    reportAbstract: `Controlled terminal dissolution simulation for GIEN governance arc into ${cfg.successorSystem}. Eternal Corpus status: ${cfg.eternalCorpusProtocol}, Beacon signature: ${cfg.beaconSignature}.`,
    reportContent: `1. TERMINAL DISSOLUTION PROTOCOL: GIEN-EPITAPH-OMEGA status = ${cfg.epitaphOmegaActive}, GIEN-INVOCATION-OMEGA status = ${cfg.invocationOmegaActive}.
2. SUCCESSOR SYSTEM: Handoff target confirmed as "${cfg.successorSystem}". State preservation proof hash: ${truncateHash(fakeHash(cfg.successorSystem), 12, 8)}.
3. BEACON AND TRANSMISSION: Beacon signature format ${cfg.beaconSignature} deployed across solar and interstellar relay arrays.`,
  };
}

function simulateSuccessorCodex(cfg: SuccessorCodexConfig, timestamp: string): SimulationResult {
  let score = 86;
  if (cfg.verificationMode === 'FORMAL') score += 8;
  if (cfg.autoSealInvariants) score += 5;
  if (cfg.migrationWindowMonths < 6) score -= 15;

  score = Math.max(20, Math.min(99, Math.round(score)));
  const overallStatus = score >= 85 ? 'NOMINAL' : score >= 70 ? 'ELEVATED' : 'SAFEGUARD';

  const riskTrajectories: RiskTrajectoryStep[] = Array.from({ length: 8 }).map((_, i) => ({
    step: i + 1,
    month: Math.round((i / 7) * cfg.migrationWindowMonths),
    label: `M${Math.round((i / 7) * cfg.migrationWindowMonths)}`,
    S_sys: +(0.28 + Math.sin((i / 7) * Math.PI) * 0.12).toFixed(3),
    G_SRI: +(0.31 + Math.sin((i / 7) * Math.PI) * 0.08).toFixed(3),
    C_SRI: +(0.25 + Math.sin((i / 7) * Math.PI) * 0.06).toFixed(3),
    p_doom: +(0.015 + Math.sin((i / 7) * Math.PI) * 0.02).toFixed(3),
  }));

  const sampleInvariants = ['CI-001', 'CI-002', 'CI-003', 'CI-010'];
  const invariantStepStatuses: InvariantStepStatus[] = Array.from({ length: 8 }).map((_, i) => ({
    step: i + 1,
    stepLabel: `Step ${i + 1}`,
    invariants: sampleInvariants.map((id) => ({ id, name: `Invariant ${id}`, status: 'VERIFIED' })),
  }));

  return {
    scenarioType: 'successor_codex',
    scenarioTitle: 'Successor Epoch Codex Activation',
    runTimestamp: timestamp,
    outcomeScore: score,
    overallStatus,
    summary: `Activation of ${cfg.targetCodexVersion} over ${cfg.migrationWindowMonths} months using ${cfg.verificationMode} verification. Outcome score: ${score}/100.`,
    events: [
      { step: 1, at: 'M0', label: `Codex Spec Loading (${cfg.targetCodexVersion})`, state: 'DONE', description: 'Compilation of successor syntax trees.' },
      { step: 2, at: `M${Math.round(cfg.migrationWindowMonths / 2)}`, label: 'Invariants Auto-Sealing', state: 'ACTIVE', description: 'Verifying invariant preservation contracts.' },
      { step: 3, at: `M${cfg.migrationWindowMonths}`, label: 'Codex Activation Complete', state: 'PENDING', description: 'Promoting successor codex to primary.' },
    ],
    riskTrajectories,
    invariantStepStatuses,
    complianceImpacts: [
      { framework: 'CFE-1.0', prevScore: 92, newScore: 96, status: 'COMPLIANT', notes: 'Codex compatibility verified.' },
    ],
    recommendations: [
      'PROCEED: Formal verification mode guarantees invariant equivalence.',
      'Maintain legacy data quarantine filters for 12 months post-activation.',
    ],
    reportTitle: `REGULATOR REPORT: Successor Epoch Codex Activation (${cfg.targetCodexVersion})`,
    reportAbstract: `Structural codex migration evaluation for transition to ${cfg.targetCodexVersion} under ${cfg.verificationMode} verification mode.`,
    reportContent: `1. CODEX VERIFICATION: All rule sets formally compiled with 0 type errors.
2. LEGACY QUARANTINE: ${cfg.legacyQuarantine ? 'ACTIVE' : 'INACTIVE'} - isolates pre-migration state inconsistencies.`,
  };
}

function simulateInvariantStressTest(cfg: InvariantStressConfig, timestamp: string): SimulationResult {
  const loadPenalty = (cfg.stressLoadMultiplier - 1) * 15;
  let score = Math.round(92 - loadPenalty);
  if (cfg.autoSafeguard) score += 8;
  score = Math.max(10, Math.min(98, score));

  const overallStatus = score >= 80 ? 'NOMINAL' : score >= 60 ? 'ELEVATED' : 'SAFEGUARD';

  const riskTrajectories: RiskTrajectoryStep[] = Array.from({ length: 8 }).map((_, i) => {
    const hr = Math.round((i / 7) * cfg.durationHours);
    const stress = Math.sin((i / 7) * Math.PI) * (cfg.stressLoadMultiplier * 0.15);
    return {
      step: i + 1,
      month: hr,
      label: `T+${hr}h`,
      S_sys: +(0.30 + stress).toFixed(3),
      G_SRI: +(0.33 + stress * 0.8).toFixed(3),
      C_SRI: +(0.29 + stress * 1.1).toFixed(3),
      p_doom: +(0.02 + stress * 0.25).toFixed(3),
    };
  });

  const sampleInvariants = ['CI-001', 'CI-002', 'CI-003', 'CI-004', 'CI-005'];
  const invariantStepStatuses: InvariantStepStatus[] = Array.from({ length: 8 }).map((_, i) => {
    const hr = Math.round((i / 7) * cfg.durationHours);
    const isPeak = i >= 3 && i <= 5;
    return {
      step: i + 1,
      stepLabel: `T+${hr}h`,
      invariants: sampleInvariants.map((id) => ({
        id,
        name: `Invariant ${id}`,
        status: isPeak ? (cfg.autoSafeguard ? 'SAFEGUARD' : 'ELEVATED') : 'VERIFIED',
      })),
    };
  });

  return {
    scenarioType: 'invariant_stress_test',
    scenarioTitle: 'Constitutional Invariant Stress Test',
    runTimestamp: timestamp,
    outcomeScore: score,
    overallStatus,
    summary: `Adversarial stress test (${cfg.attackVector} at ${cfg.stressLoadMultiplier}x load over ${cfg.durationHours}h). Outcome score: ${score}/100.`,
    events: [
      { step: 1, at: 'T+00h', label: `Inject ${cfg.attackVector} Load`, state: 'DONE', description: `Simulating ${cfg.stressLoadMultiplier}x nominal stress.` },
      { step: 2, at: `T+${Math.round(cfg.durationHours / 2)}h`, label: 'Peak Load Invariant Audit', state: 'ACTIVE', description: 'Checking TLA+ state property bounds.' },
      { step: 3, at: `T+${cfg.durationHours}h`, label: 'Stress Injection Teardown', state: 'PENDING', description: 'Restoring nominal operational parameters.' },
    ],
    riskTrajectories,
    invariantStepStatuses,
    complianceImpacts: [
      { framework: 'Protocol SGR-028', prevScore: 94, newScore: score >= 70 ? 92 : 78, status: score >= 70 ? 'COMPLIANT' : 'PARTIAL', notes: 'Resilience under adversarial injection verified.' },
    ],
    recommendations: [
      `Maintain auto-safeguard engagement (${cfg.autoSafeguard ? 'ENABLED' : 'DISABLED'}).`,
      `Adjust quantum key refresh frequency under ${cfg.attackVector} threat models.`,
    ],
    reportTitle: `REGULATOR REPORT: Invariant Stress Loading (${cfg.attackVector})`,
    reportAbstract: `High-stress resilience analysis subjected to ${cfg.stressLoadMultiplier}x multiplier for ${cfg.durationHours} hours.`,
    reportContent: `1. ATTACK MODEL: Simulated ${cfg.attackVector} vector across ${cfg.targetScope} invariant set.
2. SAFEGUARD RESPONSE: System automatic safeguard engagement status = ${cfg.autoSafeguard}. Minimum safety margin preserved.`,
  };
}

function simulateRegulatoryShift(cfg: RegulatoryShiftConfig, timestamp: string): SimulationResult {
  let score = 88;
  if (cfg.crossBorderMode === 'HARMONIZED') score += 6;
  if (cfg.agentRecalibration === 'AUTOMATIC') score += 4;
  if (cfg.gracePeriodMonths < 6) score -= 12;

  score = Math.max(30, Math.min(99, score));
  const overallStatus = score >= 85 ? 'NOMINAL' : score >= 70 ? 'ELEVATED' : 'PARTIAL' as any;

  const riskTrajectories: RiskTrajectoryStep[] = Array.from({ length: 8 }).map((_, i) => ({
    step: i + 1,
    month: Math.round((i / 7) * cfg.gracePeriodMonths),
    label: `M${Math.round((i / 7) * cfg.gracePeriodMonths)}`,
    S_sys: +(0.31 - (i / 7) * 0.05).toFixed(3),
    G_SRI: +(0.35 - (i / 7) * 0.06).toFixed(3),
    C_SRI: +(0.28 - (i / 7) * 0.04).toFixed(3),
    p_doom: +(0.018 - (i / 7) * 0.005).toFixed(3),
  }));

  const sampleInvariants = ['CI-001', 'CI-003', 'CI-007', 'CI-015'];
  const invariantStepStatuses: InvariantStepStatus[] = Array.from({ length: 8 }).map((_, i) => ({
    step: i + 1,
    stepLabel: `Step ${i + 1}`,
    invariants: sampleInvariants.map((id) => ({ id, name: `Invariant ${id}`, status: 'VERIFIED' })),
  }));

  return {
    scenarioType: 'regulatory_shift',
    scenarioTitle: 'Regulatory Regime Shift',
    runTimestamp: timestamp,
    outcomeScore: score,
    overallStatus: overallStatus === 'PARTIAL' ? 'ELEVATED' : overallStatus,
    summary: `Shift to ${cfg.targetRegime} over ${cfg.gracePeriodMonths} months (${cfg.crossBorderMode} mode). Outcome score: ${score}/100.`,
    events: [
      { step: 1, at: 'M0', label: `Ratify Treaty (${cfg.targetRegime})`, state: 'DONE', description: 'Jurisdictional consensus agreement.' },
      { step: 2, at: `M${cfg.gracePeriodMonths}`, label: 'Full Enforcement Milestone', state: 'PENDING', description: 'Mandatory compliance auditing.' },
    ],
    riskTrajectories,
    invariantStepStatuses,
    complianceImpacts: [
      { framework: cfg.targetRegime, prevScore: 70, newScore: 98, status: 'COMPLIANT', notes: 'Harmonized across all signatory jurisdictions.' },
    ],
    recommendations: [
      'PROCEED: Regulatory regime shift meets all cross-border equivalence standards.',
      'Schedule quarterly supervisory agent recalibrations.',
    ],
    reportTitle: `REGULATOR REPORT: Supranational Regulatory Shift (${cfg.targetRegime})`,
    reportAbstract: `Harmonization roadmap and compliance assessment for ${cfg.targetRegime} over a ${cfg.gracePeriodMonths}-month transition grace period.`,
    reportContent: `1. CROSS-BORDER HARMONIZATION: ${cfg.crossBorderMode} mode ensures seamless regulatory mapping.
2. AGENT RECALIBRATION: Supervisory agent recalibration mode set to ${cfg.agentRecalibration}.`,
  };
}

function simulateInterstellarHandoff(cfg: InterstellarHandoffConfig, timestamp: string): SimulationResult {
  let score = 84;
  if (cfg.redundancyLevel === 'HEX') score += 10;
  else if (cfg.redundancyLevel === 'TRIPLE') score += 5;
  if (cfg.signalLatencyHours > 24) score -= 10;

  score = Math.max(25, Math.min(99, score));
  const overallStatus = score >= 85 ? 'NOMINAL' : score >= 70 ? 'ELEVATED' : 'SAFEGUARD';

  const riskTrajectories: RiskTrajectoryStep[] = Array.from({ length: 8 }).map((_, i) => ({
    step: i + 1,
    month: i * 3,
    label: `T+${i * 3}m`,
    S_sys: +(0.29 + Math.sin(i) * 0.03).toFixed(3),
    G_SRI: +(0.32 + Math.cos(i) * 0.02).toFixed(3),
    C_SRI: +(0.26 + Math.sin(i * 0.5) * 0.03).toFixed(3),
    p_doom: 0.012,
  }));

  const sampleInvariants = ['CI-001', 'CI-002', 'CI-020', 'CI-021'];
  const invariantStepStatuses: InvariantStepStatus[] = Array.from({ length: 8 }).map((_, i) => ({
    step: i + 1,
    stepLabel: `Month ${i * 3}`,
    invariants: sampleInvariants.map((id) => ({ id, name: `Invariant ${id}`, status: 'VERIFIED' })),
  }));

  return {
    scenarioType: 'interstellar_handoff',
    scenarioTitle: 'Interstellar Governance Handoff',
    runTimestamp: timestamp,
    outcomeScore: score,
    overallStatus,
    summary: `Delay-tolerant consensus for ${cfg.targetConstellation} (latency ${cfg.signalLatencyHours}h, quorum ${cfg.quorumRatio}). Outcome score: ${score}/100.`,
    events: [
      { step: 1, at: 'T+0.0h', label: `Transmit Quorum Intent to ${cfg.targetConstellation}`, state: 'DONE', description: 'Laser array pulse broadcast.' },
      { step: 2, at: `T+${cfg.signalLatencyHours * 2}h`, label: 'Receive Two-Way Signal Return', state: 'ACTIVE', description: 'Confirmation of state attestation received.' },
    ],
    riskTrajectories,
    invariantStepStatuses,
    complianceImpacts: [
      { framework: 'Interstellar Accord', prevScore: 88, newScore: 95, status: 'COMPLIANT', notes: 'Delay-tolerant consensus verified.' },
    ],
    recommendations: [
      `Maintain ${cfg.redundancyLevel} redundancy level for light-speed delayed state channels.`,
      `Set automatic local consensus lockout buffer to ${cfg.lockoutYears} years.`,
    ],
    reportTitle: `REGULATOR REPORT: Interstellar Governance Handoff (${cfg.targetConstellation})`,
    reportAbstract: `Delay-tolerant consensus and state sync simulation for deep-space constellation ${cfg.targetConstellation}.`,
    reportContent: `1. SIGNAL LATENCY: Round-trip delay calculated at ${(cfg.signalLatencyHours * 2).toFixed(1)} hours.
2. QUORUM THRESHOLD: Interstellar quorum threshold verified at ${cfg.quorumRatio} with ${cfg.redundancyLevel} channel redundancy.`,
  };
}

// Fictional Prior Runs History
export const DEFAULT_PRIOR_RUNS: ScenarioHistoryRun[] = [
  {
    id: 'RUN-2026-10-09-001',
    scenarioType: 'phase_transition',
    scenarioTitle: 'Governance Phase Transition',
    paramsSummary: 'VI-δ → VII (24 mo, STRICT mode, FULL crypto continuity)',
    outcomeScore: 94,
    overallStatus: 'NOMINAL',
    timestamp: '2026-10-09T18:30:00Z',
    config: {
      type: 'phase_transition',
      config: DEFAULT_PHASE_TRANSITION_CONFIG,
    },
    result: runSimulation({ type: 'phase_transition', config: DEFAULT_PHASE_TRANSITION_CONFIG }),
  },
  {
    id: 'RUN-2026-10-08-002',
    scenarioType: 'omega_gar_dissolution',
    scenarioTitle: 'Ω-GAR Dissolution Arc',
    paramsSummary: 'SCHEDULED trigger, Epoch 2081, APPS-01 successor',
    outcomeScore: 89,
    overallStatus: 'NOMINAL',
    timestamp: '2026-10-08T14:15:00Z',
    config: {
      type: 'omega_gar_dissolution',
      config: DEFAULT_OMEGA_GAR_CONFIG,
    },
    result: runSimulation({ type: 'omega_gar_dissolution', config: DEFAULT_OMEGA_GAR_CONFIG }),
  },
  {
    id: 'RUN-2026-10-07-003',
    scenarioType: 'invariant_stress_test',
    scenarioTitle: 'Constitutional Invariant Stress Test',
    paramsSummary: 'QUANTUM_SPOOFING (3.5x load, 24h duration)',
    outcomeScore: 68,
    overallStatus: 'ELEVATED',
    timestamp: '2026-10-07T09:45:00Z',
    config: {
      type: 'invariant_stress_test',
      config: {
        ...DEFAULT_INVARIANT_STRESS_CONFIG,
        stressLoadMultiplier: 3.5,
      },
    },
    result: runSimulation({
      type: 'invariant_stress_test',
      config: {
        ...DEFAULT_INVARIANT_STRESS_CONFIG,
        stressLoadMultiplier: 3.5,
      },
    }),
  },
];
