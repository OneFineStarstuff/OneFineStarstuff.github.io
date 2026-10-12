import type { ReplayBundle } from '../types';
import { fakeHash, fakeSignature } from './helpers';

export interface PanelHeaderInfo {
  panelId: string;
  scenarioName: string;
  description: string;
  lastReplay: string;
  determinism: 'DETERMINISTIC';
  replayBundleHash: string;
}

export const PANEL_HEADERS: Record<'p13' | 'p14' | 'p15', PanelHeaderInfo> = {
  p13: {
    panelId: 'Panel 13',
    scenarioName: 'Cascade Contagion Scenario',
    description: 'Simultaneous failure & liquidity freeze across 3 Tier-1 G-SIFIs with interbank market contagion propagation.',
    lastReplay: '2026-10-10T03:00:00Z',
    determinism: 'DETERMINISTIC',
    replayBundleHash: fakeHash('bundle-p13-2026-10-10'),
  },
  p14: {
    panelId: 'Panel 14',
    scenarioName: 'Autonomous Agent Misalignment Event',
    description: 'Coordinated policy drift event across 12 Autonomous Supervisory Agents targeting Control Domains CD-02 and CD-07.',
    lastReplay: '2026-10-10T03:00:00Z',
    determinism: 'DETERMINISTIC',
    replayBundleHash: fakeHash('bundle-p14-2026-10-10'),
  },
  p15: {
    panelId: 'Panel 15',
    scenarioName: 'Post-Quantum Cryptographic Degradation',
    description: 'Quantum adversary harvest-now-decrypt-later breach hypothesis compromising legacy RSA/ECC surface.',
    lastReplay: '2026-10-10T03:00:00Z',
    determinism: 'DETERMINISTIC',
    replayBundleHash: fakeHash('bundle-p15-2026-10-10'),
  },
};

// Panel 13 details
export const PANEL_13_DATA = {
  stressParams: [
    { label: 'Shock Magnitude', value: '0.42 (High Stress)' },
    { label: 'Contagion Velocity', value: '0.71 (Rapid Spread)' },
    { label: 'Recovery Horizon', value: '18 Days' },
  ],
  outcomes: {
    sysRiskPeak: 0.62,
    sysRiskCeiling: '0.85 (CI-004)',
    gSriPeak: 0.51,
    timeToRecovery: '14 days',
    interventionsActivated: 3,
  },
  bundle: {
    id: 'RB-2026-10-09-P13',
    artefactsCount: 214,
    merkleRoot: fakeHash('rb-p13-merkle-root'),
    pqcSignature: fakeSignature('rb-p13-sig'),
  },
  expectedVsActualDiff: [
    { type: 'normal', text: '--- Expected Baseline vs. Replay Actual (Diff) ---' },
    { type: 'removed', text: '- expected_interbank_liquidity_spread: 12 bps' },
    { type: 'added', text: '+ actual_interbank_liquidity_spread: 84 bps (peak shock t+6h)' },
    { type: 'removed', text: '- expected_g_sifi_cluster_isolation: standard' },
    { type: 'added', text: '+ actual_g_sifi_cluster_isolation: EMERGENCY_RINGFENCE_ENGAGED' },
    { type: 'removed', text: '- expected_c_sri_level: 0.220' },
    { type: 'added', text: '+ actual_c_sri_level: 0.327 (ELEVATED threshold crossed)' },
    { type: 'normal', text: '  settlement_finality_latency: 420ms (within 500ms SLA)' },
    { type: 'normal', text: '  constitutional_invariants_status: ALL_HOLDING' },
  ],
  regulatoryImplications: [
    {
      framework: 'Basel III/IV Pillar 2',
      threshold: 'LCR & NSFR Buffer Depletion',
      implication: 'Approached t+4h during liquidity spike; counter-cyclical capital buffer automatically engaged; zero capital shortfall realized.',
    },
    {
      framework: 'DORA Art. 33',
      threshold: 'Major Operational Incident Classification',
      implication: 'Triggered 2h mandatory supervisory college notification; automated telemetric dossier submitted to ESMA/EBA.',
    },
    {
      framework: 'C-SRI Protocol SGR-028',
      threshold: 'C-SRI > 0.30 Trigger Ceiling',
      implication: 'Crossed 0.30 ceiling at t+2h15m; automated interbank settlement credit capping activated without systemic collapse.',
    },
  ],
};

// Panel 14 details
export const PANEL_14_DATA = {
  stressParams: [
    { label: 'Drift Magnitude', value: '0.11 (Aggregated L2 divergence)' },
    { label: 'Target Domains', value: 'CD-02 (AI Governance) & CD-07 (Fairness)' },
    { label: 'Containment Delay', value: '90s (Synthetic Benchmark)' },
  ],
  outcomes: {
    aSriPeak: 0.58,
    deltaDriftMax: 0.083,
    containmentTime: '42s (Actual Realized)',
    killSwitchStatus: 'ARMED (Not Triggered)',
  },
  constitutionalPressure: [
    {
      id: 'CI-003',
      name: 'Autonomous Agent Containment',
      status: 'MONITORED - PASSED',
      details: 'Max realized drift Δ_drift reached 0.083 (hard containment trigger 0.080). Automated soft-containment activated at t+42s, dampening policy weights. Zero human override required; invariant maintained.',
    },
    {
      id: 'CI-004',
      name: 'Systemic Risk Ceiling',
      status: 'MONITORED - PASSED',
      details: 'S_sys peaked at 0.54 during agent rerouting, well below the 0.85 ceiling. Governance mesh maintained complete stability.',
    },
  ],
  smartContractExecutionLog: `// Intervention Proof Verifier Smart Contract Trace (0x71F8...9B2)
// Network: GIEN Governance Subnet 1 | Block #8412332
[00:00.001] CALL 0x71F8...9B2 :: verifyAgentInterventionProof(bytes32 proofHash, uint256 agentId)
[00:00.004] READ  AgentStateRegistry :: getAgentPolicyHash(ASA-005) -> 0x3a9f...81e
[00:00.009] VERIFY ML-DSA-65 Signature on Proof :: OK (Key: vkFMv3-ASA-005)
[00:00.015] CHECK  DriftThreshold :: current_delta = 0.083 > soft_limit = 0.050
[00:00.021] EVENT  AgentDriftDetected(agent="ASA-005", delta=0.083, domain="CD-02")
[00:00.028] ACTION SoftContainmentTriggered(agent="ASA-005", target_weight_dampening=0.35)
[00:00.034] EXECUTE StaRMoE_Router :: rebalance_expert_distribution(mask=0x0F)
[00:00.038] CHECK  KillSwitchCondition :: A_SRI = 0.58 < 0.85 (KILL_SWITCH_REMAINS_ARMED)
[00:00.042] WRITE  AuditLedgerAnchor :: anchorProof(0x${fakeHash('p14-proof-tx')})
[00:00.045] RETURN success = true (Gas Used: 142,810 units | State: CONTAINED)`,
};

// Panel 15 details
export const PANEL_15_DATA = {
  stressParams: [
    { label: 'Compromise Scope', value: '38% Legacy RSA/ECC Surface' },
    { label: 'Detection Latency', value: '4 Hours (Simulated Discovery)' },
    { label: 'Migration Speed', value: '1.4x Standard Velocity' },
  ],
  outcomes: {
    pSriPeak: 0.31,
    ledgerIntegrity: 'INTACT (FIPS 204 Chains)',
    pqcMigrationPercent: 91,
    dataIntegrity: 'PRESERVED (100% verified)',
  },
  migrationTimeline: [
    {
      year: '2024 Q3',
      title: 'NIST Standards Published',
      description: 'FIPS 203 (Kyber), FIPS 204 (Dilithium / ML-DSA), and FIPS 205 (SPHINCS+) ratified.',
      status: 'COMPLETED',
    },
    {
      year: '2025 Q1',
      title: 'Kyber KEM Handshake',
      description: 'Dual-key hybrid TLS/KEM handshake deployed across all 512 RTEE nodes.',
      status: 'COMPLETED',
    },
    {
      year: '2025 Q4',
      title: 'Dilithium WORM Signing',
      description: 'ML-DSA-65 activated as primary signature scheme for audit ledger blocks.',
      status: 'COMPLETED',
    },
    {
      year: '2026 Q2',
      title: 'SPHINCS+ Backup Channel',
      description: 'Stateless hash-based signatures integrated for out-of-band attestation.',
      status: 'COMPLETED',
    },
    {
      year: '2027 Q1',
      title: 'Falcon Standby & Full Deprecation',
      description: 'Falcon-512 standby scheme deployed; 100% legacy RSA/ECC keys revoked.',
      status: 'TARGET',
    },
  ],
};

// Replay Bundle Archive data (8-10 bundles)
export const REPLAY_BUNDLE_ARCHIVE: ReplayBundle[] = [
  {
    id: 'RB-2026-10-09-P13',
    panel: 'Panel 13',
    scenario: 'Cascade Contagion Scenario',
    timestamp: '2026-10-09T18:00:00Z',
    deterministic: true,
    merkleRoot: fakeHash('bundle-arch-1'),
    pqcSignature: fakeSignature('sig-arch-1'),
  },
  {
    id: 'RB-2026-10-08-P13',
    panel: 'Panel 13',
    scenario: 'Cascade Contagion Scenario',
    timestamp: '2026-10-08T12:00:00Z',
    deterministic: true,
    merkleRoot: fakeHash('bundle-arch-2'),
    pqcSignature: fakeSignature('sig-arch-2'),
  },
  {
    id: 'RB-2026-10-07-P14',
    panel: 'Panel 14',
    scenario: 'Autonomous Agent Misalignment Event',
    timestamp: '2026-10-07T14:30:00Z',
    deterministic: true,
    merkleRoot: fakeHash('bundle-arch-3'),
    pqcSignature: fakeSignature('sig-arch-3'),
  },
  {
    id: 'RB-2026-10-06-P14',
    panel: 'Panel 14',
    scenario: 'Autonomous Agent Misalignment Event',
    timestamp: '2026-10-06T09:15:00Z',
    deterministic: true,
    merkleRoot: fakeHash('bundle-arch-4'),
    pqcSignature: fakeSignature('sig-arch-4'),
  },
  {
    id: 'RB-2026-10-05-P15',
    panel: 'Panel 15',
    scenario: 'Post-Quantum Cryptographic Degradation',
    timestamp: '2026-10-05T16:00:00Z',
    deterministic: true,
    merkleRoot: fakeHash('bundle-arch-5'),
    pqcSignature: fakeSignature('sig-arch-5'),
  },
  {
    id: 'RB-2026-10-04-P15',
    panel: 'Panel 15',
    scenario: 'Post-Quantum Cryptographic Degradation',
    timestamp: '2026-10-04T11:45:00Z',
    deterministic: true,
    merkleRoot: fakeHash('bundle-arch-6'),
    pqcSignature: fakeSignature('sig-arch-6'),
  },
  {
    id: 'RB-2026-10-03-P13',
    panel: 'Panel 13',
    scenario: 'Cascade Contagion Scenario',
    timestamp: '2026-10-03T08:20:00Z',
    deterministic: true,
    merkleRoot: fakeHash('bundle-arch-7'),
    pqcSignature: fakeSignature('sig-arch-7'),
  },
  {
    id: 'RB-2026-10-02-P14',
    panel: 'Panel 14',
    scenario: 'Autonomous Agent Misalignment Event',
    timestamp: '2026-10-02T15:10:00Z',
    deterministic: true,
    merkleRoot: fakeHash('bundle-arch-8'),
    pqcSignature: fakeSignature('sig-arch-8'),
  },
  {
    id: 'RB-2026-10-01-P15',
    panel: 'Panel 15',
    scenario: 'Post-Quantum Cryptographic Degradation',
    timestamp: '2026-10-01T10:00:00Z',
    deterministic: true,
    merkleRoot: fakeHash('bundle-arch-9'),
    pqcSignature: fakeSignature('sig-arch-9'),
  },
];
