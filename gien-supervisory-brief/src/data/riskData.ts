import { RISK_INDICES } from './gienData';
import type { GraphNode, GraphEdge } from '../components/NodeGraph';

export interface AgentAttestationDetails {
  agentId: string;
  policyHash: string;
  pqcSignature: string;
  attestationEpoch: string;
  attestationProof: string;
  telemetryLogs: string[];
}

export const RISK_CORRELATION_EDGES: GraphEdge[] = [
  { from: 'S_sys', to: 'G-SRI', weight: 0.82 },
  { from: 'G-SRI', to: 'C-SRI', weight: 0.74 },
  { from: 'A-SRI', to: 'Δ_drift', weight: 0.69 },
  { from: 'P-SRI', to: 'p(doom)', weight: 0.61 },
  { from: 'p(doom)', to: 'p(doom)_kernel', weight: 0.95 },
  { from: 'CGR-I', to: 'CCR-I', weight: 0.58 },
  { from: 'Δ_drift', to: 'Δ_OSCAL', weight: 0.52 },
  { from: 'S_sys', to: 'C-SRI', weight: 0.77 },
  { from: 'A-SRI', to: 'CGR-I', weight: 0.48 },
  { from: 'G-SRI', to: 'G-SRI-VII', weight: 0.65 },
  { from: 'C-SRI', to: 'A-SRI', weight: 0.55 },
  { from: 'P-SRI', to: 'CCR-I', weight: 0.42 },
  { from: 'p(doom)_kernel', to: 'CGR-I', weight: 0.38 },
];

export function getRiskGraphNodes(): GraphNode[] {
  return RISK_INDICES.map((idx) => ({
    id: idx.id,
    label: idx.id,
    value: Math.min(1, idx.value / idx.threshold),
    status: idx.status,
  }));
}

export const AGENT_ATTESTATIONS: Record<string, AgentAttestationDetails> = {
  'ASA-001': {
    agentId: 'ASA-001',
    policyHash: '0x8f4b29a1c0d3e5f789123456789abcdef0123456789abcdef0123456789abc11',
    pqcSignature: 'ML-DSA-65:0x93f0a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789a12',
    attestationEpoch: 'Epoch 2026-10-12T08:00:00Z',
    attestationProof: `[SYSTEM_ATTESTATION_QUOTE_BEGIN]
Platform: RTEE-Enclave-v4
Enclave ID: 0x4a7f902b11e8
PCR-00: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
PCR-01: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284ddd200126d9069b
Policy Integrity: VALID (0x8f4b...abc11)
Drift L2 Norm: 0.0241 (Threshold: 0.050)
Containment Level: UNCONTAINED (Normal Autonomous Operation)
Supervisory Action: Pass through to supervisory college transmission log.
[SYSTEM_ATTESTATION_QUOTE_END]`,
    telemetryLogs: [
      '08:57:00Z [INFO] Telemetry pulse received: S_sys = 0.312, G-SRI = 0.354',
      '08:50:00Z [INFO] Routine model weights checksum verified against WORM Merkle root',
      '08:45:00Z [INFO] TLA+ Invariant CI-004 assertion satisfied (S_sys < 0.85)',
    ],
  },
  'ASA-002': {
    agentId: 'ASA-002',
    policyHash: '0x123a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abc22',
    pqcSignature: 'ML-DSA-65:0x88f1a2b3c4d5e6f7890123456789abcdef0123456789abcdef0123456789a22',
    attestationEpoch: 'Epoch 2026-10-12T08:00:00Z',
    attestationProof: `[COMPLIANCE_HARVESTER_QUOTE_BEGIN]
Platform: TPM-2.0-FIPS140-3
Enclave ID: 0x9c3e100f28a9
OSCAL Spec Mapping Version: 1.1.2
Active Control Matrix: CD-01..CD-10 (41 active controls)
Drift L2 Norm: 0.0310 (Threshold: 0.050)
Containment Level: UNCONTAINED
Harvest Result: 20 regulatory frameworks scanned, 0 unmapped violations detected.
[COMPLIANCE_HARVESTER_QUOTE_END]`,
    telemetryLogs: [
      '08:54:00Z [INFO] OSCAL assessment results compiled for SGR-028 bundle',
      '08:30:00Z [INFO] DORA Art. 33 compliance mapping refreshed',
    ],
  },
  'ASA-005': {
    agentId: 'ASA-005',
    policyHash: '0x555a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abc55',
    pqcSignature: 'ML-DSA-65:0x55f1a2b3c4d5e6f7890123456789abcdef0123456789abcdef0123456789a55',
    attestationEpoch: 'Epoch 2026-10-12T08:00:00Z',
    attestationProof: `[DRIFT_WATCH_QUOTE_BEGIN]
Platform: RTEE-Enclave-v4
Enclave ID: 0x2b8120fa94bc
Drift L2 Norm: 0.0520 (Threshold: 0.050 -> EXCEEDED)
Containment Level: WATCH (Soft-Containment Pre-Armed)
Interventions 24h: 1 (routing re-balance executed at 04:12Z)
Supervisory Note: Mesh topology routing policy divergence detected in StaR-MoE expert 5.
[DRIFT_WATCH_QUOTE_END]`,
    telemetryLogs: [
      '08:49:00Z [WARN] Policy drift L2 norm 0.0520 exceeded soft limit 0.050. Status set to WATCH.',
      '04:12:00Z [INTERVENTION] Applied gradient dampening on Expert 5 policy head.',
    ],
  },
  'ASA-008': {
    agentId: 'ASA-008',
    policyHash: '0x888a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abc88',
    pqcSignature: 'ML-DSA-65:0x88f1a2b3c4d5e6f7890123456789abcdef0123456789abcdef0123456789a88',
    attestationEpoch: 'Epoch 2026-10-12T08:00:00Z',
    attestationProof: `[CONTAINMENT_EXECUTOR_QUOTE_BEGIN]
Platform: RTEE-Enclave-v4
Enclave ID: 0x77c220fa11da
Drift L2 Norm: 0.0460 (Threshold: 0.050)
Containment Level: WATCH
Interventions 24h: 1
Supervisory Note: Kill-switch choreography pre-armed; readiness score 98.4%.
[CONTAINMENT_EXECUTOR_QUOTE_END]`,
    telemetryLogs: [
      '08:51:00Z [INFO] Kill-switch trigger channel ping OK',
      '06:15:00Z [INTERVENTION] Verified containment boundary on G-SIFI cluster 3 endpoints.',
    ],
  },
};

export function getAgentAttestation(id: string): AgentAttestationDetails {
  if (AGENT_ATTESTATIONS[id]) return AGENT_ATTESTATIONS[id];
  return {
    agentId: id,
    policyHash: `0x777a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abc00`,
    pqcSignature: `ML-DSA-65:0x77f1a2b3c4d5e6f7890123456789abcdef0123456789abcdef0123456789a00`,
    attestationEpoch: 'Epoch 2026-10-12T08:00:00Z',
    attestationProof: `[DEFAULT_AGENT_ATTESTATION_QUOTE_BEGIN]
Platform: RTEE-Enclave-v4
Agent ID: ${id}
Attestation Status: VALID
Drift Score: Nominal (< 0.05)
Containment Status: UNCONTAINED
[DEFAULT_AGENT_ATTESTATION_QUOTE_END]`,
    telemetryLogs: [
      `08:55:00Z [INFO] Routine heartbeat for ${id} recorded in WORM ledger.`,
      `08:00:00Z [INFO] Enclave quote verified via hardware root of trust.`,
    ],
  };
}
