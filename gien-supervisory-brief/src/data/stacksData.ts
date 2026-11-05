import type { GraphEdge, GraphNode } from '../components/NodeGraph';
import type { TimelineEvent } from '../components/TimelineVisualization';
import type { SLAException } from '../types';
import { fakeHash, series } from './helpers';

export interface SentinelComponent {
  id: string;
  name: string;
  version: string;
  status: 'NOMINAL' | 'ELEVATED' | 'ACTIVE' | 'STANDBY' | 'DEGRADED';
  lastHeartbeat: string; // e.g. "2s ago"
  description: string;
}

export const SENTINEL_COMPONENTS: SentinelComponent[] = [
  { id: 'sc-01', name: 'Model Registry', version: 'v2.4.1', status: 'NOMINAL', lastHeartbeat: '4s ago', description: 'Central cryptographic registry of 14 active StaR-MoE model weights.' },
  { id: 'sc-02', name: 'Drift Monitor', version: 'v2.4.0', status: 'NOMINAL', lastHeartbeat: '2s ago', description: 'Continuous L2 divergence calculation across fleet policy embeddings.' },
  { id: 'sc-03', name: 'Fairness Engine', version: 'v2.3.9', status: 'NOMINAL', lastHeartbeat: '8s ago', description: 'Equal opportunity & demographic parity audit across inference shards.' },
  { id: 'sc-04', name: 'Explainability Hub', version: 'v2.4.2', status: 'ELEVATED', lastHeartbeat: '18s ago', description: 'Integrated SHAP/Integrated Gradients feature attribution pipeline.' },
  { id: 'sc-05', name: 'Kill-Switch Arbiter', version: 'v2.4.0', status: 'ACTIVE', lastHeartbeat: '1s ago', description: 'Hardware-level enclave circuit breaker & sub-second quarantine arbiter.' },
  { id: 'sc-06', name: 'Attestation Notary', version: 'v2.4.1', status: 'NOMINAL', lastHeartbeat: '5s ago', description: 'ML-DSA-65 signature notary for zero-trust RTEE quotes.' },
  { id: 'sc-07', name: 'zkML Prover', version: 'v2.2.0', status: 'NOMINAL', lastHeartbeat: '12s ago', description: 'Zero-knowledge proof generator for non-disclosing model verification.' },
  { id: 'sc-08', name: 'zkML Verifier', version: 'v2.2.0', status: 'NOMINAL', lastHeartbeat: '9s ago', description: 'On-chain SNARK/STARK verifier for external supervisory validation.' },
  { id: 'sc-09', name: 'Policy Engine', version: 'v2.4.0', status: 'NOMINAL', lastHeartbeat: '3s ago', description: 'OPA-Rego rule evaluator executing 1,420 regulatory policies.' },
  { id: 'sc-10', name: 'Alert Orchestrator', version: 'v2.4.1', status: 'NOMINAL', lastHeartbeat: '6s ago', description: 'Real-time alert dispatch & supervisory college escalation bus.' },
  { id: 'sc-11', name: 'Replay Archivist', version: 'v2.3.8', status: 'NOMINAL', lastHeartbeat: '15s ago', description: 'WORM deterministic log recorder for Digital Twin scenario replay.' },
  { id: 'sc-12', name: 'Guardian Console', version: 'v2.4.2', status: 'NOMINAL', lastHeartbeat: '1s ago', description: 'Unified operator dashboard and constitutional invariant control plane.' },
];

export const MESH_NODES: GraphNode[] = [
  { id: 'sup-alpha', label: 'Supervisor Alpha', value: 0.95, status: 'NOMINAL' },
  { id: 'sup-beta', label: 'Supervisor Beta', value: 0.92, status: 'NOMINAL' },
  { id: 'sup-gamma', label: 'Supervisor Gamma', value: 0.90, status: 'NOMINAL' },
  { id: 'hub-eu', label: 'EU-Central Hub', value: 0.75, status: 'ELEVATED' }, // Degraded node #1
  { id: 'hub-useast', label: 'US-East Hub', value: 0.88, status: 'NOMINAL' },
  { id: 'hub-uswest', label: 'US-West Hub', value: 0.85, status: 'NOMINAL' },
  { id: 'hub-apac', label: 'APAC Hub', value: 0.70, status: 'ELEVATED' }, // Degraded node #2
  { id: 'relay-1', label: 'Beacon Relay #1', value: 0.60, status: 'NOMINAL' },
  { id: 'relay-2', label: 'Beacon Relay #2', value: 0.58, status: 'NOMINAL' },
  { id: 'relay-3', label: 'Beacon Relay #3', value: 0.62, status: 'NOMINAL' },
  { id: 'shard-1', label: 'Replay Shard #1', value: 0.50, status: 'NOMINAL' },
  { id: 'shard-2', label: 'Replay Shard #2', value: 0.52, status: 'NOMINAL' },
];

export const MESH_EDGES: GraphEdge[] = [
  { from: 'sup-alpha', to: 'hub-eu', weight: 0.95 },
  { from: 'sup-alpha', to: 'hub-useast', weight: 0.98 },
  { from: 'sup-beta', to: 'hub-uswest', weight: 0.94 },
  { from: 'sup-beta', to: 'hub-apac', weight: 0.88 },
  { from: 'sup-gamma', to: 'hub-eu', weight: 0.91 },
  { from: 'sup-gamma', to: 'hub-useast', weight: 0.96 },
  { from: 'hub-eu', to: 'relay-1', weight: 0.82 },
  { from: 'hub-useast', to: 'relay-2', weight: 0.89 },
  { from: 'hub-uswest', to: 'relay-3', weight: 0.87 },
  { from: 'hub-apac', to: 'shard-1', weight: 0.78 },
  { from: 'relay-1', to: 'shard-1', weight: 0.85 },
  { from: 'relay-2', to: 'shard-2', weight: 0.90 },
];

export interface MeshAnomaly {
  id: string;
  severity: 'ELEVATED' | 'CRITICAL';
  nodes: string[];
  timestamp: string;
  title: string;
  details: string;
}

export const MESH_ANOMALIES: MeshAnomaly[] = [
  {
    id: 'ANOM-2026-089',
    severity: 'ELEVATED',
    nodes: ['EU-Central Hub', 'Beacon Relay #1'],
    timestamp: '2026-10-10T08:42:15Z',
    title: 'Cross-Region Attestation Latency Spike',
    details: 'vTPM quote attestation roundtrip latency peaked at 142ms (baseline 35ms) during peak load window.',
  },
  {
    id: 'ANOM-2026-090',
    severity: 'ELEVATED',
    nodes: ['APAC Hub'],
    timestamp: '2026-10-10T07:15:00Z',
    title: 'Transient Quote Re-Verification Required',
    details: 'RTEE quote verification failed 1 check due to key rotation lag; successfully re-attested on retry.',
  },
];

export const MESH_COHERENCE_SERIES = series('mesh-coherence-2026', 99.2, 0.4);

export const DAILY_CYCLE_EVENTS: TimelineEvent[] = [
  { at: '08:00', label: 'Archive Transmission', state: 'DONE' },
  { at: '08:15', label: 'Merkle+PQC Verification', state: 'DONE' },
  { at: '08:30', label: 'Compliance Bundle Derivation', state: 'DONE' },
  { at: '12:00', label: 'SLA Exception Handling', state: 'ACTIVE' },
  { at: '23:59', label: 'Cycle Closure', state: 'PENDING' },
];

export const SLA_EXCEPTIONS: SLAException[] = [
  {
    id: 'EXC-2026-101',
    severity: 'MEDIUM',
    trigger: 'EU AI Act DPIA Evidence Pack Delay (Annex IV Art 35)',
    raisedAt: '2026-10-10T04:30:00Z',
    resolutionStatus: 'IN_PROGRESS',
  },
  {
    id: 'EXC-2026-102',
    severity: 'LOW',
    trigger: 'Fed SR 26-2 Model Inventory Re-sync (2 Shards)',
    raisedAt: '2026-10-10T06:12:00Z',
    resolutionStatus: 'OPEN',
  },
  {
    id: 'EXC-2026-103',
    severity: 'HIGH',
    trigger: 'C-SRI Contagion Stress Threshold Warning (0.327 > 0.300)',
    raisedAt: '2026-10-09T22:45:00Z',
    resolutionStatus: 'RESOLVED',
  },
];

export interface AllocationBar {
  name: string;
  baseline: number; // 0-100%
  elevated: number; // 0-100%
  unit: string;
}

export const COMPUTE_ALLOCATIONS: AllocationBar[] = [
  { name: 'TEE Enclave Hardware Attestation', baseline: 40, elevated: 75, unit: 'Cores' },
  { name: 'zkML Proof Generation & Verification', baseline: 30, elevated: 85, unit: 'TFLOPS' },
  { name: 'Deterministic Replay & Twin Sync', baseline: 20, elevated: 60, unit: 'GB/s' },
  { name: 'Audit WORM Serialization & PQC Sign', baseline: 15, elevated: 45, unit: 'Kops/s' },
];

export const KILL_SWITCH_METADATA = {
  status: 'ARMED',
  lastTest: '2026-10-09T19:30:00Z',
  heartbeatHash: fakeHash('sentinel-killswitch-heartbeat-2026'),
  dossierRef: 'SGR-030-CFE-2026-10-01-XII',
};
