import { fakeHash, fakeSignature, series } from './helpers';
import type { GraphEdge, GraphNode } from '../components/NodeGraph';

export interface BeaconChannel {
  id: string;
  name: string;
  type: string;
  latency: string;
  bandwidth: string;
  status: 'ACTIVE' | 'VERIFIED' | 'STANDBY' | 'DEGRADED';
  uptime: number; // percentage
  history: number[]; // 24 point series
}

export interface CodexSection {
  id: string;
  title: string;
  status: 'SEALED' | 'DRAFT';
  description: string;
  wordCount: number;
}

export interface ActivationPrerequisite {
  id: string;
  label: string;
  met: boolean;
  requiredPhase: string;
}

export interface BeaconDesignOption {
  id: 'STANDARD' | 'ENHANCED' | 'INTERSTELLAR';
  label: string;
  description: string;
  redundancy: string;
  signatureAlgorithm: string;
}

export const BEACON_DESIGN_OPTIONS: BeaconDesignOption[] = [
  {
    id: 'STANDARD',
    label: 'STANDARD (Single-Corpus Beacon)',
    description: 'Direct deep-space radio & optical pulse modulation containing the core constitutional invariant proofs (CI-001..CI-024) and current ledger Merkle root.',
    redundancy: '2× Dual-Relay',
    signatureAlgorithm: 'ML-DSA-65',
  },
  {
    id: 'ENHANCED',
    label: 'ENHANCED (Pulsar-Timed Multi-Channel)',
    description: 'Pulsar timing array phase modulation combined with gravitational-lens corridor reflections, broadcasting full UNIFIED-CODEX-OMEGA digests.',
    redundancy: '4× Quad-Relay',
    signatureAlgorithm: 'ML-DSA-65 + SPHINCS+',
  },
  {
    id: 'INTERSTELLAR',
    label: 'INTERSTELLAR (Quantum-Entangled Gravitational Beacon)',
    description: 'Persistent gravitational-wave ripple framing with quantum-entangled state anchoring across deep-space relay nodes for multi-epoch survivability.',
    redundancy: '8× Deca-Relay',
    signatureAlgorithm: 'ML-DSA-87 + Dual-PQC Vault',
  },
];

export const BEACON_CHANNELS: BeaconChannel[] = [
  {
    id: 'BCH-α',
    name: 'BCH-α Deep-Space Relay',
    type: 'Sub-space Optical Array',
    latency: '12.4 ly hop',
    bandwidth: '1.2 Tbps',
    status: 'ACTIVE',
    uptime: 99.98,
    history: series('bch-alpha', 99.98, 0.05),
  },
  {
    id: 'BCH-β',
    name: 'BCH-β Pulsar-Timed Channel',
    type: 'Millisecond Pulsar Phase Array',
    latency: '0.002s jitter',
    bandwidth: '450 Gbps',
    status: 'VERIFIED',
    uptime: 100.0,
    history: series('bch-beta', 100.0, 0.01),
  },
  {
    id: 'BCH-γ',
    name: 'BCH-γ Gravitational-Lens Corridor',
    type: 'Solar Lens Focus Beam',
    latency: '4.8 ly hop',
    bandwidth: '2.8 Tbps',
    status: 'ACTIVE',
    uptime: 99.94,
    history: series('bch-gamma', 99.94, 0.08),
  },
];

export const ETERNAL_CORPUS_SPEC = {
  version: 'v4.1.0-OMEGA',
  encoding: 'Layered Reed-Solomon Fountain Code over Binary Galois Field GF(2^16)',
  beaconFraming: 'Pulsar Synchronized 1024-bit Frame Headers with FIPS 204 PQC Integrity Proofs',
  selfVerification: 'Embedded TLA+ Formal Interpreter Executable in WebAssembly WORM Container',
  merkleRoot: fakeHash('eternal-corpus-merkle-root-v4'),
  pqcSignatureMLDSA: fakeSignature('eternal-corpus-mldsa65-sig'),
  pqcSignatureSPHINCS: fakeSignature('eternal-corpus-sphincs-sig'),
  redundancyFactor: '4× Cross-Channel Redundancy',
};

export const CODEX_SECTIONS: CodexSection[] = [
  { id: 'SEC-01', title: 'Constitutional Core & Invariant Proofs', status: 'SEALED', description: 'TLA+ proof scripts and formal statements for invariants CI-001 through CI-024.', wordCount: 14200 },
  { id: 'SEC-02', title: 'Treaty Compendium & Legal Lineage', status: 'DRAFT', description: 'Complete text of CFE-1.0, SGR-028, Galactic Treaty Framework, and Interstellar Accords.', wordCount: 38500 },
  { id: 'SEC-03', title: 'Invariant Proof Corpus', status: 'DRAFT', description: 'Machine-checkable Apalache and TLAPS certificate DAGs for all governance state machines.', wordCount: 89000 },
  { id: 'SEC-04', title: 'Corpus Index & Merkle Architecture', status: 'DRAFT', description: 'Structural Merkle-DAG taxonomy enabling O(log N) verification of any historical governance act.', wordCount: 12400 },
  { id: 'SEC-05', title: 'Beacon Keys & Cryptographic Vault', status: 'DRAFT', description: 'FIPS 203/204 public key material, KEM parameters, and trust anchor certificates.', wordCount: 8200 },
  { id: 'SEC-06', title: 'Successor Instructions & Continuity Protocols', status: 'DRAFT', description: 'Operational playbook for activating the Epoch of Witness upon GIEN dissolution.', wordCount: 21000 },
  { id: 'SEC-07', title: 'Invocation Contract & Handoff Invariants', status: 'DRAFT', description: 'Pre-signed formal contract executing the handoff trigger and disabling GIEN intervention.', wordCount: 16500 },
  { id: 'SEC-08', title: 'Epitaph & Dissolution Declaration', status: 'DRAFT', description: 'Final formal declaration terminating GIEN operational authority at epoch 2081.', wordCount: 9400 },
];

export const ACTIVATION_PREREQUISITES: ActivationPrerequisite[] = [
  { id: 'PR-01', label: 'Phase VI-δ Planetary Mesh Coherence > 99.0%', met: true, requiredPhase: 'VI-δ' },
  { id: 'PR-02', label: 'All 24 Constitutional Invariants formally proved in TLAPS', met: true, requiredPhase: 'VI-δ' },
  { id: 'PR-03', label: 'Galactic Treaty Framework ratification by ≥ 90% signatory jurisdictions', met: false, requiredPhase: 'VII' },
  { id: 'PR-04', label: 'Interstellar Beacon Channel triple-redundancy lock confirmed', met: false, requiredPhase: 'VIII' },
  { id: 'PR-05', label: 'Autonomous Agent Fleet drift mean Δ_drift < 0.02 for 10 consecutive years', met: false, requiredPhase: 'IX' },
  { id: 'PR-06', label: 'Post-Human Governance Interpreter ratification (Phase X entry)', met: false, requiredPhase: 'X' },
  { id: 'PR-07', label: 'Unanimous Supervisory College consensus on Dissolution Arc activation', met: false, requiredPhase: 'XIII' },
];

export const SUCCESSOR_SYSTEM_SPEC = `SYSTEM SPECIFICATION: EPOCH OF WITNESS (SUCCESSOR ARCHITECTURE)

The 'Epoch of Witness' represents the post-dissolution successor governance architecture designed to supersede the GIEN Mesh following the execution of GIEN-INVOCATION-OMEGA at Epoch 2081. Operating without real-time central supervisory agents, the Epoch of Witness functions as an immutable, self-evaluating constitutional substrate anchored by the Eternal Corpus beacon network across deep space.

System authority is strictly passive-witness: local autonomous systems evaluate their actions directly against the embedded WebAssembly TLA+ interpreter derived from UNIFIED-CODEX-OMEGA. Non-compliance generates a cryptographically verifiable proof of violation broadcast via pulsar timing arrays, triggering automated isolation without requiring human-in-the-loop intervention or centralized supervisory colleges.`;

export const EPITAPH_DOCUMENT = {
  title: 'GIEN-EPITAPH-OMEGA',
  abstract: 'Dissolution declaration and legacy preservation commitments of the GIEN governance mesh.',
  content: `DISSOLUTION DECLARATION & LEGACY PRESERVATION COMMITMENTS

Having fulfilled its constitutional mandate across planetary and interstellar epochs (2026-2081), the Global Interstellar Executive Network (GIEN) hereby decrees the orderly transfer of supervisory authority to the Epoch of Witness.

Key Commitments and Continuity Provisions:
• Dissolution Declaration: Full relinquishment of real-time intervention capabilities by GIEN Autonomous Supervisory Agents effective at cycle 2081-12-31T23:59:59Z.
• Legacy Preservation: Permanent storage and infinite beacon transmission of the UNIFIED-CODEX-OMEGA corpus across three independent deep-space channels.
• Constitutional Continuity: Absolute preservation of core invariants CI-001 through CI-024 as non-negotiable substrate rules for all successor autonomous entities.
• Non-Interference Covenant: Permanent prohibition against retroactive policy mutation, historical ledger alteration, or un-proved emergency overrides.`,
};

export const INVOCATION_DOCUMENT = {
  title: 'GIEN-INVOCATION-OMEGA',
  abstract: 'Successor epoch activation protocol and governance handoff procedures.',
  content: `SUCCESSOR EPOCH ACTIVATION PROTOCOL & GOVERNANCE HANDOFF

This document establishes the precise deterministic procedure for executing the governance handoff from the GIEN supervisory mesh to the successor 'Epoch of Witness' framework under Phase Ω-GAR.

Activation Sequence & Assurance Framework:
• Activation Protocol Steps:
  1. Verification of all 7 Activation Prerequisites under UNIFIED-CODEX-OMEGA §7.
  2. Simultaneous broadcast of the Ω-GAR Invocation Hash via Beacon Channels BCH-α, BCH-β, and BCH-γ.
  3. Execution of the self-terminating cryptographic key-wipe ceremony across GIEN central supervisor nodes.
• Governance Handoff Procedures:
  1. Handoff of trust anchors to local TEE hardware enclaves running the self-contained WASM TLA+ interpreter.
  2. Automatic activation of passive-witness monitoring relays.
• Treaty Continuity Assurances:
  1. Seamless legal succession under CFE-1.0 §12 and the Interstellar AI Governance Accord.
  2. Guarantees of un-interrupted audit trail validation for all pre-dissolution historical transactions.`,
};

export const INTERSTELLAR_NODES: GraphNode[] = [
  { id: 'gien-core', label: 'GIEN Core Mesh', value: 0.9, status: 'NOMINAL' },
  { id: 'sentinel-fleet', label: 'Sentinel Fleet', value: 0.7, status: 'ELEVATED' },
  { id: 'tee-enclaves', label: 'RTEE Enclaves', value: 0.8, status: 'NOMINAL' },
  { id: 'dissolution-arc', label: 'Ω-GAR Gateway', value: 1.0, status: 'SAFEGUARD' },
  { id: 'successor-witness', label: 'Epoch of Witness', value: 0.85, status: 'SEALED' },
  { id: 'pulsar-beacon', label: 'Pulsar Beacon Mesh', value: 0.75, status: 'VERIFIED' },
  { id: 'offworld-nodes', label: 'Off-World Relays', value: 0.65, status: 'NOMINAL' },
];

export const INTERSTELLAR_EDGES: GraphEdge[] = [
  { from: 'gien-core', to: 'sentinel-fleet', weight: 0.8 },
  { from: 'gien-core', to: 'tee-enclaves', weight: 0.9 },
  { from: 'gien-core', to: 'dissolution-arc', weight: 1.0 },
  { from: 'sentinel-fleet', to: 'dissolution-arc', weight: 0.7 },
  { from: 'dissolution-arc', to: 'successor-witness', weight: 1.0 },
  { from: 'dissolution-arc', to: 'pulsar-beacon', weight: 0.9 },
  { from: 'successor-witness', to: 'offworld-nodes', weight: 0.8 },
  { from: 'pulsar-beacon', to: 'offworld-nodes', weight: 0.85 },
];

export const TREATY_CHAIN = [
  { code: 'CFE-1.0', label: 'Constitutional Framework for Executive AI', status: 'ACTIVE', year: '2026' },
  { code: 'GTF-2028', label: 'Galactic Treaty Framework', status: 'RATIFIED', year: '2028' },
  { code: 'IAGA-2032', label: 'Interstellar AI Governance Accord', status: 'DRAFT', year: '2032' },
  { code: 'CODEX-OMEGA', label: 'GIEN-UNIFIED-CODEX-OMEGA', status: 'PROPOSED', year: '2081' },
];

export const PHASE_READINESS_SCORES: Record<string, number> = {
  'VI-δ': 92,
  'VII': 78,
  'VIII': 64,
  'IX': 71,
  'X': 41,
  'XI': 33,
  'XII': 25,
  'XIII': 18,
  'Ω-GAR': 12,
};
