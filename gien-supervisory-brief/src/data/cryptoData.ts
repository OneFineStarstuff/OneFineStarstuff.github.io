import type { RteeNode } from '../types';
import { fakeHash, fakeSignature, truncateHash } from './helpers';

// ---------------------------------------------------------------------------
// Section A: Merkle-DAG & Audit Ledger Data
// ---------------------------------------------------------------------------

export interface DagNode {
  id: string;
  blockNumber: number;
  label: string;
  timestamp: string;
  opType: 'ARCHIVE_SEAL' | 'KEY_ROTATION' | 'ATTESTATION_ANCHOR' | 'INVARIANT_PROOF' | 'BRANCH_POINT';
  hash: string;
  parentIds: string[];
  txCount: number;
  isBranch?: boolean;
}

export const DAG_BLOCKS: DagNode[] = [
  {
    id: 'blk-8412328',
    blockNumber: 8412328,
    label: '#8412328 Root Anchor',
    timestamp: '2026-10-10T06:15:00Z',
    opType: 'ARCHIVE_SEAL',
    hash: fakeHash('blk-8412328'),
    parentIds: [],
    txCount: 1120,
  },
  {
    id: 'blk-8412329',
    blockNumber: 8412329,
    label: '#8412329 Key Rotation',
    timestamp: '2026-10-10T06:30:00Z',
    opType: 'KEY_ROTATION',
    hash: fakeHash('blk-8412329'),
    parentIds: ['blk-8412328'],
    txCount: 980,
  },
  {
    id: 'blk-8412330',
    blockNumber: 8412330,
    label: '#8412330 Attestation Branch',
    timestamp: '2026-10-10T06:45:00Z',
    opType: 'BRANCH_POINT',
    hash: fakeHash('blk-8412330'),
    parentIds: ['blk-8412329'],
    txCount: 1450,
    isBranch: true,
  },
  {
    id: 'blk-8412331',
    blockNumber: 8412331,
    label: '#8412331 Branch A (TEE Quote)',
    timestamp: '2026-10-10T07:00:00Z',
    opType: 'ATTESTATION_ANCHOR',
    hash: fakeHash('blk-8412331'),
    parentIds: ['blk-8412330'],
    txCount: 620,
  },
  {
    id: 'blk-8412332',
    blockNumber: 8412332,
    label: '#8412332 Branch B (zkML Proof)',
    timestamp: '2026-10-10T07:10:00Z',
    opType: 'INVARIANT_PROOF',
    hash: fakeHash('blk-8412332'),
    parentIds: ['blk-8412330'],
    txCount: 840,
    isBranch: true,
  },
  {
    id: 'blk-8412333',
    blockNumber: 8412333,
    label: '#8412333 Re-converge Merge',
    timestamp: '2026-10-10T07:25:00Z',
    opType: 'ARCHIVE_SEAL',
    hash: fakeHash('blk-8412333'),
    parentIds: ['blk-8412331', 'blk-8412332'],
    txCount: 1510,
  },
  {
    id: 'blk-8412334',
    blockNumber: 8412334,
    label: '#8412334 Anchor Audit',
    timestamp: '2026-10-10T07:35:00Z',
    opType: 'ATTESTATION_ANCHOR',
    hash: fakeHash('blk-8412334'),
    parentIds: ['blk-8412333'],
    txCount: 1040,
  },
  {
    id: 'blk-8412335',
    blockNumber: 8412335,
    label: '#8412335 Invariant Seal',
    timestamp: '2026-10-10T07:45:00Z',
    opType: 'INVARIANT_PROOF',
    hash: fakeHash('blk-8412335'),
    parentIds: ['blk-8412334'],
    txCount: 1190,
  },
  {
    id: 'blk-8412336',
    blockNumber: 8412336,
    label: '#8412336 Key Sync',
    timestamp: '2026-10-10T07:55:00Z',
    opType: 'KEY_ROTATION',
    hash: fakeHash('blk-8412336'),
    parentIds: ['blk-8412335'],
    txCount: 1005,
  },
  {
    id: 'blk-8412337',
    blockNumber: 8412337,
    label: '#8412337 HEAD (Latest)',
    timestamp: '2026-10-10T08:00:12Z',
    opType: 'ARCHIVE_SEAL',
    hash: fakeHash('blk-8412337'),
    parentIds: ['blk-8412336'],
    txCount: 1284,
  },
];

export interface LedgerAuditEntry {
  blockNumber: number;
  hash: string;
  timestamp: string;
  operationType: 'ARCHIVE_SEAL' | 'KEY_ROTATION' | 'ATTESTATION_ANCHOR' | 'INVARIANT_PROOF' | 'SETTLEMENT_SEAL' | 'ZK_BATCH_ANCHOR';
  txCount: number;
  verificationStatus: 'VERIFIED' | 'SEALED';
  signature: string;
}

export const AUDIT_LEDGER_ENTRIES: LedgerAuditEntry[] = [
  {
    blockNumber: 8412337,
    hash: fakeHash('ledger-8412337'),
    timestamp: '2026-10-10T08:00:12Z',
    operationType: 'ARCHIVE_SEAL',
    txCount: 1284,
    verificationStatus: 'VERIFIED',
    signature: fakeSignature('sig-8412337'),
  },
  {
    blockNumber: 8412336,
    hash: fakeHash('ledger-8412336'),
    timestamp: '2026-10-10T07:55:00Z',
    operationType: 'KEY_ROTATION',
    txCount: 1005,
    verificationStatus: 'SEALED',
    signature: fakeSignature('sig-8412336'),
  },
  {
    blockNumber: 8412335,
    hash: fakeHash('ledger-8412335'),
    timestamp: '2026-10-10T07:45:00Z',
    operationType: 'INVARIANT_PROOF',
    txCount: 1190,
    verificationStatus: 'VERIFIED',
    signature: fakeSignature('sig-8412335'),
  },
  {
    blockNumber: 8412334,
    hash: fakeHash('ledger-8412334'),
    timestamp: '2026-10-10T07:35:00Z',
    operationType: 'ATTESTATION_ANCHOR',
    txCount: 1040,
    verificationStatus: 'VERIFIED',
    signature: fakeSignature('sig-8412334'),
  },
  {
    blockNumber: 8412333,
    hash: fakeHash('ledger-8412333'),
    timestamp: '2026-10-10T07:25:00Z',
    operationType: 'ZK_BATCH_ANCHOR',
    txCount: 1510,
    verificationStatus: 'SEALED',
    signature: fakeSignature('sig-8412333'),
  },
  {
    blockNumber: 8412332,
    hash: fakeHash('ledger-8412332'),
    timestamp: '2026-10-10T07:10:00Z',
    operationType: 'INVARIANT_PROOF',
    txCount: 840,
    verificationStatus: 'VERIFIED',
    signature: fakeSignature('sig-8412332'),
  },
  {
    blockNumber: 8412331,
    hash: fakeHash('ledger-8412331'),
    timestamp: '2026-10-10T07:00:00Z',
    operationType: 'ATTESTATION_ANCHOR',
    txCount: 620,
    verificationStatus: 'VERIFIED',
    signature: fakeSignature('sig-8412331'),
  },
  {
    blockNumber: 8412330,
    hash: fakeHash('ledger-8412330'),
    timestamp: '2026-10-10T06:45:00Z',
    operationType: 'SETTLEMENT_SEAL',
    txCount: 1450,
    verificationStatus: 'SEALED',
    signature: fakeSignature('sig-8412330'),
  },
  {
    blockNumber: 8412329,
    hash: fakeHash('ledger-8412329'),
    timestamp: '2026-10-10T06:30:00Z',
    operationType: 'KEY_ROTATION',
    txCount: 980,
    verificationStatus: 'VERIFIED',
    signature: fakeSignature('sig-8412329'),
  },
  {
    blockNumber: 8412328,
    hash: fakeHash('ledger-8412328'),
    timestamp: '2026-10-10T06:15:00Z',
    operationType: 'ARCHIVE_SEAL',
    txCount: 1120,
    verificationStatus: 'SEALED',
    signature: fakeSignature('sig-8412328'),
  },
  {
    blockNumber: 8412327,
    hash: fakeHash('ledger-8412327'),
    timestamp: '2026-10-10T06:00:00Z',
    operationType: 'ZK_BATCH_ANCHOR',
    txCount: 1302,
    verificationStatus: 'VERIFIED',
    signature: fakeSignature('sig-8412327'),
  },
  {
    blockNumber: 8412326,
    hash: fakeHash('ledger-8412326'),
    timestamp: '2026-10-10T05:45:00Z',
    operationType: 'ATTESTATION_ANCHOR',
    txCount: 890,
    verificationStatus: 'VERIFIED',
    signature: fakeSignature('sig-8412326'),
  },
  {
    blockNumber: 8412325,
    hash: fakeHash('ledger-8412325'),
    timestamp: '2026-10-10T05:30:00Z',
    operationType: 'INVARIANT_PROOF',
    txCount: 1045,
    verificationStatus: 'SEALED',
    signature: fakeSignature('sig-8412325'),
  },
  {
    blockNumber: 8412324,
    hash: fakeHash('ledger-8412324'),
    timestamp: '2026-10-10T05:15:00Z',
    operationType: 'ARCHIVE_SEAL',
    txCount: 1150,
    verificationStatus: 'VERIFIED',
    signature: fakeSignature('sig-8412324'),
  },
];

export const WORM_COMPLIANCE_DETAILS = {
  rule: 'SEC Rule 17a-4(f) WORM Compliance',
  status: 'VERIFIED',
  retentionActive: '6 Years Immutable / 3 Years Online Active WORM',
  immutabilityMechanism: 'S3 Object Lock Legal Hold + Hardware TEE Enclave Sealed Roots',
  lastAuditDate: '2026-10-01',
  auditJurisdiction: 'SEC / FINRA / CFTC Inter-agency Supervisory Board',
  deletionPrevention: 'ENFORCED (Hardware WORM Fuse Engaged)',
  complianceReference: 'SEC-17A4-WORM-2026-09-VERIFIED',
};

// ---------------------------------------------------------------------------
// Section B: Zero-Knowledge Proof Pipeline Data
// ---------------------------------------------------------------------------

export interface ProofTypeRow {
  type: string;
  name: string;
  count24h: number;
  avgGenTime: string;
  circuitDetails: string;
  statusText: string;
  statusBadge: string;
}

export const PROOF_TYPE_BREAKDOWN: ProofTypeRow[] = [
  {
    type: 'zkML',
    name: 'zkML Inference Proofs',
    count24h: 2847,
    avgGenTime: '312 ms',
    circuitDetails: 'Model weight integrity & quantization bounds (2^20 constraints)',
    statusText: 'LIVENESS OK',
    statusBadge: 'NOMINAL',
  },
  {
    type: 'zk-SNARK',
    name: 'zk-SNARK Circuit Proofs',
    count24h: 812,
    avgGenTime: '185 ms',
    circuitDetails: 'Circuit size 2^18 constraints (262,144 constraints)',
    statusText: 'PHASE-2 COMPLETE',
    statusBadge: 'VERIFIED',
  },
  {
    type: 'zk-STARK',
    name: 'zk-STARK Scalable Proofs',
    count24h: 319,
    avgGenTime: '640 ms',
    circuitDetails: 'Proof size 51 KB, FRI domain 128 queries',
    statusText: 'TRANSPARENT',
    statusBadge: 'VERIFIED',
  },
  {
    type: 'SnarkPack',
    name: 'SnarkPack Aggregated',
    count24h: 150,
    avgGenTime: '410 ms',
    circuitDetails: 'Aggregation ratio 40:1, batch size 40 proofs/sub-tree',
    statusText: 'BATCH 40 ACTIVE',
    statusBadge: 'ACTIVE',
  },
];

export const VK_ROTATION_DATA = {
  currentKey: 'vkFMv2 (Legacy FIPS 204 Beta)',
  nextKey: 'vkFMv3 (Production FIPS 204 Active)',
  status: 'DEPRECATED → ACTIVE',
  progressPercent: 84,
  estimatedCompletion: '2026-10-15T00:00:00Z',
};

export interface FairnessMetric {
  metricName: string;
  proofCount: number;
  parityDelta: string;
  status: 'VERIFIED' | 'COMPLIANT';
}

export const FAIRNESS_PIPELINE: FairnessMetric[] = [
  {
    metricName: 'Demographic Parity',
    proofCount: 1204,
    parityDelta: '±0.41%',
    status: 'VERIFIED',
  },
  {
    metricName: 'Equalized Odds',
    proofCount: 1187,
    parityDelta: '±0.68%',
    status: 'VERIFIED',
  },
  {
    metricName: 'Counterfactual Fairness',
    proofCount: 931,
    parityDelta: '±0.29%',
    status: 'VERIFIED',
  },
];

export const ZK_VOTING_STATUS = {
  lastVoteDate: '2026-10-08',
  proposalRef: 'GIP-042 (PQC Migration Acceleration Protocol)',
  ballotCount: 96,
  verifiedBallots: 96,
  nullifierCollisions: 0,
  anonymitySetSize: 512,
  protocolStatus: 'ALL VERIFIED',
};

// ---------------------------------------------------------------------------
// Section C: Hardware TEE / TPM Attestation Data
// ---------------------------------------------------------------------------

export const TEE_GAUGE_SUMMARY = {
  totalNodes: 512,
  activeAttestedNodes: 509,
  densityPercent: 99.4,
  coherenceScore: 0.987,
  staleCount: 2,
  failedCount: 1,
};

export const RTEE_NODES: RteeNode[] = [
  {
    id: 'RTEE-SGX-001',
    type: 'TEE',
    platform: 'Intel SGX2/TDX',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:58:12Z',
    pcrSummary: truncateHash(fakeHash('pcr-sgx-001'), 8, 4),
    firmware: 'v4.18.0-pqc',
  },
  {
    id: 'RTEE-SGX-002',
    type: 'TEE',
    platform: 'Intel SGX2',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:45:00Z',
    pcrSummary: truncateHash(fakeHash('pcr-sgx-002'), 8, 4),
    firmware: 'v4.18.0-pqc',
  },
  {
    id: 'RTEE-TPM-101',
    type: 'TPM',
    platform: 'TPM 2.0 (Discrete)',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:55:30Z',
    pcrSummary: truncateHash(fakeHash('pcr-tpm-101'), 8, 4),
    firmware: 'v2.8.1-sec',
  },
  {
    id: 'RTEE-TPM-102',
    type: 'TPM',
    platform: 'TPM 2.0 (Firmware)',
    attestationStatus: 'STALE',
    lastQuote: '2026-10-10T06:12:00Z',
    pcrSummary: truncateHash(fakeHash('pcr-tpm-102'), 8, 4),
    firmware: 'v2.8.0-sec',
  },
  {
    id: 'RTEE-NITRO-201',
    type: 'vTPM',
    platform: 'AWS Nitro vTPM',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:59:01Z',
    pcrSummary: truncateHash(fakeHash('pcr-nitro-201'), 8, 4),
    firmware: 'v5.2.0-nitro',
  },
  {
    id: 'RTEE-NITRO-202',
    type: 'vTPM',
    platform: 'AWS Nitro vTPM',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:57:44Z',
    pcrSummary: truncateHash(fakeHash('pcr-nitro-202'), 8, 4),
    firmware: 'v5.2.0-nitro',
  },
  {
    id: 'RTEE-SEV-301',
    type: 'RTEE',
    platform: 'AMD SEV-SNP',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:56:10Z',
    pcrSummary: truncateHash(fakeHash('pcr-sev-301'), 8, 4),
    firmware: 'v1.54.0-sev',
  },
  {
    id: 'RTEE-SEV-302',
    type: 'RTEE',
    platform: 'AMD SEV-SNP',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:58:33Z',
    pcrSummary: truncateHash(fakeHash('pcr-sev-302'), 8, 4),
    firmware: 'v1.54.0-sev',
  },
  {
    id: 'RTEE-TDX-401',
    type: 'TEE',
    platform: 'Intel TDX',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:59:50Z',
    pcrSummary: truncateHash(fakeHash('pcr-tdx-401'), 8, 4),
    firmware: 'v3.1.2-tdx',
  },
  {
    id: 'RTEE-TDX-402',
    type: 'TEE',
    platform: 'Intel TDX',
    attestationStatus: 'FAILED',
    lastQuote: '2026-10-10T04:12:08Z',
    pcrSummary: truncateHash(fakeHash('pcr-tdx-402'), 8, 4),
    firmware: 'v3.1.0-tdx',
  },
  {
    id: 'RTEE-VTPM-501',
    type: 'vTPM',
    platform: 'GCP Shielded vTPM',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:54:19Z',
    pcrSummary: truncateHash(fakeHash('pcr-vtpm-501'), 8, 4),
    firmware: 'v2.1.0-gcp',
  },
  {
    id: 'RTEE-VTPM-502',
    type: 'vTPM',
    platform: 'Azure Confidential vTPM',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:58:05Z',
    pcrSummary: truncateHash(fakeHash('pcr-vtpm-502'), 8, 4),
    firmware: 'v2.4.0-az',
  },
  {
    id: 'RTEE-RTEE-601',
    type: 'RTEE',
    platform: 'Remote TEE Enclave',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:57:12Z',
    pcrSummary: truncateHash(fakeHash('pcr-rtee-601'), 8, 4),
    firmware: 'v1.0.8-rtee',
  },
  {
    id: 'RTEE-RTEE-602',
    type: 'RTEE',
    platform: 'Remote TEE Enclave',
    attestationStatus: 'STALE',
    lastQuote: '2026-10-10T05:30:00Z',
    pcrSummary: truncateHash(fakeHash('pcr-rtee-602'), 8, 4),
    firmware: 'v1.0.7-rtee',
  },
  {
    id: 'RTEE-TPM-701',
    type: 'TPM',
    platform: 'TPM 2.0 (On-Prem)',
    attestationStatus: 'VALID',
    lastQuote: '2026-10-10T08:59:15Z',
    pcrSummary: truncateHash(fakeHash('pcr-tpm-701'), 8, 4),
    firmware: 'v2.8.1-sec',
  },
];

export interface AttestationFailureRecord {
  id: string;
  nodeId: string;
  timestamp: string;
  cause: string;
  remediation: string;
  status: 'RESOLVED' | 'REMEDIATED';
}

export const ATTESTATION_FAILURES: AttestationFailureRecord[] = [
  {
    id: 'FAIL-2026-10-10-01',
    nodeId: 'RTEE-TDX-402',
    timestamp: '2026-10-10T04:12:08Z',
    cause: 'PCR-04 measurement mismatch post kernel hot-patch',
    remediation: 'Re-measured boot sequence & key re-attested automatically at 04:15:22Z',
    status: 'RESOLVED',
  },
  {
    id: 'FAIL-2026-10-09-02',
    nodeId: 'RTEE-SGX-002',
    timestamp: '2026-10-09T18:45:00Z',
    cause: 'Quote expiration due to stale TCB advisory release',
    remediation: 'Updated CPU microcode to patch 0x27 and refreshed enclave quote',
    status: 'REMEDIATED',
  },
];

export const GITOPS_ZERO_TRUST_POSTURE = {
  policyEnforcement: 'ENFORCED (OPA/Kyverno Policy Gate)',
  gitopsCommitHash: fakeHash('gitops-commit-2026-10-10'),
  gitopsSignatureStatus: 'VERIFIED (ML-DSA-65 / Cosign Signed)',
  policyGateStatus: 'PASSED (142/142 rules satisfied)',
  networkPolicyCoverage: '97% (mTLS via SPIFFE/SPIRE)',
  vaultSealStatus: 'SEALED (Shamir Threshold 3/5 active)',
  keyRotationSchedule: 'Automated 30-day rotation schedule active; next key cycle in 4 days (2026-10-14 00:00 UTC).',
};
