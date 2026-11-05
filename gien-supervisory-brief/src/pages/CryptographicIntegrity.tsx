import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Cpu,
  Database,
  ExternalLink,
  Eye,
  FileCode,
  GitBranch,
  Info,
  Key,
  Layers,
  Lock,
  Network,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  Terminal,
  X,
  Zap,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import CodeBlock from '../components/CodeBlock';
import DetailDrawer from '../components/DetailDrawer';
import ExpandableSection from '../components/ExpandableSection';
import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import ProgressBar from '../components/ProgressBar';
import StatusBadge, { KV } from '../components/StatusBadge';
import { useGovernance } from '../context/GovernanceContext';
import {
  ATTESTATION_FAILURES,
  AUDIT_LEDGER_ENTRIES,
  DAG_BLOCKS,
  FAIRNESS_PIPELINE,
  GITOPS_ZERO_TRUST_POSTURE,
  PROOF_TYPE_BREAKDOWN,
  RTEE_NODES,
  TEE_GAUGE_SUMMARY,
  VK_ROTATION_DATA,
  WORM_COMPLIANCE_DETAILS,
  ZK_VOTING_STATUS,
  type DagNode,
  type LedgerAuditEntry,
} from '../data/cryptoData';
import {
  LAST_BLOCK_SIGNATURE,
  LEDGER_BLOCK_NUMBER,
  MERKLE_ROOT,
  PQC_ALGORITHMS,
} from '../data/gienData';
import { fakeHash, fakeSignature, truncateHash } from '../data/helpers';
import type { RteeNode } from '../types';

export default function CryptographicIntegrity() {
  const { role } = useGovernance();
  const isExecutive = role === 'EXECUTIVE';

  // State for pagination & drawers
  const [auditPage, setAuditPage] = useState(0);
  const rowsPerPage = 5;

  const [selectedBlock, setSelectedBlock] = useState<DagNode | null>(null);
  const [selectedEntry, setSelectedEntry] = useState<LedgerAuditEntry | null>(null);
  const [selectedRteeNode, setSelectedRteeNode] = useState<RteeNode | null>(null);
  const [merkleDrawerOpen, setMerkleDrawerOpen] = useState(false);
  const [rteeSearch, setRteeSearch] = useState('');
  const [rteeFilter, setRteeFilter] = useState<'ALL' | 'VALID' | 'STALE' | 'FAILED'>('ALL');

  // Ledger Pagination math
  const totalPages = Math.ceil(AUDIT_LEDGER_ENTRIES.length / rowsPerPage);
  const paginatedAuditEntries = useMemo(() => {
    const start = auditPage * rowsPerPage;
    return AUDIT_LEDGER_ENTRIES.slice(start, start + rowsPerPage);
  }, [auditPage]);

  // Filtered RTEE Nodes
  const filteredRteeNodes = useMemo(() => {
    return RTEE_NODES.filter((node) => {
      const matchesSearch =
        node.id.toLowerCase().includes(rteeSearch.toLowerCase()) ||
        node.platform.toLowerCase().includes(rteeSearch.toLowerCase()) ||
        node.type.toLowerCase().includes(rteeSearch.toLowerCase());
      const matchesFilter = rteeFilter === 'ALL' || node.attestationStatus === rteeFilter;
      return matchesSearch && matchesFilter;
    });
  }, [rteeSearch, rteeFilter]);

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <PageHeader
        title="Cryptographic Integrity & Post-Quantum Provenance"
        subtitle="Post-Quantum WORM Audit Ledger, ZK-Proof Pipelines, and Hardware TEE/TPM Remote Attestation"
        crumbs={[
          { label: 'GIEN Governance', to: '/dashboard' },
          { label: 'Cryptographic Integrity' },
        ]}
        actions={
          <div className="flex items-center gap-3">
            <StatusBadge variant="VERIFIED" label="WORM DAG INTACT" />
            <span className="hidden font-mono text-xs text-cyan-400 sm:inline">
              FIPS 204/205/206 ACTIVE
            </span>
          </div>
        }
      />

      {/* Role Notice for Executive View */}
      {isExecutive && (
        <div className="flex items-center gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-300">
          <Info size={18} className="shrink-0 text-amber-400" />
          <div>
            <span className="font-semibold text-amber-200">EXECUTIVE VIEW ACTIVE:</span> High-level
            cryptographic integrity and regulatory compliance indicators are fully presented below.
            Detailed PCR byte-level digests and low-level enclave quotes are masked for executive overview.
          </div>
        </div>
      )}

      {/* SECTION A: Post-Quantum WORM Merkle-DAG Audit Ledger */}
      <section className="space-y-6">
        <div className="flex flex-col gap-2 border-b border-gray-800 pb-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-400">
              <Lock size={18} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-gray-100">
                Section A — Post-Quantum WORM Merkle-DAG Audit Ledger
              </h2>
              <p className="text-xs text-gray-400">
                Immutable ledger rooted in ML-DSA-65 post-quantum signatures & S3 Legal Hold WORM
              </p>
            </div>
          </div>
          <StatusBadge variant="VERIFIED" label="LEDGER INTACT" />
        </div>

        {/* Root Anchor & Latest Block Overview Cards */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {/* Status Badge Card */}
          <div className="flex flex-col justify-between rounded-lg border border-gray-700 bg-gray-800/60 p-4">
            <div className="flex items-start justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                Ledger Health
              </span>
              <StatusBadge variant="VERIFIED" label="INTACT" />
            </div>
            <div className="my-3 flex items-center gap-3">
              <ShieldCheck size={28} className="text-cyan-400" />
              <div>
                <div className="font-mono text-xl font-bold text-gray-100">Treaty-Grade</div>
                <div className="text-xs text-gray-400">100% Merkle Path Validated</div>
              </div>
            </div>
            <div className="border-t border-gray-700/60 pt-2 text-xs text-gray-400">
              SEC Rule 17a-4(f) WORM Compliant
            </div>
          </div>

          {/* Merkle Root Interactive Card */}
          <button
            type="button"
            onClick={() => setMerkleDrawerOpen(true)}
            className="flex flex-col justify-between rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-4 text-left transition-all hover:border-cyan-400 hover:bg-cyan-950/40"
          >
            <div className="flex items-start justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                Merkle Root (Click to Inspect)
              </span>
              <Eye size={16} className="text-cyan-400" />
            </div>
            <div className="my-2">
              <div className="font-mono text-sm font-bold text-cyan-200">
                {truncateHash(MERKLE_ROOT, 14, 8)}
              </div>
              <div className="mt-1 text-xs text-gray-400">
                Post-Quantum State Root Anchor (FIPS 204)
              </div>
            </div>
            <div className="border-t border-cyan-800/40 pt-2 text-[11px] text-cyan-300/80">
              Click for full DAG root details & legal hold metadata
            </div>
          </button>

          {/* Last Block Card */}
          <div className="flex flex-col justify-between rounded-lg border border-gray-700 bg-gray-800/60 p-4">
            <div className="flex items-start justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                Latest Sealed Block
              </span>
              <span className="font-mono text-xs font-bold text-indigo-400">
                #{LEDGER_BLOCK_NUMBER.toLocaleString()}
              </span>
            </div>
            <div className="my-2 space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-gray-400">Timestamp:</span>
                <span className="font-mono text-gray-200">2026-10-12T08:58:45Z</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-gray-400">Transactions:</span>
                <span className="font-mono text-gray-200">4,280 txns</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-gray-400">Signature:</span>
                <span className="font-mono text-cyan-400">
                  {truncateHash(LAST_BLOCK_SIGNATURE, 8, 6)}
                </span>
              </div>
            </div>
            <div className="border-t border-gray-700/60 pt-2 text-xs text-gray-400">
              ML-DSA-65 Signed & WORM Sealed
            </div>
          </div>
        </div>

        {/* PQC Algorithm Suite Table */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4">
          <div className="mb-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Key size={16} className="text-indigo-400" />
              <h3 className="text-sm font-semibold text-gray-200">
                Post-Quantum Cryptography (PQC) Algorithm Suite
              </h3>
            </div>
            <span className="text-xs text-gray-400">NIST FIPS 203 / 204 / 205 / 206 Standards</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-gray-700 bg-gray-900/60 font-semibold text-gray-400">
                <tr>
                  <th className="px-3 py-2">Algorithm Name</th>
                  <th className="px-3 py-2">NIST Standard</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Public Key Size</th>
                  <th className="px-3 py-2">Last Rotation</th>
                </tr>
              </thead>
              <tbody className="divide-y border-gray-700/50 text-gray-300">
                {PQC_ALGORITHMS.map((algo) => (
                  <tr key={algo.name} className="hover:bg-gray-800/50">
                    <td className="px-3 py-2.5 font-mono font-medium text-gray-100">{algo.name}</td>
                    <td className="px-3 py-2.5 text-gray-300">{algo.standard}</td>
                    <td className="px-3 py-2.5">
                      <StatusBadge variant={algo.status} />
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">
                      {algo.keySizeBytes.toLocaleString()} Bytes
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-400">
                      {algo.lastRotation.replace('T', ' ').replace('Z', ' UTC')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Merkle-DAG SVG Visualization */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4">
          <div className="mb-4 flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h3 className="text-sm font-semibold text-gray-200">
                Merkle-DAG Topology & Branch Verification
              </h3>
              <p className="text-xs text-gray-400">
                Visualizing recent block lineage, parallel attestation branches, and convergence points
              </p>
            </div>
            <span className="font-mono text-xs text-cyan-400">10 Blocks • 2 Branch Points</span>
          </div>

          {/* Custom Hand-rolled Interactive SVG Merkle-DAG */}
          <div className="overflow-x-auto rounded-lg border border-gray-800 bg-gray-950 p-4">
            <svg
              viewBox="0 0 960 220"
              className="w-full min-w-[700px]"
              role="img"
              aria-label="Merkle-DAG Visualization with branch points"
            >
              <defs>
                <linearGradient id="dagLineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#6366f1" stopOpacity="0.8" />
                </linearGradient>
                <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
              </defs>

              {/* Connecting Edges */}
              {/* Root -> KeyRotation */}
              <line x1="60" y1="110" x2="140" y2="110" stroke="#06b6d4" strokeWidth="2" />
              {/* KeyRotation -> BranchPoint */}
              <line x1="140" y1="110" x2="220" y2="110" stroke="#06b6d4" strokeWidth="2" />

              {/* BranchPoint -> Branch A (TEE Quote) */}
              <path
                d="M 220 110 C 260 110, 280 50, 320 50"
                fill="none"
                stroke="#f59e0b"
                strokeWidth="2"
                strokeDasharray="4 2"
              />
              {/* BranchPoint -> Branch B (zkML Proof) */}
              <path
                d="M 220 110 C 260 110, 280 170, 320 170"
                fill="none"
                stroke="#a855f7"
                strokeWidth="2"
                strokeDasharray="4 2"
              />

              {/* Branch A -> Re-converge Merge */}
              <path
                d="M 320 50 C 370 50, 390 110, 430 110"
                fill="none"
                stroke="#f59e0b"
                strokeWidth="2"
              />
              {/* Branch B -> Re-converge Merge */}
              <path
                d="M 320 170 C 370 170, 390 110, 430 110"
                fill="none"
                stroke="#a855f7"
                strokeWidth="2"
              />

              {/* Merge -> Anchor Audit */}
              <line x1="430" y1="110" x2="530" y2="110" stroke="#6366f1" strokeWidth="2" />
              {/* Anchor Audit -> Invariant Seal */}
              <line x1="530" y1="110" x2="630" y2="110" stroke="#6366f1" strokeWidth="2" />
              {/* Invariant Seal -> Key Sync */}
              <line x1="630" y1="110" x2="730" y2="110" stroke="#6366f1" strokeWidth="2" />
              {/* Key Sync -> HEAD */}
              <line x1="730" y1="110" x2="840" y2="110" stroke="#10b981" strokeWidth="2.5" />

              {/* Block Nodes */}
              {DAG_BLOCKS.map((blk) => {
                // Determine SVG coords based on block id
                let x = 60;
                let y = 110;
                let color = '#06b6d4';

                if (blk.id === 'blk-8412328') {
                  x = 60;
                  y = 110;
                } else if (blk.id === 'blk-8412329') {
                  x = 140;
                  y = 110;
                } else if (blk.id === 'blk-8412330') {
                  x = 220;
                  y = 110;
                  color = '#38bdf8';
                } else if (blk.id === 'blk-8412331') {
                  x = 320;
                  y = 50;
                  color = '#f59e0b';
                } else if (blk.id === 'blk-8412332') {
                  x = 320;
                  y = 170;
                  color = '#a855f7';
                } else if (blk.id === 'blk-8412333') {
                  x = 430;
                  y = 110;
                  color = '#6366f1';
                } else if (blk.id === 'blk-8412334') {
                  x = 530;
                  y = 110;
                } else if (blk.id === 'blk-8412335') {
                  x = 630;
                  y = 110;
                } else if (blk.id === 'blk-8412336') {
                  x = 730;
                  y = 110;
                } else if (blk.id === 'blk-8412337') {
                  x = 840;
                  y = 110;
                  color = '#10b981';
                }

                const isHead = blk.id === 'blk-8412337';

                return (
                  <g
                    key={blk.id}
                    onClick={() => setSelectedBlock(blk)}
                    className="cursor-pointer transition-transform hover:scale-105"
                  >
                    {isHead && (
                      <circle
                        cx={x}
                        cy={y}
                        r="22"
                        fill="none"
                        stroke="#10b981"
                        strokeWidth="1.5"
                        opacity="0.6"
                      />
                    )}
                    <circle
                      cx={x}
                      cy={y}
                      r={blk.isBranch ? '16' : '14'}
                      fill={color}
                      opacity={0.2}
                    />
                    <circle
                      cx={x}
                      cy={y}
                      r={blk.isBranch ? '10' : '8'}
                      fill={color}
                      filter={isHead ? 'url(#glow)' : undefined}
                    />
                    <text
                      x={x}
                      y={y - 20}
                      fill="#e5e7eb"
                      fontSize="10"
                      fontWeight="600"
                      textAnchor="middle"
                      fontFamily="monospace"
                    >
                      #{blk.blockNumber}
                    </text>
                    <text
                      x={x}
                      y={y + 24}
                      fill="#9ca3af"
                      fontSize="9"
                      textAnchor="middle"
                    >
                      {blk.opType.replace('_', ' ')}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* SEC Rule 17a-4 WORM Compliance Panel */}
        <ExpandableSection
          title="SEC Rule 17a-4(f) WORM Compliance & Retention Matrix"
          subtitle="Hardware-enforced non-rewritable, non-erasable (WORM) storage alignment details"
          defaultOpen={true}
          badge={<StatusBadge variant="VERIFIED" label="WORM VERIFIED" />}
        >
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="space-y-2 rounded-md bg-gray-900/60 p-3 text-xs">
              <KV label="Rule Reference" value={WORM_COMPLIANCE_DETAILS.rule} />
              <KV
                label="Compliance Status"
                value={<StatusBadge variant={WORM_COMPLIANCE_DETAILS.status} />}
              />
              <KV
                label="Active Retention Schedule"
                value={WORM_COMPLIANCE_DETAILS.retentionActive}
              />
              <KV
                label="Immutability Mechanism"
                value={WORM_COMPLIANCE_DETAILS.immutabilityMechanism}
              />
            </div>
            <div className="space-y-2 rounded-md bg-gray-900/60 p-3 text-xs">
              <KV label="Last Inter-Agency Audit" value={WORM_COMPLIANCE_DETAILS.lastAuditDate} />
              <KV label="Audit Jurisdiction" value={WORM_COMPLIANCE_DETAILS.auditJurisdiction} />
              <KV
                label="Deletion Prevention"
                value={
                  <span className="font-semibold text-emerald-400">
                    {WORM_COMPLIANCE_DETAILS.deletionPrevention}
                  </span>
                }
              />
              <KV
                label="Compliance Certificate"
                value={WORM_COMPLIANCE_DETAILS.complianceReference}
                mono
              />
            </div>
          </div>
        </ExpandableSection>

        {/* Paginated Ledger Audit Trail Table */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4">
          <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h3 className="text-sm font-semibold text-gray-200">
                WORM Ledger Audit Trail (14 Blocks)
              </h3>
              <p className="text-xs text-gray-400">
                Click any record to inspect raw ML-DSA-65 signature and verification details
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <span>
                Page <strong className="text-gray-200">{auditPage + 1}</strong> of{' '}
                <strong className="text-gray-200">{totalPages}</strong>
              </span>
              <button
                type="button"
                disabled={auditPage === 0}
                onClick={() => setAuditPage((p) => Math.max(0, p - 1))}
                className="rounded border border-gray-700 p-1 hover:bg-gray-700 disabled:opacity-40"
                aria-label="Previous audit ledger page"
              >
                <ChevronLeft size={16} />
              </button>
              <button
                type="button"
                disabled={auditPage >= totalPages - 1}
                onClick={() => setAuditPage((p) => Math.min(totalPages - 1, p + 1))}
                className="rounded border border-gray-700 p-1 hover:bg-gray-700 disabled:opacity-40"
                aria-label="Next audit ledger page"
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-gray-700 bg-gray-900/60 font-semibold text-gray-400">
                <tr>
                  <th className="px-3 py-2">Block #</th>
                  <th className="px-3 py-2">Block Hash</th>
                  <th className="px-3 py-2">Operation Type</th>
                  <th className="px-3 py-2">Tx Count</th>
                  <th className="px-3 py-2">Timestamp</th>
                  <th className="px-3 py-2">Verification</th>
                  <th className="px-3 py-2">ML-DSA Signature</th>
                </tr>
              </thead>
              <tbody className="divide-y border-gray-700/50 text-gray-300">
                {paginatedAuditEntries.map((entry) => (
                  <tr
                    key={entry.blockNumber}
                    onClick={() => setSelectedEntry(entry)}
                    className="cursor-pointer transition-colors hover:bg-gray-800/80"
                  >
                    <td className="px-3 py-2.5 font-mono font-medium text-cyan-400">
                      #{entry.blockNumber}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">
                      {truncateHash(entry.hash, 8, 4)}
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="inline-block rounded bg-gray-900 px-2 py-0.5 font-mono text-[10px] text-gray-300">
                        {entry.operationType}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">
                      {entry.txCount.toLocaleString()}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-400">
                      {entry.timestamp.replace('T', ' ').replace('Z', '')}
                    </td>
                    <td className="px-3 py-2.5">
                      <StatusBadge variant={entry.verificationStatus} />
                    </td>
                    <td className="px-3 py-2.5 font-mono text-indigo-300">
                      {truncateHash(entry.signature, 8, 4)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* SECTION B: zkML / zk-SNARK / zk-STARK / SnarkPack Proof Pipeline */}
      <section className="space-y-6">
        <div className="flex flex-col gap-2 border-b border-gray-800 pb-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-purple-500/30 bg-purple-500/10 text-purple-400">
              <Zap size={18} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-gray-100">
                Section B — Zero-Knowledge Proof Pipelines
              </h2>
              <p className="text-xs text-gray-400">
                zkML model inference, zk-SNARK/STARK circuit execution & SnarkPack proof aggregation
              </p>
            </div>
          </div>
          <StatusBadge variant="ACTIVE" label="PIPELINE LIVENESS 100%" />
        </div>

        {/* Metric Cards Grid */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <MetricCard
            label="Proofs Generated (24h)"
            value="14,250,000"
            status="NOMINAL"
            footer="zkML, SNARK, STARK & SnarkPack"
          />
          <MetricCard
            label="Proofs Verified (24h)"
            value="14,249,998"
            status="VERIFIED"
            footer="99.9999% verification rate"
          />
          <MetricCard
            label="Pipeline Failure Rate"
            value="0.0013%"
            status="NOMINAL"
            footer="Well within SLA threshold (<0.01%)"
          />
          <MetricCard
            label="Enclave Liveness"
            value="100.0%"
            status="ACTIVE"
            footer="Zero downtime in 24h window"
          />
        </div>

        {/* SVG Pipeline Flowchart */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4">
          <div className="mb-3">
            <h3 className="text-sm font-semibold text-gray-200">
              Zero-Knowledge Verification Architecture
            </h3>
            <p className="text-xs text-gray-400">
              End-to-end dataflow from circuit constraint generation to WORM ledger anchoring
            </p>
          </div>

          <div className="flex flex-col items-center justify-between gap-3 rounded-lg border border-gray-800 bg-gray-950 p-4 lg:flex-row">
            {/* Step 1 */}
            <div className="flex w-full flex-1 items-center gap-3 rounded-md border border-purple-500/30 bg-purple-950/30 p-3">
              <Cpu size={24} className="shrink-0 text-purple-400" />
              <div>
                <div className="text-xs font-semibold text-purple-200">
                  1. Proof Generation
                </div>
                <div className="text-[11px] text-gray-400">
                  zkML (2^20), SNARK (2^18), STARK (51KB)
                </div>
              </div>
            </div>

            <ChevronRight className="hidden text-gray-600 lg:block shrink-0" size={20} />

            {/* Step 2 */}
            <div className="flex w-full flex-1 items-center gap-3 rounded-md border border-indigo-500/30 bg-indigo-950/30 p-3">
              <Layers size={24} className="shrink-0 text-indigo-400" />
              <div>
                <div className="text-xs font-semibold text-indigo-200">
                  2. SnarkPack Aggregation
                </div>
                <div className="text-[11px] text-gray-400">
                  40:1 Batch Compression (475k batches)
                </div>
              </div>
            </div>

            <ChevronRight className="hidden text-gray-600 lg:block shrink-0" size={20} />

            {/* Step 3 */}
            <div className="flex w-full flex-1 items-center gap-3 rounded-md border border-cyan-500/30 bg-cyan-950/30 p-3">
              <ShieldCheck size={24} className="shrink-0 text-cyan-400" />
              <div>
                <div className="text-xs font-semibold text-cyan-200">
                  3. Enclave Verification
                </div>
                <div className="text-[11px] text-gray-400">
                  TEE/SGX Hardware Verification Kernel
                </div>
              </div>
            </div>

            <ChevronRight className="hidden text-gray-600 lg:block shrink-0" size={20} />

            {/* Step 4 */}
            <div className="flex w-full flex-1 items-center gap-3 rounded-md border border-emerald-500/30 bg-emerald-950/30 p-3">
              <Database size={24} className="shrink-0 text-emerald-400" />
              <div>
                <div className="text-xs font-semibold text-emerald-200">
                  4. Ledger Anchoring
                </div>
                <div className="text-[11px] text-gray-400">
                  WORM Merkle-DAG Block #14,892,401
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Proof-Type Breakdown Table */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-gray-200">
              Proof System Breakdown & Circuit Performance
            </h3>
            <span className="text-xs text-gray-400">24-Hour Aggregated Metrics</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-gray-700 bg-gray-900/60 font-semibold text-gray-400">
                <tr>
                  <th className="px-3 py-2">Proof System</th>
                  <th className="px-3 py-2">Description</th>
                  <th className="px-3 py-2">24h Proof Volume</th>
                  <th className="px-3 py-2">Avg Gen Time</th>
                  <th className="px-3 py-2">Circuit & Constraint Specs</th>
                  <th className="px-3 py-2">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y border-gray-700/50 text-gray-300">
                {PROOF_TYPE_BREAKDOWN.map((row) => (
                  <tr key={row.type} className="hover:bg-gray-800/50">
                    <td className="px-3 py-2.5 font-mono font-bold text-purple-300">
                      {row.type}
                    </td>
                    <td className="px-3 py-2.5 font-medium text-gray-200">{row.name}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-200">
                      {row.type === 'zkML'
                        ? '14,250,000'
                        : row.type === 'zk-SNARK'
                        ? '12,100,000'
                        : row.type === 'zk-STARK'
                        ? '2,150,000'
                        : '475,000 batches'}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{row.avgGenTime}</td>
                    <td className="px-3 py-2.5 text-gray-400">{row.circuitDetails}</td>
                    <td className="px-3 py-2.5">
                      <StatusBadge variant={row.statusBadge} label={row.statusText} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Key Rotation & Fairness Grid */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Verification Key Rotation Progress */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <RefreshCw size={16} className="text-cyan-400" />
                <h3 className="text-sm font-semibold text-gray-200">
                  Verification Key Rotation Protocol
                </h3>
              </div>
              <StatusBadge variant="ACTIVE" label="ROTATION IN PROGRESS" />
            </div>

            <p className="text-xs text-gray-400">
              Migrating legacy verification keys ({VK_ROTATION_DATA.currentKey}) to post-quantum active standards ({VK_ROTATION_DATA.nextKey}).
            </p>

            <ProgressBar
              value={78}
              threshold={100}
              label="vkFMv2 DEPRECATED → vkFMv3 ACTIVE Transition Progress"
              color="bg-cyan-500"
            />

            <div className="grid grid-cols-2 gap-2 rounded bg-gray-900/60 p-2 text-xs">
              <div>
                <span className="text-gray-500">Current Key:</span>
                <p className="font-mono text-gray-300">vkFMv2 DEPRECATED</p>
              </div>
              <div>
                <span className="text-gray-500">Target Key:</span>
                <p className="font-mono text-cyan-300">vkFMv3 ACTIVE</p>
              </div>
              <div>
                <span className="text-gray-500">Target Completion:</span>
                <p className="font-mono text-gray-300">2026-10-13 00:00 UTC</p>
              </div>
              <div>
                <span className="text-gray-500">Validation Mode:</span>
                <p className="font-mono text-emerald-400">Dual-Sign Active</p>
              </div>
            </div>
          </div>

          {/* Fairness Proof Pipeline */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield size={16} className="text-emerald-400" />
                <h3 className="text-sm font-semibold text-gray-200">
                  Fairness & Parity Proof Pipeline
                </h3>
              </div>
              <StatusBadge variant="VERIFIED" label="PARITY OK" />
            </div>

            <p className="text-xs text-gray-400">
              Zero-knowledge mathematical proofs guaranteeing algorithmic demographic parity and non-discrimination.
            </p>

            <div className="divide-y divide-gray-700/60 border-t border-b border-gray-700/60">
              {FAIRNESS_PIPELINE.map((f) => (
                <div key={f.metricName} className="flex items-center justify-between py-2 text-xs">
                  <div>
                    <span className="font-medium text-gray-200">{f.metricName}</span>
                    <span className="ml-2 font-mono text-gray-400">
                      ({f.proofCount.toLocaleString()} proofs)
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-emerald-400">{f.parityDelta}</span>
                    <StatusBadge variant={f.status} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Zero-Knowledge Voting Protocol Status */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <FileCode size={16} className="text-indigo-400" />
              <div>
                <h3 className="text-sm font-semibold text-gray-200">
                  Zero-Knowledge Voting Protocol Status
                </h3>
                <p className="text-xs text-gray-400">
                  Proposal {ZK_VOTING_STATUS.proposalRef} • Last Ballot Cast: 2026-10-11
                </p>
              </div>
            </div>
            <StatusBadge variant="VERIFIED" label="96 ZK BALLOTS VERIFIED" />
          </div>

          <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4 rounded bg-gray-900/60 p-3 text-xs">
            <div>
              <span className="text-gray-500">Verified Ballots:</span>
              <p className="font-mono text-base font-semibold text-emerald-400">
                {ZK_VOTING_STATUS.verifiedBallots} / {ZK_VOTING_STATUS.ballotCount}
              </p>
            </div>
            <div>
              <span className="text-gray-500">Nullifier Collisions:</span>
              <p className="font-mono text-base font-semibold text-cyan-400">
                {ZK_VOTING_STATUS.nullifierCollisions} (0%)
              </p>
            </div>
            <div>
              <span className="text-gray-500">Anonymity Set Size:</span>
              <p className="font-mono text-base font-semibold text-purple-400">
                {ZK_VOTING_STATUS.anonymitySetSize} Voters
              </p>
            </div>
            <div>
              <span className="text-gray-500">Protocol Status:</span>
              <p className="font-mono text-base font-semibold text-emerald-400">
                {ZK_VOTING_STATUS.protocolStatus}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION C: Hardware TEE / TPM / vTPM / RTEE Remote Attestation */}
      <section className="space-y-6">
        <div className="flex flex-col gap-2 border-b border-gray-800 pb-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
              <Server size={18} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-gray-100">
                Section C — Hardware TEE / TPM Attestation
              </h2>
              <p className="text-xs text-gray-400">
                Remote TEE enclave quote verification across Intel SGX/TDX, AMD SEV-SNP, and vTPM nodes
              </p>
            </div>
          </div>
          <StatusBadge variant="VERIFIED" label="8,020 NODES ATTESTED" />
        </div>

        {/* Attestation Gauge & Coherence Grid */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Hand-Rolled SVG Ring Gauge */}
          <div className="flex flex-col items-center justify-center rounded-lg border border-gray-700 bg-gray-800/40 p-5 text-center">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400">
              Enclave Attestation Density
            </h3>

            <div className="relative my-4 flex items-center justify-center">
              <svg width="140" height="140" viewBox="0 0 140 140" role="img" aria-label="Attestation density 99%">
                <circle
                  cx="70"
                  cy="70"
                  r="56"
                  fill="none"
                  stroke="#374151"
                  strokeWidth="12"
                />
                <circle
                  cx="70"
                  cy="70"
                  r="56"
                  fill="none"
                  stroke="#10b981"
                  strokeWidth="12"
                  strokeDasharray="351.8"
                  strokeDashoffset="3.5" // 99% filled
                  strokeLinecap="round"
                  transform="rotate(-90 70 70)"
                />
              </svg>
              <div className="absolute flex flex-col items-center">
                <span className="font-mono text-2xl font-bold text-gray-100">99.0%</span>
                <span className="text-[10px] text-emerald-400">7,940 / 8,020 Active</span>
              </div>
            </div>

            <p className="text-xs text-gray-400">
              8,020 Remote TEE / TPM 2.0 enclaves under continuous hardware quote attestation
            </p>
          </div>

          {/* Coherence & Summary Cards */}
          <div className="flex flex-col justify-between space-y-3 rounded-lg border border-gray-700 bg-gray-800/40 p-4">
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                Attestation Coherence Score
              </span>
              <div className="mt-1 font-mono text-3xl font-bold text-cyan-400">0.9994</div>
              <p className="mt-1 text-xs text-gray-400">
                Cross-enclave measurement consensus across distributed clusters
              </p>
            </div>

            <div className="space-y-2 border-t border-gray-700/60 pt-3 text-xs">
              <KV label="Intel SGX/TDX Active Enclaves" value="3,410 nodes" />
              <KV label="AMD SEV-SNP Confidential VMs" value="2,890 nodes" />
              <KV label="GCP/Azure Shielded vTPM" value="1,720 nodes" />
              <KV label="Attestation Stale / Refreshing" value="80 nodes (1.0%)" />
            </div>
          </div>


          {/* Attestation Density Heatmap (hand-rolled SVG, no chart library) */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4 lg:col-span-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                RTEE Attestation Density Heatmap
              </span>
              <div className="flex items-center gap-3 text-[10px] text-gray-400">
                <span className="flex items-center gap-1">
                  <span className="inline-block h-2 w-2 rounded-sm bg-emerald-500" /> attested
                </span>
                <span className="flex items-center gap-1">
                  <span className="inline-block h-2 w-2 rounded-sm bg-amber-500" /> stale
                </span>
                <span className="flex items-center gap-1">
                  <span className="inline-block h-2 w-2 rounded-sm bg-red-500" /> failed
                </span>
              </div>
            </div>
            <svg viewBox="0 0 320 132" className="mt-3 w-full" role="img" aria-label="Attestation density heatmap across 8,020 RTEE nodes">
              {Array.from({ length: 12 }).map((_, r) =>
                Array.from({ length: 32 }).map((__, c) => {
                  const seed = fakeHash(`attest-heat-${r}-${c}`);
                  const v = parseInt(seed.slice(2, 6), 16) % 1000;
                  const fill = v < 990 ? '#10b981' : v < 997 ? '#f59e0b' : '#ef4444';
                  return (
                    <rect
                      key={`${r}-${c}`}
                      x={c * 10 + 1}
                      y={r * 11 + 1}
                      width={8}
                      height={9}
                      rx={1.2}
                      fill={fill}
                      opacity={0.35 + (v % 60) / 100}
                    />
                  );
                })
              )}
            </svg>
            <p className="mt-2 text-[11px] text-gray-500">
              384 cluster cells aggregating 8,020 RTEE nodes; 99.0% attested, 1.0% stale or refreshing, 0 failed at snapshot time.
            </p>
          </div>

          {/* Attestation Failures Log Card */}
          <div className="flex flex-col justify-between space-y-3 rounded-lg border border-gray-700 bg-gray-800/40 p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                Recent Attestation Events
              </span>
              <span className="font-mono text-xs text-emerald-400">2 Remediated</span>
            </div>

            <div className="space-y-2 overflow-y-auto max-h-48 pr-1">
              {ATTESTATION_FAILURES.map((fail) => (
                <div key={fail.id} className="rounded bg-gray-900/60 p-2 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-amber-400">{fail.nodeId}</span>
                    <StatusBadge variant="NOMINAL" label={fail.status} />
                  </div>
                  <p className="text-gray-300">{fail.cause}</p>
                  <p className="text-[11px] text-gray-400">{fail.remediation}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* RTEE Node Attestation Table */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4 space-y-3">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <Network size={16} className="text-cyan-400" />
              <h3 className="text-sm font-semibold text-gray-200">
                RTEE Node Attestation Register
              </h3>
            </div>

            {/* Filter and search */}
            <div className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                placeholder="Search nodes or platform..."
                value={rteeSearch}
                onChange={(e) => setRteeSearch(e.target.value)}
                className="rounded border border-gray-700 bg-gray-900 px-2.5 py-1 text-xs text-gray-200 placeholder-gray-500 focus:border-cyan-500 focus:outline-none"
              />
              <select
                value={rteeFilter}
                onChange={(e) =>
                  setRteeFilter(e.target.value as 'ALL' | 'VALID' | 'STALE' | 'FAILED')
                }
                className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200 focus:border-cyan-500 focus:outline-none"
              >
                <option value="ALL">All Statuses</option>
                <option value="VALID">VALID</option>
                <option value="STALE">STALE</option>
                <option value="FAILED">FAILED</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-gray-700 bg-gray-900/60 font-semibold text-gray-400">
                <tr>
                  <th className="px-3 py-2">Node ID</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Platform</th>
                  <th className="px-3 py-2">Attestation Status</th>
                  <th className="px-3 py-2">Last Quote Timestamp</th>
                  <th className="px-3 py-2">PCR Digest Summary</th>
                  <th className="px-3 py-2">Firmware</th>
                </tr>
              </thead>
              <tbody className="divide-y border-gray-700/50 text-gray-300">
                {filteredRteeNodes.map((node) => (
                  <tr
                    key={node.id}
                    onClick={() => setSelectedRteeNode(node)}
                    className="cursor-pointer transition-colors hover:bg-gray-800/80"
                  >
                    <td className="px-3 py-2.5 font-mono font-bold text-gray-100">{node.id}</td>
                    <td className="px-3 py-2.5 font-mono text-gray-300">{node.type}</td>
                    <td className="px-3 py-2.5 text-gray-200">{node.platform}</td>
                    <td className="px-3 py-2.5">
                      <StatusBadge
                        variant={
                          node.attestationStatus === 'VALID'
                            ? 'VERIFIED'
                            : node.attestationStatus === 'STALE'
                            ? 'ELEVATED'
                            : 'CRITICAL'
                        }
                        label={node.attestationStatus}
                      />
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-400">
                      {node.lastQuote.replace('T', ' ').replace('Z', '')}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-cyan-300">
                      {isExecutive ? '• • • • • • • •' : node.pcrSummary}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-gray-400">{node.firmware}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Kubernetes / GitOps Zero-Trust Posture Sub-Panel */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal size={16} className="text-indigo-400" />
              <h3 className="text-sm font-semibold text-gray-200">
                Kubernetes & GitOps Zero-Trust Posture
              </h3>
            </div>
            <StatusBadge variant="VERIFIED" label="GATE PASSED" />
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            <div className="rounded bg-gray-900/60 p-3 text-xs space-y-1.5">
              <span className="text-gray-400">Policy Enforcement</span>
              <p className="font-semibold text-emerald-400">
                {GITOPS_ZERO_TRUST_POSTURE.policyEnforcement}
              </p>
              <p className="text-[11px] text-gray-500">
                Strict admission webhook checking container images & PQC Cosign signatures
              </p>
            </div>

            <div className="rounded bg-gray-900/60 p-3 text-xs space-y-1.5">
              <span className="text-gray-400">GitOps Commit & Signature</span>
              <p className="font-mono text-cyan-300">
                {truncateHash(fakeHash('gitops-commit-2026-10-12'), 10, 6)}
              </p>
              <p className="text-[11px] text-emerald-400">
                {GITOPS_ZERO_TRUST_POSTURE.gitopsSignatureStatus}
              </p>
            </div>

            <div className="rounded bg-gray-900/60 p-3 text-xs space-y-1.5">
              <span className="text-gray-400">Network & Vault Posture</span>
              <p className="font-semibold text-purple-300">
                99% mTLS Coverage (SPIFFE/SPIRE)
              </p>
              <p className="text-[11px] text-emerald-400">
                {GITOPS_ZERO_TRUST_POSTURE.vaultSealStatus}
              </p>
            </div>
          </div>

          <div className="rounded bg-gray-950 p-3 text-xs text-gray-300 font-mono">
            <span className="text-gray-500"># Automated Key Lifecycle & Schedule:</span>
            <p className="mt-1 text-gray-300">
              {GITOPS_ZERO_TRUST_POSTURE.keyRotationSchedule}
            </p>
          </div>
        </div>
      </section>

      {/* DRAWERS */}

      {/* 1. Merkle Root Drawer */}
      <DetailDrawer
        open={merkleDrawerOpen}
        onClose={() => setMerkleDrawerOpen(false)}
        title="Post-Quantum Merkle Root & Root Anchor Inspection"
        subtitle="Cryptographic proof tree root details & legal hold metadata"
      >
        <div className="space-y-4 text-xs text-gray-300">
          <div className="rounded bg-gray-950 p-3 font-mono">
            <span className="text-gray-500"># Full Merkle Root Hash:</span>
            <p className="mt-1 text-cyan-300 break-all">{MERKLE_ROOT}</p>
          </div>

          <div className="space-y-2 rounded bg-gray-800/60 p-3">
            <KV label="Genesis Block Anchor" value="#8412300 (2026-09-01)" mono />
            <KV label="Latest Block Anchor" value={`#${LEDGER_BLOCK_NUMBER.toLocaleString()}`} mono />
            <KV label="Tree Depth" value="28 Levels (2^28 leaves capacity)" />
            <KV label="PQC Signature Standard" value="ML-DSA-65 (NIST FIPS 204)" />
            <KV label="WORM Legal Hold Status" value="ACTIVE S3 OBJECT LOCK" />
          </div>

          <div>
            <h4 className="mb-2 font-semibold text-gray-200">Merkle Root Verification Code Logic</h4>
            <CodeBlock
              language="typescript"
              code={`// Deterministic Merkle Root Verification Kernel
import { sha3_512, mlDsa65Verify } from '@gien/crypto';

export function verifyStateRoot(merkleRoot: string, signature: string, publicKey: string): boolean {
  const rootBuffer = Buffer.from(merkleRoot.replace('0x', ''), 'hex');
  const sigValid = mlDsa65Verify(rootBuffer, signature, publicKey);
  return sigValid && verifyWormObjectLock('S3_LEGAL_HOLD_ACTIVE');
}`}
            />
          </div>
        </div>
      </DetailDrawer>

      {/* 2. Block Detail Drawer */}
      <DetailDrawer
        open={selectedBlock !== null}
        onClose={() => setSelectedBlock(null)}
        title={selectedBlock ? `Block #${selectedBlock.blockNumber} Detail` : ''}
        subtitle={selectedBlock ? `OpType: ${selectedBlock.opType}` : ''}
      >
        {selectedBlock && (
          <div className="space-y-4 text-xs text-gray-300">
            <div className="space-y-2 rounded bg-gray-800/60 p-3">
              <KV label="Block Number" value={`#${selectedBlock.blockNumber}`} mono />
              <KV label="Label" value={selectedBlock.label} />
              <KV label="Timestamp" value={selectedBlock.timestamp} mono />
              <KV label="Transaction Count" value={`${selectedBlock.txCount} txns`} />
              <KV
                label="Parent Block IDs"
                value={selectedBlock.parentIds.join(', ') || 'None (Genesis Root)'}
                mono
              />
            </div>

            <div className="rounded bg-gray-950 p-3 font-mono">
              <span className="text-gray-500"># Block Hash:</span>
              <p className="mt-1 text-cyan-300 break-all">{selectedBlock.hash}</p>
            </div>

            <div>
              <h4 className="mb-2 font-semibold text-gray-200">Raw Block Verification Payload</h4>
              <CodeBlock
                language="json"
                code={JSON.stringify(selectedBlock, null, 2)}
              />
            </div>
          </div>
        )}
      </DetailDrawer>

      {/* 3. Audit Entry Detail Drawer */}
      <DetailDrawer
        open={selectedEntry !== null}
        onClose={() => setSelectedEntry(null)}
        title={selectedEntry ? `Ledger Block #${selectedEntry.blockNumber} Audit Record` : ''}
        subtitle={selectedEntry ? `Operation: ${selectedEntry.operationType}` : ''}
      >
        {selectedEntry && (
          <div className="space-y-4 text-xs text-gray-300">
            <div className="space-y-2 rounded bg-gray-800/60 p-3">
              <KV label="Block Number" value={`#${selectedEntry.blockNumber}`} mono />
              <KV label="Timestamp" value={selectedEntry.timestamp} mono />
              <KV label="Transactions Sealed" value={`${selectedEntry.txCount}`} />
              <KV
                label="Verification Status"
                value={<StatusBadge variant={selectedEntry.verificationStatus} />}
              />
            </div>

            <div className="space-y-2 rounded bg-gray-950 p-3 font-mono">
              <div>
                <span className="text-gray-500"># Full Block Hash:</span>
                <p className="mt-1 text-cyan-300 break-all">{selectedEntry.hash}</p>
              </div>
              <div className="pt-2 border-t border-gray-800">
                <span className="text-gray-500"># ML-DSA-65 Signature:</span>
                <p className="mt-1 text-indigo-300 break-all">{selectedEntry.signature}</p>
              </div>
            </div>

            <div>
              <h4 className="mb-2 font-semibold text-gray-200">Full Audit Entry Payload</h4>
              <CodeBlock
                language="json"
                code={JSON.stringify(selectedEntry, null, 2)}
              />
            </div>
          </div>
        )}
      </DetailDrawer>

      {/* 4. RTEE Node Detail Drawer */}
      <DetailDrawer
        open={selectedRteeNode !== null}
        onClose={() => setSelectedRteeNode(null)}
        title={selectedRteeNode ? `Attestation Quote: ${selectedRteeNode.id}` : ''}
        subtitle={selectedRteeNode ? `Platform: ${selectedRteeNode.platform}` : ''}
      >
        {selectedRteeNode && (
          <div className="space-y-4 text-xs text-gray-300">
            <div className="space-y-2 rounded bg-gray-800/60 p-3">
              <KV label="Node Identifier" value={selectedRteeNode.id} mono />
              <KV label="Enclave Type" value={selectedRteeNode.type} />
              <KV label="Platform / TEE Family" value={selectedRteeNode.platform} />
              <KV
                label="Attestation Status"
                value={
                  <StatusBadge
                    variant={
                      selectedRteeNode.attestationStatus === 'VALID'
                        ? 'VERIFIED'
                        : selectedRteeNode.attestationStatus === 'STALE'
                        ? 'ELEVATED'
                        : 'CRITICAL'
                    }
                    label={selectedRteeNode.attestationStatus}
                  />
                }
              />
              <KV label="Last Quote Timestamp" value={selectedRteeNode.lastQuote} mono />
              <KV label="Firmware / Patch Level" value={selectedRteeNode.firmware} mono />
            </div>

            {!isExecutive && (
              <div className="rounded bg-gray-950 p-3 font-mono">
                <span className="text-gray-500"># PCR Digest Summary (PCR[0..7]):</span>
                <p className="mt-1 text-cyan-300 break-all">{selectedRteeNode.pcrSummary}</p>
              </div>
            )}

            <div>
              <h4 className="mb-2 font-semibold text-gray-200 font-sans">Enclave Attestation Structure</h4>
              <CodeBlock
                language="json"
                code={JSON.stringify(selectedRteeNode, null, 2)}
              />
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
