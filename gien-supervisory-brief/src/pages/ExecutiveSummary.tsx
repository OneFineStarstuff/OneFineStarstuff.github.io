import { useLocation, Link } from 'react-router-dom';
import {
  ArrowRight,
  CircleCheck,
  Clock,
  FileText,
  Layers,
  Lock,
  ShieldAlert,
} from 'lucide-react';
import ExpandableSection from '../components/ExpandableSection';
import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import SparklineChart from '../components/SparklineChart';
import StatusBadge from '../components/StatusBadge';
import TaggedDocument from '../components/TaggedDocument';
import Watermark from '../components/Watermark';
import { useGovernance } from '../context/GovernanceContext';
import { EXECUTIVE_DECISIONS } from '../data/execData';
import { RISK_INDICES } from '../data/gienData';

export default function ExecutiveSummary() {
  const { role, phase, filingRef, evaluationWindow } = useGovernance();
  const { search } = useLocation();

  // Select 6 risk indices for the compact sparkline risk strip
  const sparklineIndices = RISK_INDICES.slice(0, 6);

  return (
    <div className="space-y-6">
      <Watermark />

      <PageHeader
        title="Executive Governance Summary"
        subtitle="Board-level posture overview, active decision items, and critical systemic risk indicators."
        crumbs={[{ label: 'Home', to: `/${search}` }, { label: 'Executive Summary' }]}
        actions={
          <div className="flex items-center gap-2">
            <span className="rounded bg-indigo-500/10 px-2.5 py-1 text-xs font-mono text-indigo-400 border border-indigo-500/20">
              Ref: {filingRef}
            </span>
            <span className="rounded bg-amber-500/10 px-2.5 py-1 text-xs font-mono text-amber-400 border border-amber-500/20">
              Posture: ELEVATED
            </span>
          </div>
        }
      />

      {/* Tagged Executive Abstract Document */}
      <TaggedDocument
        title="GIEN Planetary Governance Executive Briefing"
        abstract="Supervisory evaluation cycle briefing confirming overall posture ELEVATED, 10 out of 12 systemic risk indices operating within nominal thresholds, and 100% formal invariant verification under TLA+ specifications."
      >
        <p>
          <strong>Operational Posture &amp; Contagion State:</strong> The current planetary governance posture is classified as <strong>ELEVATED</strong>. 10 of 12 systemic risk telemetry indices remain nominal across all monitored channels. Contagion Systemic Risk Index (C-SRI) at 0.33 (threshold 0.30) and Autonomous Supervisory Agent SRI (A-SRI) at 0.48 (threshold 0.45) remain actively contained within designated tolerance bounds without requiring emergency escalation to the supervisory college.
        </p>
        <p>
          <strong>Cryptographic Integrity &amp; Invariants:</strong> The audit ledger state is verified <strong>INTACT</strong> under post-quantum WORM Merkle-DAG attestation. All 24 of 24 constitutional invariants (CI-001 through CI-024) are fully verified under TLA+ formal specifications with zero invariant violations recorded. Treaty-grade regulatory adherence across international governance accords stands at 100%.
        </p>
        <p>
          <strong>Zero-Trust AI Infrastructure Readiness:</strong> The Zero-Trust AI Control Domain (GIEN-ZTAI-02) is operating at 85% deployment completion. Real-time TEE attestation quotes and vTPM state validations confirm hardware-enforced policy execution across all active supervisory agent nodes.
        </p>
      </TaggedDocument>

      {/* 4 Metric Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Systemic Posture"
          value="ELEVATED"
          status="ELEVATED"
          footer={
            <div className="flex items-center justify-between text-xs text-gray-400">
              <span>10 / 12 Indices Nominal</span>
              <span className="font-mono text-amber-400">C-SRI &amp; A-SRI</span>
            </div>
          }
        />
        <MetricCard
          label="Contagion Risk (C-SRI)"
          value="0.330"
          threshold="0.300"
          trend={0.019}
          status="ELEVATED"
          footer={
            <div className="text-xs text-gray-400">
              Contagion channel stress in G-SIFI Cluster 3
            </div>
          }
        />
        <MetricCard
          label="Invariant Pass Rate"
          value="24 / 24"
          unit="(100%)"
          status="VERIFIED"
          footer={
            <div className="flex items-center gap-1 text-xs text-cyan-400">
              <CircleCheck size={12} />
              <span>TLA+ Formal Proofs Intact</span>
            </div>
          }
        />
        <MetricCard
          label="Agent Drift (A-SRI)"
          value="0.480"
          threshold="0.450"
          trend={0.021}
          status="ELEVATED"
          footer={
            <div className="text-xs text-gray-400">
              Autonomous fleet drift watch active
            </div>
          }
        />
      </div>

      {/* Compact Risk Strip with 6 Sparklines */}
      <div className="rounded-lg border border-gray-700 bg-gray-800/60 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
            Key Telemetry Indices (24h Trend Strip)
          </h2>
          <span className="text-xs text-gray-400 font-mono">Window: {evaluationWindow}</span>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {sparklineIndices.map((idx) => (
            <div
              key={idx.id}
              className="flex items-center justify-between rounded-md border border-gray-700/60 bg-gray-900/60 p-3"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-indigo-300">{idx.id}</span>
                  <StatusBadge variant={idx.status} />
                </div>
                <div className="text-xs text-gray-400 truncate max-w-[140px]">{idx.name}</div>
                <div className="font-mono text-sm font-semibold text-gray-100">
                  {idx.value}{' '}
                  <span className="text-[10px] text-gray-500 font-normal">(thresh {idx.threshold})</span>
                </div>
              </div>

              <div className="shrink-0">
                <SparklineChart
                  data={idx.history}
                  width={100}
                  height={32}
                  color={idx.status === 'ELEVATED' ? '#f59e0b' : idx.status === 'CRITICAL' ? '#ef4444' : '#10b981'}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Decisions Required This Cycle */}
      <div className="rounded-lg border border-gray-700 bg-gray-800/60 p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-gray-700/80 pb-3">
          <div className="flex items-center gap-2">
            <Clock className="h-5 w-5 text-indigo-400" />
            <h2 className="text-base font-semibold text-gray-100">Decisions Required This Cycle</h2>
          </div>
          <span className="rounded bg-indigo-500/10 px-2 py-0.5 text-xs font-mono text-indigo-300 border border-indigo-500/20">
            Cycle: {phase}
          </span>
        </div>

        <div className="space-y-3">
          {EXECUTIVE_DECISIONS.map((item) => (
            <div
              key={item.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-gray-700/80 bg-gray-900/70 p-4 hover:border-gray-600 transition-colors"
            >
              <div className="space-y-1 max-w-xl">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs text-indigo-400 font-bold">{item.id}</span>
                  <span className="text-sm font-semibold text-gray-100">{item.title}</span>
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] font-bold border ${
                      item.impact === 'CRITICAL'
                        ? 'bg-red-500/15 text-red-400 border-red-500/30'
                        : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                    }`}
                  >
                    {item.impact}
                  </span>
                </div>
                <p className="text-xs text-gray-300">{item.description}</p>
                <div className="flex items-center gap-4 text-[11px] text-gray-400 font-mono pt-1">
                  <span>Owner: {item.owner}</span>
                  <span>Due: {item.dueDate}</span>
                </div>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                <StatusBadge variant={item.status === 'PREPARED' ? 'VERIFIED' : item.status === 'UNDER_REVIEW' ? 'ACTIVE' : 'PENDING'} label={item.status.replace('_', ' ')} />
                <Link
                  to={`/submission-packages${search}`}
                  className="inline-flex items-center gap-1 rounded bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-500 transition-colors"
                >
                  <span>Review Brief</span>
                  <ArrowRight size={12} />
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Read Next Navigation Grid */}
      <div className="space-y-3">
        <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider">
          Recommended Executive Navigation
        </h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Link
            to={`/risk-indices${search}`}
            className="group flex flex-col justify-between rounded-lg border border-gray-700 bg-gray-800/60 p-4 hover:border-indigo-500 hover:bg-gray-800/90 transition-all"
          >
            <div>
              <div className="flex items-center justify-between text-xs text-gray-400 font-mono">
                <span>01</span>
                <ShieldAlert size={16} className="text-indigo-400 group-hover:text-indigo-300" />
              </div>
              <h3 className="mt-2 text-sm font-semibold text-gray-100 group-hover:text-indigo-300">
                Systemic Risk Telemetry
              </h3>
              <p className="mt-1 text-xs text-gray-400">
                Inspect 12 real-time telemetry indices including C-SRI and A-SRI breakdown.
              </p>
            </div>
            <div className="mt-3 flex items-center gap-1 text-xs text-indigo-400 font-medium">
              <span>View Telemetry</span>
              <ArrowRight size={12} className="group-hover:translate-x-1 transition-transform" />
            </div>
          </Link>

          <Link
            to={`/compliance${search}`}
            className="group flex flex-col justify-between rounded-lg border border-gray-700 bg-gray-800/60 p-4 hover:border-indigo-500 hover:bg-gray-800/90 transition-all"
          >
            <div>
              <div className="flex items-center justify-between text-xs text-gray-400 font-mono">
                <span>02</span>
                <FileText size={16} className="text-indigo-400 group-hover:text-indigo-300" />
              </div>
              <h3 className="mt-2 text-sm font-semibold text-gray-100 group-hover:text-indigo-300">
                Compliance Matrix
              </h3>
              <p className="mt-1 text-xs text-gray-400">
                Cross-jurisdictional OSCAL controls mapped across 20 regulatory frameworks.
              </p>
            </div>
            <div className="mt-3 flex items-center gap-1 text-xs text-indigo-400 font-medium">
              <span>View Matrix</span>
              <ArrowRight size={12} className="group-hover:translate-x-1 transition-transform" />
            </div>
          </Link>

          <Link
            to={`/roadmap${search}`}
            className="group flex flex-col justify-between rounded-lg border border-gray-700 bg-gray-800/60 p-4 hover:border-indigo-500 hover:bg-gray-800/90 transition-all"
          >
            <div>
              <div className="flex items-center justify-between text-xs text-gray-400 font-mono">
                <span>03</span>
                <Layers size={16} className="text-indigo-400 group-hover:text-indigo-300" />
              </div>
              <h3 className="mt-2 text-sm font-semibold text-gray-100 group-hover:text-indigo-300">
                Supervisory Roadmap
              </h3>
              <p className="mt-1 text-xs text-gray-400">
                12-month supervisory timeline of regulatory milestones &amp; attestations.
              </p>
            </div>
            <div className="mt-3 flex items-center gap-1 text-xs text-indigo-400 font-medium">
              <span>View Roadmap</span>
              <ArrowRight size={12} className="group-hover:translate-x-1 transition-transform" />
            </div>
          </Link>

          <Link
            to={`/alerts${search}`}
            className="group flex flex-col justify-between rounded-lg border border-gray-700 bg-gray-800/60 p-4 hover:border-indigo-500 hover:bg-gray-800/90 transition-all"
          >
            <div>
              <div className="flex items-center justify-between text-xs text-gray-400 font-mono">
                <span>04</span>
                <Lock size={16} className="text-indigo-400 group-hover:text-indigo-300" />
              </div>
              <h3 className="mt-2 text-sm font-semibold text-gray-100 group-hover:text-indigo-300">
                Governance Alerts
              </h3>
              <p className="mt-1 text-xs text-gray-400">
                Historical incident log, severity filters, and exportable audit records.
              </p>
            </div>
            <div className="mt-3 flex items-center gap-1 text-xs text-indigo-400 font-medium">
              <span>View Alerts</span>
              <ArrowRight size={12} className="group-hover:translate-x-1 transition-transform" />
            </div>
          </Link>
        </div>
      </div>

      {/* Engineering Implications Section (shown when role !== EXECUTIVE) */}
      {role !== 'EXECUTIVE' && (
        <ExpandableSection
          title="Engineering & Technical Implementation Details"
          subtitle={`Technical countermeasures, TLA+ invariant assertions, and PQC rotation parameters active under ${role} mode`}
          defaultOpen={false}
          badge={<StatusBadge variant="ACTIVE" label="ENGINEERING LAYER" />}
        >
          <div className="space-y-3 pt-2 text-xs text-gray-300 leading-relaxed">
            <div className="rounded border border-indigo-500/20 bg-indigo-950/20 p-3">
              <h4 className="font-mono font-bold text-indigo-300 uppercase tracking-wider mb-1">
                Contagion Countermeasures &amp; Invariant CI-003
              </h4>
              <p>
                Contagion Systemic Risk Index (C-SRI = 0.33) is monitored by TLA+ invariant CI-003 (`SystemicContainment`). In the event C-SRI exceeds 0.35 for 6 consecutive evaluation cycles, the kernel automatically engages Tier-2 collateral isolation buffers in G-SIFI cluster 3.
              </p>
            </div>
            <div className="rounded border border-amber-500/20 bg-amber-950/20 p-3">
              <h4 className="font-mono font-bold text-amber-300 uppercase tracking-wider mb-1">
                Agent Drift Containment Protocol (A-SRI = 0.48)
              </h4>
              <p>
                Autonomous Supervisory Agent drift delta (Δ_drift = 0.031) triggers StaR-MoE routing load rebalancing. If A-SRI exceeds 0.55, the execution engine initiates hard containment on Agent fleet Delta, restricting execution to pre-signed deterministic playbooks.
              </p>
            </div>
            <div className="rounded border border-cyan-500/20 bg-cyan-950/20 p-3">
              <h4 className="font-mono font-bold text-cyan-300 uppercase tracking-wider mb-1">
                PQC Ledger &amp; Key Rotation State
              </h4>
              <p>
                Post-quantum cryptographic migration is governed under NIST FIPS 203/204/205. Key pair vkFMv3 rotation is scheduled for Q1 2027 under milestone MS-2027-02, maintaining dual RSA-4096 / ML-DSA-65 signature chains during transition.
              </p>
            </div>
          </div>
        </ExpandableSection>
      )}
    </div>
  );
}
