import {
  Activity,
  ArrowUpRight,
  BookOpen,
  Check,
  ChevronRight,
  Clock,
  Cpu,
  FileCheck2,
  FileText,
  Info,
  Layers,
  Lock,
  Network,
  Scale,
  Server,
  Shield,
  ShieldCheck,
  TriangleAlert,
  Workflow,
  Zap,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import ExpandableSection from '../components/ExpandableSection';
import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import ProgressBar from '../components/ProgressBar';
import StatusBadge, { KV } from '../components/StatusBadge';
import TaggedDocument from '../components/TaggedDocument';
import { useGovernance } from '../context/GovernanceContext';
import {
  DASHBOARD_QUICK_LINKS,
  EXECUTIVE_RECOMMENDATIONS,
  STAR_MOE_EXPERTS,
  SUPERVISORY_CHECKPOINTS,
} from '../data/dashboardData';
import { FILING_METADATA } from '../data/gienData';
import { truncateHash } from '../data/helpers';

export default function Dashboard() {
  const { role, evaluationWindow, filingRef } = useGovernance();

  // Map quick link icons
  const getQuickLinkIcon = (path: string) => {
    switch (path) {
      case '/risk-indices':
        return Activity;
      case '/compliance':
        return Scale;
      case '/cryptographic-integrity':
        return Lock;
      case '/digital-twin':
        return Server;
      case '/control-domains':
        return Layers;
      case '/constitutional':
        return ShieldCheck;
      case '/scenario-planner':
        return Workflow;
      case '/submission-packages':
        return FileCheck2;
      default:
        return FileText;
    }
  };

  const isExecutive = role === 'EXECUTIVE';
  const isEducation = role === 'EDUCATION';
  const isRegulatorOrInstitution = role === 'REGULATOR' || role === 'INSTITUTION';

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <PageHeader
        title="Daily Supervisory Brief"
        subtitle={`24-Hour Evaluation Window ending 2026-10-12T09:00Z (${evaluationWindow})`}
        crumbs={[{ label: 'GIEN Governance' }, { label: 'Daily Supervisory Brief' }]}
        actions={
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 rounded-full border border-gray-700 bg-gray-900 px-3 py-1 text-xs font-medium text-gray-300">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              Role: <span className="font-semibold text-indigo-400">{role}</span>
            </span>
            <StatusBadge variant="ELEVATED" label="POSTURE: ELEVATED" />
          </div>
        }
      />

      {/* TIER 1: Executive Summary, Posture, Metric Cards, Transmission Row */}
      <div className="grid gap-6">
        {/* TaggedDocument Executive Summary */}
        <TaggedDocument
          title="Daily Supervisory Executive Brief & Telemetry Analysis"
          abstract="Simulated 24-hour multi-jurisdictional supervisory evaluation cycle for the Global Interstellar Executive Network (GIEN)."
        >
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <p className="text-gray-300 leading-relaxed max-w-3xl">
              The overall planetary governance posture remains <span className="font-semibold text-amber-400">ELEVATED</span>.
              Currently, <span className="font-semibold text-emerald-400">10 of 12</span> systemic risk indices remain in NOMINAL territory.
              Contagion risk (C-SRI at 0.327) and Autonomous Agent risk (A-SRI at 0.463) are contained under Tier-1 supervisory oversight.
              The post-quantum Merkle-DAG audit ledger integrity is 100% <span className="font-semibold text-cyan-400 font-mono">INTACT</span> with zero signature breaks.
            </p>
            <div className="shrink-0 flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3">
              <TriangleAlert className="h-5 w-5 text-amber-400 shrink-0" />
              <div>
                <p className="text-xs font-semibold text-amber-300">Active Alert Watch</p>
                <p className="text-[11px] text-amber-200/80">C-SRI & A-SRI exceeding primary baseline thresholds</p>
              </div>
            </div>
          </div>
        </TaggedDocument>

        {/* 4-Column Stat Metric Cards Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard
            label="Overall Compliance"
            value="95"
            unit="%"
            status="NOMINAL"
            threshold="Min 90%"
            footer={<span className="text-xs text-gray-400">20 Frameworks mapped (OSCAL 1.1.2)</span>}
          />
          <MetricCard
            label="Active Vulnerabilities"
            value="1"
            status="ELEVATED"
            threshold="Target 0"
            footer={<span className="text-xs text-amber-400 font-mono">GIEN-ZTAI-02 (CVSS 8.8)</span>}
          />
          <MetricCard
            label="PQC Ledger Integrity"
            value="100%"
            status="VERIFIED"
            threshold="100% Required"
            footer={<span className="text-xs text-cyan-400 font-mono">ML-DSA-65 • WORM Intact</span>}
          />
          <MetricCard
            label="Invariants Verified"
            value="24/24"
            status="NOMINAL"
            threshold="24/24 Active"
            footer={<span className="text-xs text-emerald-400 font-mono">100% TLA+ Proof Coverage</span>}
          />
        </div>

        {/* Supervisory College Transmission Row */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/60 p-5">
          <div className="flex items-center justify-between mb-4 border-b border-gray-700/60 pb-3">
            <div className="flex items-center gap-2">
              <Network className="h-5 w-5 text-indigo-400" />
              <h3 className="text-sm font-semibold text-gray-100">Supervisory College Transmission Cadence</h3>
            </div>
            <span className="font-mono text-xs text-gray-400">Filing Ref: {filingRef}</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {SUPERVISORY_CHECKPOINTS.map((cp) => {
              const isCompleted = cp.status === 'COMPLETED';
              return (
                <div
                  key={cp.time}
                  className={`rounded-md border p-3 flex flex-col justify-between transition-colors ${
                    isCompleted
                      ? 'border-emerald-500/30 bg-emerald-950/10'
                      : 'border-blue-500/30 bg-blue-950/10'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="font-mono text-xs font-bold text-gray-300">{cp.time}</span>
                    <span
                      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold ${
                        isCompleted
                          ? 'bg-emerald-500/20 text-emerald-400'
                          : 'bg-blue-500/20 text-blue-400'
                      }`}
                    >
                      {isCompleted ? (
                        <>
                          <Check className="h-3 w-3" /> DONE
                        </>
                      ) : (
                        <>
                          <Clock className="h-3 w-3 animate-spin" /> PENDING
                        </>
                      )}
                    </span>
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold text-gray-200 mb-1">{cp.title}</h4>
                    <p className="text-[11px] text-gray-400 line-clamp-2">{cp.detail}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* TIER 2: ExpandableSection 'Operational Status Summary' (Regulator / Institution View) */}
      {isRegulatorOrInstitution && (
        <ExpandableSection
          title="Operational Status Summary"
          subtitle="Sentinel engines, mesh coherence, SCP exceptions, zero-trust vulnerabilities & StaR-MoE expert routing"
          defaultOpen={true}
          badge={<StatusBadge variant="ACTIVE" label="OPERATIONAL" />}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 p-2">
            {/* Sentinel v2.4 */}
            <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-emerald-400" />
                  <h4 className="text-xs font-bold text-gray-200">Sentinel v2.4 Engine</h4>
                </div>
                <StatusBadge variant="ACTIVE" />
              </div>
              <div className="space-y-1 divide-y divide-gray-800 text-xs">
                <KV label="Heartbeat" value="2026-10-12T08:58:00Z" mono />
                <KV label="Drift L2 Norm" value="0.024 (Nominal < 0.05)" mono />
                <KV label="Engine Mode" value="Real-time Telemetry Processing" />
              </div>
            </div>

            {/* Omni-Sentinel Mesh v4.0 */}
            <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-indigo-400" />
                  <h4 className="text-xs font-bold text-gray-200">Omni-Sentinel Mesh v4.0</h4>
                </div>
                <span className="font-mono text-xs font-semibold text-emerald-400">99.2% Coherence</span>
              </div>
              <div className="space-y-1 divide-y divide-gray-800 text-xs">
                <KV label="Active Enclave Nodes" value="512 Nodes" mono />
                <KV label="Anomalies Flagged" value="2 Nodes (Quarantined)" mono />
                <KV label="Topology Health" value="Sub-millisecond Cross-Sync" />
              </div>
            </div>

            {/* Unified SCP v3.0 */}
            <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Zap className="h-4 w-4 text-amber-400" />
                  <h4 className="text-xs font-bold text-gray-200">Unified SCP v3.0</h4>
                </div>
                <StatusBadge variant="ELEVATED" label="POST-TRANSMISSION" />
              </div>
              <div className="space-y-1 divide-y divide-gray-800 text-xs">
                <KV label="Execution Phase" value="Post-Transmission / Exception Handling" />
                <KV label="SLA Exceptions" value="3 SLA Exceptions (Logged)" mono />
                <KV label="Epoch Seal" value="PENDING (23:59 UTC Seal)" mono />
              </div>
            </div>

            {/* Vulnerability GIEN-ZTAI-02 */}
            <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-4 space-y-3 md:col-span-2 lg:col-span-1">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <TriangleAlert className="h-4 w-4 text-red-400" />
                  <h4 className="text-xs font-bold text-gray-200">Vulnerability: GIEN-ZTAI-02</h4>
                </div>
                <span className="rounded bg-red-500/20 px-1.5 py-0.5 font-mono text-[10px] font-bold text-red-400">
                  CVSS 8.8
                </span>
              </div>
              <p className="text-[11px] text-gray-300">
                TEE Sandbox Escape vector detected in legacy attestation shim. Remediation patch deployment active.
              </p>
              <div className="space-y-2">
                <ProgressBar value={85} label="Patch Deployment Progress" color="bg-indigo-500" />
                <KV label="Remediation ETA" value="2026-10-12T15:00:00Z" mono />
              </div>
            </div>

            {/* StaR-MoE Expert Routing Heatmap */}
            <div className="rounded-lg border border-gray-700 bg-gray-900/60 p-4 space-y-3 md:col-span-2 lg:col-span-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4 text-cyan-400" />
                  <h4 className="text-xs font-bold text-gray-200">StaR-MoE Routing & Load Heatmap</h4>
                </div>
                <span className="font-mono text-xs text-gray-300">
                  Stability Index: <span className="text-emerald-400 font-bold">0.93</span>
                </span>
              </div>

              {/* 8 Expert cells colored emerald/amber by load via opacity */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {STAR_MOE_EXPERTS.map((exp) => {
                  const isElevated = exp.status === 'ELEVATED';
                  const bgClass = isElevated ? 'bg-amber-500' : 'bg-emerald-500';
                  const borderClass = isElevated ? 'border-amber-500/40' : 'border-emerald-500/40';
                  const opacityStyle = { opacity: Math.max(0.35, exp.loadPercent / 100) };

                  return (
                    <div
                      key={exp.id}
                      className={`relative overflow-hidden rounded border ${borderClass} bg-gray-950 p-2 text-left`}
                    >
                      <div
                        className={`absolute inset-0 ${bgClass} pointer-events-none transition-opacity`}
                        style={opacityStyle}
                      />
                      <div className="relative z-10 flex flex-col justify-between h-full">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] font-bold text-gray-200">{exp.id}</span>
                          <span className="font-mono text-[10px] font-bold text-gray-100">{exp.loadPercent}%</span>
                        </div>
                        <p className="text-[11px] font-semibold text-gray-100 truncate mt-1">{exp.name}</p>
                        <p className="text-[9px] text-gray-300 truncate">{exp.taskCategory}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </ExpandableSection>
      )}

      {/* EXECUTIVE ROLE CALLOUT: Strategic Recommendations Card */}
      {isExecutive && (
        <div className="rounded-lg border border-purple-500/30 bg-purple-950/20 p-5 space-y-3">
          <div className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-purple-400" />
            <h3 className="text-sm font-bold text-purple-200">Executive Strategic Recommendations</h3>
          </div>
          <ul className="space-y-2 text-xs text-gray-200">
            {EXECUTIVE_RECOMMENDATIONS.map((rec, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="font-mono text-purple-400 font-bold">•</span>
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* EDUCATION ROLE CALLOUT: Educational Callout Box */}
      {isEducation && (
        <div className="rounded-lg border border-indigo-500/30 bg-indigo-950/20 p-5 space-y-3">
          <div className="flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-indigo-400" />
            <h3 className="text-sm font-bold text-indigo-200">Educational Briefing: GIEN Supervisory Architecture</h3>
          </div>
          <p className="text-xs text-gray-300 leading-relaxed">
            The Global Interstellar Executive Network (GIEN) operates a continuous 24-hour supervisory cycle. Telemetry feeds from 512 distributed RTEE enclave nodes evaluate 12 core Systemic Risk Indices (SRIs). Post-quantum signatures (ML-DSA-65) seal the WORM Merkle-DAG audit log before transmission to international supervisory college endpoints at fixed daily checkpoints.
          </p>
        </div>
      )}

      {/* TIER 3: Navigation Grid to 8 Sub-Pages */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
            Supervisory Modules & Deep-Dive Telemetry
          </h3>
          <span className="text-xs text-gray-500 font-mono">8 Core Navigation Endpoints</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {DASHBOARD_QUICK_LINKS.map((link) => {
            const IconComponent = getQuickLinkIcon(link.to);
            return (
              <Link
                key={link.to}
                to={link.to}
                className="group relative flex flex-col justify-between rounded-lg border border-gray-700 bg-gray-800/40 p-4 transition-all duration-200 hover:border-indigo-500/60 hover:bg-gray-800/90"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="p-2 rounded-md bg-indigo-500/10 text-indigo-400 group-hover:bg-indigo-500/20 group-hover:text-indigo-300">
                      <IconComponent className="h-5 w-5" />
                    </span>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-gray-500">
                      {link.category}
                    </span>
                  </div>
                  <h4 className="text-sm font-semibold text-gray-100 group-hover:text-indigo-300 flex items-center justify-between">
                    {link.title}
                    <ArrowUpRight className="h-4 w-4 opacity-0 group-hover:opacity-100 transition-opacity text-indigo-400" />
                  </h4>
                  <p className="mt-1 text-xs text-gray-400 leading-normal line-clamp-2">{link.description}</p>
                </div>
                <div className="mt-3 flex items-center gap-1 text-[11px] font-medium text-indigo-400 group-hover:translate-x-0.5 transition-transform">
                  Access Telemetry <ChevronRight className="h-3 w-3" />
                </div>
              </Link>
            );
          })}
        </div>
      </div>

      {/* FILING REFERENCE BLOCK */}
      <div className="rounded-lg border border-gray-700/80 bg-gray-900/80 p-5">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-gray-800 pb-3 mb-3">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-widest text-indigo-400">
              [SGR-028 OFFICIAL REGULATORY FILING]
            </span>
            <h3 className="text-base font-bold text-gray-100 font-mono">{FILING_METADATA.reference}</h3>
          </div>
          <StatusBadge variant={FILING_METADATA.verificationStatus} label="STATUS: VERIFIED" />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div>
            <p className="text-gray-400">Filing Date</p>
            <p className="font-mono font-semibold text-gray-200">{FILING_METADATA.filingDate}</p>
          </div>
          <div>
            <p className="text-gray-400">PQC Signature Scheme</p>
            <p className="font-mono font-semibold text-cyan-400">{FILING_METADATA.pqcSignatureAlgorithm}</p>
          </div>
          <div>
            <p className="text-gray-400">Corpus Manifest Hash</p>
            <p className="font-mono text-gray-300">{truncateHash(FILING_METADATA.corpusManifestHash)}</p>
          </div>
          <div>
            <p className="text-gray-400">Merkle Root</p>
            <p className="font-mono text-gray-300">{truncateHash(FILING_METADATA.merkleRoot)}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
