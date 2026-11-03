import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Clock,
  Cpu,
  Database,
  ExternalLink,
  Info,
  Key,
  Lock,
  Network,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Sparkles,
  Zap,
} from 'lucide-react';
import DetailDrawer from '../components/DetailDrawer';
import MetricCard from '../components/MetricCard';
import NodeGraph from '../components/NodeGraph';
import PageHeader from '../components/PageHeader';
import ProgressBar from '../components/ProgressBar';
import SparklineChart from '../components/SparklineChart';
import StatusBadge, { KV } from '../components/StatusBadge';
import TimelineVisualization from '../components/TimelineVisualization';
import { useGovernance } from '../context/GovernanceContext';
import { CONTROL_DOMAINS, INFINITY_PILLARS } from '../data/gienData';
import { fakeHash, truncateHash } from '../data/helpers';
import {
  COMPUTE_ALLOCATIONS,
  DAILY_CYCLE_EVENTS,
  KILL_SWITCH_METADATA,
  MESH_ANOMALIES,
  MESH_COHERENCE_SERIES,
  MESH_EDGES,
  MESH_NODES,
  SENTINEL_COMPONENTS,
  SLA_EXCEPTIONS,
} from '../data/stacksData';
import type { ControlDomain } from '../types';

export default function GovernanceStacks() {
  const { phase, filingRef, evaluationWindow } = useGovernance();

  // Tab State
  const [activeTab, setActiveTab] = useState<'sentinel' | 'mesh' | 'scp'>('sentinel');

  // Allocation toggle for SCP Tab
  const [allocationMode, setAllocationMode] = useState<'baseline' | 'elevated'>('baseline');

  // Selected Control Domain for Drawer
  const [selectedDomain, setSelectedDomain] = useState<ControlDomain | null>(null);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Governance Stacks & Infrastructure"
        subtitle="Operational telemetry for Sentinel v2.4, Omni-Sentinel Mesh v4.0, and Unified SCP v3.0 core stacks."
        crumbs={[{ label: 'Home', to: '/' }, { label: 'Governance Stacks' }]}
        actions={
          <div className="flex items-center gap-2">
            <span className="rounded bg-indigo-500/10 px-2.5 py-1 text-xs font-mono text-indigo-400 border border-indigo-500/20">
              {phase}
            </span>
            <span className="rounded bg-emerald-500/10 px-2.5 py-1 text-xs font-mono text-emerald-400 border border-emerald-500/20">
              Ref: {filingRef}
            </span>
          </div>
        }
      />

      {/* Accessible Tab Navigation */}
      <div className="border-b border-gray-700 bg-gray-900/60 rounded-t-lg p-1">
        <div className="flex flex-wrap gap-2" role="tablist" aria-label="Governance Stacks Tabs">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'sentinel'}
            onClick={() => setActiveTab('sentinel')}
            className={`flex items-center gap-2 rounded-md px-4 py-2.5 text-xs font-semibold transition-all ${
              activeTab === 'sentinel'
                ? 'bg-indigo-600 text-white shadow-md'
                : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
            }`}
          >
            <Shield className="h-4 w-4" />
            <span>Sentinel v2.4</span>
            <span className="rounded bg-emerald-500/20 px-1.5 py-0.5 text-[10px] text-emerald-300 font-mono">
              ACTIVE
            </span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'mesh'}
            onClick={() => setActiveTab('mesh')}
            className={`flex items-center gap-2 rounded-md px-4 py-2.5 text-xs font-semibold transition-all ${
              activeTab === 'mesh'
                ? 'bg-indigo-600 text-white shadow-md'
                : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
            }`}
          >
            <Network className="h-4 w-4" />
            <span>Omni-Sentinel Mesh v4.0</span>
            <span className="rounded bg-indigo-500/20 px-1.5 py-0.5 text-[10px] text-indigo-300 font-mono">
              512 NODES
            </span>
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'scp'}
            onClick={() => setActiveTab('scp')}
            className={`flex items-center gap-2 rounded-md px-4 py-2.5 text-xs font-semibold transition-all ${
              activeTab === 'scp'
                ? 'bg-indigo-600 text-white shadow-md'
                : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
            }`}
          >
            <Clock className="h-4 w-4" />
            <span>Unified SCP v3.0</span>
            <span className="rounded bg-cyan-500/20 px-1.5 py-0.5 text-[10px] text-cyan-300 font-mono">
              DAILY CYCLE
            </span>
          </button>
        </div>
      </div>

      {/* TAB A: Sentinel v2.4 */}
      {activeTab === 'sentinel' && (
        <div className="space-y-6 animate-fadeIn">
          {/* Top Key Metrics */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard
              label="Stack Status"
              value="ACTIVE"
              status="ACTIVE"
              footer={<span className="text-xs text-gray-400 font-mono">Guardian Attestation Verified</span>}
            />
            <MetricCard
              label="Active Model Estate"
              value="14 Models"
              status="NOMINAL"
              footer={<span className="text-xs text-gray-400">StaR-MoE Policy Ensemble</span>}
            />
            <MetricCard
              label="Fleet L2 Drift"
              value="0.031"
              threshold="0.050"
              status="NOMINAL"
              footer={<span className="text-xs text-emerald-400 font-mono">Below 0.05 Threshold</span>}
            />
            <MetricCard
              label="Model Explainability"
              value="0.94"
              threshold="0.90"
              status="NOMINAL"
              footer={<span className="text-xs text-gray-400 font-mono">Fairness Gap: 0.8%</span>}
            />
          </div>

          {/* Key Controls & Kill-Switch Panel */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            {/* Kill-Switch Arbiter Card */}
            <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-red-400 font-semibold text-sm">
                  <ShieldAlert className="h-5 w-5" />
                  <span>Hardware Kill-Switch</span>
                </div>
                <StatusBadge variant="CRITICAL" label="ARMED" />
              </div>

              <p className="text-xs text-gray-300">
                Sub-second enclave quarantine arbiter &amp; automated payload containment circuit breaker.
              </p>

              <div className="space-y-2 border-t border-red-900/40 pt-3">
                <KV label="Last Drill Test" value="2026-10-11 19:30:00 UTC" mono />
                <KV
                  label="On-Chain Heartbeat Hash"
                  value={truncateHash(fakeHash('killswitch-hb'), 10, 6)}
                  mono
                />
                <KV label="Guardian Attestation Ref" value={KILL_SWITCH_METADATA.dossierRef} mono />
              </div>
            </div>

            {/* vkFM Key Rotation Progress Card */}
            <div className="rounded-lg border border-gray-700 bg-gray-800/80 p-4 space-y-3 lg:col-span-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-indigo-400 font-semibold text-sm">
                  <Key className="h-5 w-5" />
                  <span>Verification Key Migration (vkFMv2 → vkFMv3)</span>
                </div>
                <StatusBadge variant="ELEVATED" label="IN PROGRESS" />
              </div>

              <p className="text-xs text-gray-300">
                Phased post-quantum key rotation from Dilithium-2 (v2) to FIPS 204 ML-DSA-65 (v3) across 14 inference shards.
              </p>

              <div className="space-y-2 pt-2">
                <ProgressBar value={78} label="Migration Progress (11/14 Shards Migrated)" color="bg-indigo-500" />
                <div className="flex justify-between text-[11px] text-gray-400 font-mono">
                  <span>vkFMv2 Legacy: 3 Shards</span>
                  <span>vkFMv3 ML-DSA-65: 11 Shards</span>
                  <span>Est. Completion: 2026-10-13</span>
                </div>
              </div>
            </div>
          </div>

          {/* Sub-component Health Grid */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-300 flex items-center gap-2">
              <Server className="h-4 w-4 text-indigo-400" />
              <span>Sentinel Sub-Component Health (12 Microservices)</span>
            </h3>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {SENTINEL_COMPONENTS.map((comp) => (
                <div
                  key={comp.id}
                  className="rounded-lg border border-gray-700/80 bg-gray-900/60 p-3.5 space-y-2 hover:border-indigo-500/40 transition-colors"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-xs font-bold text-gray-200">{comp.name}</div>
                      <div className="text-[10px] font-mono text-gray-400">{comp.version}</div>
                    </div>
                    <StatusBadge variant={comp.status} label={comp.status} />
                  </div>

                  <p className="text-[11px] text-gray-300 line-clamp-2">{comp.description}</p>

                  <div className="flex items-center justify-between text-[10px] font-mono text-gray-400 border-t border-gray-800 pt-2">
                    <span>Heartbeat: {comp.lastHeartbeat}</span>
                    <span className="text-indigo-300">{comp.id}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB B: Omni-Sentinel Mesh v4.0 */}
      {activeTab === 'mesh' && (
        <div className="space-y-6 animate-fadeIn">
          {/* Summary Metrics */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard
              label="Mesh Node Roster"
              value="512 Nodes"
              status="NOMINAL"
              footer={<span className="text-xs text-gray-400">508 Nominal / 3 Degraded / 1 Offline</span>}
            />
            <MetricCard
              label="Coherence Score"
              value="99.2%"
              status="VERIFIED"
              footer={
                <div className="mt-1">
                  <SparklineChart data={MESH_COHERENCE_SERIES} width={120} height={24} color="#10b981" />
                </div>
              }
            />
            <MetricCard
              label="Consensus Status"
              value="NOMINAL"
              status="NOMINAL"
              footer={<span className="text-xs text-gray-400 font-mono">BFT Quorum: 99.8%</span>}
            />
            <MetricCard
              label="Active Anomaly Alerts"
              value={MESH_ANOMALIES.length}
              status={MESH_ANOMALIES.length > 0 ? 'ELEVATED' : 'NOMINAL'}
              footer={<span className="text-xs text-amber-400">2 Transient Latency Spikes</span>}
            />
          </div>

          {/* Mesh Topology SVG Graph & Anomalies */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            {/* Graph Node Canvas */}
            <div className="rounded-lg border border-gray-700 bg-gray-900/80 p-4 space-y-3 lg:col-span-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm font-semibold text-gray-200">
                  <Network className="h-4 w-4 text-indigo-400" />
                  <span>Supervisory Mesh Topology Graph (Representative Shards)</span>
                </div>
                <span className="text-xs text-gray-400 font-mono">12 Primary Hubs Shown</span>
              </div>

              <div className="flex justify-center rounded-lg bg-gray-950 p-4 border border-gray-800">
                <NodeGraph nodes={MESH_NODES} edges={MESH_EDGES} size={500} height={320} />
              </div>

              <div className="flex items-center justify-around text-[11px] text-gray-400 font-mono">
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-emerald-400"></span> Nominal Node
                </span>
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-amber-400"></span> Degraded / Elevated Node
                </span>
                <span className="flex items-center gap-1">
                  <span className="h-2 w-2 rounded-full bg-red-400"></span> Offline Node
                </span>
              </div>
            </div>

            {/* Active Anomalies List */}
            <div className="rounded-lg border border-gray-700 bg-gray-800/80 p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                <div className="flex items-center gap-2 text-sm font-semibold text-amber-400">
                  <CircleAlert className="h-4 w-4" />
                  <span>Active Anomalies ({MESH_ANOMALIES.length})</span>
                </div>
                <StatusBadge variant="ELEVATED" label="ELEVATED" />
              </div>

              <div className="space-y-3">
                {MESH_ANOMALIES.map((anom) => (
                  <div key={anom.id} className="rounded-md border border-amber-500/30 bg-amber-950/20 p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-amber-300">{anom.title}</span>
                      <span className="text-[10px] font-mono text-amber-400">{anom.id}</span>
                    </div>
                    <p className="text-xs text-gray-300">{anom.details}</p>
                    <div className="flex flex-wrap gap-1 pt-1">
                      {anom.nodes.map((n) => (
                        <span key={n} className="rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] text-amber-200 font-mono">
                          {n}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Infinity Pillars Readiness Strip */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/80 p-4 space-y-4">
            <div className="flex items-center justify-between border-b border-gray-700 pb-2">
              <div className="flex items-center gap-2 text-sm font-semibold text-cyan-300">
                <Sparkles className="h-4 w-4 text-cyan-400" />
                <span>Infinity Pillar Readiness Strip (IP-I through IP-VII)</span>
              </div>
              <span className="text-xs text-gray-400 font-mono">Multi-Generational Epoch Readiness</span>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-7">
              {INFINITY_PILLARS.map((pillar) => (
                <div key={pillar.id} className="rounded-md border border-gray-700 bg-gray-900/60 p-2.5 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-cyan-400">{pillar.id}</span>
                    <span
                      className={`text-[9px] font-mono px-1 rounded ${
                        pillar.status === 'ACTIVE'
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : pillar.status === 'INITIALIZING'
                          ? 'bg-amber-500/20 text-amber-300'
                          : 'bg-gray-700 text-gray-400'
                      }`}
                    >
                      {pillar.status}
                    </span>
                  </div>
                  <div className="text-xs font-medium text-gray-200 truncate" title={pillar.name}>
                    {pillar.name}
                  </div>
                  <ProgressBar
                    value={pillar.readinessScore}
                    color={
                      pillar.readinessScore >= 90
                        ? 'bg-emerald-500'
                        : pillar.readinessScore >= 80
                        ? 'bg-indigo-500'
                        : 'bg-amber-500'
                    }
                  />
                  <div className="text-[10px] text-right font-mono text-gray-400">{pillar.readinessScore}%</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB C: Unified SCP v3.0 */}
      {activeTab === 'scp' && (
        <div className="space-y-6 animate-fadeIn">
          {/* Daily 24h Cycle Timeline */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/80 p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-700 pb-3">
              <div>
                <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                  <Clock className="h-4 w-4 text-cyan-400" />
                  <span>Daily SCP Supervisory Cycle Schedule (24h Window)</span>
                </h3>
                <p className="text-xs text-gray-400 mt-0.5">Evaluation Window: {evaluationWindow}</p>
              </div>
              <StatusBadge variant="ACTIVE" label={`CURRENT PHASE: ${phase}`} />
            </div>

            <div className="py-2 overflow-x-auto">
              <TimelineVisualization events={DAILY_CYCLE_EVENTS} startHour={0} endHour={24} height={110} />
            </div>
          </div>

          {/* Compute Governance & SLA Exceptions */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Compute Allocation Bars with Baseline/Elevated Toggle */}
            <div className="rounded-lg border border-gray-700 bg-gray-800/80 p-4 space-y-4">
              <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                <div className="flex items-center gap-2 text-sm font-semibold text-indigo-300">
                  <Cpu className="h-4 w-4 text-indigo-400" />
                  <span>Compute Governance Resource Allocations</span>
                </div>

                {/* Allocation Mode Toggle */}
                <div className="inline-flex rounded-md bg-gray-900 p-0.5 border border-gray-700">
                  <button
                    type="button"
                    onClick={() => setAllocationMode('baseline')}
                    className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                      allocationMode === 'baseline' ? 'bg-indigo-600 text-white' : 'text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    BASELINE
                  </button>
                  <button
                    type="button"
                    onClick={() => setAllocationMode('elevated')}
                    className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                      allocationMode === 'elevated' ? 'bg-amber-600 text-white' : 'text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    ELEVATED
                  </button>
                </div>
              </div>

              <div className="space-y-3">
                {COMPUTE_ALLOCATIONS.map((alloc) => {
                  const val = allocationMode === 'baseline' ? alloc.baseline : alloc.elevated;
                  return (
                    <div key={alloc.name} className="space-y-1">
                      <div className="flex items-center justify-between text-xs text-gray-300">
                        <span>{alloc.name}</span>
                        <span className="font-mono text-indigo-300">
                          {val}% ({val * 10} {alloc.unit})
                        </span>
                      </div>
                      <ProgressBar
                        value={val}
                        color={
                          allocationMode === 'elevated'
                            ? val >= 80
                              ? 'bg-amber-500'
                              : 'bg-indigo-500'
                            : 'bg-indigo-500'
                        }
                      />
                    </div>
                  );
                })}
              </div>
            </div>

            {/* SLA Exception Handling Table */}
            <div className="rounded-lg border border-gray-700 bg-gray-800/80 p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                <div className="flex items-center gap-2 text-sm font-semibold text-gray-200">
                  <Activity className="h-4 w-4 text-indigo-400" />
                  <span>SLA Exceptions &amp; Governance Breaches</span>
                </div>
                <span className="text-xs text-gray-400 font-mono">3 Active Items</span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-gray-700 text-gray-400 font-mono">
                      <th className="py-2 pr-2">ID</th>
                      <th className="py-2 px-2">Severity</th>
                      <th className="py-2 px-2">Trigger Event</th>
                      <th className="py-2 pl-2 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800">
                    {SLA_EXCEPTIONS.map((exc) => (
                      <tr key={exc.id} className="hover:bg-gray-900/40">
                        <td className="py-2.5 pr-2 font-mono text-indigo-300">{exc.id}</td>
                        <td className="py-2.5 px-2">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                              exc.severity === 'HIGH'
                                ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                                : exc.severity === 'MEDIUM'
                                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                            }`}
                          >
                            {exc.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-2 text-gray-300 font-sans">{exc.trigger}</td>
                        <td className="py-2.5 pl-2 text-right font-mono">
                          <StatusBadge variant={exc.resolutionStatus === 'RESOLVED' ? 'NOMINAL' : 'ELEVATED'} label={exc.resolutionStatus} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* BOTTOM SECTION: Control Domains CD-01 through CD-10 Grid (5x2) */}
      <div className="rounded-lg border border-gray-700 bg-gray-950 p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 pb-3">
          <div>
            <h3 className="text-base font-semibold text-gray-100 flex items-center gap-2">
              <Shield className="h-5 w-5 text-indigo-400" />
              <span>Control Domains Status Grid (CD-01 through CD-10)</span>
            </h3>
            <p className="text-xs text-gray-400">
              Overview of system control domains. Click any domain card for operational details or navigate to the explorer.
            </p>
          </div>

          <Link
            to="/control-domains"
            className="inline-flex items-center gap-1.5 rounded bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500 transition-colors shadow"
          >
            <span>Control Domains Explorer</span>
            <ChevronRight className="h-4 w-4" />
          </Link>
        </div>

        {/* 5x2 Grid */}
        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5">
          {CONTROL_DOMAINS.map((domain) => (
            <div
              key={domain.id}
              onClick={() => setSelectedDomain(domain)}
              className="group cursor-pointer rounded-lg border border-gray-700/80 bg-gray-900/60 p-3.5 space-y-2.5 hover:border-indigo-500/50 hover:bg-gray-900/90 transition-all shadow-sm"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-indigo-400">{domain.id}</span>
                <StatusBadge variant={domain.status} label={domain.status} />
              </div>

              <div className="font-semibold text-xs text-gray-200 group-hover:text-indigo-300 transition-colors line-clamp-1" title={domain.name}>
                {domain.name}
              </div>

              <div className="space-y-1">
                <ProgressBar
                  value={domain.complianceScore}
                  color={
                    domain.complianceScore >= 95
                      ? 'bg-emerald-500'
                      : domain.complianceScore >= 90
                      ? 'bg-indigo-500'
                      : 'bg-amber-500'
                  }
                />
                <div className="flex justify-between text-[10px] text-gray-400 font-mono">
                  <span>Score</span>
                  <span>{domain.complianceScore}%</span>
                </div>
              </div>

              <div className="flex items-center justify-between text-[10px] text-gray-400 border-t border-gray-800/80 pt-2 font-mono">
                <span>Active: {domain.activeControls}</span>
                <span className={domain.openFindings > 0 ? 'text-amber-400 font-semibold' : 'text-emerald-400'}>
                  Findings: {domain.openFindings}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Control Domain Quick Detail Drawer */}
      <DetailDrawer
        open={!!selectedDomain}
        onClose={() => setSelectedDomain(null)}
        title={selectedDomain ? `${selectedDomain.id}: ${selectedDomain.name}` : ''}
        subtitle={selectedDomain ? `Compliance Score: ${selectedDomain.complianceScore}%` : ''}
      >
        {selectedDomain && (
          <div className="space-y-5">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <StatusBadge variant={selectedDomain.status} label={selectedDomain.status} />
              <span className="font-mono text-xs text-indigo-300">Score: {selectedDomain.complianceScore}%</span>
            </div>

            <p className="text-xs text-gray-300 leading-relaxed">{selectedDomain.description}</p>

            <div className="grid grid-cols-2 gap-3">
              <KV label="Active Controls" value={selectedDomain.activeControls} mono />
              <KV label="Open Findings" value={selectedDomain.openFindings} mono />
            </div>

            <div className="rounded-lg border border-indigo-500/30 bg-indigo-950/20 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-indigo-300">
                <Info className="h-4 w-4 text-indigo-400" />
                <span>Full Domain Mapping Available</span>
              </div>
              <p className="text-xs text-gray-300">
                Explore cross-framework mapping, OPA-Rego policies, and remediation plans for {selectedDomain.id} in the Control Domains Explorer.
              </p>
              <div className="pt-2">
                <Link
                  to="/control-domains"
                  className="inline-flex items-center gap-1.5 rounded bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500 transition-colors"
                >
                  <span>Open Control Domains Explorer</span>
                  <ExternalLink className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
