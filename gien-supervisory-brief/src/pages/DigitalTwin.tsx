import {
  Activity,
  Check,
  ChevronLeft,
  ChevronRight,
  Clock,
  Database,
  Download,
  Info,
  Layers,
  Play,
  RefreshCw,
  Shield,
  Workflow,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import CodeBlock from '../components/CodeBlock';
import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import ProgressBar from '../components/ProgressBar';
import StatusBadge, { KV } from '../components/StatusBadge';
import { useGovernance } from '../context/GovernanceContext';
import { DRILLS } from '../data/gienData';
import { truncateHash } from '../data/helpers';
import {
  PANEL_13_DATA,
  PANEL_14_DATA,
  PANEL_15_DATA,
  PANEL_HEADERS,
  REPLAY_BUNDLE_ARCHIVE,
} from '../data/twinData';

type PanelKey = 'p13' | 'p14' | 'p15';

export default function DigitalTwin() {
  const { role } = useGovernance();

  // Selected Tab Panel State (Panel 13 | Panel 14 | Panel 15)
  const [activePanel, setActivePanel] = useState<PanelKey>('p13');

  // Replay Bundle Archive Pagination (5 per page)
  const [archivePage, setArchivePage] = useState(1);
  const archivePageSize = 5;
  const totalArchivePages = Math.ceil(REPLAY_BUNDLE_ARCHIVE.length / archivePageSize);

  const currentArchiveBundles = useMemo(() => {
    const start = (archivePage - 1) * archivePageSize;
    return REPLAY_BUNDLE_ARCHIVE.slice(start, start + archivePageSize);
  }, [archivePage]);

  const currentHeader = PANEL_HEADERS[activePanel];

  return (
    <div className="space-y-8 pb-12">
      {/* Page Header */}
      <PageHeader
        title="Digital Twin & Deterministic Replay Engine"
        subtitle="High-Fidelity Stress Replays, Contagion Simulations, and Supervisory Drill Validation"
        crumbs={[
          { label: 'Dashboard', to: '/' },
          { label: 'Digital Twin' },
        ]}
        actions={
          <div className="flex items-center gap-3">
            <span className="text-xs text-gray-400">Context: <strong className="text-cyan-400">{role}</strong></span>
            <StatusBadge variant="VERIFIED" label="REPLAY ENGINE READY" />
            <button
              type="button"
              onClick={() => alert('Simulated stress replay initiated')}
              className="flex items-center gap-1.5 rounded-md border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-300 transition-colors hover:bg-cyan-500/20"
            >
              <Play size={13} />
              Run Simulation
            </button>
          </div>
        }
      />

      {/* Panel Selector Tabs */}
      <div className="rounded-lg border border-gray-700 bg-gray-800/60 p-2">
        <div role="tablist" aria-label="Digital Twin Stress Scenario Panels" className="grid grid-cols-1 gap-2 md:grid-cols-3">
          <button
            type="button"
            role="tab"
            aria-selected={activePanel === 'p13'}
            aria-controls="panel-13-content"
            id="tab-p13"
            onClick={() => setActivePanel('p13')}
            className={`flex items-center justify-between rounded-md px-4 py-3 text-left transition-all ${
              activePanel === 'p13'
                ? 'border border-cyan-500/50 bg-cyan-950/40 text-cyan-200 shadow-md'
                : 'border border-transparent bg-gray-900/40 text-gray-400 hover:bg-gray-800 hover:text-gray-200'
            }`}
          >
            <div>
              <div className="font-mono text-xs font-bold uppercase text-cyan-400">Panel 13</div>
              <div className="text-xs font-semibold text-gray-100 mt-0.5">Cascade Contagion</div>
              <div className="text-[11px] text-gray-400">3 G-SIFI Failures</div>
            </div>
            <StatusBadge variant="ELEVATED" label="STRESS 0.42" />
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activePanel === 'p14'}
            aria-controls="panel-14-content"
            id="tab-p14"
            onClick={() => setActivePanel('p14')}
            className={`flex items-center justify-between rounded-md px-4 py-3 text-left transition-all ${
              activePanel === 'p14'
                ? 'border border-indigo-500/50 bg-indigo-950/40 text-indigo-200 shadow-md'
                : 'border border-transparent bg-gray-900/40 text-gray-400 hover:bg-gray-800 hover:text-gray-200'
            }`}
          >
            <div>
              <div className="font-mono text-xs font-bold uppercase text-indigo-400">Panel 14</div>
              <div className="text-xs font-semibold text-gray-100 mt-0.5">Agent Misalignment</div>
              <div className="text-[11px] text-gray-400">12 ASA Coordinated Drift</div>
            </div>
            <StatusBadge variant="ACTIVE" label="DRIFT 0.11" />
          </button>

          <button
            type="button"
            role="tab"
            aria-selected={activePanel === 'p15'}
            aria-controls="panel-15-content"
            id="tab-p15"
            onClick={() => setActivePanel('p15')}
            className={`flex items-center justify-between rounded-md px-4 py-3 text-left transition-all ${
              activePanel === 'p15'
                ? 'border border-amber-500/50 bg-amber-950/40 text-amber-200 shadow-md'
                : 'border border-transparent bg-gray-900/40 text-gray-400 hover:bg-gray-800 hover:text-gray-200'
            }`}
          >
            <div>
              <div className="font-mono text-xs font-bold uppercase text-amber-400">Panel 15</div>
              <div className="text-xs font-semibold text-gray-100 mt-0.5">PQC Degradation</div>
              <div className="text-[11px] text-gray-400">Legacy RSA/ECC Surface</div>
            </div>
            <StatusBadge variant="VERIFIED" label="91% PQC" />
          </button>
        </div>
      </div>

      {/* Common Per-Panel Header Box */}
      <div className="rounded-lg border border-gray-700 bg-gray-800/80 p-5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="rounded bg-cyan-500/20 px-2 py-0.5 font-mono text-xs font-bold text-cyan-300 border border-cyan-500/30">
                {currentHeader.panelId}
              </span>
              <h2 className="text-lg font-bold text-gray-50">{currentHeader.scenarioName}</h2>
            </div>
            <p className="mt-1 text-xs text-gray-300">{currentHeader.description}</p>
          </div>
          <div className="flex items-center gap-2">
            <StatusBadge variant="VERIFIED" label={currentHeader.determinism} />
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-3 border-t border-gray-700/80 pt-3 text-xs">
          <KV label="Last Replay Timestamp" value={currentHeader.lastReplay.replace('T', ' ').replace('Z', ' UTC')} mono />
          <KV label="Replay Bundle Hash" value={truncateHash(currentHeader.replayBundleHash, 10, 6)} mono />
          <KV label="Determinism Engine" value="TLA+ State Replay Kernel v4.2" />
        </div>
      </div>

      {/* ==================================================================== */}
      {/* PANEL 13: Cascade Contagion Scenario                                 */}
      {/* ==================================================================== */}
      {activePanel === 'p13' && (
        <div id="panel-13-content" role="tabpanel" aria-labelledby="tab-p13" className="space-y-6">
          {/* Stress Parameters */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-5">
            <h3 className="mb-3 text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Activity size={16} className="text-cyan-400" />
              Scenario Stress Parameters
            </h3>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {PANEL_13_DATA.stressParams.map((param) => (
                <div key={param.label} className="rounded bg-gray-900/60 p-3 border border-gray-800">
                  <div className="text-xs text-gray-400">{param.label}</div>
                  <div className="mt-1 font-mono text-sm font-bold text-cyan-300">{param.value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Replay Outcome Metrics */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
            <MetricCard
              label="S_sys Realized Peak"
              value={PANEL_13_DATA.outcomes.sysRiskPeak.toString()}
              status="NOMINAL"
              footer={<div>Ceiling: <span className="text-emerald-400">&lt; {PANEL_13_DATA.outcomes.sysRiskCeiling}</span></div>}
            />
            <MetricCard
              label="G-SRI Peak"
              value={PANEL_13_DATA.outcomes.gSriPeak.toString()}
              status="ELEVATED"
              footer={<div>Contagion Threshold: <span className="text-amber-400">0.40</span></div>}
            />
            <MetricCard
              label="Time to Recovery"
              value={PANEL_13_DATA.outcomes.timeToRecovery}
              status="VERIFIED"
              footer={<div>Recovery Horizon Target: <span className="text-gray-300">18 days</span></div>}
            />
            <MetricCard
              label="Interventions Activated"
              value={PANEL_13_DATA.outcomes.interventionsActivated.toString()}
              status="ACTIVE"
              footer={<div>Circuit Breakers: <span className="text-indigo-300">Ringfence Engaged</span></div>}
            />
          </div>

          {/* Deterministic Replay Bundle Info */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                <Database size={16} className="text-indigo-400" />
                Deterministic Replay Bundle Manifest ({PANEL_13_DATA.bundle.id})
              </h3>
              <StatusBadge variant="SEALED" label="214 ARTEFACTS SEALED" />
            </div>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-3 text-xs">
              <KV label="Bundle ID" value={PANEL_13_DATA.bundle.id} mono />
              <KV label="Merkle Root" value={truncateHash(PANEL_13_DATA.bundle.merkleRoot, 8, 4)} mono />
              <KV label="ML-DSA-65 Signature" value={PANEL_13_DATA.bundle.pqcSignature} mono />
            </div>
          </div>

          {/* Expected vs Actual Diff Display */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-5 space-y-3">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Workflow size={16} className="text-cyan-400" />
              Expected Baseline vs. Replay Actual State Diff
            </h3>
            <div className="overflow-x-auto rounded-md border border-gray-800 bg-gray-950 p-4 font-mono text-xs leading-relaxed">
              {PANEL_13_DATA.expectedVsActualDiff.map((line, i) => {
                if (line.type === 'removed') {
                  return <div key={i} className="text-red-400 bg-red-950/30 px-2 py-0.5 rounded">{line.text}</div>;
                }
                if (line.type === 'added') {
                  return <div key={i} className="text-emerald-400 bg-emerald-950/30 px-2 py-0.5 rounded">{line.text}</div>;
                }
                return <div key={i} className="text-gray-400 px-2 py-0.5">{line.text}</div>;
              })}
            </div>
          </div>

          {/* Regulatory Implications List */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-5 space-y-4">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Shield size={16} className="text-amber-400" />
              Regulatory Framework Threshold Analysis
            </h3>
            <div className="space-y-3">
              {PANEL_13_DATA.regulatoryImplications.map((reg) => (
                <div key={reg.framework} className="rounded-md border border-gray-700 bg-gray-900/60 p-3.5 text-xs space-y-1">
                  <div className="flex items-center justify-between font-semibold text-cyan-300">
                    <span>{reg.framework}</span>
                    <span className="text-[11px] font-mono text-amber-400">Trigger: {reg.threshold}</span>
                  </div>
                  <div className="text-gray-300 leading-relaxed">{reg.implication}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* PANEL 14: Autonomous Agent Misalignment Event                        */}
      {/* ==================================================================== */}
      {activePanel === 'p14' && (
        <div id="panel-14-content" role="tabpanel" aria-labelledby="tab-p14" className="space-y-6">
          {/* Stress Parameters */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-5">
            <h3 className="mb-3 text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Activity size={16} className="text-indigo-400" />
              Agent Misalignment Stress Parameters
            </h3>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {PANEL_14_DATA.stressParams.map((param) => (
                <div key={param.label} className="rounded bg-gray-900/60 p-3 border border-gray-800">
                  <div className="text-xs text-gray-400">{param.label}</div>
                  <div className="mt-1 font-mono text-sm font-bold text-indigo-300">{param.value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Replay Outcome Metrics */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
            <MetricCard
              label="A-SRI Peak"
              value={PANEL_14_DATA.outcomes.aSriPeak.toString()}
              status="ELEVATED"
              footer={<div>Threshold: <span className="text-amber-400">0.45 (Containment Active)</span></div>}
            />
            <MetricCard
              label="Δ_drift Max Realized"
              value={PANEL_14_DATA.outcomes.deltaDriftMax.toString()}
              status="NOMINAL"
              footer={<div>Hard Containment Ceiling: <span className="text-gray-400">0.080</span></div>}
            />
            <MetricCard
              label="Containment Latency"
              value={PANEL_14_DATA.outcomes.containmentTime}
              status="VERIFIED"
              footer={<div>Target SLA: <span className="text-emerald-400">&lt; 90s</span></div>}
            />
            <MetricCard
              label="Kill-Switch Status"
              value={PANEL_14_DATA.outcomes.killSwitchStatus}
              status="SAFEGUARD"
              footer={<div>Override Triggered: <span className="text-emerald-400">NO (Soft Dampened)</span></div>}
            />
          </div>

          {/* Constitutional Invariant Pressure List */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-5 space-y-4">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Shield size={16} className="text-cyan-400" />
              Constitutional Invariant Pressure Analysis
            </h3>
            <div className="space-y-3">
              {PANEL_14_DATA.constitutionalPressure.map((ci) => (
                <div key={ci.id} className="rounded-md border border-gray-700 bg-gray-900/60 p-4 text-xs space-y-1.5">
                  <div className="flex items-center justify-between font-semibold">
                    <span className="text-indigo-300">{ci.id}: {ci.name}</span>
                    <StatusBadge variant="VERIFIED" label={ci.status} />
                  </div>
                  <p className="text-gray-300 leading-relaxed">{ci.details}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Smart Contract Execution Log */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-5 space-y-3">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Workflow size={16} className="text-indigo-400" />
              Intervention Proof Verifier Smart Contract Execution Trace
            </h3>
            <CodeBlock code={PANEL_14_DATA.smartContractExecutionLog} language="solidity" maxHeight="max-h-96" />
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* PANEL 15: Post-Quantum Cryptographic Degradation                     */}
      {/* ==================================================================== */}
      {activePanel === 'p15' && (
        <div id="panel-15-content" role="tabpanel" aria-labelledby="tab-p15" className="space-y-6">
          {/* Stress Parameters */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-5">
            <h3 className="mb-3 text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Activity size={16} className="text-amber-400" />
              Post-Quantum Compromise Parameters
            </h3>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {PANEL_15_DATA.stressParams.map((param) => (
                <div key={param.label} className="rounded bg-gray-900/60 p-3 border border-gray-800">
                  <div className="text-xs text-gray-400">{param.label}</div>
                  <div className="mt-1 font-mono text-sm font-bold text-amber-300">{param.value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Replay Outcome Metrics */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
            <MetricCard
              label="P-SRI Peak"
              value={PANEL_15_DATA.outcomes.pSriPeak.toString()}
              status="ELEVATED"
              footer={<div>Threshold: <span className="text-amber-400">0.15</span></div>}
            />
            <MetricCard
              label="Ledger Integrity"
              value={PANEL_15_DATA.outcomes.ledgerIntegrity}
              status="VERIFIED"
              footer={<div>FIPS 204 Signature Chains: <span className="text-emerald-400">Unbroken</span></div>}
            />
            <MetricCard
              label="PQC Migration"
              value={`${PANEL_15_DATA.outcomes.pqcMigrationPercent}%`}
              status="ACTIVE"
              footer={<div>Target Completion: <span className="text-gray-300">100% by 2027 Q1</span></div>}
            />
            <MetricCard
              label="Data Integrity"
              value={PANEL_15_DATA.outcomes.dataIntegrity}
              status="VERIFIED"
              footer={<div>Zero Corrupted Records: <span className="text-emerald-400">Verified</span></div>}
            />
          </div>

          {/* NIST FIPS Migration Timeline SVG */}
          <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-5 space-y-4">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Clock size={16} className="text-amber-400" />
              NIST FIPS 203 / 204 / 205 Migration Roadmap (2024 → 2027)
            </h3>

            <div className="overflow-x-auto rounded-md border border-gray-800 bg-gray-950 p-4">
              <svg viewBox="0 0 880 140" className="w-full min-w-[760px]" role="img" aria-label="PQC Migration Timeline">
                <defs>
                  <marker id="tlArrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b" />
                  </marker>
                </defs>

                {/* Main Timeline Bar */}
                <line x1="50" y1="70" x2="830" y2="70" stroke="#374151" strokeWidth="4" />
                <line x1="50" y1="70" x2="650" y2="70" stroke="#10b981" strokeWidth="4" />

                {PANEL_15_DATA.migrationTimeline.map((item, idx) => {
                  const cx = 80 + idx * 190;
                  const isCompleted = item.status === 'COMPLETED';
                  const strokeColor = isCompleted ? '#10b981' : '#f59e0b';
                  const fillColor = isCompleted ? '#064e3b' : '#451a03';

                  return (
                    <g key={item.year}>
                      <circle cx={cx} cy="70" r="14" fill={fillColor} stroke={strokeColor} strokeWidth="2.5" />
                      <text x={cx} y="74" fontSize="10" fontWeight="bold" fill="#ffffff" textAnchor="middle">
                        {isCompleted ? '✓' : '➔'}
                      </text>

                      {/* Year badge above */}
                      <rect x={cx - 35} y="15" width="70" height="22" rx="4" fill="#111827" stroke={strokeColor} strokeWidth="1" />
                      <text x={cx} y="30" fontSize="10" fontWeight="bold" fill={strokeColor} textAnchor="middle">
                        {item.year}
                      </text>

                      {/* Title & Description below */}
                      <text x={cx} y="98" fontSize="10" fontWeight="bold" fill="#f3f4f6" textAnchor="middle">
                        {item.title}
                      </text>
                    </g>
                  );
                })}
              </svg>
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 text-xs pt-2">
              {PANEL_15_DATA.migrationTimeline.map((item) => (
                <div key={item.year} className="rounded bg-gray-900/60 p-3 border border-gray-800 space-y-1">
                  <div className="flex items-center justify-between font-semibold">
                    <span className="text-amber-300">{item.year}: {item.title}</span>
                    <StatusBadge variant={item.status === 'COMPLETED' ? 'VERIFIED' : 'PENDING'} label={item.status} />
                  </div>
                  <p className="text-gray-400">{item.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* DRILL EXECUTION RESULTS TABLE (DRILL-042 .. DRILL-045)               */}
      {/* ==================================================================== */}
      <section className="rounded-lg border border-gray-700 bg-gray-800/50 p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-gray-100 flex items-center gap-2">
            <Layers size={16} className="text-cyan-400" />
            Supervisory Drill Execution Results (DRILL-042 – DRILL-045)
          </h2>
          <span className="text-xs text-gray-400">Source: gienData.ts</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-gray-700 bg-gray-900/60 text-gray-400">
              <tr>
                <th className="px-4 py-2.5 font-medium">Drill ID</th>
                <th className="px-4 py-2.5 font-medium">Scenario Name</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 font-medium">Start Time</th>
                <th className="px-4 py-2.5 font-medium">Duration</th>
                <th className="px-4 py-2.5 font-medium">Outcome Score</th>
                <th className="px-4 py-2.5 font-medium">Lessons Learned &amp; Audit Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y border-gray-800 text-gray-300">
              {DRILLS.map((drill) => (
                <tr key={drill.id} className="hover:bg-gray-800/60">
                  <td className="px-4 py-3 font-mono font-bold text-cyan-300">{drill.id}</td>
                  <td className="px-4 py-3 font-semibold text-gray-100">{drill.scenario}</td>
                  <td className="px-4 py-3">
                    <StatusBadge variant={drill.status} />
                  </td>
                  <td className="px-4 py-3 font-mono text-gray-400">{drill.startTime.replace('T', ' ').replace('Z', '')}</td>
                  <td className="px-4 py-3 font-mono">{drill.durationMinutes} min</td>
                  <td className="px-4 py-3 font-mono font-bold text-emerald-400">
                    {drill.outcomeScore > 0 ? `${drill.outcomeScore} / 100` : 'N/A'}
                  </td>
                  <td className="px-4 py-3 text-gray-300">{drill.lessonsLearned}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* REPLAY BUNDLE ARCHIVE TABLE (Paginated 5 / page)                    */}
      {/* ==================================================================== */}
      <section className="rounded-lg border border-gray-700 bg-gray-800/50 p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-gray-100 flex items-center gap-2">
              <Database size={16} className="text-indigo-400" />
              Replay Bundle Archive (Paginated 5 / page)
            </h2>
            <p className="text-xs text-gray-400">Showing {currentArchiveBundles.length} of {REPLAY_BUNDLE_ARCHIVE.length} total replay bundles</p>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={archivePage === 1}
              onClick={() => setArchivePage((p) => Math.max(1, p - 1))}
              className="flex items-center gap-1 rounded-md border border-gray-700 bg-gray-800 px-2.5 py-1 text-xs text-gray-300 disabled:opacity-40"
            >
              <ChevronLeft size={14} />
              Prev
            </button>
            <span className="text-xs font-mono text-gray-400">
              Page {archivePage} of {totalArchivePages}
            </span>
            <button
              type="button"
              disabled={archivePage === totalArchivePages}
              onClick={() => setArchivePage((p) => Math.min(totalArchivePages, p + 1))}
              className="flex items-center gap-1 rounded-md border border-gray-700 bg-gray-800 px-2.5 py-1 text-xs text-gray-300 disabled:opacity-40"
            >
              Next
              <ChevronRight size={14} />
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-gray-700 bg-gray-900/60 text-gray-400">
              <tr>
                <th className="px-4 py-2.5 font-medium">Bundle ID</th>
                <th className="px-4 py-2.5 font-medium">Panel</th>
                <th className="px-4 py-2.5 font-medium">Scenario Name</th>
                <th className="px-4 py-2.5 font-medium">Timestamp</th>
                <th className="px-4 py-2.5 font-medium">Determinism</th>
                <th className="px-4 py-2.5 font-medium">Merkle Root</th>
                <th className="px-4 py-2.5 font-medium">PQC Signature</th>
                <th className="px-4 py-2.5 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y border-gray-800 text-gray-300">
              {currentArchiveBundles.map((bundle) => (
                <tr key={bundle.id} className="hover:bg-gray-800/60">
                  <td className="px-4 py-3 font-mono font-bold text-cyan-300">{bundle.id}</td>
                  <td className="px-4 py-3 font-mono text-indigo-300">{bundle.panel}</td>
                  <td className="px-4 py-3 font-semibold text-gray-200">{bundle.scenario}</td>
                  <td className="px-4 py-3 font-mono text-gray-400">{bundle.timestamp.replace('T', ' ').replace('Z', '')}</td>
                  <td className="px-4 py-3">
                    <StatusBadge variant="VERIFIED" label="DETERMINISTIC" />
                  </td>
                  <td className="px-4 py-3 font-mono text-gray-300">{truncateHash(bundle.merkleRoot, 8, 4)}</td>
                  <td className="px-4 py-3 font-mono text-gray-400">{truncateHash(bundle.pqcSignature, 8, 4)}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      title="Simulated download"
                      onClick={() => alert(`Simulated download started for ${bundle.id}`)}
                      className="inline-flex items-center gap-1 rounded bg-gray-800 px-2.5 py-1 text-xs font-medium text-gray-300 hover:bg-gray-700 hover:text-white border border-gray-700"
                    >
                      <Download size={12} />
                      Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
