import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  ChevronRight,
  Cpu,
  Eye,
  Info,
  Layers,
  Network,
  Radio,
  RefreshCw,
  Scale,
  Shield,
  Zap,
} from 'lucide-react';
import { useState } from 'react';
import CodeBlock from '../components/CodeBlock';
import DetailDrawer from '../components/DetailDrawer';
import NodeGraph from '../components/NodeGraph';
import PageHeader from '../components/PageHeader';
import RadarChart from '../components/RadarChart';
import SparklineChart from '../components/SparklineChart';
import StatusBadge, { KV } from '../components/StatusBadge';
import { RISK_INDICES, SUPERVISORY_AGENTS } from '../data/gienData';
import {
  getAgentAttestation,
  getRiskGraphNodes,
  RISK_CORRELATION_EDGES,
} from '../data/riskData';
import type { RiskIndex, SupervisoryAgent } from '../types';

export default function RiskIndices() {
  const [selectedRiskIndex, setSelectedRiskIndex] = useState<RiskIndex | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<SupervisoryAgent | null>(null);
  const [filterCategory, setFilterCategory] = useState<'ALL' | 'ELEVATED' | 'NOMINAL'>('ALL');

  const riskNodes = getRiskGraphNodes();

  const filteredIndices = RISK_INDICES.filter((idx) => {
    if (filterCategory === 'ELEVATED') return idx.status === 'ELEVATED' || idx.status === 'CRITICAL';
    if (filterCategory === 'NOMINAL') return idx.status === 'NOMINAL';
    return true;
  });

  // Radar chart axes & capped values (value / threshold)
  const radarAxes = RISK_INDICES.map((r) => r.id);
  const radarValues = RISK_INDICES.map((r) => Math.min(1, r.value / r.threshold));

  const agentAttestationDetails = selectedAgent ? getAgentAttestation(selectedAgent.id) : null;

  return (
    <div className="space-y-8 pb-12">
      {/* Header */}
      <PageHeader
        title="Systemic Risk Telemetry & Risk Indices"
        subtitle="12 Systemic risk indices, cross-index constellation correlation graph, and autonomous agent drift telemetry."
        crumbs={[{ label: 'GIEN Governance', to: '/dashboard' }, { label: 'Risk Telemetry' }]}
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setFilterCategory('ALL')}
              aria-label="Filter all indices"
              className={`rounded-md px-3 py-1 text-xs font-semibold transition-colors ${
                filterCategory === 'ALL'
                  ? 'bg-indigo-600 text-white'
                  : 'border border-gray-700 bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              All (12)
            </button>
            <button
              type="button"
              onClick={() => setFilterCategory('ELEVATED')}
              aria-label="Filter elevated indices"
              className={`rounded-md px-3 py-1 text-xs font-semibold transition-colors ${
                filterCategory === 'ELEVATED'
                  ? 'bg-amber-600 text-white'
                  : 'border border-gray-700 bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              Elevated Watch (2)
            </button>
            <button
              type="button"
              onClick={() => setFilterCategory('NOMINAL')}
              aria-label="Filter nominal indices"
              className={`rounded-md px-3 py-1 text-xs font-semibold transition-colors ${
                filterCategory === 'NOMINAL'
                  ? 'bg-emerald-600 text-white'
                  : 'border border-gray-700 bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              Nominal (10)
            </button>
          </div>
        }
      />

      <div className="mb-4 flex items-start gap-2 rounded-md border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-[11px] text-violet-200">
        <span className="mt-0.5 rounded bg-violet-500/20 px-1.5 py-0.5 font-bold uppercase tracking-wider">Simulation</span>
        <span>
          p(doom) and p(doom)_kernel are simulated scenario outputs from the fictional GIEN model ensemble. They are not
          forecasts, estimates, or measurements of real-world existential risk.
        </span>
      </div>

      {/* SECTION 1: 12 Systemic Risk Indices Grid */}
      <section aria-labelledby="sri-grid-heading">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-indigo-400" />
            <h2 id="sri-grid-heading" className="text-base font-bold text-gray-100">
              Systemic Risk Indices Telemetry (24h Evaluation)
            </h2>
          </div>
          <span className="text-xs text-gray-400 font-mono">Click card to inspect methodology & regulatory mappings</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {filteredIndices.map((idx) => {
            const isAboveThreshold = idx.value >= idx.threshold;
            const valueColor = isAboveThreshold ? 'text-amber-400' : 'text-emerald-400';
            const isDeltaPositive = idx.delta24h > 0;

            return (
              <div
                key={idx.id}
                onClick={() => setSelectedRiskIndex(idx)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') setSelectedRiskIndex(idx);
                }}
                aria-label={`Open details for risk index ${idx.name} (${idx.id})`}
                className="group relative cursor-pointer rounded-lg border border-gray-700 bg-gray-800/50 p-4 transition-all hover:border-indigo-500/70 hover:bg-gray-800/90 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div>
                      <span className="font-mono text-xs font-bold text-indigo-400">{idx.id}</span>
                      <h3 className="text-sm font-semibold text-gray-100 group-hover:text-indigo-300 line-clamp-1">
                        {idx.name}
                      </h3>
                    </div>
                    <div className="flex flex-col items-end gap-1">
                      <StatusBadge variant={idx.status} />
                      {idx.id.includes('doom') && (
                        <span className="rounded border border-violet-500/40 bg-violet-500/10 px-1 py-0.5 text-[9px] font-bold uppercase tracking-wider text-violet-300">
                          SIMULATION
                        </span>
                      )}
                    </div>
                  </div>

                  <p className="text-[11px] text-gray-400 line-clamp-2 mb-3">{idx.description}</p>

                  {/* Value & Delta Row */}
                  <div className="flex items-baseline justify-between mb-3 border-y border-gray-700/60 py-2">
                    <div>
                      <span className="text-[10px] text-gray-500 uppercase tracking-wider block">Current Value</span>
                      <span className={`font-mono text-2xl font-bold ${valueColor}`}>
                        {typeof idx.value === 'number' && idx.value < 0.001 ? idx.value.toFixed(6) : idx.value}
                        {idx.id.includes('doom') && (
                          <span className="ml-1 align-middle text-[9px] font-semibold uppercase text-violet-300">sim</span>
                        )}
                      </span>
                      {idx.id.includes('doom') && (
                        <span className="mt-0.5 block text-[9px] leading-tight text-violet-300/80">
                          Simulated scenario output; not a forecast of real-world probability.
                        </span>
                      )}
                    </div>

                    <div className="text-right">
                      <span className="text-[10px] text-gray-500 uppercase tracking-wider block">24h Delta</span>
                      <span
                        className={`inline-flex items-center font-mono text-xs font-semibold ${
                          isDeltaPositive ? 'text-amber-400' : 'text-emerald-400'
                        }`}
                      >
                        {isDeltaPositive ? (
                          <ArrowUpRight className="h-3 w-3 mr-0.5" />
                        ) : (
                          <ArrowDownRight className="h-3 w-3 mr-0.5" />
                        )}
                        {idx.delta24h > 0 ? `+${idx.delta24h}` : idx.delta24h}
                      </span>
                    </div>
                  </div>

                  {/* Threshold & Sparkline */}
                  <div className="flex items-center justify-between gap-2 text-xs text-gray-400 mb-1">
                    <span>
                      Threshold: <span className="font-mono text-gray-300">{idx.threshold}</span>
                    </span>
                    <span className="text-[10px] font-mono text-gray-500">24h History</span>
                  </div>

                  <div className="h-10 w-full overflow-hidden rounded bg-gray-900/60 p-1">
                    <SparklineChart
                      data={idx.history}
                      width={220}
                      height={32}
                      color={isAboveThreshold ? '#f59e0b' : '#10b981'}
                    />
                  </div>
                </div>

                <div className="mt-3 flex items-center justify-between text-[11px] text-indigo-400 group-hover:text-indigo-300">
                  <span className="flex items-center gap-1 font-medium">
                    <Eye className="h-3.5 w-3.5" /> View Methodology
                  </span>
                  <ChevronRight className="h-3.5 w-3.5 group-hover:translate-x-1 transition-transform" />
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* SECTION 2: Aggregate Visualizations (RadarChart & NodeGraph) */}
      <section aria-labelledby="visualizations-heading">
        <div className="flex items-center gap-2 mb-4">
          <Network className="h-5 w-5 text-indigo-400" />
          <h2 id="visualizations-heading" className="text-base font-bold text-gray-100">
            Systemic Risk Profile & Correlation Constellation
          </h2>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Radar Chart Card */}
          <div className="lg:col-span-5 rounded-lg border border-gray-700 bg-gray-800/40 p-5 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-bold text-gray-200">Systemic Risk Profile Radar</h3>
                <span className="text-[10px] font-mono text-gray-400">Values Normalized to Threshold (Cap = 1.0)</span>
              </div>
              <p className="text-xs text-gray-400 mb-4">
                Multivariate stress radar mapping index stress relative to threshold limits across all 12 supervisory parameters.
              </p>

              <div className="flex justify-center my-2">
                <RadarChart axes={radarAxes} values={radarValues} size={300} />
              </div>
            </div>

            <div className="mt-4 border-t border-gray-700/60 pt-3 text-xs text-gray-400 space-y-1">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-emerald-400" /> Nominal Zone (&lt; 1.0)
                </span>
                <span className="font-mono text-emerald-400">10 Indices</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-amber-400" /> Threshold Watch (&ge; 1.0)
                </span>
                <span className="font-mono text-amber-400">2 Indices (C-SRI, A-SRI)</span>
              </div>
            </div>
          </div>

          {/* Node Graph Constellation Card */}
          <div className="lg:col-span-7 rounded-lg border border-gray-700 bg-gray-800/40 p-5">
            <div className="flex items-center justify-between mb-2">
              <div>
                <h3 className="text-sm font-bold text-gray-200">Risk Constellation Topology</h3>
                <p className="text-xs text-gray-400">
                  Cross-index empirical correlation edges derived from high-frequency telemetry.
                </p>
              </div>
              <span className="rounded bg-indigo-500/10 border border-indigo-500/30 px-2 py-0.5 font-mono text-[10px] text-indigo-300">
                13 Inter-Index Correlation Edges
              </span>
            </div>

            <div className="flex justify-center bg-gray-900/60 rounded-lg p-2 border border-gray-800 my-2">
              <NodeGraph nodes={riskNodes} edges={RISK_CORRELATION_EDGES} size={420} height={360} />
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-4 text-[11px] font-mono text-gray-400">
              <div className="p-2 rounded bg-gray-900/40 border border-gray-800">
                <span className="text-gray-500 block">S_sys - G-SRI</span>
                <span className="text-indigo-300 font-bold">0.82 Correlation</span>
              </div>
              <div className="p-2 rounded bg-gray-900/40 border border-gray-800">
                <span className="text-gray-500 block">G-SRI - C-SRI</span>
                <span className="text-indigo-300 font-bold">0.74 Correlation</span>
              </div>
              <div className="p-2 rounded bg-gray-900/40 border border-gray-800">
                <span className="text-gray-500 block">A-SRI - Δ_drift</span>
                <span className="text-indigo-300 font-bold">0.69 Correlation</span>
              </div>
              <div className="p-2 rounded bg-gray-900/40 border border-gray-800">
                <span className="text-gray-500 block">P-SRI - p(doom)</span>
                <span className="text-indigo-300 font-bold">0.61 Correlation</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 3: Autonomous Supervisory Agent Drift Panel */}
      <section aria-labelledby="agent-drift-heading">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Radio className="h-5 w-5 text-indigo-400" />
            <h2 id="agent-drift-heading" className="text-base font-bold text-gray-100">
              Autonomous Supervisory Agent Drift Panel
            </h2>
          </div>
          <span className="text-xs text-gray-400 font-mono">
            Fleet Mean Drift L2: <span className="text-emerald-400 font-bold">0.026</span> (Threshold: 0.050)
          </span>
        </div>

        <div className="overflow-x-auto rounded-lg border border-gray-700 bg-gray-800/40">
          <table className="w-full text-left text-xs" aria-label="Autonomous Supervisory Agents Drift Table">
            <thead className="bg-gray-900/80 text-gray-400 font-mono text-[11px] uppercase tracking-wider border-b border-gray-700">
              <tr>
                <th scope="col" className="p-3">Agent ID</th>
                <th scope="col" className="p-3">Role</th>
                <th scope="col" className="p-3">Drift Score</th>
                <th scope="col" className="p-3">Containment Status</th>
                <th scope="col" className="p-3">Last Attestation</th>
                <th scope="col" className="p-3">24h Interventions</th>
                <th scope="col" className="p-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {SUPERVISORY_AGENTS.map((agent) => {
                const isExceeded = agent.driftScore >= 0.05;
                const driftColor = isExceeded ? 'text-amber-400 font-bold' : 'text-emerald-400';

                return (
                  <tr
                    key={agent.id}
                    onClick={() => setSelectedAgent(agent)}
                    className="hover:bg-gray-800/80 transition-colors cursor-pointer"
                  >
                    <td className="p-3 font-mono font-semibold text-indigo-300">{agent.id}</td>
                    <td className="p-3 font-medium text-gray-200">{agent.role}</td>
                    <td className="p-3 font-mono">
                      <span className={driftColor}>{agent.driftScore.toFixed(3)}</span>
                      <span className="text-[10px] text-gray-500 ml-1">/ 0.050</span>
                    </td>
                    <td className="p-3">
                      <StatusBadge variant={agent.containmentStatus} />
                    </td>
                    <td className="p-3 font-mono text-gray-400">{agent.lastAttestation}</td>
                    <td className="p-3 font-mono text-gray-300">{agent.interventionCount24h}</td>
                    <td className="p-3 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAgent(agent);
                        }}
                        aria-label={`Inspect agent attestation transcript for ${agent.id}`}
                        className="inline-flex items-center gap-1 rounded border border-gray-700 bg-gray-800 px-2 py-1 text-[11px] font-medium text-indigo-400 hover:bg-gray-700 hover:text-indigo-300"
                      >
                        <Eye className="h-3 w-3" /> Transcript
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* DETAIL DRAWER 1: Risk Index Methodology & Factors Drawer */}
      {selectedRiskIndex && (
        <DetailDrawer
          open={Boolean(selectedRiskIndex)}
          onClose={() => setSelectedRiskIndex(null)}
          title={`[${selectedRiskIndex.id}] ${selectedRiskIndex.name}`}
          subtitle={`Telemetry & Methodology Breakdown (${selectedRiskIndex.status})`}
        >
          <div className="space-y-6 text-xs text-gray-200">
            {/* Header Status & Value */}
            <div className="rounded-lg border border-gray-700 bg-gray-950 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-gray-400 uppercase tracking-wider text-[10px]">Index Telemetry State</span>
                <StatusBadge variant={selectedRiskIndex.status} />
              </div>
              <div className="flex items-baseline justify-between">
                <span className="font-mono text-3xl font-bold text-gray-50">
                  {selectedRiskIndex.value}
                </span>
                <span className="font-mono text-xs text-gray-400">
                  Threshold: <span className="text-gray-200 font-bold">{selectedRiskIndex.threshold}</span>
                </span>
              </div>
              <p className="text-gray-300 text-xs leading-relaxed">{selectedRiskIndex.description}</p>
            </div>

            {/* Methodology */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-indigo-400 uppercase tracking-wider font-mono">
                &lt;methodology&gt;
              </h4>
              <p className="p-3 rounded border border-gray-800 bg-gray-950/80 leading-relaxed text-gray-300">
                {selectedRiskIndex.methodology}
              </p>
            </div>

            {/* Contributing Factors */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-indigo-400 uppercase tracking-wider font-mono">
                &lt;contributing_factors&gt;
              </h4>
              <ul className="space-y-1.5 p-3 rounded border border-gray-800 bg-gray-950/80">
                {selectedRiskIndex.factors.map((f, i) => (
                  <li key={i} className="flex items-center gap-2 text-gray-300">
                    <span className="h-1.5 w-1.5 rounded-full bg-indigo-400" />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Remediation Triggers */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-amber-400 uppercase tracking-wider font-mono">
                &lt;remediation_triggers&gt;
              </h4>
              <ul className="space-y-1.5 p-3 rounded border border-amber-500/20 bg-amber-950/10 text-amber-200/90 font-mono text-[11px]">
                {selectedRiskIndex.remediationTriggers.map((t, i) => (
                  <li key={i} className="flex items-center gap-2">
                    <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                    <span>{t}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Regulatory Mappings */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider font-mono">
                &lt;regulatory_mappings&gt;
              </h4>
              <div className="flex flex-wrap gap-2 pt-1">
                {selectedRiskIndex.regulatoryMappings.map((m, i) => (
                  <span
                    key={i}
                    className="rounded border border-cyan-500/30 bg-cyan-950/30 px-2 py-1 font-mono text-[11px] text-cyan-300"
                  >
                    {m}
                  </span>
                ))}
              </div>
            </div>

            {/* 24h Trend History */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider font-mono">
                &lt;24h_telemetry_series&gt;
              </h4>
              <div className="p-3 rounded border border-gray-800 bg-gray-950/80">
                <SparklineChart data={selectedRiskIndex.history} width={380} height={48} color="#818cf8" />
              </div>
            </div>
          </div>
        </DetailDrawer>
      )}

      {/* DETAIL DRAWER 2: Supervisory Agent Attestation Drawer */}
      {selectedAgent && agentAttestationDetails && (
        <DetailDrawer
          open={Boolean(selectedAgent)}
          onClose={() => setSelectedAgent(null)}
          title={`[${selectedAgent.id}] ${selectedAgent.role}`}
          subtitle="Autonomous Supervisory Agent RTEE Attestation & Policy Audit"
        >
          <div className="space-y-6 text-xs text-gray-200">
            {/* Agent Overview KV */}
            <div className="rounded-lg border border-gray-700 bg-gray-950 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-indigo-400 font-bold">{selectedAgent.id}</span>
                <StatusBadge variant={selectedAgent.containmentStatus} />
              </div>
              <div className="divide-y divide-gray-800 text-xs">
                <KV label="Agent Role" value={selectedAgent.role} />
                <KV label="Drift L2 Norm" value={`${selectedAgent.driftScore.toFixed(3)} / 0.050`} mono />
                <KV label="24h Interventions" value={selectedAgent.interventionCount24h} mono />
                <KV label="Last Hardware Attestation" value={selectedAgent.lastAttestation} mono />
              </div>
            </div>

            {/* Policy & PQC Signatures */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-indigo-400 uppercase tracking-wider font-mono">
                &lt;cryptographic_identity&gt;
              </h4>
              <div className="space-y-1 divide-y divide-gray-800 rounded border border-gray-800 bg-gray-950 p-3 font-mono text-[11px]">
                <div className="py-1">
                  <span className="text-gray-500 block text-[10px]">Policy Hash</span>
                  <span className="text-gray-300 break-all">{agentAttestationDetails.policyHash}</span>
                </div>
                <div className="pt-2">
                  <span className="text-gray-500 block text-[10px]">PQC Signature</span>
                  <span className="text-cyan-400 break-all">{agentAttestationDetails.pqcSignature}</span>
                </div>
              </div>
            </div>

            {/* Hardware Attestation Transcript in CodeBlock */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-indigo-400 uppercase tracking-wider font-mono">
                &lt;hardware_attestation_transcript&gt;
              </h4>
              <CodeBlock code={agentAttestationDetails.attestationProof} language="log" maxHeight="max-h-64" />
            </div>

            {/* Recent Telemetry Logs */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider font-mono">
                &lt;recent_telemetry_logs&gt;
              </h4>
              <div className="space-y-1 rounded border border-gray-800 bg-gray-950 p-3 font-mono text-[11px]">
                {agentAttestationDetails.telemetryLogs.map((log, i) => (
                  <p key={i} className="text-gray-300 border-b border-gray-900 pb-1 last:border-0">
                    {log}
                  </p>
                ))}
              </div>
            </div>
          </div>
        </DetailDrawer>
      )}
    </div>
  );
}
