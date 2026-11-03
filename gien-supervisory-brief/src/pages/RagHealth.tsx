import { Activity, Database, Info, RefreshCw, Server, ShieldCheck, Zap } from 'lucide-react';
import ExpandableSection from '../components/ExpandableSection';
import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import SparklineChart from '../components/SparklineChart';
import StatusBadge, { KV } from '../components/StatusBadge';
import Watermark, { watermarkProvenance } from '../components/Watermark';
import { useGovernance } from '../context/GovernanceContext';
import { series } from '../data/helpers';
import {
  RAG_FAILURE_MODES,
  RAG_INDEXES,
  RAG_REMEDIATION_QUEUE,
  RAGAS_METRICS,
} from '../data/ragData';

export default function RagHealth() {
  const { filingRef } = useGovernance();
  const provenance = watermarkProvenance(filingRef);

  // Corpus freshness history (24 points around 98.4%)
  const freshnessData = series('corpus-freshness-telemetry', 98.4, 1.2, 24);

  return (
    <div className="space-y-8 pb-12">
      <Watermark />

      <PageHeader
        title="RAG Health Monitor"
        subtitle="Retrieval augmented generation telemetry, index drift metrics, and RAGAS evaluation pipeline status."
        crumbs={[{ label: 'GIEN Governance', to: '/dashboard' }, { label: 'RAG Health' }]}
        actions={
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              Retriever Online
            </span>
          </div>
        }
      />

      {/* Metric Cards Grid */}
      <section aria-label="RAG Key Metrics">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <MetricCard
            label="Retrieval Precision@K"
            value="0.91"
            unit="(k=5)"
            status="NOMINAL"
            threshold="≥ 0.85"
            footer={<span className="text-[11px] text-gray-400">Top-5 relevant chunk ratio</span>}
          />
          <MetricCard
            label="Groundedness"
            value="0.94"
            status="NOMINAL"
            threshold="≥ 0.90"
            footer={<span className="text-[11px] text-gray-400">Source attribution match rate</span>}
          />
          <MetricCard
            label="Answer Relevance"
            value="0.89"
            status="NOMINAL"
            threshold="≥ 0.85"
            footer={<span className="text-[11px] text-gray-400">Semantic alignment to prompt</span>}
          />
          <MetricCard
            label="Hallucination Rate"
            value="0.012"
            unit="(1.2%)"
            status="NOMINAL"
            threshold="≤ 0.020"
            footer={<span className="text-[11px] text-emerald-400">Ungrounded token incidence</span>}
          />
        </div>
      </section>

      {/* Corpus Freshness & Latency Visualizations */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Sparkline Corpus Freshness Card */}
        <div className="flex flex-col justify-between rounded-lg border border-gray-700 bg-gray-800/40 p-5 lg:col-span-5">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-indigo-400" />
                <h3 className="text-sm font-bold text-gray-100">Corpus Freshness Telemetry</h3>
              </div>
              <span className="font-mono text-xs text-emerald-400">98.4% Average</span>
            </div>
            <p className="text-xs text-gray-400 mb-4">
              Real-time synchronization percentage across vector stores and regulatory policy source repositories (24h window).
            </p>

            <div className="h-24 w-full rounded bg-gray-900/60 p-2">
              <SparklineChart data={freshnessData} width={380} height={80} color="#10b981" />
            </div>
          </div>

          <div className="mt-4 flex items-center justify-between border-t border-gray-700/60 pt-3 text-xs text-gray-400">
            <span>Last Sync: 12m ago</span>
            <span className="font-mono text-[11px] text-gray-500">Ref: {provenance.filing_reference}</span>
          </div>
        </div>

        {/* Hand-Rolled SVG Retrieval Latency p50/p95 Bar Chart */}
        <div className="rounded-lg border border-gray-700 bg-gray-800/40 p-5 lg:col-span-7">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-gray-100">Retrieval Latency p50 / p95 (ms)</h3>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1">
                <span className="h-2.5 w-2.5 rounded-sm bg-cyan-500" /> p50 Latency
              </span>
              <span className="flex items-center gap-1">
                <span className="h-2.5 w-2.5 rounded-sm bg-indigo-500" /> p95 Latency
              </span>
            </div>
          </div>

          <p className="text-xs text-gray-400 mb-4">
            Sub-second query response time benchmark across all 6 index vector collections.
          </p>

          <div className="space-y-3">
            {RAG_INDEXES.map((idx) => {
              const maxMs = 120;
              const p50Pct = Math.min(100, (idx.p50Ms / maxMs) * 100);
              const p95Pct = Math.min(100, (idx.p95Ms / maxMs) * 100);

              return (
                <div key={idx.id} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-gray-300 font-medium">{idx.name}</span>
                    <span className="font-mono text-[11px] text-gray-400">
                      p50: <strong className="text-cyan-400">{idx.p50Ms}ms</strong> | p95:{' '}
                      <strong className="text-indigo-400">{idx.p95Ms}ms</strong>
                    </span>
                  </div>
                  <div className="relative h-4 w-full overflow-hidden rounded bg-gray-900/80">
                    <div
                      className="absolute top-0 bottom-0 left-0 bg-indigo-500/60 transition-all"
                      style={{ width: `${p95Pct}%` }}
                    />
                    <div
                      className="absolute top-0 bottom-0 left-0 bg-cyan-400 transition-all"
                      style={{ width: `${p50Pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Per-Index Health Table */}
      <section aria-labelledby="index-health-heading">
        <div className="flex items-center gap-2 mb-3">
          <Server className="h-4 w-4 text-indigo-400" />
          <h2 id="index-health-heading" className="text-base font-bold text-gray-100">
            Per-Index Health & Embedding Drift Register
          </h2>
        </div>

        <div className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800/40">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-gray-700 bg-gray-900/80 font-semibold text-gray-300 uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-3">Index Identifier</th>
                  <th className="px-4 py-3">Docs Count</th>
                  <th className="px-4 py-3">Last Ingest</th>
                  <th className="px-4 py-3">Embedding Drift</th>
                  <th className="px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/60 font-mono text-gray-200">
                {RAG_INDEXES.map((idx) => (
                  <tr key={idx.id} className="hover:bg-gray-800/60 transition-colors">
                    <td className="px-4 py-3 font-semibold text-indigo-300">{idx.id}</td>
                    <td className="px-4 py-3">{idx.docsCount.toLocaleString()} docs</td>
                    <td className="px-4 py-3 text-gray-400">{idx.lastIngest}</td>
                    <td className="px-4 py-3">
                      <span
                        className={
                          idx.embeddingDrift > 0.05
                            ? 'text-amber-400 font-bold'
                            : 'text-emerald-400'
                        }
                      >
                        {idx.embeddingDrift.toFixed(3)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge variant={idx.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* 3 Expandable Sections */}
      <div className="space-y-4">
        {/* 1. Evaluation Pipeline */}
        <ExpandableSection
          title="Evaluation pipeline (RAGAS-style Metrics)"
          subtitle="Continuous automated assessment across faithfulness, answer relevance, context precision, and recall."
          defaultOpen={true}
          badge={<StatusBadge variant="NOMINAL" label="4 / 4 PASSING" />}
        >
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 p-2">
            {RAGAS_METRICS.map((m) => (
              <div key={m.name} className="rounded-md border border-gray-700/80 bg-gray-900/60 p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-gray-200">{m.name}</span>
                  <StatusBadge variant="COMPLIANT" label={m.status} />
                </div>
                <div className="flex items-baseline justify-between">
                  <span className="font-mono text-2xl font-bold text-emerald-400">{m.score.toFixed(2)}</span>
                  <span className="text-[11px] font-mono text-gray-400">Target: ≥ {m.threshold.toFixed(2)}</span>
                </div>
                <p className="text-[11px] text-gray-400 leading-relaxed">{m.description}</p>
              </div>
            ))}
          </div>
        </ExpandableSection>

        {/* 2. Failure Modes Observed */}
        <ExpandableSection
          title="Failure modes observed (Telemetry Audit Log)"
          subtitle="5 Documented edge-case failure modes with automated and human mitigations."
          defaultOpen={false}
          badge={<StatusBadge variant="ELEVATED" label="5 FAILURE MODES" />}
        >
          <div className="overflow-x-auto p-2">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-gray-700 bg-gray-900/60 font-semibold text-gray-400 uppercase">
                <tr>
                  <th className="px-3 py-2">Failure Mode</th>
                  <th className="px-3 py-2">Count (24h)</th>
                  <th className="px-3 py-2">Mitigation Procedure</th>
                  <th className="px-3 py-2">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700/60 text-gray-300">
                {RAG_FAILURE_MODES.map((fm) => (
                  <tr key={fm.id} className="hover:bg-gray-800/50">
                    <td className="px-3 py-2.5 font-semibold text-gray-100">{fm.mode}</td>
                    <td className="px-3 py-2.5 font-mono text-amber-400 font-bold">{fm.count}</td>
                    <td className="px-3 py-2.5 text-gray-300">{fm.mitigation}</td>
                    <td className="px-3 py-2.5">
                      <StatusBadge variant={fm.severity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </ExpandableSection>

        {/* 3. Remediation Queue */}
        <ExpandableSection
          title="Remediation queue (Engineering Backlog)"
          subtitle="4 Active engineering tasks for index optimization, re-indexing, and retriever fine-tuning."
          defaultOpen={false}
          badge={<StatusBadge variant="PENDING" label="4 IN QUEUE" />}
        >
          <div className="space-y-3 p-2">
            {RAG_REMEDIATION_QUEUE.map((item) => (
              <div
                key={item.id}
                className="flex flex-col gap-2 rounded-md border border-gray-700/80 bg-gray-900/60 p-3 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-indigo-400">{item.id}</span>
                    <span className="text-xs font-semibold text-gray-100">{item.task}</span>
                  </div>
                  <div className="flex items-center gap-4 text-[11px] text-gray-400">
                    <span>Owner: <strong className="text-gray-300">{item.owner}</strong></span>
                    <span>ETA: <strong className="font-mono text-gray-300">{item.eta}</strong></span>
                  </div>
                </div>
                <div>
                  <StatusBadge variant={item.status === 'IN_PROGRESS' ? 'ELEVATED' : 'PENDING'} label={item.status} />
                </div>
              </div>
            ))}
          </div>
        </ExpandableSection>
      </div>
    </div>
  );
}
