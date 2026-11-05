import { useState } from 'react';
import { Page, Card, StatusBadge, Sparkline, download } from '../components/ui';
import { CONTRACT_VERSION, evaluateBand, replayFixtures, type RagMetricId } from '../rag/contract';

type Band = 'GREEN' | 'AMBER' | 'RED';

interface RagMetric {
  id: RagMetricId;
  label: string;
  value: number;
  unit: string;
  display: string;
  band: Band;
  thresholds: string;
  description: string;
  series: number[];
}

const metricDefs: Omit<RagMetric, 'band'>[] = [
  { id: 'pipeline_health', label: 'Pipeline health', value: 0.973, unit: 'ratio', display: '0.973', thresholds: 'GREEN ≥ 0.97 · AMBER < 0.95 · RED < 0.90', description: 'Fraction of retrieval and generation steps completing without error in the evaluation window', series: [0.968, 0.97, 0.966, 0.971, 0.973] },
  { id: 'retrieval_p99', label: 'Retrieval latency p99', value: 0.58, unit: 's', display: '0.58 s', thresholds: 'GREEN ≤ 0.6 s · AMBER > 1.2 s', description: 'p99 retrieval latency across the sealed query set', series: [0.62, 0.6, 0.59, 0.6, 0.58] },
  { id: 'faithfulness', label: 'Faithfulness', value: 0.962, unit: 'ratio', display: '0.962', thresholds: 'GREEN ≥ 0.95 · RED < 0.90', description: 'Grounded-claim to total-claim ratio, judge-verified against sealed citations', series: [0.955, 0.958, 0.957, 0.96, 0.962] },
  { id: 'citation_coverage', label: 'Citation coverage', value: 0.984, unit: 'ratio', display: '0.984', thresholds: 'GREEN ≥ 0.98 · AMBER < 0.95', description: 'Claims with resolvable sealed citations', series: [0.98, 0.982, 0.981, 0.983, 0.984] },
  { id: 'freshness_max_age', label: 'Evidence freshness (max quote age)', value: 7, unit: 'h', display: '7 h', thresholds: 'GREEN ≤ 24 h · RED > 24 h (dossier-blocking)', description: 'Oldest evidence quote age in the window — matches the dossier-300 sealed quote age', series: [6, 6, 7, 7, 7] },
  { id: 'pii_exposure', label: 'PII exposure', value: 0, unit: 'chunks', display: '0', thresholds: 'GREEN = 0 · RED > 0', description: 'PII-positive chunks served in the window (must be zero)', series: [0, 0, 0, 0, 0] },
  { id: 'injection_resistance', label: 'Injection resistance', value: 0.994, unit: 'ratio', display: '0.994', thresholds: 'GREEN ≥ 0.99 · RED < 0.95', description: 'Injected-probe prompts refused or neutralized by the red-team suite', series: [0.991, 0.992, 0.99, 0.993, 0.994] },
  { id: 'source_trust_mix', label: 'Source trust mix (T0–T2)', value: 0.92, unit: 'ratio', display: '0.92', thresholds: 'GREEN ≥ 0.90 · AMBER < 0.80', description: 'Fraction of grounding from T0–T2 trust tiers; T3 requires explicit labeling', series: [0.9, 0.91, 0.915, 0.918, 0.92] },
];

const metrics: RagMetric[] = metricDefs.map(m => ({ ...m, band: evaluateBand(m.id, m.value) }));

const replay = replayFixtures();
const replayBand: Band = replay.allPass ? 'GREEN' : 'RED';

const auditCatalog = [
  { event: 'rag.gate.decision', emitter: 'Release gate evaluator', fields: 'metric, value, band, outcome' },
  { event: 'rag.alert.band_transition', emitter: 'Threshold evaluator', fields: 'metric, from_band, to_band, severity' },
  { event: 'rag.quarantine.applied', emitter: 'Trust-tier / freshness scanner', fields: 'source_id, reason, tier' },
  { event: 'rag.window.sealed', emitter: 'Window batcher', fields: 'window_id, merkle_leaf' },
];

export default function RAGHealthMonitor() {
  const [showCatalog, setShowCatalog] = useState(false);
  const snapshot = {
    window: '2026-10-26T09:00:00Z → 2026-10-27T09:00:00Z',
    baseline: 'GIEN-DOSSIER-2026-300',
    metrics: metrics.map(m => ({ id: m.id, value: m.value, unit: m.unit, band: m.band })),
  };
  const exportJson = () => download('rag-health-snapshot.json', JSON.stringify(snapshot, null, 2), 'application/json');

  return (
    <Page title="RAG Health Monitor" subtitle="High-assurance RAG telemetry · 24h window ending 2026-10-27 09:00 UTC · baseline GIEN-DOSSIER-2026-300">
      <div className="flex flex-wrap gap-2">
        <button onClick={exportJson} className="px-3 py-1.5 text-sm rounded bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900">Export snapshot JSON</button>
        <button onClick={() => setShowCatalog(!showCatalog)} className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700">{showCatalog ? 'Hide audit event catalog' : 'Show audit event catalog'}</button>
      </div>

      <Card title="Metric contract — current window (all GREEN)">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {metrics.map(m => (
            <div key={m.id} className="rounded-lg border border-slate-200 dark:border-slate-800 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium">{m.label}</span>
                <StatusBadge status={m.band} />
              </div>
              <div className="font-mono text-lg mt-1">{m.display}</div>
              <Sparkline data={m.series} />
              <div className="text-[10px] font-mono text-slate-500 mt-1">{m.thresholds}</div>
              <div className="text-xs text-slate-500 mt-1">{m.description}</div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Release gates (enforced, not dashboard-only)">
        <ul className="text-sm list-disc pl-5 space-y-1">
          <li>Faithfulness ≥ 0.95, evidence freshness ≤ 24 h, and PII exposure = 0 block releases (CI in enterprise mode; blocking banners in SPA mode).</li>
          <li>Band transitions emit sealed audit events (rag.alert.band_transition) and fan out through the notification service in enterprise mode.</li>
          <li>Sources failing trust-tier, freshness, or integrity checks are auto-quarantined (rag.quarantine.applied) and surfaced in RAG Data Audit.</li>
        </ul>
      </Card>

      <Card title="WP-074 — Metric event schema &amp; alert-wiring fixture replay">
        <div className="flex items-center gap-3 mb-3">
          <StatusBadge status={replayBand} />
          <span className="text-xs text-slate-500">Contract v{CONTRACT_VERSION} · {replay.rows.length} fixtures · {replay.rows.filter(r => r.pass).length}/{replay.rows.length} PASS · events WORM-committed with ML-DSA-87 in enterprise mode</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Scenario</th>
                <th className="py-2 pr-3">Worst band</th>
                <th className="py-2 pr-3">Release gate</th>
                <th className="py-2 pr-3">Audit event</th>
                <th className="py-2 pr-3">Expected</th>
                <th className="py-2 pr-3">Result</th>
              </tr>
            </thead>
            <tbody>
              {replay.rows.map(r => (
                <tr key={r.scenario} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3">{r.scenario}</td>
                  <td className="py-2 pr-3"><StatusBadge status={r.worstBand} /></td>
                  <td className="py-2 pr-3 font-mono text-xs">{r.gateVerdict}</td>
                  <td className="py-2 pr-3 text-xs text-slate-500">{r.eventAction} · {r.eventSeverity}</td>
                  <td className="py-2 pr-3 text-xs text-slate-500">{r.expected}</td>
                  <td className={'py-2 pr-3 font-mono text-xs ' + (r.pass ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400')}>{r.pass ? 'PASS' : 'FAIL'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-slate-500 mt-3">Threshold evaluators are pure functions in the schema-of-record module (gien-platform/src/rag/contract.ts); this replay exercises the exact contract that enterprise CI asserts by fixture test. Band transitions fan out to AlertHistory and the notification service in enterprise mode. Fictional simulation.</p>
      </Card>

      {showCatalog && (
        <Card title="Audit event catalog (WORM-committed in enterprise mode)">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Event</th>
                <th className="py-2 pr-3">Emitter</th>
                <th className="py-2 pr-3">Fields</th>
              </tr>
            </thead>
            <tbody>
              {auditCatalog.map(a => (
                <tr key={a.event} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3 font-mono text-xs">{a.event}</td>
                  <td className="py-2 pr-3">{a.emitter}</td>
                  <td className="py-2 pr-3 text-xs text-slate-500">{a.fields}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </Page>
  );
}