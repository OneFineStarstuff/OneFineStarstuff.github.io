import { useState } from 'react';
import { Page, Card, RiskGauge, Sparkline, download, toCsv } from '../components/ui';
import { riskIndices } from '../data';
import { formatReportingWindow, getReportingWindow } from '../reportingWindow.js';
import type { RiskIndex } from '../types';


const omegaGar = [
  { id: 'CESI', label: 'CESI', value: 0.526, delta: '+0.001', note: 'Constitutional Entropy Stability Index' },
  { id: 'UCSI', label: 'UCSI', value: 0.697, delta: '+0.001', note: 'Universal Compliance Synthesis Index' },
  { id: 'UCI', label: 'UCI', value: 0.723, delta: '+0.001', note: 'Universal Coherence Index' },
  { id: 'CDS', label: 'CDS', value: 0.135, delta: '-0.001', note: 'Constitutional Divergence Score' },
  { id: 'IP', label: 'Infinity Pillar', value: 0.84, delta: '+1 pp', note: 'Long-horizon readiness demonstration' },
];

export default function SystemicRiskTelemetry() {
  const [selected, setSelected] = useState<RiskIndex | null>(null);
  const reportingWindow = getReportingWindow();
  const windowLabel = formatReportingWindow(reportingWindow);

  const exportCsv = () => {
    const rows = riskIndices.map(r => ({
      id: r.id,
      assessmentStatus: r.assessmentStatus,
      sourceKind: r.sourceKind,
      demoValue: r.value,
      demoDelta: r.delta,
      observedAt: r.observedAt ?? 'NOT OBSERVED',
      windowStart: r.windowStart ?? '',
      windowEnd: r.windowEnd ?? '',
      methodVersion: r.methodVersion ?? '',
      evidenceRefs: r.evidenceRefs.join(';'),
      note: 'SYNTHETIC DEMONSTRATION VALUE; NOT AN OPERATIONAL OBSERVATION',
    }));
    download(`risk-indices-demo-${reportingWindow.end.slice(0, 10)}.csv`, toCsv(rows), 'text/csv');
  };

  return (
    <Page
      title="Systemic Risk Telemetry"
      subtitle={`Demonstration values only · reporting window ${windowLabel} · no live telemetry connector configured`}
    >
      <Card title="Evidence state">
        <div className="space-y-2 text-sm">
          <p><strong>Operational assessment: NOT ASSESSED.</strong> All twelve displayed series are seeded synthetic fixtures. Their values, deltas, chart bands and trends are illustrative and must not be used as risk conclusions.</p>
          <p className="text-slate-500">The reporting window defines the requested time interval only. It does not assert that observations, source attestations or verified measurements were received for that interval.</p>
        </div>
      </Card>

      <div className="flex flex-wrap items-center gap-2">
        <button onClick={exportCsv} className="px-3 py-1.5 text-sm rounded bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900">Export demo CSV</button>
        <span className="text-xs text-slate-500">Export includes source status, assessment status and evidence-reference fields.</span>
      </div>

      <Card title="Headline indices — synthetic fixture values">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {riskIndices.slice(0, 8).map(r => (
            <button key={r.id} onClick={() => setSelected(r)} className="text-left rounded-lg border border-slate-200 dark:border-slate-800 p-3 hover:border-sky-400 transition">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-sm">{r.label}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded border border-amber-300 bg-amber-50 text-amber-900 dark:bg-amber-950/50 dark:text-amber-200">NOT ASSESSED</span>
              </div>
              <RiskGauge value={r.value} thresholds={r.thresholds} label={`${r.label} synthetic demo value`} />
              <div className="mt-1 flex items-center justify-between gap-2">
                <Sparkline data={r.series} />
                <span className="text-xs font-mono text-slate-500">{r.delta > 0 ? '+' : ''}{r.delta.toFixed(3)} demo Δ</span>
              </div>
              <div className="mt-2 text-[10px] uppercase tracking-wide text-amber-700 dark:text-amber-300">Synthetic demonstration value: {r.value.toFixed(3)}</div>
            </button>
          ))}
        </div>
      </Card>

      <Card title="Extended indices — simulation fields">
        <div className="grid md:grid-cols-2 gap-3">
          {riskIndices.slice(8).map(r => (
            <div key={r.id} className="flex items-center justify-between gap-3 rounded border border-slate-200 dark:border-slate-800 p-3">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm">{r.label}</span>
                  <span className="text-[9px] px-1 rounded bg-amber-100 text-amber-800 border border-amber-300">SIMULATED</span>
                  <span className="text-[9px] px-1 rounded border border-slate-300 text-slate-600 dark:text-slate-300">NOT ASSESSED</span>
                </div>
                <div className="text-xs text-slate-500 max-w-xs mt-0.5">{r.description}</div>
                <div className="text-[10px] text-slate-500 mt-1">Source: {r.sourceKind} · Evidence references: {r.evidenceRefs.length}</div>
              </div>
              <div className="text-right">
                <div className="font-mono text-sm">Demo {r.value.toFixed(3)}</div>
                <Sparkline data={r.series} width={100} height={24} />
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Ω-GAR slow-frequency indices — synthetic simulation fields">
        <p className="text-xs text-slate-500 mb-3">
          Illustrative long-horizon scenario fields for 2035–2100+. These numbers are synthetic demonstrations, not observations,
          forecasts, operational risk estimates, evidence of quarterly review, or assessment results.
        </p>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {omegaGar.map(o => (
            <div key={o.id} className="rounded-lg border border-slate-200 dark:border-slate-800 p-3">
              <div className="text-sm font-mono">{o.label}</div>
              <div className="mt-1 flex flex-wrap gap-1">
                <span className="text-[9px] px-1 rounded border border-amber-300 bg-amber-50 text-amber-900 dark:bg-amber-950/50 dark:text-amber-200">SIMULATION</span>
                <span className="text-[9px] px-1 rounded border border-slate-300 text-slate-600 dark:text-slate-300">NOT ASSESSED</span>
              </div>
              <div className="font-mono text-lg mt-2">Demo {o.value.toFixed(3)}</div>
              <div className="text-xs text-slate-500">Illustrative delta: {o.delta}</div>
              <div className="text-[10px] text-slate-500 mt-1">{o.note}</div>
            </div>
          ))}
        </div>
      </Card>

      {selected && (
        <Card title={`Demo detail — ${selected.label}`} action={<button onClick={() => setSelected(null)} className="text-xs text-slate-500">Close</button>}>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <p className="text-sm mb-3">{selected.description}</p>
              <div className="rounded border border-amber-300 bg-amber-50 dark:bg-amber-950/30 p-3 text-xs text-amber-950 dark:text-amber-100">
                <strong>NOT ASSESSED.</strong> Displayed number is generated sample data, not a current measurement. No evidence references or observation timestamp are attached.
              </div>
              <div className="mt-3 text-xs text-slate-500">Source kind: {selected.sourceKind} · Method: {selected.methodVersion ?? 'unknown'} · Observed at: {selected.observedAt ?? 'NOT OBSERVED'}</div>
            </div>
            <div className="space-y-3">
              <div className="text-xs uppercase text-slate-500">Illustrative UI bands — not validated operating limits</div>
              <div className="text-sm font-mono">AMBER ≥ {selected.thresholds.amber} · RED ≥ {selected.thresholds.red} · CRITICAL ≥ {selected.thresholds.critical}</div>
              <Sparkline data={selected.series} width={340} height={60} />
              <div className="text-xs text-slate-500">Requested reporting window: {windowLabel}</div>
            </div>
          </div>
        </Card>
      )}
    </Page>
  );
}
