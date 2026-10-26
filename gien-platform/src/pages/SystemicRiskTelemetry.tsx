import { useState } from 'react';
import { Page, Card, RiskGauge, Sparkline, StatusBadge, download, toCsv } from '../components/ui';
import { riskIndices, severityFor } from '../data';
import type { RiskIndex } from '../types';

export default function SystemicRiskTelemetry() {
  const [selected, setSelected] = useState<RiskIndex | null>(null);
  const exportCsv = () => {
    const rows = riskIndices.map(r => ({
      id: r.id, value: r.value, delta: r.delta,
      severity: severityFor(r.value, r.thresholds), fictional: r.fictional,
    }));
    download('risk-indices-2026-10-26.csv', toCsv(rows), 'text/csv');
  };

  return (
    <Page title="Systemic Risk Telemetry" subtitle="24h window ending 2026-10-26 09:00 UTC">
      <div className="flex flex-wrap gap-2">
        <button onClick={exportCsv} className="px-3 py-1.5 text-sm rounded bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900">Export CSV</button>
      </div>

      <Card title="Headline indices">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {riskIndices.slice(0, 8).map(r => {
            const sev = severityFor(r.value, r.thresholds);
            return (
              <button key={r.id} onClick={() => setSelected(r)} className="text-left rounded-lg border border-slate-200 dark:border-slate-800 p-3 hover:border-sky-400 transition">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm">{r.label}</span>
                  <StatusBadge status={sev} />
                </div>
                <RiskGauge value={r.value} thresholds={r.thresholds} label={r.label} />
                <div className="mt-1 flex items-center justify-between">
                  <Sparkline data={r.series} />
                  <span className={`text-xs font-mono ${r.delta > 0 ? 'text-red-600' : r.delta < 0 ? 'text-emerald-600' : 'text-slate-500'}`}>
                    {r.delta > 0 ? '+' : ''}{r.delta.toFixed(3)}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </Card>

      <Card title="Extended indices">
        <div className="grid md:grid-cols-2 gap-3">
          {riskIndices.slice(8).map(r => (
            <div key={r.id} className="flex items-center justify-between gap-3 rounded border border-slate-200 dark:border-slate-800 p-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm">{r.label}</span>
                  {r.fictional && <span className="text-[9px] px-1 rounded bg-amber-100 text-amber-800 border border-amber-300">SIMULATION</span>}
                </div>
                <div className="text-xs text-slate-500 max-w-xs mt-0.5">{r.description}</div>
              </div>
              <div className="text-right">
                <div className="font-mono text-sm">{r.value.toFixed(3)}</div>
                <Sparkline data={r.series} width={100} height={24} />
              </div>
            </div>
          ))}
        </div>
      </Card>

      {selected && (
        <Card title={`Detail — ${selected.label}`} action={<button onClick={() => setSelected(null)} className="text-xs text-slate-500">close</button>}>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <p className="text-sm mb-3">{selected.description}</p>
              {selected.fictional && (
                <div className="rounded border border-amber-300 bg-amber-50 dark:bg-amber-950/30 p-3 text-xs text-amber-900 dark:text-amber-200">
                  This is a <strong>simulation field</strong>. It is not a forecast and must not be interpreted as a real risk estimate.
                </div>
              )}
            </div>
            <div className="space-y-3">
              <div className="text-xs uppercase text-slate-500">Thresholds</div>
              <div className="text-sm font-mono">AMBER ≥ {selected.thresholds.amber} · RED ≥ {selected.thresholds.red} · CRITICAL ≥ {selected.thresholds.critical}</div>
              <Sparkline data={selected.series} width={340} height={60} />
            </div>
          </div>
        </Card>
      )}
    </Page>
  );
}
