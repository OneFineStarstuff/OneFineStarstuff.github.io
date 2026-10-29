import { useState } from 'react';
import { Page, Card, RiskGauge, Sparkline, StatusBadge, Disclosure, download, toCsv } from '../components/ui';
import { riskIndices, severityFor } from '../data';
import type { RiskIndex } from '../types';

const omegaGar = [
  { id: 'CESI', label: 'CESI', value: 0.526, delta: '+0.001', note: 'Constitutional Entropy Stability Index' },
  { id: 'UCSI', label: 'UCSI', value: 0.697, delta: '+0.001', note: 'Universal Compliance Synthesis Index' },
  { id: 'UCI', label: 'UCI', value: 0.723, delta: '+0.001', note: 'Universal Coherence Index' },
  { id: 'CDS', label: 'CDS', value: 0.135, delta: '-0.001', note: 'Constitutional Divergence Score' },
  { id: 'IP', label: 'Infinity Pillar', value: 0.84, delta: '+1 pp', note: 'Long-horizon readiness (84%)' },
];

export default function SystemicRiskTelemetry() {
  const [selected, setSelected] = useState<RiskIndex | null>(null);
  const exportCsv = () => {
    const rows = riskIndices.map(r => ({
      id: r.id, value: r.value, delta: r.delta,
      severity: severityFor(r.value, r.thresholds), fictional: r.fictional,
    }));
    download('risk-indices-2026-10-27.csv', toCsv(rows), 'text/csv');
  };
  const exportJson = () => {
    const snapshot = { window: '2026-10-26T09:00:00Z → 2026-10-27T09:00:00Z', baseline: 'GIEN-DOSSIER-2026-300', merkle_root: '0x9c4e1b7d5a2f8c3e6b0d4a7f1c5e9b2d6a8c0f3e5b7d1a9c2e4f6b8d0a2c5e7f', indices: riskIndices.map(r => ({ id: r.id, value: r.value, delta: r.delta, severity: severityFor(r.value, r.thresholds), fictional: r.fictional })) };
    download('risk-indices-snapshot.json', JSON.stringify(snapshot, null, 2), 'application/json');
  };

  return (
    <Page title="Systemic Risk Telemetry" subtitle="24h window ending 2026-10-27 09:00 UTC · RED band transitions open a mandatory acknowledgement flow in enterprise mode">
      <div className="flex flex-wrap gap-2">
        <button onClick={exportCsv} className="px-3 py-1.5 text-sm rounded bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900">Export CSV</button>
        <button onClick={exportJson} className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700">Export JSON snapshot</button>
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
                  <span className={'text-xs font-mono ' + (r.delta > 0 ? 'text-red-600' : r.delta < 0 ? 'text-emerald-600' : 'text-slate-500')}>
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

      <Card title="Ω-GAR slow-frequency indices" subtitle={undefined}>
        <p className="text-xs text-slate-500 mb-3">Long-horizon epoch 2035–2100+ telemetry — reviewed quarterly, rendered apart from the daily banding engine, never mixed into daily alerts.</p>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {omegaGar.map(o => (
            <div key={o.id} className="rounded-lg border border-indigo-200 dark:border-indigo-900 bg-indigo-50 dark:bg-indigo-950/30 p-3">
              <div className="text-sm font-mono">{o.label}</div>
              <div className="font-mono text-lg">{o.value.toFixed(3)}</div>
              <div className="text-xs text-indigo-700 dark:text-indigo-300">{o.delta} · slow-frequency</div>
              <div className="text-[10px] text-slate-500 mt-1">{o.note}</div>
            </div>
          ))}
        </div>
      </Card>

      {selected && (
        <Card title={'Detail — ' + selected.label} action={<button onClick={() => setSelected(null)} className="text-xs text-slate-500">close</button>}>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <p className="text-sm mb-3">{selected.description}</p>
              {selected.fictional && (
                <div className="rounded border border-amber-300 bg-amber-50 dark:bg-amber-950/30 p-3 text-xs text-amber-900 dark:text-amber-200">
                  This is a <strong>simulation field</strong>. It is not a forecast and must not be interpreted as a real risk estimate.
                </div>
              )}
              <div className="rounded border border-slate-200 dark:border-slate-800 p-3 mt-3">
                <div className="text-xs uppercase text-slate-500 mb-1">Sealed evidence — STLM-2026-300</div>
                <div className="text-sm">Quote age: 7 h (window maximum) · evidence-quote floor: 24 h</div>
                <div className="text-xs text-slate-500 mt-1">Every index value binds to its sealed quote; band transitions emit sealed audit events and feed AlertHistory.</div>
              </div>
            </div>
            <div className="space-y-3">
              <Disclosure min="engineering">
                <div className="text-xs uppercase text-slate-500">Thresholds</div>
                <div className="text-sm font-mono">AMBER ≥ {selected.thresholds.amber} · RED ≥ {selected.thresholds.red} · CRITICAL ≥ {selected.thresholds.critical}</div>
                <Sparkline data={selected.series} width={340} height={60} />
              </Disclosure>
              <Disclosure min="crypto">
                <div className="rounded border border-slate-200 dark:border-slate-800 p-3">
                  <div className="text-xs uppercase text-slate-500 mb-1">Sealing evidence</div>
                  <div className="text-xs font-mono break-all">Merkle leaf proof against dossier-300 root 0x9c4e1b7d5a2f8c3e6b0d4a7f1c5e9b2d6a8c0f3e5b7d1a9c2e4f6b8d0a2c5e7f</div>
                </div>
              </Disclosure>
            </div>
          </div>
        </Card>
      )}
    </Page>
  );
}