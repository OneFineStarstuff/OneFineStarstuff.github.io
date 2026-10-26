import { useMemo, useState } from 'react';
import { Page, Card, ComplianceProgressBar, download, toCsv } from '../components/ui';
import { frameworks } from '../data';
import type { Framework } from '../types';

export default function ComplianceMatrix() {
  const [filter, setFilter] = useState<'all' | Framework['family']>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | Framework['status']>('all');

  const filtered = useMemo(() => frameworks.filter(f =>
    (filter === 'all' || f.family === filter) &&
    (statusFilter === 'all' || f.status === statusFilter)
  ), [filter, statusFilter]);

  const exportMatrix = () => {
    download('compliance-matrix.csv', toCsv(filtered.map(f => ({
      id: f.id, name: f.name, status: f.status,
      controls: f.controls, total: f.total,
      oscalSsp: f.oscalSsp, oscalAr: f.oscalAr,
      opaViolations: f.opaViolations, opaWarnings: f.opaWarnings,
    }))), 'text/csv');
  };

  return (
    <Page title="Compliance Matrix" subtitle={`${filtered.length} of ${frameworks.length} frameworks — 18 total`}>
      <Card>
        <div className="flex flex-wrap gap-2 mb-4">
          <div className="flex flex-wrap gap-1">
            {(['all', 'ai', 'financial', 'operational', 'privacy', 'fictional'] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)} className={`text-xs px-2 py-1 rounded border ${filter === f ? 'bg-sky-600 text-white border-sky-600' : 'border-slate-300 dark:border-slate-700'}`}>
                {f === 'all' ? 'All families' : f}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap gap-1 ml-auto">
            {(['all', 'COMPLIANT', 'PARTIAL', 'NON-COMPLIANT', 'PENDING'] as const).map(s => (
              <button key={s} onClick={() => setStatusFilter(s)} className={`text-xs px-2 py-1 rounded border ${statusFilter === s ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900' : 'border-slate-300 dark:border-slate-700'}`}>
                {s === 'all' ? 'All statuses' : s}
              </button>
            ))}
          </div>
          <button onClick={exportMatrix} className="text-xs px-2 py-1 rounded bg-emerald-600 text-white ml-auto">Export CSV</button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Framework</th>
                <th className="py-2 pr-3">Status</th>
                <th className="py-2 pr-3">Controls</th>
                <th className="py-2 pr-3">OSCAL</th>
                <th className="py-2 pr-3">OPA</th>
                <th className="py-2 pr-3">Last assessed</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => (
                <tr key={f.id} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3">
                    <div className="font-medium">{f.name}</div>
                    <div className="text-xs text-slate-500">{f.family}</div>
                  </td>
                  <td className="py-2 pr-3">
                    <span className={`text-xs px-2 py-0.5 rounded ${f.status === 'COMPLIANT' ? 'bg-emerald-100 text-emerald-800' : f.status === 'PARTIAL' ? 'bg-amber-100 text-amber-800' : 'bg-red-100 text-red-800'}`}>
                      {f.status}
                    </span>
                  </td>
                  <td className="py-2 pr-3 min-w-[140px]"><ComplianceProgressBar value={f.controls} total={f.total} /></td>
                  <td className="py-2 pr-3 text-xs font-mono">{f.oscalSsp ? '✓' : '✗'}/{f.oscalAr ? '✓' : '✗'}</td>
                  <td className="py-2 pr-3 text-xs font-mono">{f.opaViolations}v / {f.opaWarnings}w</td>
                  <td className="py-2 pr-3 text-xs text-slate-500">{f.lastAssessed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </Page>
  );
}
