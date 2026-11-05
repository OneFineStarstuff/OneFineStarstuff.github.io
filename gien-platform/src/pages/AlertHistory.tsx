import { useState } from 'react';
import { Page, Card, StatusBadge, download, toCsv } from '../components/ui';
import { alerts } from '../data';
import type { Severity } from '../types';

export default function AlertHistory() {
  const [severity, setSeverity] = useState<'all' | Severity>('all');
  const [onlyUnack, setOnlyUnack] = useState(false);
  const filtered = alerts.filter(a => (severity === 'all' || a.severity === severity) && (!onlyUnack || !a.acknowledged));

  const exportCsv = () => download('alerts.csv', toCsv(filtered.map(a => ({ ...a }))), 'text/csv');

  return (
    <Page title="Alert History" subtitle="Unified alert log with severity filtering and CSV export">
      <Card>
        <div className="flex flex-wrap gap-2 mb-4 items-center">
          <div className="flex gap-1">
            {(['all', 'GREEN', 'AMBER', 'RED', 'CRITICAL'] as const).map(s => (
              <button key={s} onClick={() => setSeverity(s)} className={`text-xs px-2 py-1 rounded border ${severity === s ? 'bg-sky-600 text-white border-sky-600' : 'border-slate-300 dark:border-slate-700'}`}>{s}</button>
            ))}
          </div>
          <label className="text-xs flex items-center gap-1">
            <input type="checkbox" checked={onlyUnack} onChange={e => setOnlyUnack(e.target.checked)} />
            Unacknowledged only
          </label>
          <button onClick={exportCsv} className="text-xs px-2 py-1 rounded bg-emerald-600 text-white ml-auto">Export CSV</button>
        </div>
        <ul className="divide-y divide-slate-200 dark:divide-slate-800">
          {filtered.map(a => (
            <li key={a.id} className="py-3 flex items-start gap-3">
              <StatusBadge status={a.severity} />
              <div className="flex-1">
                <div className="text-sm">{a.message}</div>
                <div className="text-xs text-slate-500">{a.source} · {a.ts}{a.acknowledged ? ' · acknowledged' : ''}</div>
              </div>
            </li>
          ))}
          {filtered.length === 0 && <li className="py-3 text-sm text-slate-500">No alerts match the current filter.</li>}
        </ul>
      </Card>
    </Page>
  );
}
