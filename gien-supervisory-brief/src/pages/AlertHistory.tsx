import { useMemo, useState } from 'react';
import { Bell, Download } from 'lucide-react';
import DetailDrawer from '../components/DetailDrawer';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import { ALERT_HISTORY, FICTIONAL_NOTICE, type HistoryAlert } from '../data/extendedData';
import { useGovernance } from '../context/GovernanceContext';

const SEVERITIES = ['ALL', 'CRITICAL', 'ELEVATED', 'INFO'] as const;

export default function AlertHistory() {
  const { filingRef, evaluationWindow } = useGovernance();
  const [severity, setSeverity] = useState<(typeof SEVERITIES)[number]>('ALL');
  const [onlyOpen, setOnlyOpen] = useState(false);
  const [selected, setSelected] = useState<HistoryAlert | null>(null);
  const [exported, setExported] = useState<string | null>(null);

  const rows = useMemo(
    () =>
      ALERT_HISTORY.filter(
        (a) => (severity === 'ALL' || a.severity === severity) && (!onlyOpen || !a.acknowledged)
      ),
    [severity, onlyOpen]
  );

  const downloadFile = (name: string, content: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    setExported(name);
  };

  const exportCsv = () => {
    const headers = ['alert_id', 'timestamp', 'severity', 'source', 'message', 'acknowledged', 'acknowledged_by', 'filing_ref', 'window', 'watermark'];
    const escape = (v: string) => `"${v.replace(/"/g, '""')}"`;
    const lines = [headers.join(',')];
    rows.forEach((r) => {
      lines.push(
        [r.id, r.timestamp, r.severity, r.source, r.message, String(r.acknowledged), r.acknowledgedBy ?? '', filingRef, evaluationWindow, FICTIONAL_NOTICE]
          .map(escape)
          .join(',')
      );
    });
    downloadFile(`gien-alert-history-2026-11-03.csv`, lines.join('\n'), 'text/csv;charset=utf-8');
  };

  const exportJson = () => {
    const payload = {
      generated_at: '2026-11-03T09:00:00Z',
      filing_ref: filingRef,
      evaluation_window: evaluationWindow,
      watermark: FICTIONAL_NOTICE,
      count: rows.length,
      alerts: rows,
    };
    downloadFile('gien-alert-history-2026-11-03.json', JSON.stringify(payload, null, 2), 'application/json');
  };

  return (
    <div>
      <PageHeader
        title="Alert History"
        subtitle="Supervisory alert log with CSV and JSON export"
        crumbs={[{ label: 'Home', to: '/dashboard' }, { label: 'Alert History' }]}
        actions={
          <>
            <button type="button" onClick={exportCsv} className="inline-flex items-center gap-1.5 rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800">
              <Download size={13} /> CSV
            </button>
            <button type="button" onClick={exportJson} className="inline-flex items-center gap-1.5 rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800">
              <Download size={13} /> JSON
            </button>
          </>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1 rounded-md border border-gray-700 p-0.5">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSeverity(s)}
              aria-pressed={severity === s}
              className={`rounded px-2.5 py-1 text-[11px] ${severity === s ? 'bg-indigo-500 text-white' : 'text-gray-400 hover:text-gray-200'}`}
            >
              {s}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-1.5 text-[11px] text-gray-400">
          <input type="checkbox" checked={onlyOpen} onChange={(e) => setOnlyOpen(e.target.checked)} className="h-3 w-3 accent-indigo-500" />
          Unacknowledged only
        </label>
        <span className="ml-auto text-[11px] text-gray-500">{rows.length} alerts</span>
      </div>

      {exported && (
        <p className="mb-3 rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-[11px] text-emerald-300">
          Exported {exported} with FICTIONAL/SIMULATION watermark attached.
        </p>
      )}

      <div className="overflow-x-auto rounded-lg border border-gray-700">
        <table className="w-full min-w-[760px] text-left text-xs">
          <thead className="bg-gray-800/70 text-gray-400">
            <tr>
              <th className="px-3 py-2 font-medium">Timestamp (UTC)</th>
              <th className="px-3 py-2 font-medium">Severity</th>
              <th className="px-3 py-2 font-medium">Source</th>
              <th className="px-3 py-2 font-medium">Message</th>
              <th className="px-3 py-2 font-medium">State</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr
                key={a.id}
                onClick={() => setSelected(a)}
                className="cursor-pointer border-t border-gray-700/60 hover:bg-gray-800/60"
              >
                <td className="px-3 py-2 font-mono text-[11px] text-gray-400">{a.timestamp}</td>
                <td className="px-3 py-2"><StatusBadge variant={a.severity} /></td>
                <td className="px-3 py-2 font-mono text-[11px] text-indigo-300">{a.source}</td>
                <td className="px-3 py-2 text-gray-300">{a.message}</td>
                <td className="px-3 py-2">
                  <StatusBadge variant={a.acknowledged ? 'VERIFIED' : 'PENDING'} label={a.acknowledged ? 'ACK' : 'OPEN'} />
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-gray-500">No alerts match the current filters.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="mt-4 flex items-center gap-1.5 text-[11px] text-gray-500">
        <Bell size={11} /> {FICTIONAL_NOTICE}
      </p>

      <DetailDrawer open={selected !== null} onClose={() => setSelected(null)} title={selected?.id ?? ''} subtitle="Alert detail">
        {selected && (
          <dl className="space-y-3 text-sm">
            <div>
              <dt className="text-xs text-gray-500">Timestamp</dt>
              <dd className="font-mono text-gray-200">{selected.timestamp}</dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500">Severity</dt>
              <dd className="mt-1"><StatusBadge variant={selected.severity} /></dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500">Source system</dt>
              <dd className="font-mono text-gray-200">{selected.source}</dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500">Message</dt>
              <dd className="text-gray-300">{selected.message}</dd>
            </div>
            <div>
              <dt className="text-xs text-gray-500">Acknowledgment</dt>
              <dd className="text-gray-300">
                {selected.acknowledged ? `Acknowledged by ${selected.acknowledgedBy}` : 'Not yet acknowledged'}
              </dd>
            </div>
          </dl>
        )}
      </DetailDrawer>
    </div>
  );
}
