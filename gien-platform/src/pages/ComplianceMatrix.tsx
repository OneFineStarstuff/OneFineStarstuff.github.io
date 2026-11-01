import { useMemo, useState } from 'react';
import { Page, Card, download, toCsv } from '../components/ui';
import { frameworks } from '../data';
import type { Framework, FrameworkStatus } from '../types';

const sgr031 = {
  id: 'SGR-031',
  title: 'Treaty SGR-031 — pre-assembly exhibit set',
  preAssemblyPct: 90,
  exhibitsInCirculation: 12,
  exhibitsTotal: 12,
  assemblyDate: '2026-11-06',
  oscalRev: 1161,
  baseline: 'GIEN-DOSSIER-2026-300',
  sourceKind: 'synthetic',
  assessmentStatus: 'NOT_ASSESSED',
  evidenceRefs: [],
};

const statusFilters: Array<'all' | FrameworkStatus> = [
  'all', 'NOT ASSESSED', 'EVIDENCE PENDING', 'COMPLIANT', 'PARTIAL', 'NON-COMPLIANT', 'PENDING',
];

function statusClass(status: FrameworkStatus): string {
  if (status === 'COMPLIANT') return 'bg-emerald-100 text-emerald-800';
  if (status === 'PARTIAL' || status === 'EVIDENCE PENDING') return 'bg-amber-100 text-amber-900';
  if (status === 'NON-COMPLIANT') return 'bg-red-100 text-red-800';
  return 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200';
}

export default function ComplianceMatrix() {
  const [filter, setFilter] = useState<'all' | Framework['family']>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | FrameworkStatus>('all');

  const filtered = useMemo(() => frameworks.filter(f =>
    (filter === 'all' || f.family === filter) &&
    (statusFilter === 'all' || f.status === statusFilter)
  ), [filter, statusFilter]);

  const exportMatrix = () => {
    download(`compliance-matrix-demo-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(filtered.map(f => ({
      id: f.id,
      name: f.name,
      status: f.status,
      sourceKind: f.sourceKind,
      assessmentStatus: f.assessmentStatus,
      applicability: f.applicability,
      controls: f.controls ?? 'NOT ASSESSED',
      total: f.total ?? 'NOT ASSESSED',
      oscalSsp: f.oscalSsp === null ? 'NOT ASSESSED' : f.oscalSsp,
      oscalAr: f.oscalAr === null ? 'NOT ASSESSED' : f.oscalAr,
      opaViolations: f.opaViolations ?? 'NOT ASSESSED',
      opaWarnings: f.opaWarnings ?? 'NOT ASSESSED',
      lastAssessed: f.lastAssessed ?? 'NOT ASSESSED',
      evidenceRefs: f.evidenceRefs.join(';'),
    }))), 'text/csv');
  };

  const exportSgr = () => {
    download('sgr031-pre-assembly-demo.json', JSON.stringify(sgr031, null, 2), 'application/json');
  };

  return (
    <Page title="Compliance Matrix" subtitle={`${filtered.length} framework records shown · current applicability and conformance assessments are not established`}>
      <Card title="Assessment state">
        <p className="text-sm"><strong>NOT ASSESSED.</strong> Framework names are a reference catalogue; the current repository fixture contains no assessment evidence, verified control coverage, OPA execution results or OSCAL assessment artifacts. This page does not establish legal applicability or conformity.</p>
        <p className="text-xs text-slate-500 mt-2">All real-instrument applicability remains PENDING REVIEW until jurisdiction, regulated-entity role, system scope, effective date and supporting evidence have been documented. Fictional GIEN treaties are not included in real-law compliance conclusions.</p>
      </Card>

      <Card>
        <div className="flex flex-wrap gap-2 mb-4">
          <div className="flex flex-wrap gap-1">
            {(['all', 'ai', 'financial', 'operational', 'privacy', 'fictional'] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)} className={'text-xs px-2 py-1 rounded border ' + (filter === f ? 'bg-sky-600 text-white border-sky-600' : 'border-slate-300 dark:border-slate-700')}>
                {f === 'all' ? 'All families' : f}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap gap-1 ml-auto">
            {statusFilters.map(s => (
              <button key={s} onClick={() => setStatusFilter(s)} className={'text-xs px-2 py-1 rounded border ' + (statusFilter === s ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900' : 'border-slate-300 dark:border-slate-700')}>
                {s === 'all' ? 'All statuses' : s}
              </button>
            ))}
          </div>
          <button onClick={exportMatrix} className="text-xs px-2 py-1 rounded bg-emerald-600 text-white ml-auto">Export evidence-qualified CSV</button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-slate-200 dark:border-slate-800">
                <th className="py-2 pr-3">Framework</th>
                <th className="py-2 pr-3">Assessment status</th>
                <th className="py-2 pr-3">Coverage</th>
                <th className="py-2 pr-3">OSCAL evidence</th>
                <th className="py-2 pr-3">OPA result</th>
                <th className="py-2 pr-3">Last assessed</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => (
                <tr key={f.id} className="border-b border-slate-100 dark:border-slate-900">
                  <td className="py-2 pr-3">
                    <div className="font-medium">{f.name}</div>
                    <div className="text-xs text-slate-500">{f.family} · applicability {f.applicability}</div>
                  </td>
                  <td className="py-2 pr-3"><span className={'text-xs px-2 py-0.5 rounded ' + statusClass(f.status)}>{f.status}</span></td>
                  <td className="py-2 pr-3 text-xs text-slate-500">{f.controls === null || f.total === null ? 'NOT ASSESSED' : `${f.controls}/${f.total}`}</td>
                  <td className="py-2 pr-3 text-xs">{f.oscalSsp === null || f.oscalAr === null ? 'NOT ASSESSED' : `SSP ${f.oscalSsp ? 'present' : 'missing'} / AR ${f.oscalAr ? 'present' : 'missing'}`}</td>
                  <td className="py-2 pr-3 text-xs">{f.opaViolations === null || f.opaWarnings === null ? 'NOT ASSESSED' : `${f.opaViolations} violations / ${f.opaWarnings} warnings`}</td>
                  <td className="py-2 pr-3 text-xs text-slate-500">{f.lastAssessed ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Treaty pre-assembly — SGR-031 (simulation fixture)" action={
        <button onClick={exportSgr} className="text-xs px-2 py-1 rounded bg-slate-700 text-white">Export demo JSON</button>
      }>
        <p className="text-sm mb-3">{sgr031.title}. This is a project-authored scenario tracker, not a verified legal instrument, compliance assertion or signed supervisory record.</p>
        <div className="grid md:grid-cols-2 gap-4 items-start">
          <div>
            <div className="text-xs text-slate-500 mb-1">Illustrative pre-assembly progress only</div>
            <div className="h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden"><div className="h-full bg-amber-500" style={{ width: `${sgr031.preAssemblyPct}%` }} /></div>
            <p className="text-xs text-slate-500 mt-1">Demo value {sgr031.preAssemblyPct}% · {sgr031.exhibitsInCirculation}/{sgr031.exhibitsTotal} sample exhibit drafts · scenario target {sgr031.assemblyDate}.</p>
          </div>
          <div className="flex flex-wrap gap-1">
            {Array.from({ length: sgr031.exhibitsTotal }, (_, i) => (
              <span key={i} className="text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200">Demo draft {String(i + 1).padStart(2, '0')}</span>
            ))}
          </div>
        </div>
        <p className="text-xs text-slate-500 mt-3">Assembly target: {sgr031.assemblyDate}. Progress, draft count and target are simulation data; no current signed exhibit inventory was retrieved.</p>
      </Card>
    </Page>
  );
}
