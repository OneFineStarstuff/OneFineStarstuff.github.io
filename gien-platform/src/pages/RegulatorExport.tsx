import { useMemo, useState } from 'react';
import { Page, Card, download } from '../components/ui';
import { useToast } from '../contexts';
import { riskIndices, frameworks, domains } from '../data';
import { formatReportingWindow, getReportingWindow } from '../reportingWindow.js';
import type { Role, Layer, Framework } from '../types';

type Classification = 'UNCLASSIFIED' | 'RESTRICTED' | 'CONFIDENTIAL' | 'TREATY-GRADE';

interface Section { title: string; abstract: string; content: string; }

function escapeXml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}
function escapeHtml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function coverageValue(f: Framework): string {
  return f.controls === null || f.total === null ? 'NOT ASSESSED' : `${f.controls}/${f.total}`;
}
function oscalValue(f: Framework): string {
  return f.oscalSsp === null || f.oscalAr === null ? 'NOT ASSESSED' : `SSP ${f.oscalSsp ? 'present' : 'missing'} / AR ${f.oscalAr ? 'present' : 'missing'}`;
}
function opaValue(f: Framework): string {
  return f.opaViolations === null || f.opaWarnings === null ? 'NOT ASSESSED' : `${f.opaViolations} violations / ${f.opaWarnings} warnings`;
}

function buildSections(opts: {
  audience: Role; layer: Layer; classification: Classification;
  includeTelemetry: boolean; includeCompliance: boolean; includeDomains: boolean;
  frameworksFilter: 'all' | 'ai' | 'financial' | 'fictional';
}, reportingWindow: { start: string; end: string }): Section[] {
  const sections: Section[] = [];
  const windowLabel = formatReportingWindow(reportingWindow);

  if (opts.includeTelemetry) {
    sections.push({
      title: `Systemic Risk Telemetry — ${windowLabel} — ${opts.classification}`,
      abstract: 'OPERATIONAL ASSESSMENT: NOT ASSESSED. The current UI contains seeded demonstration values only; no authenticated live telemetry, source timestamps or evidence references were connected for this window.',
      content: riskIndices.map(r => [
        `Metric: ${r.label}`,
        `Assessment: ${r.assessmentStatus}`,
        `Source kind: ${r.sourceKind}`,
        `Demonstration value: ${r.value.toFixed(3)} (synthetic fixture, not an operational observation)`,
        `Demonstration delta: ${r.delta >= 0 ? '+' : ''}${r.delta.toFixed(3)} (synthetic fixture)`,
        `Observed at: ${r.observedAt ?? 'NOT OBSERVED'}`,
        `Source window: ${r.windowStart ?? 'NOT SUPPLIED'} — ${r.windowEnd ?? 'NOT SUPPLIED'}`,
        `Method version: ${r.methodVersion ?? 'NOT SUPPLIED'}`,
        `Evidence references: ${r.evidenceRefs.length ? r.evidenceRefs.join(', ') : 'NONE'}`,
      ].join('\n')).join('\n\n'),
    });
  }
  if (opts.includeCompliance) {
    const filtered = opts.frameworksFilter === 'all' ? frameworks : frameworks.filter(f => f.family === opts.frameworksFilter);
    sections.push({
      title: `Framework Assessment Register — ${filtered.length} records — ${windowLabel} — ${opts.classification}`,
      abstract: `Current evidence-backed assessments: 0. NOT ASSESSED: ${filtered.filter(f => f.status === 'NOT ASSESSED').length}/${filtered.length}. The presence of a framework name or a mapping fixture is not proof of applicability, control implementation, or conformity.`,
      content: filtered.map(f => [
        f.name,
        `Assessment status: ${f.status}`,
        `Source kind: ${f.sourceKind}`,
        `Applicability: ${f.applicability} — ${f.applicabilityRationale ?? 'RATIONALE NOT RECORDED'}`,
        `Control coverage: ${coverageValue(f)}`,
        `OSCAL artifacts: ${oscalValue(f)}`,
        `OPA execution: ${opaValue(f)}`,
        `Last assessment: ${f.lastAssessed ?? 'NONE'}`,
        `Evidence references: ${f.evidenceRefs.length ? f.evidenceRefs.join(', ') : 'NONE'}`,
      ].join('\n')).join('\n\n'),
    });
  }
  if (opts.includeDomains) {
    sections.push({
      title: `GIEN Control Domains — scenario fixtures — ${windowLabel} — ${opts.classification}`,
      abstract: 'All current operational domain assessments are NOT ASSESSED. The status and risk fields below are labelled as preloaded demonstration fixture values; they must not be interpreted as live domain assurance.',
      content: domains.map(d => [
        `Domain ${d.id} — ${d.name}`,
        'Assessment: NOT ASSESSED',
        `Fixture status: ${d.status} (SIMULATION ONLY)`,
        `Demo risk value: ${d.risk.toFixed(2)} (not an operational measurement)`,
        'Verified remediation count: NOT ASSESSED',
      ].join('\n')).join('\n\n'),
    });
  }
  return sections;
}

export default function RegulatorExport() {
  const { push } = useToast();
  const [audience, setAudience] = useState<Role>('regulator');
  const [layer, setLayer] = useState<Layer>('executive');
  const [classification, setClassification] = useState<Classification>('CONFIDENTIAL');
  const [includeTelemetry, setIncludeTelemetry] = useState(true);
  const [includeCompliance, setIncludeCompliance] = useState(true);
  const [includeDomains, setIncludeDomains] = useState(true);
  const [frameworksFilter, setFrameworksFilter] = useState<'all' | 'ai' | 'financial' | 'fictional'>('all');
  const reportingWindow = useMemo(() => getReportingWindow(), []);
  const windowLabel = formatReportingWindow(reportingWindow);

  const sections = useMemo(() => buildSections({
    audience, layer, classification, includeTelemetry, includeCompliance, includeDomains, frameworksFilter,
  }, reportingWindow), [
    audience, layer, classification, includeTelemetry, includeCompliance, includeDomains, frameworksFilter, reportingWindow,
  ]);

  const doc = sections.map(s =>
    `<title>${escapeXml(s.title)}</title>\n<abstract>${escapeXml(s.abstract)}</abstract>\n<content>\n${escapeXml(s.content)}\n</content>`
  ).join('\n\n---\n\n');

  const exportHeader = () => [
    '# GIEN Dossier — FICTIONAL / SIMULATION',
    '',
    `Classification label: ${classification} (user-selected label; not a classification authority)`,
    `Audience: ${audience}`,
    `Layer: ${layer}`,
    `Reporting window: ${windowLabel}`,
    'Operational assessment status: NOT ASSESSED',
    'Evidence status: synthetic UI fixtures only; no authenticated evidence source connected',
    'Integrity status: browser-generated, unsigned export; no server-side audit event was recorded',
    '',
    'This export is a decision-support prototype artefact, not legal advice, regulatory filing, conformity assessment or independent assurance.',
    '',
    '---',
    '',
  ].join('\n');

  const downloadMd = () => {
    const fileDate = reportingWindow.end.slice(0, 10);
    download(`gien-dossier-demo-${fileDate}.md`, exportHeader() + doc, 'text/markdown');
    push({
      severity: 'AMBER',
      title: 'Simulation dossier exported',
      body: 'Downloaded locally. The file is unsigned, uses synthetic fixtures, and has no server-side audit receipt.',
    });
  };

  const printPdf = () => {
    const w = globalThis.open('', '_blank');
    if (!w) {
      push({ severity: 'AMBER', title: 'Print window blocked', body: 'Allow the browser print window and retry.' });
      return;
    }
    const sectionHtml = sections.map(s =>
      `<h2>${escapeHtml(s.title)}</h2><p><em>${escapeHtml(s.abstract)}</em></p><pre>${escapeHtml(s.content)}</pre>`
    ).join('');
    w.document.write(`<!doctype html><html><head><meta charset="utf-8"><title>GIEN Simulation Dossier</title>
      <style>body{font-family:ui-sans-serif,sans-serif;padding:32px;max-width:900px;margin:auto;line-height:1.6;color:#111}
      .wm{background:#fff7e6;border:1px solid #f59e0b;color:#92400e;padding:8px 10px;font-size:11px;font-family:monospace;margin-bottom:16px}
      pre{white-space:pre-wrap;overflow-wrap:anywhere;font-family:ui-monospace,monospace;font-size:12px;background:#f8fafc;padding:8px;border-radius:4px}
      h2{font-size:16px;margin-top:24px}</style></head>
      <body><div class="wm">FICTIONAL / SIMULATION — NOT ASSESSED — NOT REGULATORY ADVICE</div>
      <h1>GIEN Simulation Dossier — ${escapeHtml(classification)}</h1>
      <p>Audience: ${escapeHtml(audience)} · Layer: ${escapeHtml(layer)}</p>
      <p>Reporting window: ${escapeHtml(windowLabel)}</p>
      <p>Evidence: synthetic fixtures only; no authenticated measurements or server-side audit receipt.</p>
      ${sectionHtml}</body></html>`);
    w.document.close();
    w.focus();
    w.print();
  };

  return (
    <Page title="Regulator Export" subtitle={`Build a title/abstract/content simulation dossier · reporting window ${windowLabel}`}>
      <Card title="Evidence and export limitations">
        <div className="space-y-2 text-sm">
          <p><strong>NOT ASSESSED.</strong> This prototype has no connected authenticated telemetry backend, independent compliance scanner, or server-side audit service. All reportable metrics and scenario domain states are synthetic fixtures.</p>
          <p className="text-slate-500">A local download or browser print operation does not create a signed submission, immutable record, receipt, regulator transmission or audit event. The classification field is only a user-selected label.</p>
        </div>
      </Card>
      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Configuration">
          <div className="space-y-3 text-sm">
            <label className="block">
              <span className="text-slate-500">Audience</span>
              <select value={audience} onChange={e => setAudience(e.target.value as Role)} className="mt-1 w-full border rounded px-2 py-1 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700">
                <option value="regulator">Regulator</option><option value="executive">Executive</option><option value="college">Supervisory College</option><option value="educational">Educational</option>
              </select>
            </label>
            <label className="block">
              <span className="text-slate-500">Layer</span>
              <select value={layer} onChange={e => setLayer(e.target.value as Layer)} className="mt-1 w-full border rounded px-2 py-1 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700">
                <option value="executive">Executive</option><option value="engineering">Engineering</option><option value="crypto">Cryptographic</option>
              </select>
            </label>
            <label className="block">
              <span className="text-slate-500">Classification label (not independently validated)</span>
              <select value={classification} onChange={e => setClassification(e.target.value as Classification)} className="mt-1 w-full border rounded px-2 py-1 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700">
                <option>UNCLASSIFIED</option><option>RESTRICTED</option><option>CONFIDENTIAL</option><option>TREATY-GRADE</option>
              </select>
            </label>
            <div className="space-y-1">
              <label className="flex items-center gap-2"><input type="checkbox" checked={includeTelemetry} onChange={e => setIncludeTelemetry(e.target.checked)} /> Include synthetic risk-index fixtures</label>
              <label className="flex items-center gap-2"><input type="checkbox" checked={includeCompliance} onChange={e => setIncludeCompliance(e.target.checked)} /> Include evidence-pending framework register</label>
              <label className="flex items-center gap-2"><input type="checkbox" checked={includeDomains} onChange={e => setIncludeDomains(e.target.checked)} /> Include illustrative control-domain fixtures</label>
            </div>
            <label className="block">
              <span className="text-slate-500">Framework filter</span>
              <select value={frameworksFilter} onChange={e => setFrameworksFilter(e.target.value as 'all' | 'ai' | 'financial' | 'fictional')} className="mt-1 w-full border rounded px-2 py-1 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700">
                <option value="all">All families</option><option value="ai">AI governance</option><option value="financial">Financial</option><option value="fictional">Fictional / Treaty</option>
              </select>
            </label>
            <div className="flex gap-2 pt-2">
              <button onClick={downloadMd} className="px-3 py-1.5 text-sm rounded bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900">Download simulation Markdown</button>
              <button onClick={printPdf} className="px-3 py-1.5 text-sm rounded bg-sky-600 text-white">Print / PDF</button>
            </div>
          </div>
        </Card>
        <Card title="Preview — XML-like dossier">
          <pre className="text-xs font-mono whitespace-pre-wrap max-h-[60vh] overflow-y-auto bg-slate-50 dark:bg-slate-900 p-3 rounded">
{sections.length === 0 ? 'Select at least one section to include.' : doc}
          </pre>
        </Card>
      </div>
    </Page>
  );
}
