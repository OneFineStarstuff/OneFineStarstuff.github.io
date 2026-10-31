import { useMemo, useState } from 'react';
import { Page, Card, download } from '../components/ui';
import { useToast } from '../contexts';
import { riskIndices, frameworks, domains } from '../data';
import type { Role, Layer } from '../types';

type Classification = 'UNCLASSIFIED' | 'RESTRICTED' | 'CONFIDENTIAL' | 'TREATY-GRADE';

interface Section { title: string; abstract: string; content: string; }

function buildSections(opts: {
  audience: Role; layer: Layer; classification: Classification;
  includeTelemetry: boolean; includeCompliance: boolean; includeDomains: boolean;
  frameworksFilter: 'all' | 'ai' | 'financial' | 'fictional';
}): Section[] {
  const sections: Section[] = [];
  if (opts.includeTelemetry) {
    sections.push({
      title: `Systemic Risk Telemetry — S_sys / G-SRI / C-SRI — 2026-10-26 — ${opts.classification}`,
      abstract: 'Composite indices show a slight easing across all headline measures. Narrative p(doom) fields remain simulation-only.',
      content: riskIndices.map(r =>
        `${r.label} = ${r.value.toFixed(3)} (Δ ${r.delta >= 0 ? '+' : ''}${r.delta.toFixed(3)})${r.fictional ? '  [SIMULATION FIELD]' : ''}`
      ).join('\n'),
    });
  }
  if (opts.includeCompliance) {
    const filtered = opts.frameworksFilter === 'all' ? frameworks : frameworks.filter(f => f.family === opts.frameworksFilter);
    sections.push({
      title: `Cross-Jurisdictional Compliance Matrix — ${filtered.length} Frameworks — 2026-10-26 — ${opts.classification}`,
      abstract: `${filtered.filter(f => f.status === 'COMPLIANT').length} of ${filtered.length} frameworks report COMPLIANT; ${filtered.filter(f => f.status === 'PARTIAL').length} report PARTIAL with active waiver review.`,
      content: filtered.map(f =>
        `${f.name}\n  Status: ${f.status}\n  Controls: ${f.controls}/${f.total}\n  OSCAL SSP: ${f.oscalSsp} · AR: ${f.oscalAr}\n  OPA: ${f.opaViolations} violations / ${f.opaWarnings} warnings`
      ).join('\n\n'),
    });
  }
  if (opts.includeDomains) {
    sections.push({
      title: `GIEN Control Domains 01–10 — 2026-10-26 — ${opts.classification}`,
      abstract: 'Nine of ten domains report GREEN. Domain 07 (Compliance-as-Code) reports AMBER with an active waiver.',
      content: domains.map(d => `Domain ${d.id} — ${d.name}: ${d.status} (risk ${d.risk.toFixed(2)}, ${d.openRemediations} open remediations)`).join('\n'),
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

  const sections = useMemo(() => buildSections({ audience, layer, classification, includeTelemetry, includeCompliance, includeDomains, frameworksFilter }), [audience, layer, classification, includeTelemetry, includeCompliance, includeDomains, frameworksFilter]);

  const doc = sections.map(s => `<title>${s.title}</title>\n<abstract>${s.abstract}</abstract>\n<content>\n${s.content}\n</content>`).join('\n\n---\n\n');

  const downloadMd = () => {
    const header = `# GIEN Dossier — FICTIONAL / SIMULATION\n\nClassification: ${classification}\nAudience: ${audience}\nLayer: ${layer}\nWindow: 2026-10-26T09:00:00Z\n\n---\n\n`;
    download('gien-dossier-2026-10-26.md', header + doc, 'text/markdown');
    push({ severity: 'GREEN', title: 'Dossier exported', body: 'Markdown downloaded with fictional watermark intact.' });
  };

  const printPdf = () => {
    const w = globalThis.open('', '_blank');
    if (!w) return;
    w.document.write(`<html><head><title>GIEN Dossier</title>
      <style>body{font-family:ui-sans-serif,sans-serif;padding:32px;max-width:900px;margin:auto;line-height:1.6}
      .wm{background:#fff7e6;border:1px solid #f59e0b;color:#92400e;padding:6px 10px;font-size:11px;font-family:monospace;margin-bottom:16px}
      pre{white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:12px;background:#f8fafc;padding:8px;border-radius:4px}
      h2{font-size:16px;margin-top:24px}</style></head>
      <body>
      <div class="wm">FICTIONAL / SIMULATION — NOT REGULATORY ADVICE</div>
      <h1>GIEN Dossier — ${classification}</h1>
      <p>Audience: ${audience} · Layer: ${layer} · Window: 2026-10-26T09:00:00Z</p>
      ${sections.map(s => `<h2>${s.title}</h2><p><em>${s.abstract}</em></p><pre>${s.content.replace(/</g, '&lt;')}</pre>`).join('')}
      </body></html>`);
    w.document.close();
    w.focus();
    w.print();
  };

  return (
    <Page title="Regulator Export" subtitle="Build a title/abstract/content dossier for download or PDF">
      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Configuration">
          <div className="space-y-3 text-sm">
            <label className="block">
              <span className="text-slate-500">Audience</span>
              <select value={audience} onChange={e => setAudience(e.target.value as Role)} className="mt-1 w-full border rounded px-2 py-1 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700">
                <option value="regulator">Regulator</option>
                <option value="executive">Executive</option>
                <option value="college">Supervisory College</option>
                <option value="educational">Educational</option>
              </select>
            </label>
            <label className="block">
              <span className="text-slate-500">Layer</span>
              <select value={layer} onChange={e => setLayer(e.target.value as Layer)} className="mt-1 w-full border rounded px-2 py-1 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700">
                <option value="executive">Executive</option>
                <option value="engineering">Engineering</option>
                <option value="crypto">Cryptographic</option>
              </select>
            </label>
            <label className="block">
              <span className="text-slate-500">Classification</span>
              <select value={classification} onChange={e => setClassification(e.target.value as Classification)} className="mt-1 w-full border rounded px-2 py-1 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700">
                <option>UNCLASSIFIED</option><option>RESTRICTED</option><option>CONFIDENTIAL</option><option>TREATY-GRADE</option>
              </select>
            </label>
            <div className="space-y-1">
              <label className="flex items-center gap-2"><input type="checkbox" checked={includeTelemetry} onChange={e => setIncludeTelemetry(e.target.checked)} /> Include systemic risk telemetry</label>
              <label className="flex items-center gap-2"><input type="checkbox" checked={includeCompliance} onChange={e => setIncludeCompliance(e.target.checked)} /> Include compliance matrix</label>
              <label className="flex items-center gap-2"><input type="checkbox" checked={includeDomains} onChange={e => setIncludeDomains(e.target.checked)} /> Include control domains</label>
            </div>
            <label className="block">
              <span className="text-slate-500">Framework filter</span>
              <select value={frameworksFilter} onChange={e => setFrameworksFilter(e.target.value as 'all' | 'ai' | 'financial' | 'fictional')} className="mt-1 w-full border rounded px-2 py-1 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700">
                <option value="all">All families</option>
                <option value="ai">AI governance</option>
                <option value="financial">Financial</option>
                <option value="fictional">Fictional / Treaty</option>
              </select>
            </label>
            <div className="flex gap-2 pt-2">
              <button onClick={downloadMd} className="px-3 py-1.5 text-sm rounded bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900">Download Markdown</button>
              <button onClick={printPdf} className="px-3 py-1.5 text-sm rounded bg-sky-600 text-white">Print / PDF</button>
            </div>
          </div>
        </Card>
        <Card title="Preview">
          <pre className="text-xs font-mono whitespace-pre-wrap max-h-[60vh] overflow-y-auto bg-slate-50 dark:bg-slate-900 p-3 rounded">
{sections.length === 0 ? 'Select at least one section to include.' : doc}
          </pre>
        </Card>
      </div>
    </Page>
  );
}
