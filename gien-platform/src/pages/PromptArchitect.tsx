import { useState } from 'react';
import { Page, Card, StatusBadge, download } from '../components/ui';

const templates = [
  { id: 't1', name: 'Regulator Q&A — Systemic Risk', variables: ['window', 'index', 'threshold'], frameworks: ['EU AI Act Art. 15', 'NIST AI RMF Measure'] },
  { id: 't2', name: 'Bias Review — Lending Model', variables: ['model', 'axis', 'dataset'], frameworks: ['FCRA', 'ECOA', 'GDPR Art. 22'] },
  { id: 't3', name: 'RAG Groundedness Check', variables: ['query', 'sources'], frameworks: ['NIST AI 600-1', 'ISO 42001'] },
];

const scans = [
  { rule: 'no_pii', status: 'GREEN' as const, detail: 'No PII tokens detected' },
  { rule: 'no_real_reg_text', status: 'GREEN' as const, detail: 'No verbatim regulatory text' },
  { rule: 'requires_citation', status: 'AMBER' as const, detail: '2 clauses lack source URI' },
  { rule: 'no_medical_advice', status: 'GREEN' as const, detail: 'No medical advice pattern' },
];

export default function PromptArchitect() {
  const [template, setTemplate] = useState(templates[0].id);
  const [vars, setVars] = useState<Record<string, string>>({ window: '2026-10-26', index: 'S_sys', threshold: '0.60' });
  const active = templates.find(t => t.id === template)!;
  const prompt = `${active.name}\nWindow: ${vars.window}\nIndex: ${vars.index}\nThreshold: ${vars.threshold}\nProvide: value, trend, comparable threshold bands, and evidence linkage.`;

  return (
    <Page title="Prompt Architect" subtitle="Template + variables + safety scan + compliance tagging">
      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Template">
          <select value={template} onChange={e => setTemplate(e.target.value)} className="w-full border border-slate-300 dark:border-slate-700 rounded px-2 py-1 bg-white dark:bg-slate-800 text-sm">
            {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <div className="mt-3 space-y-2">
            {active.variables.map(v => (
              <label key={v} className="block text-sm">
                <span className="text-slate-500">{v}</span>
                <input value={vars[v] || ''} onChange={e => setVars({ ...vars, [v]: e.target.value })} className="mt-1 w-full border border-slate-300 dark:border-slate-700 rounded px-2 py-1 bg-white dark:bg-slate-800 text-sm" />
              </label>
            ))}
          </div>
        </Card>
        <Card title="Safety scan (simulated OPA/Rego)">
          <ul className="space-y-2 text-sm">
            {scans.map(s => (
              <li key={s.rule} className="flex items-start gap-2">
                <StatusBadge status={s.status} />
                <div><div className="font-mono text-xs">{s.rule}</div><div className="text-xs text-slate-500">{s.detail}</div></div>
              </li>
            ))}
          </ul>
        </Card>
      </div>
      <Card title="Rendered prompt">
        <pre className="text-xs font-mono whitespace-pre-wrap bg-slate-100 dark:bg-slate-800 p-3 rounded">{prompt}</pre>
        <div className="mt-3 flex flex-wrap gap-2 items-center">
          <span className="text-xs text-slate-500">Compliance tags:</span>
          {active.frameworks.map(f => <span key={f} className="text-[10px] px-1.5 py-0.5 rounded bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300">{f}</span>)}
          <div className="ml-auto">
            <button onClick={() => download('prompt.txt', prompt)} className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-700">Download</button>
          </div>
        </div>
      </Card>
    </Page>
  );
}
