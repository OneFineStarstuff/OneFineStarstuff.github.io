import { readFileSync } from 'fs';
import path from 'path';

export const metadata = { title: 'Governance Capability Matrix' } as const;
export const dynamic = 'force-static';

type Dimension = {
  id: string;
  name: string;
  phase: string;
  score: number; // 0-5
  evidence: string[];
  gaps: string[];
  remediation: string[];
  links?: Record<string, string>;
};

type Maturity = { dimensions: Dimension[] };

function gateText(score: number) {
  if (score < 2) return { label: 'Do not advance', color: '#dc2626', note: 'Address gaps before proceeding' };
  if (score < 4) return { label: 'Proceed with guardrails', color: '#f59e0b', note: 'Monitor and document mitigations' };
  return { label: 'Clear to advance', color: '#16a34a', note: 'Maintain controls and evidence' };
}

function scoreColor(score: number) {
  if (score <= 1) return '#b91c1c';
  if (score === 2) return '#e11d48';
  if (score === 3) return '#f59e0b';
  if (score === 4) return '#10b981';
  return '#059669';
}

export default function Page() {
  const file = path.join(process.cwd(), 'next-app', 'data', 'maturity.json');
  const data: Maturity = JSON.parse(readFileSync(file, 'utf8'));
  return (
    <main className="space-y-4">
      <h1 className="text-2xl font-semibold">Governance Capability Matrix</h1>
      <p className="text-sm text-slate-600">Scores (0–5), evidence, gaps, remediation and gating guidance per dimension.</p>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {data.dimensions.map((d) => {
          const gate = gateText(d.score);
          return (
            <section key={d.id} className="rounded border bg-white p-4 shadow-sm">
              <header className="mb-2 flex items-center justify-between">
                <div>
                  <div className="text-base font-semibold text-slate-800">{d.name}</div>
                  <div className="text-xs text-slate-500">Phase: {d.phase}</div>
                </div>
                <div className="text-right">
                  <span className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs" style={{ borderColor: scoreColor(d.score), color: scoreColor(d.score) }}>
                    Score <strong className="ml-1">{d.score}</strong>
                  </span>
                  <div className="mt-1 text-xs" style={{ color: gate.color }}>{gate.label}</div>
                </div>
              </header>

              {d.evidence?.length ? (
                <div className="mb-2">
                  <div className="mb-1 text-xs font-semibold text-slate-700">Evidence</div>
                  <ul className="list-disc pl-5 text-sm text-slate-700">
                    {d.evidence.map((e, i) => (<li key={i}>{e}</li>))}
                  </ul>
                </div>
              ) : null}

              {d.gaps?.length ? (
                <div className="mb-2">
                  <div className="mb-1 text-xs font-semibold text-slate-700">Gaps</div>
                  <ul className="list-disc pl-5 text-sm text-slate-700">
                    {d.gaps.map((g, i) => (<li key={i}>{g}</li>))}
                  </ul>
                  <div className="mt-2 rounded bg-red-50 p-2 text-xs text-red-700">{gate.note}</div>
                </div>
              ) : null}

              {d.remediation?.length ? (
                <div className="mb-2">
                  <div className="mb-1 text-xs font-semibold text-slate-700">Remediation</div>
                  <ul className="list-disc pl-5 text-sm text-slate-700">
                    {d.remediation.map((r, i) => (<li key={i}>{r}</li>))}
                  </ul>
                </div>
              ) : null}

              {d.links && Object.keys(d.links).length > 0 ? (
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  {Object.entries(d.links).map(([k, v]) => (
                    <a key={k} href={v} className="rounded border border-amber-300 bg-amber-50 px-2 py-1 text-amber-800 underline">
                      {k}
                    </a>
                  ))}
                </div>
              ) : null}
            </section>
          );
        })}
      </div>
    </main>
  );
}
