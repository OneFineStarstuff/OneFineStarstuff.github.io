import { readFileSync } from 'fs';
import path from 'path';

export const metadata = { title: 'Governance Capability Matrix' } as const;
export const dynamic = 'force-static';

type Dimension = {
  id: string;
  name: string;
  phase: string;
  score: number; // 0-4 in descriptors, accepts 0-5
  dependsOn?: string[];
  evidence: string[];
  gaps: string[];
  remediation: string[];
  quickWins?: string[];
  longLead?: string[];
  refs?: { terms?: string[]; roles?: string[] };
  links?: Record<string, string>;
};

type Maturity = { descriptors?: string[]; dimensions: Dimension[] };

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
  // Build lookup for dependency status
  const byId: Record<string, Dimension> = Object.fromEntries(data.dimensions.map((d) => [d.id, d]));

  return (
    <main className="space-y-4">
      <h1 className="text-2xl font-semibold">Governance Capability Matrix</h1>
      <p className="text-sm text-slate-600">Scores (0–4 descriptors), evidence, gaps, remediation and gating guidance per dimension. Dependencies are color-coded: red (blocked), amber (needs guardrails), green (ready).</p>

      {data.descriptors?.length ? (
        <div className="rounded border bg-white p-3 text-xs text-slate-700">
          <div className="mb-1 font-semibold">Maturity descriptors</div>
          <ol className="list-decimal pl-5">
            {data.descriptors.map((t, i) => (<li key={i}><strong className="mr-1">{i}</strong>{t}</li>))}
          </ol>
        </div>
      ) : null}

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
                  {d.dependsOn?.length ? (
                    <div className="mt-1 text-[11px] text-slate-600">
                      <div className="mb-0.5 font-semibold">Dependencies</div>
                      <div className="flex flex-wrap gap-2">
                        {d.dependsOn.map((dep) => {
                          const depDim = byId[dep];
                          const depScore = depDim?.score ?? 0;
                          const depGate = gateText(depScore);
                          const color = depScore < 2 ? '#dc2626' : depScore < 4 ? '#f59e0b' : '#16a34a';
                          return (
                            <span key={dep} className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px]" style={{ borderColor: color, color }} title={`Dependency ${depDim?.name ?? dep}: ${depGate.label}`}>
                              <span className="h-2 w-2 rounded-full" style={{ background: color }} />
                              {depDim?.name ?? dep} ({depScore})
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  ) : null}
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

              {(d.quickWins?.length || d.longLead?.length) ? (
                <div className="mb-2 grid gap-2 md:grid-cols-2">
                  {d.quickWins?.length ? (
                    <div>
                      <div className="mb-1 text-xs font-semibold text-green-700">Quick wins</div>
                      <ul className="list-disc pl-5 text-sm text-slate-700">
                        {d.quickWins.map((q, i) => (<li key={i}>{q}</li>))}
                      </ul>
                    </div>
                  ) : null}
                  {d.longLead?.length ? (
                    <div>
                      <div className="mb-1 text-xs font-semibold text-indigo-700">Long-lead</div>
                      <ul className="list-disc pl-5 text-sm text-slate-700">
                        {d.longLead.map((q, i) => (<li key={i}>{q}</li>))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              ) : null}

              {d.refs && (d.refs.terms?.length || d.refs.roles?.length) ? (
                <div className="mb-2 flex flex-wrap gap-2 text-[11px] text-slate-600">
                  {d.refs.terms?.length ? (<span>Terms: {d.refs.terms.join(', ')}</span>) : null}
                  {d.refs.roles?.length ? (<span>Roles: {d.refs.roles.join(', ')}</span>) : null}
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
