export const metadata = { title: 'Governance Readiness Dashboard' } as const;
import { readFileSync } from 'fs';
import path from 'path';

type Dimension = { id:string; name:string; score:number; dependsOn?:string[]; quickWins?:string[] };

export default function Dashboard(){
  const file = path.join(process.cwd(), 'next-app', 'data', 'maturity.json');
  const data = JSON.parse(readFileSync(file, 'utf8')) as { dimensions: Dimension[] };
  const dims = data.dimensions;
  const avg = Math.round((dims.reduce((a,d)=>a+(d.score||0),0)/Math.max(1,dims.length))*10)/10;
  const gates = { block: dims.filter(d=>d.score<2).length, guard: dims.filter(d=>d.score>=2 && d.score<4).length, clear: dims.filter(d=>d.score>=4).length };
  const byId:Record<string,Dimension> = Object.fromEntries(dims.map(d=>[d.id,d]));
  const blockers = dims.flatMap(d=> (d.dependsOn||[]).map(dep=>({dim:d, dep, depScore: byId[dep]?.score??0}))).filter(x=>x.depScore<2);
  const nextActions = dims.flatMap(d=> (d.quickWins||[]).map(q=>({ dim:d.name, action:q }))).slice(0,5);
  return (
    <main className="space-y-4">
      <h1 className="text-2xl font-semibold">Governance Readiness Dashboard</h1>
      <p className="text-sm text-slate-600">Summary of maturity, gates, blockers, and next actions. Demo values read from maturity.json.</p>
      <section className="grid gap-3 sm:grid-cols-3">
        <div className="rounded border bg-white p-3"><div className="text-xs text-slate-500">Average score</div><div className="text-2xl font-bold">{avg}</div></div>
        <div className="rounded border bg-white p-3"><div className="text-xs text-slate-500">Gates</div><div className="text-sm">Block: {gates.block} • Guard: {gates.guard} • Clear: {gates.clear}</div></div>
        <div className="rounded border bg-white p-3"><div className="text-xs text-slate-500">Dimensions</div><div className="text-sm">{dims.length}</div></div>
      </section>
      <section className="grid gap-3 sm:grid-cols-2">
        <div className="rounded border bg-white p-3">
          <div className="mb-2 text-sm font-semibold">Dependency blockers</div>
          {blockers.length? (<ul className="list-disc pl-5 text-sm">{blockers.map((b,i)=>(<li key={i}>{b.dim.name} blocked by {b.dep} (score {b.depScore})</li>))}</ul>) : (<div className="text-sm text-slate-500">None</div>)}
        </div>
        <div className="rounded border bg-white p-3">
          <div className="mb-2 text-sm font-semibold">Top 5 next actions</div>
          {nextActions.length? (<ol className="list-decimal pl-5 text-sm">{nextActions.map((a,i)=>(<li key={i}><span className="font-semibold">{a.dim}:</span> {a.action}</li>))}</ol>) : (<div className="text-sm text-slate-500">No actions</div>)}
        </div>
      </section>
    </main>
  );
}
