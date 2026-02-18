export const metadata = { title: 'Executive Pack Visuals' } as const;

function Badge({color, children}:{color:string;children:any}){
  return <span className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs" style={{borderColor:color,color}}>
    <span className="h-2 w-2 rounded-full" style={{background:color}} />{children}
  </span>;
}

export default function Visuals(){
  return (
    <main className="space-y-6">
      <h1 className="text-2xl font-semibold">Executive Pack Visuals</h1>

      {/* 1) Visual Timeline */}
      <section className="rounded border bg-white p-4">
        <h2 className="mb-2 text-sm font-semibold">0–12 Month Timeline</h2>
        <div className="relative h-24">
          <div className="absolute left-0 right-0 top-8 h-1 bg-slate-200" />
          {[
            {m:'0–3', label:'Assessment', color:'#334155', gate:'Baseline Scoring'},
            {m:'3–6', label:'Foundation', color:'#0ea5e9', gate:'Q2 Strategy Refresh'},
            {m:'6', label:'Baseline', color:'#10b981', gate:'Annual Budget Cycle'},
            {m:'6–9', label:'Integration', color:'#f59e0b', gate:'Q3 Risk Review'},
            {m:'9–12', label:'Excellence', color:'#8b5cf6', gate:'Rollout Go/No-Go'}
          ].map((p,i)=> (
            <div key={i} className="absolute top-6" style={{left:`${i*20}%`}}>
              <div className="h-4 w-4 rounded-full" style={{background:p.color}} />
              <div className="mt-1 text-[11px] font-medium text-slate-700">{p.m}</div>
              <div className="mt-0.5 text-[10px] text-slate-600">{p.label}</div>
              <div className="mt-0.5 text-[9px] text-blue-600">🔷 {p.gate}</div>
            </div>
          ))}
        </div>
        <div className="mt-3 rounded-sm bg-blue-50 px-2 py-1.5 text-[11px] text-blue-800">
          <span className="font-semibold">Planning Integration:</span> Decision gates align with quarterly strategy refresh (Q2), annual budget cycle (Month 6), quarterly risk review (Q3), and year-end rollout planning (Q4).
        </div>
      </section>

      {/* 2) Capability Dashboard (Grid) */}
      <section className="rounded border bg-white p-4">
        <h2 className="mb-2 text-sm font-semibold">Capability Dashboard</h2>
        <div className="mb-3 rounded-sm bg-slate-50 px-2 py-1.5 text-[11px] text-slate-700">
          <span className="font-semibold">Format Clarity:</span> Each row shows a pilot capability with current maturity, 12-month target, named owner, primary risk with mitigation strategy, and quantified business impact.
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-[900px] border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50">
                {['Capability','Current (L0–L3)','Target (L3)','Owner','Top Risk & Mitigation','Business Impact'].map((h,i)=>(<th key={i} className="border px-2 py-2 text-left font-semibold">{h}</th>))}
              </tr>
            </thead>
            <tbody>
              {[{
                cap:'Incentive Alignment', current:'L0 (Absent)', target:'L3 (Operational)', owner:'Alex Chen (Product Development)', rm:'Risk: Objective conflicts • Mitigation: Quarterly strategy cross‑review with executive sponsor sign-off', impact:'↑ 90% adoption of governance practices; ↓ misalignment costs ~40% ($2.1M annually)'
              },{
                cap:'Measurement Infrastructure', current:'L1 (Nascent)', target:'L3 (Operational)', owner:'Jordan Kim (AI Ops/Engineering)', rm:'Risk: Data quality/availability • Mitigation: Phased rollout with manual backup dashboards for first 6 months', impact:'↓ incident response time ~60% (90min → 36min); enables proactive risk management'
              },{
                cap:'Authority Mapping', current:'L1 (Nascent)', target:'L3 (Operational)', owner:'Sam Patel (Risk & Compliance)', rm:'Risk: Authority conflicts during handoffs • Mitigation: Executive sponsor arbitration protocol with 48hr SLA', impact:'↓ escalation delays ~40% in safety‑critical decisions; ↑ stakeholder trust score +2.3'
              }].map((r,i)=> (
                <tr key={i}>
                  <td className="border px-2 py-2 font-semibold">{r.cap}</td>
                  <td className="border px-2 py-2">{r.current}</td>
                  <td className="border px-2 py-2">{r.target}</td>
                  <td className="border px-2 py-2 text-slate-700">{r.owner}</td>
                  <td className="border px-2 py-2">{r.rm}</td>
                  <td className="border px-2 py-2 text-slate-700">{r.impact}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-2 text-[11px] text-slate-500">
          <span className="font-semibold">Maturity Legend:</span> L0 = Absent • L1 = Nascent (ad-hoc) • L2 = Emerging (documented pilots) • L3 = Operational (integrated, measured, cross-team)
        </div>
      </section>

      {/* 3) Side-by-Side Capability Panel */}
      <section className="rounded border bg-white p-4">
        <h2 className="mb-2 text-sm font-semibold">Pilot Capability Snapshot</h2>
        <div className="grid gap-3 md:grid-cols-3">
          {[{
            name:'Incentive Alignment', owner:'Alex Chen (Product Dev)', l3:'≥90% alignment; board‑level oversight', rag:'amber', risk:'Objective conflicts', mit:'Quarterly Strategy cross‑review'
          },{
            name:'Measurement Infrastructure', owner:'Jordan Kim (AI Ops)', l3:'Exec dashboard + alerts for prod systems', rag:'green', risk:'Data quality/availability', mit:'Phased rollout + manual backups'
          },{
            name:'Authority Mapping', owner:'Sam Patel (Risk)', l3:'RACI active; feedback loops operational', rag:'amber', risk:'Authority conflicts', mit:'Sponsor arbitration protocol'
          }].map((c,i)=>{
            const color = c.rag==='green'?'#16a34a':c.rag==='amber'?'#f59e0b':'#dc2626';
            return (
              <div key={i} className="rounded border p-3">
                <div className="mb-1 text-sm font-semibold">{c.name}</div>
                <div className="mb-2 text-xs text-slate-600">Owner: {c.owner}</div>
                <div className="mb-2 text-xs"><Badge color={color}>RAG: {c.rag}</Badge></div>
                <div className="mb-1 text-xs"><span className="font-semibold">Level 3:</span> {c.l3}</div>
                <div className="text-[11px] text-slate-600"><span className="font-semibold">Risk:</span> {c.risk}; <span className="font-semibold">Mitigation:</span> {c.mit}</div>
              </div>
            );
          })}
        </div>
      </section>

      {/* 3.5) Strategic Value Metrics */}
      <section className="rounded border bg-white p-4">
        <h2 className="mb-2 text-sm font-semibold">Strategic Value Metrics (Baseline → Target)</h2>
        <div className="mb-3 rounded-sm bg-green-50 px-2 py-1.5 text-[11px] text-green-800">
          <span className="font-semibold">Value Capture:</span> Each metric shows baseline performance (Month 0), 12-month target (Month 12), and progress indicator. All targets align with business planning cycle.
        </div>
        <div className="space-y-4">
          {[{
            cap:'Incentive Alignment',
            metrics:[
              {name:'Governance Practice Adoption Rate', baseline:12, target:90, unit:'%', impact:'↑78pp'},
              {name:'Misalignment Cost (Annual)', baseline:5.3, target:3.2, unit:'$M', impact:'↓$2.1M (~40%)'}
            ]
          },{
            cap:'Measurement Infrastructure',
            metrics:[
              {name:'Incident Response Time (Median)', baseline:90, target:36, unit:'min', impact:'↓54min (~60%)'},
              {name:'Policy Automation Coverage', baseline:55, target:95, unit:'%', impact:'↑40pp'}
            ]
          },{
            cap:'Authority Mapping',
            metrics:[
              {name:'Escalation Delay (Safety-Critical)', baseline:4.2, target:2.5, unit:'days', impact:'↓1.7d (~40%)'},
              {name:'Stakeholder Trust Score (1-10)', baseline:6.2, target:8.5, unit:'', impact:'+2.3pts'}
            ]
          }].map((cap,i)=> (
            <div key={i} className="rounded border border-slate-200 p-3">
              <div className="mb-2 text-sm font-semibold text-slate-800">{cap.cap}</div>
              <div className="space-y-3">
                {cap.metrics.map((m,j)=> {
                  const pct = ((m.target - m.baseline) / (m.target - m.baseline + m.baseline)) * 100;
                  const progressPct = Math.min(Math.max(pct, 0), 100);
                  return (
                    <div key={j}>
                      <div className="mb-1 flex items-baseline justify-between text-xs">
                        <span className="font-medium text-slate-700">{m.name}</span>
                        <span className="text-slate-600">{m.impact}</span>
                      </div>
                      <div className="mb-1 flex items-center gap-2">
                        <span className="text-[11px] text-slate-500">Baseline:</span>
                        <span className="text-xs font-semibold text-red-600">{m.baseline}{m.unit}</span>
                        <span className="text-slate-400">→</span>
                        <span className="text-[11px] text-slate-500">Target:</span>
                        <span className="text-xs font-semibold text-green-600">{m.target}{m.unit}</span>
                      </div>
                      <div className="relative h-2 w-full overflow-hidden rounded-full bg-slate-100">
                        <div className="absolute left-0 top-0 h-full bg-gradient-to-r from-red-500 via-amber-500 to-green-500" style={{width:`${progressPct}%`}} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 4) Readiness Heatmap with Trend Arrows */}
      <section className="rounded border bg-white p-4">
        <h2 className="mb-2 text-sm font-semibold">Readiness Heatmap</h2>
        <div className="overflow-x-auto">
          <table className="min-w-[720px] border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50">
                {['Function','Incentive Alignment','Measurement Infrastructure','Authority Mapping'].map((h,i)=>(<th key={i} className="border px-2 py-2 text-left font-semibold">{h}</th>))}
              </tr>
            </thead>
            <tbody>
              {[
                {fn:'Product Development', data:[{rag:'amber',trend:'↗'},{rag:'amber',trend:'→'},{rag:'amber',trend:'↗'}]},
                {fn:'AI Operations/Engineering', data:[{rag:'green',trend:'↗'},{rag:'green',trend:'↗'},{rag:'green',trend:'→'}]},
                {fn:'Risk & Compliance', data:[{rag:'amber',trend:'→'},{rag:'amber',trend:'↗'},{rag:'amber',trend:'↘'}]}
              ].map((row,i)=> (
                <tr key={i}>
                  <td className="border px-2 py-2 font-semibold">{row.fn}</td>
                  {row.data.map((cell,j)=> {
                    const color = cell.rag==='green'?'#16a34a':cell.rag==='amber'?'#f59e0b':'#dc2626';
                    const label = cell.rag==='green'?'Green':cell.rag==='amber'?'Amber':'Red';
                    const trendColor = cell.trend==='↗'?'#10b981':cell.trend==='→'?'#64748b':'#dc2626';
                    return (
                      <td key={j} className="border px-2 py-2">
                        <div className="flex items-center gap-2">
                          <Badge color={color}>{label}</Badge>
                          <span style={{color:trendColor}} className="text-base font-semibold">{cell.trend}</span>
                        </div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-2 space-y-1 text-[11px] text-slate-500">
          <div><span className="font-semibold">Status Legend:</span> Green = ready for deployment • Amber = needs integration work • Red = blocked</div>
          <div><span className="font-semibold">Trend Legend:</span> <span style={{color:'#10b981'}}>↗ Improving</span> • <span style={{color:'#64748b'}}>→ Static</span> • <span style={{color:'#dc2626'}}>↘ Declining</span></div>
        </div>
      </section>

      {/* 5) Activation Flow Footer with Icons */}
      <section className="rounded border bg-white p-4">
        <h2 className="mb-2 text-sm font-semibold">Activation Kit Schematic (Continuous Loop)</h2>
        <div className="flex flex-wrap items-center justify-center gap-3 text-xs">
          {[
            {step:'Assess', icon:'🔍', desc:'Baseline evaluation'},
            {step:'Score', icon:'📊', desc:'Maturity measurement'},
            {step:'Remediate', icon:'🔧', desc:'Gap closure actions'},
            {step:'Track', icon:'📈', desc:'Progress monitoring'},
            {step:'Re‑score', icon:'🔄', desc:'Quarterly refresh'}
          ].map((s,i)=> (
            <div key={i} className="flex items-center gap-3">
              <div className="flex flex-col items-center gap-1">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-gradient-to-br from-blue-500 to-purple-600 text-2xl shadow-md">
                  {s.icon}
                </div>
                <div className="text-center">
                  <div className="font-semibold text-slate-800">{s.step}</div>
                  <div className="text-[10px] text-slate-500">{s.desc}</div>
                </div>
              </div>
              {i<4 && (
                <div className="flex flex-col items-center">
                  <span className="text-2xl text-slate-400">→</span>
                </div>
              )}
            </div>
          ))}
        </div>
        <div className="mt-3 rounded-sm bg-purple-50 px-2 py-1.5 text-center text-[11px] text-purple-800">
          <span className="font-semibold">Continuous Governance Loop:</span> After Re-score (Month 12), cycle returns to Assess for next planning period, ensuring sustained oversight effectiveness.
        </div>
      </section>
    </main>
  );
}
