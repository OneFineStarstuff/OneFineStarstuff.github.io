export const metadata = { title: 'Board Pack - Commissioning Overlay' } as const;

// Reusable components
/**
 * Renders a metric dial component displaying the change percentage from baseline to target.
 */
function MetricDial({label, baseline, target, unit, color}: {label:string; baseline:number; target:number; unit:string; color:string}) {
  const pct = Math.round(((target - baseline) / baseline) * 100);
  const isPositive = pct > 0;
  const arrow = isPositive ? '↑' : '↓';
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative h-20 w-20">
        <svg viewBox="0 0 100 100" className="transform -rotate-90">
          <circle cx="50" cy="50" r="40" fill="none" stroke="#e2e8f0" strokeWidth="8" />
          <circle
            cx="50" cy="50" r="40" fill="none" stroke={color} strokeWidth="8"
            strokeDasharray={`${Math.abs(pct) * 2.51} 251`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center text-lg font-bold" style={{color}}>
          {arrow}{Math.abs(pct)}%
        </div>
      </div>
      <div className="text-center text-xs">
        <div className="font-semibold text-slate-700">{label}</div>
        <div className="text-[10px] text-slate-500">{baseline}{unit} → {target}{unit}</div>
      </div>
    </div>
  );
}

/**
 * Renders a LoadCell component with dynamic styling based on load and trend.
 *
 * The function determines background, text, and trend colors based on the
 * provided load and trend values. It returns a styled div containing the
 * function name and trend indicator, ensuring visual representation aligns
 * with the specified load and trend states.
 *
 * @param {Object} params - The parameters for the LoadCell component.
 * @param {string} params.fn - The function name to display.
 * @param {'low'|'medium'|'high'} params.load - The load level affecting colors.
 * @param {'↗'|'→'|'↘'} params.trend - The trend indicator affecting colors.
 */
function LoadCell({fn, load, trend}: {fn:string; load:'low'|'medium'|'high'; trend:'↗'|'→'|'↘'}) {
  const bgColor = load === 'low' ? '#d1fae5' : load === 'medium' ? '#fef3c7' : '#fee2e2';
  const textColor = load === 'low' ? '#065f46' : load === 'medium' ? '#92400e' : '#991b1b';
  const trendColor = trend === '↗' ? '#10b981' : trend === '→' ? '#64748b' : '#ef4444';
  return (
    <div className="flex items-center justify-between rounded border p-2 text-xs" style={{background: bgColor}}>
      <span className="font-medium" style={{color: textColor}}>{fn}</span>
      <span className="text-base font-bold" style={{color: trendColor}}>{trend}</span>
    </div>
  );
}

/**
 * Render the Board Pack component for the Executive Readiness View.
 *
 * This component structures the layout into a main section containing various subsections, including a Capability Snapshot,
 * Organizational Load Heatmap, Milestone Timeline, Strategic Value Metrics, and an Activation Kit Schematic. Each subsection
 * presents critical information regarding organizational capabilities, resource allocation, and strategic goals,
 * facilitating decision-making for the board.
 *
 * @returns A JSX element representing the Board Pack layout.
 */
export default function BoardPack() {
  return (
    <main className="min-h-screen bg-slate-50 p-6">
      <div className="mx-auto max-w-7xl">
        <h1 className="mb-6 text-2xl font-bold text-slate-800">Commissioning Overlay – Executive Readiness View</h1>
        
        {/* CSS Grid: 2 columns, 3 rows (top quadrants, center band, bottom quadrants) */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          
          {/* 1. TOP-LEFT: Capability Snapshot */}
          <section className="rounded-lg border bg-white p-4 shadow-sm">
            <h2 className="mb-3 text-sm font-bold text-slate-700">1. Capability Snapshot</h2>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-100">
                    {['Pilot Function', 'Current Maturity', 'Target & Timeline', 'Owner', 'Strategic Theme', 'Business Impact'].map((h,i) => (
                      <th key={i} className="border-b-2 border-slate-300 px-2 py-2 text-left font-semibold">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[
                    {
                      pilot: 'Model Risk Registry',
                      current: 'Emerging',
                      currentPct: 50,
                      target: 'Advanced →',
                      timeline: '9 months',
                      owner: 'Chief Risk Officer',
                      theme: 'Trust',
                      impact: 'Audit traceability → reduced regulatory exposure'
                    },
                    {
                      pilot: 'Ethics Review Loop',
                      current: 'Ad-hoc',
                      currentPct: 25,
                      target: 'Defined →',
                      timeline: '6 months',
                      owner: 'Head of Compliance',
                      theme: 'Confidence',
                      impact: 'External partner demo → stakeholder trust gain'
                    },
                    {
                      pilot: 'Data Provenance Hub',
                      current: 'Initial',
                      currentPct: 33,
                      target: 'Advanced →',
                      timeline: 'Year-end',
                      owner: 'Chief Information Officer',
                      theme: 'Efficiency',
                      impact: 'Reduced pipeline duplication → operational cost savings'
                    }
                  ].map((row, i) => (
                    <tr key={i} className="border-b border-slate-200">
                      <td className="px-2 py-2 font-semibold">{row.pilot}</td>
                      <td className="px-2 py-2">
                        <div className="flex flex-col gap-0.5">
                          <span className="text-[10px] font-medium">{row.current}</span>
                          <div className="h-2 w-20 overflow-hidden rounded-full bg-slate-200">
                            <div className="h-full bg-amber-500" style={{width: `${row.currentPct}%`}} />
                          </div>
                        </div>
                      </td>
                      <td className="px-2 py-2">
                        <div className="flex flex-col gap-0.5">
                          <span className="text-green-700 font-semibold text-[10px]">{row.target}</span>
                          <span className="text-[9px] text-slate-500">{row.timeline}</span>
                        </div>
                      </td>
                      <td className="px-2 py-2 text-slate-700 text-[10px]">{row.owner}</td>
                      <td className="px-2 py-2">
                        <span className="rounded-full bg-blue-100 px-2 py-0.5 text-[9px] font-semibold text-blue-800">
                          {row.theme}
                        </span>
                      </td>
                      <td className="px-2 py-2 text-teal-700 text-[10px] font-medium">{row.impact}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-2 rounded-sm bg-green-50 px-2 py-1 text-[10px] text-green-800">
              <span className="font-semibold">Trajectory signals:</span> Upward arrows indicate positive capability movement toward targets
            </div>
          </section>

          {/* 2. TOP-RIGHT: Organizational Load Heatmap */}
          <section className="rounded-lg border bg-white p-4 shadow-sm">
            <h2 className="mb-3 text-sm font-bold text-slate-700">2. Organizational Load Heatmap</h2>
            <div className="space-y-2">
              {[
                {fn: 'Risk & Compliance', load: 'medium' as const, trend: '↗' as const, note: 'Stretched, improving with automation tools'},
                {fn: 'Human Resources', load: 'high' as const, trend: '↗' as const, note: 'Overcapacity, improving with training investment'},
                {fn: 'Legal & Regulatory', load: 'medium' as const, trend: '↘' as const, note: 'Stretched and deteriorating due to case load'},
                {fn: 'Technology Delivery', load: 'low' as const, trend: '→' as const, note: 'Balanced load, stable trend'},
                {fn: 'Finance', load: 'low' as const, trend: '→' as const, note: 'Comfortable capacity, stable'}
              ].map((item, i) => (
                <div key={i} className="space-y-1">
                  <LoadCell fn={item.fn} load={item.load} trend={item.trend} />
                  <div className="pl-3 text-[9px] italic text-slate-500">{item.note}</div>
                </div>
              ))}
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-3 text-[10px]">
              <div className="flex items-center gap-1">
                <div className="h-3 w-3 rounded" style={{background: '#d1fae5'}} />
                <span className="font-medium">Green = Stable</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="h-3 w-3 rounded" style={{background: '#fef3c7'}} />
                <span className="font-medium">Yellow = Stretched</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="h-3 w-3 rounded" style={{background: '#fee2e2'}} />
                <span className="font-medium">Red = Overcapacity</span>
              </div>
            </div>
            <div className="mt-2 text-[10px] text-slate-500">
              Purpose: Capacity visibility and proactive resource allocation
            </div>
          </section>

          {/* 3. CENTER BAND: Milestone Timeline (spans full width) */}
          <section className="rounded-lg border bg-white p-4 shadow-sm lg:col-span-2">
            <h2 className="mb-3 text-sm font-bold text-slate-700">3. Milestone Timeline (Q1 2025 – Q1 2026)</h2>
            <div className="relative h-28">
              <div className="absolute left-0 right-0 top-12 h-2 rounded-full bg-slate-200" />
              {[
                { q: 'Q1 2025', label: 'Risk Registry Pilot', gate: '✔ Complete', color: '#10b981', pos: '8%', status: 'complete' },
                { q: 'Q2 2025', label: 'Board Resourcing', gate: '⚑ Approval Required', color: '#0ea5e9', pos: '32%', status: 'pending' },
                { q: 'Q3 2025', label: 'Ethics Review Gate', gate: '⚑ Institutionalization Decision', color: '#f59e0b', pos: '56%', status: 'pending' },
                { q: 'Q4 2025', label: 'Provenance Hub', gate: '✔ Operational', color: '#8b5cf6', pos: '80%', status: 'complete' }
              ].map((m, i) => (
                <div key={i} className="absolute top-10" style={{ left: m.pos }}>
                  <div className="flex flex-col items-center gap-0.5">
                    <div 
                      className="h-5 w-5 rounded-full shadow flex items-center justify-center text-[10px]" 
                      style={{ background: m.color, opacity: m.status === 'complete' ? 1 : m.status === 'pending' ? 0.9 : 0.6 }}
                    >
                      {m.status === 'complete' && <span className="text-white font-bold">✓</span>}
                    </div>
                    <div className="text-[9px] font-bold text-slate-800 whitespace-nowrap">{m.q}</div>
                    <div className="text-[8px] text-slate-600 whitespace-nowrap max-w-[80px] text-center">{m.label}</div>
                    <div className="mt-0.5 rounded-sm bg-blue-50 px-1 text-[7px] text-blue-800 max-w-[100px] text-center">
                      {m.gate}
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-3 rounded-sm bg-blue-50 px-2 py-1 text-[10px] text-blue-800">
              <span className="font-semibold">Spine Alignment:</span> Milestones synchronized with organizational planning cycles. Q1 pilot complete, Q2 board resourcing approval critical path, Q3 decision gate for Ethics institutionalization, Q4 hub operational.
            </div>
          </section>

          {/* 4. BOTTOM-LEFT: Strategic Value Metrics */}
          <section className="rounded-lg border bg-white p-4 shadow-sm">
            <h2 className="mb-3 text-sm font-bold text-slate-700">4. Strategic Value Metrics</h2>
            <div className="space-y-3">
              {[
                {label: 'AI Risk Incidents / Year', baseline: 6, target: 2, unit: '', color: '#ef4444', status: '↓ trending'},
                {label: 'Operational Cost Efficiency', baseline: 78, target: 85, unit: '%', color: '#10b981', status: '↑ improving'},
                {label: 'Stakeholder Trust Index', baseline: 62, target: 80, unit: '%', color: '#0ea5e9', status: '↑ improving'},
                {label: 'Compliance Findings per Audit', baseline: 4, target: 0, unit: '', color: '#f59e0b', status: '↓ trending'}
              ].map((m, i) => {
                const pct = Math.round(Math.abs((m.target - m.baseline) / m.baseline) * 100);
                const isPositive = m.target > m.baseline;
                return (
                  <div key={i} className="flex items-center gap-3 rounded border border-slate-200 p-2">
                    <div className="relative h-16 w-16 flex-shrink-0">
                      <svg viewBox="0 0 100 100" className="transform -rotate-90">
                        <circle cx="50" cy="50" r="40" fill="none" stroke="#e2e8f0" strokeWidth="8" />
                        <circle
                          cx="50" cy="50" r="40" fill="none" stroke={m.color} strokeWidth="8"
                          strokeDasharray={`${pct * 2.51} 251`}
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center text-sm font-bold" style={{color: m.color}}>
                        {isPositive ? '↑' : '↓'}{pct}%
                      </div>
                    </div>
                    <div className="flex-1">
                      <div className="text-xs font-semibold text-slate-700">{m.label}</div>
                      <div className="text-[10px] text-slate-500">
                        Baseline (2024): <span className="font-medium text-slate-700">{m.baseline}{m.unit}</span>
                      </div>
                      <div className="text-[10px] text-slate-500">
                        Target (2025/26): <span className="font-medium" style={{color: m.color}}>{m.target}{m.unit}</span>
                      </div>
                      <div className="mt-0.5 text-[9px] font-medium" style={{color: m.color}}>{m.status}</div>
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="mt-3 text-[10px] text-slate-500">
              Purpose: Before/after visibility with trajectory indicators for investment justification
            </div>
          </section>

          {/* 5. BOTTOM-RIGHT: Activation Kit Schematic */}
          <section className="rounded-lg border bg-white p-4 shadow-sm">
            <h2 className="mb-3 text-sm font-bold text-slate-700">5. Activation Kit Schematic</h2>
            <div className="flex items-center justify-center">
              <div className="relative h-48 w-48">
                {/* Circular loop background */}
                <svg viewBox="0 0 200 200" className="absolute inset-0">
                  <circle
                    cx="100" cy="100" r="70"
                    fill="none" stroke="#cbd5e1" strokeWidth="2"
                    strokeDasharray="4 4"
                  />
                  {/* Arrows */}
                  <defs>
                    <marker id="arrowhead" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                      <polygon points="0 0, 10 3, 0 6" fill="#64748b" />
                    </marker>
                  </defs>
                  <path
                    d="M 100 30 A 70 70 0 0 1 170 100"
                    fill="none" stroke="#64748b" strokeWidth="2"
                    markerEnd="url(#arrowhead)"
                  />
                </svg>
                
                {/* 5 nodes positioned in circle */}
                {[
                  { icon: '🔍', label: 'Assess', angle: -90, color: '#0ea5e9' },
                  { icon: '📋', label: 'Plan', angle: -18, color: '#10b981' },
                  { icon: '⚙️', label: 'Implement', angle: 54, color: '#f59e0b' },
                  { icon: '📊', label: 'Monitor', angle: 126, color: '#8b5cf6' },
                  { icon: '🔄', label: 'Adapt', angle: 198, color: '#ec4899' }
                ].map((node, i) => {
                  const radius = 70;
                  const x = 100 + radius * Math.cos((node.angle * Math.PI) / 180);
                  const y = 100 + radius * Math.sin((node.angle * Math.PI) / 180);
                  return (
                    <div
                      key={i}
                      className="absolute flex flex-col items-center gap-1"
                      style={{
                        left: `${x}px`,
                        top: `${y}px`,
                        transform: 'translate(-50%, -50%)'
                      }}
                    >
                      <div
                        className="flex h-12 w-12 items-center justify-center rounded-full text-xl shadow-md"
                        style={{ background: node.color }}
                      >
                        {node.icon}
                      </div>
                      <div className="text-[10px] font-semibold text-slate-700">{node.label}</div>
                    </div>
                  );
                })}
              </div>
            </div>
            <div className="mt-3 space-y-1 text-center">
              <div className="text-xs font-semibold italic text-slate-700">
                "Governance as a Living Operating System – Continuous, Adaptive, Owned."
              </div>
              <div className="text-[10px] text-slate-500">
                Purpose: Reinforces governance as continuous operating system, not one-time project
              </div>
            </div>
          </section>

        </div>

        {/* Board Ask Footer */}
        <div className="mt-4 space-y-2">
          <div className="rounded-lg border-2 border-amber-500 bg-amber-50 p-4">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-2xl">📋</span>
              <h3 className="text-sm font-bold text-amber-900">Board Ask – Action Required</h3>
            </div>
            <p className="text-xs text-amber-900">
              <span className="font-semibold">Endorse Q2 2025 resourcing allocation</span> to sustain governance trajectory. 
              This approval is critical to maintaining capability momentum shown in snapshot and achieving 2025/26 strategic value targets.
            </p>
          </div>
          
          <div className="rounded-lg bg-blue-50 p-3 text-xs text-blue-800">
            <span className="font-semibold">Commissioning Overlay Outcome:</span> This single high-impact view shows what's launching, 
            who owns it, when decisions land, and why it matters—enabling the board to see readiness, momentum, and required actions instantly.
          </div>
        </div>
      </div>
    </main>
  );
}
