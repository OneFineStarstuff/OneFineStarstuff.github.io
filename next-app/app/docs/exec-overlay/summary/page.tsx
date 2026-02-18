export const metadata = { title: 'Executive Summary - Governance Commissioning' } as const;

export default function ExecutiveSummary() {
  return (
    <main className="mx-auto max-w-4xl space-y-6 p-6">
      <div className="rounded-lg border-2 border-blue-600 bg-gradient-to-br from-blue-50 to-slate-50 p-6 shadow-lg">
        <h1 className="mb-2 text-2xl font-bold text-blue-900">
          Executive Summary — Responsible AI Governance Commissioning Overlay
        </h1>
        <div className="text-sm text-blue-700">Board-Ready Strategic Brief</div>
      </div>

      {/* Status & Positioning */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">📊</span> Status & Positioning
        </h2>
        <ul className="space-y-2 text-sm text-slate-700">
          <li className="flex items-start gap-2">
            <span className="mt-1 text-green-600">✓</span>
            <span>Framework transformation complete: <span className="font-semibold">theory → practice → deployment</span>.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-1 text-green-600">✓</span>
            <span>Positioned as <span className="font-semibold text-blue-700">enterprise capability</span>, not compliance burden.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-1 text-green-600">✓</span>
            <span>Strategic alignment: <span className="font-semibold">Trust, Efficiency, Confidence</span>.</span>
          </li>
        </ul>
      </section>

      {/* Capability Implementation */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-4 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">🔧</span> Capability Implementation
        </h2>
        <div className="space-y-4">
          {[
            {
              name: 'Model Risk Registry',
              progress: 45,
              status: '45% complete',
              target: 'advanced capability in 9 months',
              owner: 'Chief Risk Officer',
              color: '#ef4444'
            },
            {
              name: 'Ethics Review Loop',
              progress: 30,
              status: 'Integrated',
              target: 'integrated into product lifecycle processes',
              owner: 'Head of Product',
              color: '#0ea5e9'
            },
            {
              name: 'Data Provenance Hub',
              progress: 20,
              status: 'In Progress',
              target: 'progressing toward audit traceability and regulatory alignment',
              owner: 'Chief Data Officer',
              color: '#8b5cf6'
            }
          ].map((cap, i) => (
            <div key={i} className="rounded border border-slate-200 p-3">
              <div className="mb-2 flex items-center justify-between">
                <div className="font-semibold text-slate-800">{cap.name}</div>
                <div className="text-xs font-medium" style={{ color: cap.color }}>
                  {cap.status}
                </div>
              </div>
              <div className="mb-2 h-2 overflow-hidden rounded-full bg-slate-200">
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${cap.progress}%`, background: cap.color }}
                />
              </div>
              <div className="text-xs text-slate-600">{cap.target}</div>
              <div className="mt-1 text-xs text-slate-600">
                <span className="font-medium">Owner:</span> {cap.owner}
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3 rounded-sm bg-blue-50 px-2 py-1.5 text-xs text-blue-800">
          <span className="font-semibold">Leadership ownership</span> ensures accountability and prevents responsibility diffusion.
        </div>
      </section>

      {/* Organizational Capacity */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-4 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">⚡</span> Organizational Capacity
        </h2>
        <div className="space-y-3">
          <div className="flex items-start gap-3 rounded border-l-4 border-amber-500 bg-amber-50 p-3">
            <div className="text-lg">🟡</div>
            <div className="flex-1">
              <div className="font-semibold text-amber-900">Risk & Compliance</div>
              <div className="text-xs text-amber-800">
                Stretched but improving (automation and process optimization underway).
              </div>
            </div>
            <div className="text-amber-600">↗</div>
          </div>
          <div className="flex items-start gap-3 rounded border-l-4 border-red-500 bg-red-50 p-3">
            <div className="text-lg">🔴</div>
            <div className="flex-1">
              <div className="font-semibold text-red-900">Legal & Regulatory</div>
              <div className="text-xs text-red-800">
                Deteriorating capacity; requires <span className="font-bold">immediate executive intervention</span>.
              </div>
            </div>
            <div className="text-red-600">↘</div>
          </div>
        </div>
        <div className="mt-3 rounded-sm bg-slate-100 px-2 py-1.5 text-xs text-slate-700">
          <span className="font-semibold">Heatmap intelligence</span> provides predictive view of sustainability and intervention points.
        </div>
      </section>

      {/* Strategic Value Metrics */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-4 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">📈</span> Strategic Value Metrics
        </h2>
        <div className="grid gap-3 md:grid-cols-2">
          {[
            { metric: 'Model risk incidents reduced', baseline: '6', target: '2', unit: 'annually', theme: 'risk management', color: '#ef4444' },
            { metric: 'Operational efficiency improved', baseline: '78%', target: '85%', unit: '', theme: 'process optimization', color: '#10b981' },
            { metric: 'Stakeholder confidence', baseline: '62%', target: '75%', unit: '', theme: 'trending positive', color: '#0ea5e9' },
            { metric: 'Compliance metrics', baseline: '4', target: '0', unit: 'findings', theme: 'trending positive', color: '#f59e0b' }
          ].map((m, i) => (
            <div key={i} className="flex items-center gap-3 rounded border border-slate-200 p-3">
              <div className="flex-1">
                <div className="text-xs font-medium text-slate-600">{m.metric}</div>
                <div className="mt-1 flex items-center gap-2 text-sm font-semibold">
                  <span className="text-slate-700">{m.baseline}</span>
                  <span className="text-slate-400">→</span>
                  <span style={{ color: m.color }}>{m.target}</span>
                  {m.unit && <span className="text-xs text-slate-500">{m.unit}</span>}
                </div>
                <div className="mt-0.5 text-[10px] text-slate-500">({m.theme})</div>
              </div>
              <div className="text-2xl" style={{ color: m.color }}>
                {m.baseline > m.target || (typeof m.baseline === 'string' && parseFloat(m.baseline) > parseFloat(m.target)) ? '↓' : '↑'}
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3 rounded-sm bg-green-50 px-2 py-1.5 text-xs text-green-800">
          <span className="font-semibold">ROI demonstrated</span> through measurable outcomes, not abstract compliance gains.
        </div>
      </section>

      {/* Timeline & Milestones */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-4 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">📅</span> Timeline & Milestones
        </h2>
        <div className="space-y-3">
          {[
            { q: 'Q1', label: 'Pilot launches complete', status: 'complete', icon: '✔', color: '#10b981' },
            { q: 'Q2', label: 'Board decision gate: resourcing endorsement required', status: 'critical', icon: '⚑', color: '#0ea5e9' },
            { q: 'Q3', label: 'Risk Registry operational target', status: 'pending', icon: '⚑', color: '#f59e0b' },
            { q: 'Q4', label: 'Full activation rollout', status: 'pending', icon: '⚑', color: '#8b5cf6' }
          ].map((milestone, i) => (
            <div key={i} className="flex items-center gap-4">
              <div
                className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full text-lg font-bold text-white"
                style={{ background: milestone.color }}
              >
                {milestone.icon}
              </div>
              <div className="flex-1">
                <div className="font-semibold text-slate-800">{milestone.q}</div>
                <div className="text-xs text-slate-600">{milestone.label}</div>
              </div>
              <div className="text-xs font-medium text-slate-500">
                {milestone.status === 'complete' ? 'Complete' : milestone.status === 'critical' ? 'Critical' : 'Pending'}
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3 rounded-sm bg-blue-50 px-2 py-1.5 text-xs text-blue-800">
          <span className="font-semibold">Milestones aligned</span> with planning/budget cycles for sustained momentum.
        </div>
      </section>

      {/* Board Specification */}
      <section className="rounded-lg border-2 border-amber-500 bg-gradient-to-br from-amber-50 to-orange-50 p-5 shadow-md">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-amber-900">
          <span className="text-2xl">📋</span> Board Specification
        </h2>
        <ul className="space-y-2 text-sm text-amber-900">
          <li className="flex items-start gap-2">
            <span className="mt-0.5 font-bold">•</span>
            <span><span className="font-semibold">Immediate action:</span> approve <span className="font-bold underline">Q2 resourcing package</span> to maintain trajectory.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-0.5 font-bold">•</span>
            <span>Governance positioned as <span className="font-semibold">enterprise capability</span> requiring sustained sponsorship.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-0.5 font-bold">•</span>
            <span>Activation loop reinforces continuous adaptation, not one-off project.</span>
          </li>
        </ul>
      </section>

      {/* Strategic Implication */}
      <section className="rounded-lg border bg-gradient-to-br from-blue-50 to-slate-50 p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-blue-900">
          <span className="text-2xl">💡</span> Strategic Implication
        </h2>
        <ul className="space-y-2 text-sm text-slate-700">
          <li className="flex items-start gap-2">
            <span className="mt-0.5 text-blue-600">▸</span>
            <span>Governance is now a <span className="font-semibold text-blue-700">competitive advantage lever</span> through superior risk management and trust.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-0.5 text-blue-600">▸</span>
            <span>Sustained success depends on <span className="font-semibold text-red-700">executive intervention in Legal capacity</span> and <span className="font-semibold text-amber-700">Q2 endorsement</span>.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-0.5 text-blue-600">▸</span>
            <span>Commissioning overlay delivers <span className="font-semibold">decision-ready documentation</span>: progress, risks, and ROI visible at a glance.</span>
          </li>
        </ul>
      </section>

      {/* Footer Links */}
      <div className="rounded-lg border bg-slate-50 p-4">
        <div className="text-xs font-semibold text-slate-600 mb-2">Related Documentation</div>
        <div className="flex flex-wrap gap-3 text-xs">
          <a href="/docs/exec-overlay/board-pack" className="text-blue-600 hover:underline">
            → Full Board Pack (Visual Overlay)
          </a>
          <a href="/docs/launch-brief" className="text-blue-600 hover:underline">
            → Launch Brief (Detailed)
          </a>
          <a href="/governance" className="text-blue-600 hover:underline">
            → Governance Cockpit
          </a>
          <a href="/governance/dashboard" className="text-blue-600 hover:underline">
            → Readiness Dashboard
          </a>
        </div>
      </div>
    </main>
  );
}
