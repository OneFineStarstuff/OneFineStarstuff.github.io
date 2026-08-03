export const metadata = { title: 'Board Action Brief - Governance Framework' } as const;

export default function BoardActionBrief() {
  return (
    <main className="mx-auto max-w-4xl space-y-6 p-6">
      {/* Visual Header Banner */}
      <div className="rounded-lg border-2 border-blue-600 bg-gradient-to-r from-blue-600 via-indigo-700 to-purple-700 p-6 shadow-xl">
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <h1 className="mb-2 text-2xl font-bold text-white">
              Board Action Brief
            </h1>
            <div className="text-sm text-blue-100">Governance Framework Completion</div>
          </div>
          <div className="flex gap-6 border-l border-blue-400 pl-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-white">67%</div>
              <div className="text-xs text-blue-200">Risk ↓</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-white">+7%</div>
              <div className="text-xs text-blue-200">Efficiency ↑</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-white">Q2</div>
              <div className="text-xs text-blue-200">Decision</div>
            </div>
          </div>
        </div>
      </div>

      {/* Headline (Featured) */}
      <section className="rounded-lg border-2 border-green-500 bg-gradient-to-br from-green-50 to-emerald-50 p-5 shadow-md">
        <div className="mb-2 flex items-center gap-2">
          <span className="text-2xl">⭐</span>
          <h2 className="text-lg font-bold text-green-900">Headline</h2>
        </div>
        <p className="text-base font-bold leading-relaxed text-green-900">
          Governance trajectory on track – ROI visible, Q2 decision critical
        </p>
      </section>

      {/* Status & Trajectory */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">↗️</span> Status & Trajectory
        </h2>
        <ul className="space-y-2 text-sm text-slate-700">
          <li className="flex items-start gap-2">
            <span className="mt-0.5 text-green-600">✓</span>
            <span>Transition achieved: <span className="font-semibold">Principles → Methodology → Pilots → Decision‑ready framework</span>.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-0.5 text-green-600">✓</span>
            <span>Governance positioned as <span className="font-semibold text-blue-700">enterprise capability</span>, not compliance burden.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-0.5 text-green-600">✓</span>
            <span>Competitive advantage: Enhanced risk management & stakeholder confidence.</span>
          </li>
        </ul>
      </section>

      {/* Capacity & Risks */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">🛡️</span> Capacity & Risks
        </h2>
        <div className="space-y-3">
          <div className="flex items-start gap-3 rounded border-l-4 border-amber-500 bg-amber-50 p-3">
            <div className="text-lg">🟡</div>
            <div className="flex-1">
              <div className="font-semibold text-amber-900">Risk & Compliance</div>
              <div className="text-xs text-amber-800">
                Stretched but improving via automation.
              </div>
            </div>
            <div className="text-amber-600">↗</div>
          </div>
          <div className="flex items-start gap-3 rounded border-l-4 border-red-600 bg-red-50 p-3">
            <div className="text-lg">🔴</div>
            <div className="flex-1">
              <div className="font-semibold text-red-900">Legal & Regulatory</div>
              <div className="text-xs text-red-800">
                Capacity deteriorating → <span className="font-bold">critical bottleneck</span> requiring immediate intervention.
              </div>
            </div>
            <div className="text-red-600">↘</div>
          </div>
        </div>
        <div className="mt-3 rounded-sm bg-red-100 border-l-4 border-red-600 px-3 py-2 text-xs">
          <div className="font-semibold text-red-900">⚠️ Milestone-Linked Risk:</div>
          <div className="text-red-800">Legal bottleneck threatens Q3 registry operationalization if unaddressed in Q2.</div>
        </div>
        <div className="mt-2 rounded-sm bg-slate-100 px-3 py-2 text-xs text-slate-700">
          <span className="font-semibold">Predictive intelligence:</span> Risk surfaced before momentum is compromised.
        </div>
      </section>

      {/* Strategic Value Metrics */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">💰</span> Strategic Value Metrics
        </h2>
        <div className="grid gap-3 md:grid-cols-2">
          {[
            { metric: 'Model risk incidents reduced', change: '6 → 2 annually', color: '#ef4444', arrow: '↓', progress: 67 },
            { metric: 'Operational efficiency improved', change: '78% → 85%', color: '#10b981', arrow: '↑', progress: 70 },
            { metric: 'Stakeholder confidence', change: 'trending positive', color: '#0ea5e9', arrow: '↗', progress: 55 },
            { metric: 'Compliance metrics', change: 'trending positive', color: '#f59e0b', arrow: '↗', progress: 60 }
          ].map((item, i) => (
            <div key={i} className="rounded border border-slate-200 p-3">
              <div className="flex items-center gap-3 mb-2">
                <div className="text-2xl" style={{ color: item.color }}>
                  {item.arrow}
                </div>
                <div className="flex-1">
                  <div className="text-xs font-semibold text-slate-700">{item.metric}</div>
                  <div className="mt-0.5 text-xs text-slate-600">{item.change}</div>
                </div>
              </div>
              <div className="h-1.5 w-full rounded-full bg-slate-200">
                <div
                  className="h-1.5 rounded-full transition-all"
                  style={{ width: `${item.progress}%`, backgroundColor: item.color }}
                />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Timeline & Milestones */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">📅</span> Timeline & Milestones
        </h2>
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-green-600 text-lg font-bold text-white">
              ✔
            </div>
            <div className="flex-1">
              <div className="font-semibold text-slate-800">Q1: Pilot launches complete</div>
              <div className="text-xs text-slate-600">Foundation established with operational pilots</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-blue-600 text-lg font-bold text-white">
              ⚑
            </div>
            <div className="flex-1">
              <div className="font-semibold text-slate-800">Q2: Board resourcing approval required</div>
              <div className="text-xs text-red-700 font-medium">ACTION REQUIRED</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-green-600 text-lg font-bold text-white">
              ✔
            </div>
            <div className="flex-1">
              <div className="font-semibold text-slate-800">Integration with planning & budget cycles established</div>
              <div className="text-xs text-slate-600">Quarterly milestones aligned with organizational rhythm</div>
            </div>
          </div>
        </div>
      </section>

      {/* Board Action Required */}
      <section className="rounded-lg border-4 border-red-600 bg-gradient-to-br from-red-50 to-orange-50 p-6 shadow-lg">
        <div className="mb-3 flex items-center gap-2">
          <span className="text-3xl">⚖️</span>
          <h2 className="text-xl font-bold text-red-900">Board Action Required</h2>
        </div>
        <div className="mb-4 text-base font-bold text-red-900">
          Approve Q2 resourcing package to:
        </div>
        <ul className="space-y-2 text-sm text-red-900">
          <li className="flex items-start gap-2">
            <span className="mt-0.5 font-bold">•</span>
            <span><span className="font-semibold">Sustain capability trajectory</span></span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-0.5 font-bold">•</span>
            <span><span className="font-semibold">Prioritize Legal & Regulatory function intervention</span> to maintain momentum</span>
          </li>
        </ul>
      </section>

      {/* Takeaway Section */}
      <section className="rounded-lg border-2 border-slate-300 bg-gradient-to-br from-slate-50 to-slate-100 p-5 shadow-sm">
        <div className="mb-2 text-xs font-bold uppercase tracking-wide text-slate-600">Takeaway</div>
        <p className="text-sm leading-relaxed text-slate-800">
          Governance is now a <span className="font-semibold">visible, measurable enterprise capability</span> delivering ROI.
          Board approval in Q2 is the lever that sustains trajectory, mitigates Legal bottleneck risk, and secures competitive positioning.
        </p>
      </section>

      {/* Supporting Documentation Links */}
      <section className="rounded-lg border bg-slate-50 p-4">
        <div className="mb-2 text-xs font-semibold text-slate-600">Supporting Documentation</div>
        <div className="flex flex-wrap gap-3 text-xs">
          <a href="/docs/exec-overlay/summary" className="font-medium text-blue-600 hover:underline">
            → Executive Summary (Full Detail)
          </a>
          <a href="/docs/exec-overlay/board-pack" className="font-medium text-blue-600 hover:underline">
            → Board Pack (Visual Overlay)
          </a>
          <a href="/governance/dashboard" className="font-medium text-blue-600 hover:underline">
            → Readiness Dashboard
          </a>
          <a href="/governance" className="font-medium text-blue-600 hover:underline">
            → Governance Cockpit
          </a>
        </div>
      </section>
    </main>
  );
}
