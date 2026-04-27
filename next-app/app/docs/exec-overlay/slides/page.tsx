export const metadata = { title: 'Board Slides - Governance Framework' } as const;

export default function BoardSlidesPage() {
  return (
    <main className="mx-auto max-w-6xl space-y-8 p-6">
      {/* Page Header */}
      <div className="rounded-lg border-2 border-indigo-600 bg-gradient-to-r from-indigo-600 to-purple-700 p-6 shadow-xl">
        <h1 className="mb-2 text-3xl font-bold text-white">
          Board Presentation Storyboard
        </h1>
        <div className="text-sm text-indigo-100">5-Minute Executive Slot · 3 Slides</div>
      </div>

      {/* Executive Assessment Banner */}
      <div className="rounded-lg border-2 border-amber-500 bg-gradient-to-r from-amber-50 via-orange-50 to-red-50 p-5 shadow-lg">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-4xl">📊</span>
            <div>
              <div className="text-lg font-bold text-amber-900">Executive Communication Assessment</div>
              <div className="text-sm text-amber-700">Professional evaluation of dry run transcript · Strategic refinements</div>
            </div>
          </div>
          <a
            href="/docs/exec-overlay/slides/assessment"
            className="rounded-lg border-2 border-amber-600 bg-amber-600 px-6 py-3 font-bold text-white hover:bg-amber-700"
          >
            View Assessment →
          </a>
        </div>
        <div className="mt-3 rounded bg-white p-3 text-sm italic text-amber-900">
          <span className="font-semibold">Executive verdict:</span> "This dry run transcript is excellent. It has the discipline of cadence
          and the flexibility of pivot points, which is exactly what you need in a boardroom setting."
        </div>
      </div>

      {/* Communication Playbook Trifecta */}
      <div className="rounded-lg border-2 border-slate-600 bg-gradient-to-r from-slate-50 via-blue-50 to-indigo-50 p-6 shadow-lg">
        <div className="mb-4 flex items-center gap-3">
          <span className="text-4xl">📚</span>
          <div>
            <div className="text-xl font-bold text-slate-900">Complete Communication Playbook</div>
            <div className="text-sm text-slate-700">Modular, scalable governance communication architecture</div>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          <a href="/docs/exec-overlay/slides/script-dry-run" className="group rounded-lg border-2 border-indigo-500 bg-white p-4 shadow-md transition-all hover:border-indigo-600 hover:shadow-xl">
            <div className="mb-2 text-2xl">⚡</div>
            <div className="mb-1 text-base font-bold text-indigo-900">90-Second Precision</div>
            <div className="text-xs text-slate-600">Tight slots, openers, elevator pitch</div>
          </a>
          <a href="/docs/exec-overlay/slides/script-expanded" className="group rounded-lg border-2 border-purple-500 bg-white p-4 shadow-md transition-all hover:border-purple-600 hover:shadow-xl">
            <div className="mb-2 text-2xl">🎯</div>
            <div className="mb-1 text-base font-bold text-purple-900">5-Minute Expanded ⭐⭐</div>
            <div className="text-xs text-slate-600">Full board slot with anecdotes & Q&A</div>
          </a>
          <a href="/docs/exec-overlay/board-handout" className="group rounded-lg border-2 border-green-500 bg-white p-4 shadow-md transition-all hover:border-green-600 hover:shadow-xl">
            <div className="mb-2 text-2xl">📄</div>
            <div className="mb-1 text-base font-bold text-green-900">1-Page Handout 🆕</div>
            <div className="text-xs text-slate-600">Visual anchors, print-ready reference</div>
          </a>
        </div>
        <div className="mt-4 rounded bg-slate-100 p-3 text-xs text-slate-700">
          <span className="font-semibold">Strategic Benefit:</span> This trifecta provides modular, repeatable governance
          communication for any board context — from quick briefings to comprehensive decision sessions with leave-behind materials.
        </div>
      </div>

      {/* Featured: 5-Minute Expanded Script */}
      <div className="rounded-lg border-2 border-purple-600 bg-gradient-to-r from-purple-50 via-indigo-50 to-blue-50 p-6 shadow-lg">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-4xl">🎯</span>
            <div>
              <div className="text-lg font-bold text-purple-900">5-Minute Expanded Delivery Script ⭐⭐</div>
              <div className="text-sm text-purple-700">Complete guide with anecdotes, Q&A pivots, and gesture coordination</div>
            </div>
          </div>
          <a
            href="/docs/exec-overlay/slides/script-expanded"
            className="rounded-lg border-2 border-purple-600 bg-purple-600 px-6 py-3 font-bold text-white hover:bg-purple-700"
          >
            View Expanded Script →
          </a>
        </div>
        <div className="mt-3 rounded bg-white p-3 text-sm italic text-purple-900">
          <span className="font-semibold">Timing:</span> Slide 1 (~1 min) + Slide 2 (~1.5 min) + Anecdote (~1 min) + Slide 3 (~1.5 min) = 5 minutes total
        </div>
      </div>

      {/* Speaker Scripts Banner */}
      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border-2 border-teal-500 bg-gradient-to-r from-teal-50 to-cyan-50 p-4 shadow-md">
          <div className="mb-3 flex items-center gap-3">
            <span className="text-3xl">🎭</span>
            <div>
              <div className="font-bold text-teal-900">Hybrid Script</div>
              <div className="text-xs text-teal-700">Verbatim + Adaptability · Best of both</div>
            </div>
          </div>
          <a
            href="/docs/exec-overlay/slides/script-hybrid"
            className="block rounded-lg border-2 border-teal-600 bg-teal-600 px-4 py-2 text-center font-bold text-white hover:bg-teal-700"
          >
            View Hybrid Script →
          </a>
        </div>

        <div className="rounded-lg border-2 border-indigo-500 bg-gradient-to-r from-indigo-50 to-purple-50 p-4 shadow-md">
          <div className="mb-3 flex items-center gap-3">
            <span className="text-3xl">⚡</span>
            <div>
              <div className="font-bold text-indigo-900">90-Second Dry Run</div>
              <div className="text-xs text-indigo-700">Natural cadence · Pause markers</div>
            </div>
          </div>
          <a
            href="/docs/exec-overlay/slides/script-dry-run"
            className="block rounded-lg border-2 border-indigo-600 bg-indigo-600 px-4 py-2 text-center font-bold text-white hover:bg-indigo-700"
          >
            View Dry Run →
          </a>
        </div>

        <div className="rounded-lg border-2 border-purple-500 bg-gradient-to-r from-purple-50 to-pink-50 p-4 shadow-md">
          <div className="mb-3 flex items-center gap-3">
            <span className="text-3xl">🎤</span>
            <div>
              <div className="font-bold text-purple-900">Detailed Script</div>
              <div className="text-xs text-purple-700">Full guidance · Q&A prep</div>
            </div>
          </div>
          <a
            href="/docs/exec-overlay/slides/script"
            className="block rounded-lg border-2 border-purple-600 bg-purple-600 px-4 py-2 text-center font-bold text-white hover:bg-purple-700"
          >
            View Full Script →
          </a>
        </div>
      </div>

      {/* Slide Navigation */}
      <div className="flex gap-4 rounded-lg border border-slate-200 bg-white p-4">
        <a href="#slide1" className="flex-1 rounded-lg border-2 border-green-500 bg-green-50 p-3 text-center font-semibold text-green-900 hover:bg-green-100">
          Slide 1: Trajectory & Value
        </a>
        <a href="#slide2" className="flex-1 rounded-lg border-2 border-amber-500 bg-amber-50 p-3 text-center font-semibold text-amber-900 hover:bg-amber-100">
          Slide 2: Capacity & Risks
        </a>
        <a href="#slide3" className="flex-1 rounded-lg border-2 border-red-500 bg-red-50 p-3 text-center font-semibold text-red-900 hover:bg-red-100">
          Slide 3: Decision & Action
        </a>
      </div>

      {/* Slide 1: Trajectory & Value */}
      <section id="slide1" className="rounded-xl border-4 border-green-600 bg-white p-8 shadow-2xl">
        <div className="mb-6 flex items-center justify-between border-b-2 border-green-600 pb-4">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wide text-green-700">Slide 1 of 3</div>
            <h2 className="text-2xl font-bold text-slate-900">Governance as Enterprise Capability</h2>
          </div>
          <div className="rounded-full bg-green-600 px-4 py-2 text-sm font-bold text-white">
            90 seconds
          </div>
        </div>

        {/* Trajectory Arc Visual */}
        <div className="mb-6 rounded-lg bg-gradient-to-r from-blue-50 via-indigo-50 to-purple-50 p-6">
          <div className="mb-4 text-center text-sm font-semibold text-slate-600">
            Transformation Journey
          </div>
          <div className="flex items-center justify-between">
            {[
              { stage: 'Principles', status: 'complete', color: 'bg-green-600' },
              { stage: 'Framework', status: 'complete', color: 'bg-green-600' },
              { stage: 'Pilots', status: 'complete', color: 'bg-green-600' },
              { stage: 'Operations', status: 'active', color: 'bg-blue-600' }
            ].map((item, i) => (
              <div key={i} className="flex flex-col items-center">
                <div className={`mb-2 flex h-16 w-16 items-center justify-center rounded-full ${item.color} text-2xl font-bold text-white shadow-lg`}>
                  {item.status === 'complete' ? '✓' : '⚡'}
                </div>
                <div className="text-xs font-semibold text-slate-700">{item.stage}</div>
                {i < 3 && (
                  <div className="absolute ml-24 mt-8 h-1 w-24 bg-slate-300" />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* ROI Evidence Grid */}
        <div className="mb-6 grid gap-4 md:grid-cols-2">
          <div className="rounded-lg border-2 border-red-200 bg-red-50 p-4">
            <div className="mb-2 text-xs font-bold uppercase tracking-wide text-red-700">Risk Management</div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold text-red-900">6 → 2</span>
              <span className="text-sm text-red-700">incidents annually</span>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <div className="h-2 flex-1 rounded-full bg-red-200">
                <div className="h-2 w-2/3 rounded-full bg-red-600" />
              </div>
              <span className="text-xs font-bold text-red-700">67% ↓</span>
            </div>
          </div>

          <div className="rounded-lg border-2 border-green-200 bg-green-50 p-4">
            <div className="mb-2 text-xs font-bold uppercase tracking-wide text-green-700">Process Optimization</div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold text-green-900">78% → 85%</span>
              <span className="text-sm text-green-700">efficiency</span>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <div className="h-2 flex-1 rounded-full bg-green-200">
                <div className="h-2 w-3/4 rounded-full bg-green-600" />
              </div>
              <span className="text-xs font-bold text-green-700">+7% ↑</span>
            </div>
          </div>
        </div>

        {/* Key Message */}
        <div className="rounded-lg border-l-4 border-green-600 bg-green-50 p-4">
          <div className="mb-2 text-xs font-bold uppercase tracking-wide text-green-800">Key Message</div>
          <p className="text-base font-semibold italic text-green-900">
            "Momentum is strong; value creation is measurable"
          </p>
        </div>

        {/* Talking Point */}
        <div className="mt-6 rounded-lg bg-slate-100 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">🎤</span>
            <span className="text-xs font-bold uppercase tracking-wide text-slate-600">Talking Point</span>
          </div>
          <p className="text-sm leading-relaxed text-slate-700">
            "We've moved from abstract principles to operational impact. The ROI is already visible in reduced
            incidents and improved efficiency. Governance is functioning as a capability that enhances competitive advantage."
          </p>
        </div>
      </section>

      {/* Slide 2: Capacity & Risks */}
      <section id="slide2" className="rounded-xl border-4 border-amber-600 bg-white p-8 shadow-2xl">
        <div className="mb-6 flex items-center justify-between border-b-2 border-amber-600 pb-4">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wide text-amber-700">Slide 2 of 3</div>
            <h2 className="text-2xl font-bold text-slate-900">Pinpointing Bottlenecks, Not Broad Restructuring</h2>
          </div>
          <div className="rounded-full bg-amber-600 px-4 py-2 text-sm font-bold text-white">
            90 seconds
          </div>
        </div>

        {/* Traffic Light Grid */}
        <div className="mb-6 rounded-lg bg-slate-50 p-6">
          <div className="mb-4 text-center text-sm font-semibold text-slate-600">
            Organizational Capacity Assessment
          </div>
          <div className="space-y-3">
            {[
              {
                fn: 'Risk & Compliance',
                status: 'improving',
                color: 'amber',
                icon: '🟡',
                note: 'Stretched but improving via automation',
                trend: '↗'
              },
              {
                fn: 'Legal & Regulatory',
                status: 'critical',
                color: 'red',
                icon: '🔴',
                note: 'Capacity deteriorating — critical bottleneck',
                trend: '↘'
              },
              {
                fn: 'Technology Delivery',
                status: 'stable',
                color: 'green',
                icon: '🟢',
                note: 'Balanced load, stable trajectory',
                trend: '→'
              },
              {
                fn: 'Finance',
                status: 'stable',
                color: 'green',
                icon: '🟢',
                note: 'Comfortable capacity, no bottlenecks',
                trend: '→'
              }
            ].map((item, i) => (
              <div
                key={i}
                className={`flex items-center gap-4 rounded-lg border-2 p-4 ${
                  item.color === 'red' ? 'border-red-600 bg-red-50' :
                  item.color === 'amber' ? 'border-amber-500 bg-amber-50' :
                  'border-green-500 bg-green-50'
                }`}
              >
                <div className="text-3xl">{item.icon}</div>
                <div className="flex-1">
                  <div className={`font-bold ${
                    item.color === 'red' ? 'text-red-900' :
                    item.color === 'amber' ? 'text-amber-900' :
                    'text-green-900'
                  }`}>
                    {item.fn}
                  </div>
                  <div className={`text-xs ${
                    item.color === 'red' ? 'text-red-700' :
                    item.color === 'amber' ? 'text-amber-700' :
                    'text-green-700'
                  }`}>
                    {item.note}
                  </div>
                </div>
                <div className={`text-3xl ${
                  item.color === 'red' ? 'text-red-600' :
                  item.color === 'amber' ? 'text-amber-600' :
                  'text-green-600'
                }`}>
                  {item.trend}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Milestone Risk Alert */}
        <div className="mb-6 rounded-lg border-4 border-red-600 bg-red-50 p-5">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-2xl">⚠️</span>
            <span className="text-sm font-bold uppercase tracking-wide text-red-900">Milestone Risk</span>
          </div>
          <p className="text-base font-semibold text-red-900">
            Legal bottleneck jeopardizes Q3 registry operationalization
          </p>
          <p className="mt-2 text-sm text-red-800">
            If unaddressed in Q2, capacity deterioration will stall ROI gains and threaten competitive positioning.
          </p>
        </div>

        {/* Talking Point */}
        <div className="rounded-lg bg-slate-100 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">🎤</span>
            <span className="text-xs font-bold uppercase tracking-wide text-slate-600">Talking Point</span>
          </div>
          <p className="text-sm leading-relaxed text-slate-700">
            "Overall, functions are improving—but Legal & Regulatory are under real pressure. Unless resourced in Q2,
            the Q3 registry milestone is at risk, which could stall ROI gains."
          </p>
        </div>
      </section>

      {/* Slide 3: Decision & Action */}
      <section id="slide3" className="rounded-xl border-4 border-red-600 bg-white p-8 shadow-2xl">
        <div className="mb-6 flex items-center justify-between border-b-2 border-red-600 pb-4">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wide text-red-700">Slide 3 of 3</div>
            <h2 className="text-2xl font-bold text-slate-900">Single Board Ask</h2>
          </div>
          <div className="rounded-full bg-red-600 px-4 py-2 text-sm font-bold text-white">
            60 seconds
          </div>
        </div>

        {/* Decision Callout */}
        <div className="mb-6 rounded-xl border-4 border-red-600 bg-gradient-to-br from-red-50 to-orange-50 p-8 shadow-lg">
          <div className="mb-4 flex items-center justify-center gap-3">
            <span className="text-5xl">⚖️</span>
            <div className="text-center">
              <div className="text-sm font-bold uppercase tracking-wide text-red-800">Board Decision Required</div>
              <div className="text-3xl font-bold text-red-900">Approve Q2 Resourcing</div>
            </div>
          </div>

          {/* Intervention Arrow */}
          <div className="flex items-center justify-center gap-4 py-4">
            <div className="rounded-lg bg-white px-6 py-3 text-center shadow-md">
              <div className="text-xs font-semibold text-slate-600">Current State</div>
              <div className="text-sm font-bold text-red-900">Legal Bottleneck</div>
            </div>
            <div className="flex flex-col items-center">
              <div className="text-4xl text-red-600">→</div>
              <div className="text-xs font-bold text-red-700">Q2 Action</div>
            </div>
            <div className="rounded-lg bg-green-600 px-6 py-3 text-center shadow-md">
              <div className="text-xs font-semibold text-green-100">Target State</div>
              <div className="text-sm font-bold text-white">Q3 On Track</div>
            </div>
          </div>
        </div>

        {/* Board Lever */}
        <div className="mb-6 grid gap-4 md:grid-cols-2">
          <div className="rounded-lg border-2 border-blue-300 bg-blue-50 p-5">
            <div className="mb-2 text-xs font-bold uppercase tracking-wide text-blue-800">Decision Required</div>
            <div className="text-base font-semibold text-blue-900">
              Approve targeted resourcing in Q2
            </div>
          </div>
          <div className="rounded-lg border-2 border-purple-300 bg-purple-50 p-5">
            <div className="mb-2 text-xs font-bold uppercase tracking-wide text-purple-800">Board Lever</div>
            <div className="text-base font-semibold text-purple-900">
              Address Legal capacity directly
            </div>
          </div>
        </div>

        {/* Executive Framing */}
        <div className="mb-6 rounded-lg border-l-4 border-red-600 bg-slate-100 p-5">
          <div className="mb-2 text-xs font-bold uppercase tracking-wide text-slate-700">Executive Framing</div>
          <p className="text-lg font-bold italic text-slate-900">
            "Momentum is strong, ROI is visible, sustained trajectory depends on one decision now."
          </p>
        </div>

        {/* Key Points */}
        <div className="mb-6 rounded-lg bg-red-50 p-5">
          <div className="mb-3 text-sm font-bold uppercase tracking-wide text-red-900">Why This Matters</div>
          <ul className="space-y-2 text-sm text-red-900">
            <li className="flex items-start gap-2">
              <span className="mt-0.5">•</span>
              <span><span className="font-semibold">Targeted, not broad:</span> One function, one quarter, measurable outcome</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="mt-0.5">•</span>
              <span><span className="font-semibold">Time-bound:</span> Q2 approval unlocks Q3 delivery</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="mt-0.5">•</span>
              <span><span className="font-semibold">Low risk:</span> No restructuring, just capacity support where bottleneck exists</span>
            </li>
          </ul>
        </div>

        {/* Talking Point */}
        <div className="rounded-lg bg-slate-100 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">🎤</span>
            <span className="text-xs font-bold uppercase tracking-wide text-slate-600">Talking Point</span>
          </div>
          <p className="text-sm leading-relaxed text-slate-700">
            "The ask is focused and time-bound: approve Legal resourcing in Q2. That's the lever to keep the trajectory
            on track and ensure Q3 delivery. No broad restructuring needed—just targeted support where the bottleneck sits."
          </p>
        </div>
      </section>

      {/* Summary Footer */}
      <div className="rounded-lg border-2 border-slate-300 bg-gradient-to-br from-slate-50 to-slate-100 p-6">
        <div className="mb-3 text-center text-sm font-bold uppercase tracking-wide text-slate-600">
          5-Minute Narrative Arc
        </div>
        <div className="flex items-center justify-between text-xs">
          <div className="flex-1 text-center">
            <div className="mb-1 text-lg font-bold text-green-700">Slide 1</div>
            <div className="text-slate-600">Establish momentum & ROI</div>
          </div>
          <div className="text-2xl text-slate-400">→</div>
          <div className="flex-1 text-center">
            <div className="mb-1 text-lg font-bold text-amber-700">Slide 2</div>
            <div className="text-slate-600">Surface specific bottleneck</div>
          </div>
          <div className="text-2xl text-slate-400">→</div>
          <div className="flex-1 text-center">
            <div className="mb-1 text-lg font-bold text-red-700">Slide 3</div>
            <div className="text-slate-600">Request targeted decision</div>
          </div>
        </div>
      </div>

      {/* Navigation Links */}
      <div className="rounded-lg border bg-slate-50 p-4">
        <div className="mb-2 text-xs font-semibold text-slate-600">Related Documentation</div>
        <div className="flex flex-wrap gap-3 text-xs">
          <a href="/docs/exec-overlay/action-brief" className="font-medium text-blue-600 hover:underline">
            → Board Action Brief
          </a>
          <a href="/docs/exec-overlay/summary" className="font-medium text-blue-600 hover:underline">
            → Executive Summary
          </a>
          <a href="/docs/exec-overlay/board-pack" className="font-medium text-blue-600 hover:underline">
            → Board Pack (Visual Overlay)
          </a>
          <a href="/governance" className="font-medium text-blue-600 hover:underline">
            → Governance Cockpit
          </a>
        </div>
      </div>
    </main>
  );
}
