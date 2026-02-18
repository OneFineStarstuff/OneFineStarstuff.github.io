export const metadata = { title: 'Executive Summary - Governance Commissioning' } as const;

export default function ExecutiveSummary() {
  return (
    <main className="mx-auto max-w-4xl space-y-6 p-6">
      <div className="rounded-lg border-2 border-blue-600 bg-gradient-to-br from-blue-50 to-slate-50 p-6 shadow-lg">
        <h1 className="mb-2 text-2xl font-bold text-blue-900">
          Executive Summary — Responsible AI Governance Commissioning Overlay
        </h1>
        <div className="text-sm text-blue-700">One-Page Strategic Briefing for Board Review</div>
      </div>

      {/* Status */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">📊</span> Status
        </h2>
        <p className="text-sm leading-relaxed text-slate-700">
          Governance framework successfully transformed from theory to practice. Commissioning overlay 
          completed and executive-ready. Three pilot initiatives underway with measurable outcomes and 
          senior leadership ownership.
        </p>
      </section>

      {/* Strategic Positioning */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">🎯</span> Strategic Positioning
        </h2>
        <ul className="space-y-2 text-sm text-slate-700">
          <li className="flex items-start gap-2">
            <span className="mt-1 text-green-600">✓</span>
            <span>Governance positioned as <span className="font-semibold italic">enterprise capability</span>, not compliance burden.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-1 text-green-600">✓</span>
            <span>Direct alignment to strategic themes: <span className="font-semibold">Trust, Efficiency, Confidence</span>.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="mt-1 text-green-600">✓</span>
            <span>Competitive advantage through superior risk management and stakeholder confidence.</span>
          </li>
        </ul>
      </section>

      {/* Key Capabilities */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">⚙️</span> Key Capabilities
        </h2>
        <div className="space-y-3">
          {[
            {
              name: 'Model Risk Registry',
              pct: 45,
              color: '#0ea5e9',
              timeline: '9 months to advanced capability',
              owner: 'Chief Risk Officer'
            },
            {
              name: 'Ethics Review Loop',
              pct: 30,
              color: '#10b981',
              timeline: 'Embedded in product lifecycle',
              owner: 'Chief Ethics Officer'
            },
            {
              name: 'Data Provenance Hub',
              pct: 20,
              color: '#8b5cf6',
              timeline: 'Audit traceability under development',
              owner: 'Chief Data Officer'
            }
          ].map((cap, i) => (
            <div key={i} className="rounded border border-slate-200 p-3">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-sm font-semibold text-slate-800">{cap.name}</span>
                <span className="text-xs font-bold" style={{ color: cap.color }}>
                  {cap.pct}% complete
                </span>
              </div>
              <div className="mb-2 h-2 overflow-hidden rounded-full bg-slate-100">
                <div
                  className="h-full transition-all duration-500"
                  style={{ width: `${cap.pct}%`, background: cap.color }}
                />
              </div>
              <div className="text-xs text-slate-600">
                <div className="mb-0.5">{cap.timeline}</div>
                <div><span className="font-semibold">Owner:</span> {cap.owner}</div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Organizational Capacity */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">📈</span> Organizational Capacity
        </h2>
        <div className="space-y-2">
          <div className="flex items-start gap-2 text-sm">
            <span className="flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-amber-100 text-xs font-bold text-amber-700">
              ↗
            </span>
            <div>
              <span className="font-semibold text-slate-800">Risk & Compliance</span>
              <span className="text-slate-600"> — stretched but improving (automation and process optimization underway).</span>
            </div>
          </div>
          <div className="flex items-start gap-2 text-sm">
            <span className="flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-red-100 text-xs font-bold text-red-700">
              ↘
            </span>
            <div>
              <span className="font-semibold text-slate-800">Legal & Regulatory</span>
              <span className="text-slate-600"> — deteriorating capacity; </span>
              <span className="font-semibold text-red-700">potential bottleneck requiring Q2 executive intervention</span>.
            </div>
          </div>
        </div>
      </section>

      {/* Value Metrics */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">💰</span> Value Metrics (Baseline → Target)
        </h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {[
            { label: 'Model risk incidents', baseline: 6, target: 2, color: '#ef4444' },
            { label: 'Operational efficiency', baseline: '78%', target: '85%', color: '#10b981' },
            { label: 'Stakeholder trust index', baseline: '62%', target: '75%', color: '#0ea5e9' },
            { label: 'Regulatory findings', baseline: 4, target: 0, color: '#f59e0b' }
          ].map((m, i) => (
            <div key={i} className="rounded border border-slate-200 p-3">
              <div className="mb-1 text-xs font-semibold text-slate-700">{m.label}</div>
              <div className="flex items-center gap-2 text-sm">
                <span className="font-bold text-slate-600">{m.baseline}</span>
                <span className="text-slate-400">→</span>
                <span className="font-bold" style={{ color: m.color }}>
                  {m.target}
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Timeline Spine */}
      <section className="rounded-lg border bg-white p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">📅</span> Timeline Spine
        </h2>
        <div className="space-y-2">
          {[
            { q: 'Q1', label: 'Pilot launches', status: 'complete', icon: '✔' },
            { q: 'Q2', label: 'Board decision gate — resourcing endorsement', status: 'pending', icon: '⚑' },
            { q: 'Q3', label: 'Risk registry operational', status: 'complete', icon: '✔' },
            { q: 'Q4', label: 'Full activation kit rollout', status: 'pending', icon: '⚑' }
          ].map((milestone, i) => {
            const color = milestone.status === 'complete' ? '#10b981' : '#f59e0b';
            return (
              <div key={i} className="flex items-center gap-3 text-sm">
                <div
                  className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full text-white font-bold"
                  style={{ background: color }}
                >
                  {milestone.icon}
                </div>
                <div>
                  <span className="font-semibold text-slate-800">{milestone.q}:</span>{' '}
                  <span className="text-slate-700">{milestone.label}</span>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Board Ask */}
      <section className="rounded-lg border-2 border-amber-500 bg-amber-50 p-5 shadow-md">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-amber-900">
          <span className="text-2xl">📋</span> Board Ask
        </h2>
        <p className="text-sm font-semibold text-amber-900">
          Approve Q2 resourcing package to sustain trajectory and unlock full governance activation.
        </p>
      </section>

      {/* Strategic Implication */}
      <section className="rounded-lg border bg-gradient-to-br from-blue-50 to-purple-50 p-5 shadow-sm">
        <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-slate-800">
          <span className="text-2xl">🎯</span> Strategic Implication
        </h2>
        <p className="text-sm leading-relaxed text-slate-700">
          Governance now positioned as <span className="font-semibold">enterprise capability</span>. 
          Sustaining requires continued executive sponsorship and Q2 endorsement to maintain momentum 
          and secure competitive advantage.
        </p>
      </section>

      {/* Footer Navigation */}
      <div className="rounded-lg border bg-slate-50 p-4">
        <div className="mb-2 text-xs font-semibold text-slate-600">Related Artifacts</div>
        <div className="flex flex-wrap gap-2 text-xs">
          <a href="/docs/exec-overlay/board-pack" className="rounded bg-blue-600 px-3 py-1.5 text-white hover:bg-blue-700">
            📊 Full Board Pack
          </a>
          <a href="/governance" className="rounded bg-slate-600 px-3 py-1.5 text-white hover:bg-slate-700">
            🎛️ Governance Cockpit
          </a>
          <a href="/docs/launch-brief" className="rounded bg-green-600 px-3 py-1.5 text-white hover:bg-green-700">
            📄 Launch Brief
          </a>
        </div>
      </div>
    </main>
  );
}
