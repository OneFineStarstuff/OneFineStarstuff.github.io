export const metadata = { title: 'Hybrid Script - Board Presentation' } as const;

export default function HybridScriptPage() {
  return (
    <main className="mx-auto max-w-5xl space-y-8 p-6">
      {/* Page Header */}
      <div className="rounded-lg border-2 border-teal-600 bg-gradient-to-r from-teal-600 via-cyan-700 to-blue-700 p-6 shadow-xl">
        <h1 className="mb-2 text-3xl font-bold text-white">
          Hybrid Board Presentation Script
        </h1>
        <div className="text-sm text-teal-100">
          Verbatim cadence + Adaptability cues · Disciplined delivery with built-in flexibility
        </div>
      </div>

      {/* Key Features */}
      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border-2 border-blue-300 bg-blue-50 p-4 text-center">
          <div className="mb-2 text-2xl">🎯</div>
          <div className="text-xs font-bold text-blue-900">Memorability</div>
          <div className="mt-1 text-xs text-blue-700">Verbatim cadence for anchor phrases</div>
        </div>
        <div className="rounded-lg border-2 border-purple-300 bg-purple-50 p-4 text-center">
          <div className="mb-2 text-2xl">🔄</div>
          <div className="text-xs font-bold text-purple-900">Adaptability</div>
          <div className="mt-1 text-xs text-purple-700">Bullet cues for board dynamics</div>
        </div>
        <div className="rounded-lg border-2 border-green-300 bg-green-50 p-4 text-center">
          <div className="mb-2 text-2xl">⚖️</div>
          <div className="text-xs font-bold text-green-900">Balance</div>
          <div className="mt-1 text-xs text-green-700">Discipline meets flexibility</div>
        </div>
      </div>

      {/* Slide 1: Trajectory & Value */}
      <section className="rounded-xl border-4 border-green-600 bg-white p-8 shadow-2xl">
        <div className="mb-6 flex items-center justify-between border-b-2 border-green-600 pb-4">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wide text-green-700">Slide 1 of 3</div>
            <h2 className="text-2xl font-bold text-slate-900">Trajectory & Value</h2>
          </div>
          <div className="rounded-full bg-green-600 px-4 py-2 text-sm font-bold text-white">
            ~90 seconds
          </div>
        </div>

        {/* Opening Line (Verbatim Cadence) */}
        <div className="mb-6 rounded-lg border-l-4 border-green-600 bg-green-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">🎯</span>
            <span className="text-xs font-bold uppercase tracking-wide text-green-800">Opening Line (Cadence)</span>
          </div>
          <p className="font-mono text-base font-semibold leading-relaxed text-green-900">
            "Momentum is strong. ROI is visible. <span className="italic text-slate-500">[pause]</span> Governance is now enterprise capability, not compliance overhead."
          </p>
        </div>

        {/* Core Points (Bullets + Cues) */}
        <div className="mb-6 rounded-lg border border-slate-200 bg-slate-50 p-5">
          <div className="mb-3 flex items-center gap-2">
            <span className="text-lg">📋</span>
            <span className="text-sm font-bold text-slate-800">Core Points (Bullets + Cues)</span>
          </div>

          <div className="space-y-4">
            <div className="rounded-lg border-l-4 border-blue-500 bg-white p-4">
              <div className="mb-2 font-semibold text-blue-900">
                <span className="font-bold">Trajectory:</span> Principles → Framework → Operations.
              </div>
              <div className="rounded bg-blue-50 px-3 py-2 text-xs italic text-blue-800">
                <span className="font-semibold">If pressed:</span> "Each stage builds measurable capability — no gaps, no drift."
              </div>
            </div>

            <div className="rounded-lg border-l-4 border-green-500 bg-white p-4">
              <div className="mb-2 font-semibold text-green-900">
                <span className="font-bold">ROI Metrics:</span> Risk incidents ↓67% (6 → 2). Efficiency ↑7 pts (78% → 85%).
              </div>
              <div className="mb-2 text-xs text-slate-600">
                <span className="italic text-slate-500">[short pause]</span>
              </div>
              <div className="rounded bg-yellow-100 px-3 py-2 text-xs italic text-amber-900">
                <span className="font-semibold">Optional emphasis:</span> "These are business performance numbers, not abstract governance."
              </div>
            </div>
          </div>
        </div>

        {/* Anchor Phrase */}
        <div className="rounded-lg border-2 border-green-500 bg-green-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-xl">⚓</span>
            <span className="text-xs font-bold uppercase tracking-wide text-green-800">Anchor Phrase</span>
          </div>
          <p className="text-base font-bold text-green-900">
            "Momentum is strong. ROI is visible."
          </p>
          <div className="mt-2 text-xs text-green-700">
            (Repeated in Slide 3 for bookend continuity)
          </div>
        </div>
      </section>

      {/* Slide 2: Capacity & Risks */}
      <section className="rounded-xl border-4 border-amber-600 bg-white p-8 shadow-2xl">
        <div className="mb-6 flex items-center justify-between border-b-2 border-amber-600 pb-4">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wide text-amber-700">Slide 2 of 3</div>
            <h2 className="text-2xl font-bold text-slate-900">Capacity & Risks</h2>
          </div>
          <div className="rounded-full bg-amber-600 px-4 py-2 text-sm font-bold text-white">
            ~90 seconds
          </div>
        </div>

        {/* Opening Line (Verbatim Cadence) */}
        <div className="mb-6 rounded-lg border-l-4 border-amber-600 bg-amber-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">🎯</span>
            <span className="text-xs font-bold uppercase tracking-wide text-amber-800">Opening Line (Cadence)</span>
          </div>
          <p className="font-mono text-base font-semibold leading-relaxed text-amber-900">
            "Most functions improving. One bottleneck emerging. <span className="italic text-slate-500">[pause]</span> Legal capacity."
          </p>
        </div>

        {/* Core Points (Bullets + Cues) */}
        <div className="mb-6 rounded-lg border border-slate-200 bg-slate-50 p-5">
          <div className="mb-3 flex items-center gap-2">
            <span className="text-lg">📋</span>
            <span className="text-sm font-bold text-slate-800">Core Points (Bullets + Cues)</span>
          </div>

          <div className="space-y-4">
            <div className="rounded-lg border-l-4 border-green-500 bg-white p-4">
              <div className="mb-2 font-semibold text-green-900">
                <span className="font-bold">Risk & Compliance:</span> Improving through automation (↗ trend).
              </div>
            </div>

            <div className="rounded-lg border-l-4 border-red-500 bg-white p-4">
              <div className="mb-2 font-semibold text-red-900">
                <span className="font-bold">Legal & Regulatory:</span> Capacity deteriorating (↘ trend).
              </div>
              <div className="rounded bg-red-50 px-3 py-2 text-xs italic text-red-800">
                <span className="font-semibold">If challenged:</span> "Automation can't substitute in Legal — this is the non‑substitutable bottleneck."
              </div>
            </div>

            <div className="rounded-lg border-l-4 border-orange-500 bg-white p-4">
              <div className="mb-2 font-semibold text-orange-900">
                <span className="font-bold">Risk Linkage:</span> "If Legal capacity not addressed → Q3 registry delivery at risk."
              </div>
            </div>
          </div>
        </div>

        {/* Anchor Phrase */}
        <div className="rounded-lg border-2 border-amber-500 bg-amber-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-xl">⚓</span>
            <span className="text-xs font-bold uppercase tracking-wide text-amber-800">Anchor Phrase</span>
          </div>
          <p className="text-base font-bold text-amber-900">
            "Pinpointed bottleneck. Predictable consequence."
          </p>
        </div>
      </section>

      {/* Slide 3: Decision & Action */}
      <section className="rounded-xl border-4 border-red-600 bg-white p-8 shadow-2xl">
        <div className="mb-6 flex items-center justify-between border-b-2 border-red-600 pb-4">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wide text-red-700">Slide 3 of 3</div>
            <h2 className="text-2xl font-bold text-slate-900">Decision & Action</h2>
          </div>
          <div className="rounded-full bg-red-600 px-4 py-2 text-sm font-bold text-white">
            ~90 seconds
          </div>
        </div>

        {/* Opening Line (Verbatim Cadence) */}
        <div className="mb-6 rounded-lg border-l-4 border-red-600 bg-red-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">🎯</span>
            <span className="text-xs font-bold uppercase tracking-wide text-red-800">Opening Line (Cadence)</span>
          </div>
          <p className="font-mono text-base font-semibold leading-relaxed text-red-900">
            "One decision. One quarter. One lever. <span className="italic text-slate-500">[pause]</span> Resourcing Legal."
          </p>
        </div>

        {/* Core Points (Bullets + Cues) */}
        <div className="mb-6 rounded-lg border border-slate-200 bg-slate-50 p-5">
          <div className="mb-3 flex items-center gap-2">
            <span className="text-lg">📋</span>
            <span className="text-sm font-bold text-slate-800">Core Points (Bullets + Cues)</span>
          </div>

          <div className="space-y-4">
            <div className="rounded-lg border-l-4 border-blue-500 bg-white p-4">
              <div className="font-semibold text-blue-900">
                <span className="font-bold">Board Action:</span> Approve Q2 resourcing package.
              </div>
            </div>

            <div className="rounded-lg border-l-4 border-green-500 bg-white p-4">
              <div className="font-semibold text-green-900">
                <span className="font-bold">Outcome:</span> Secures Q3 delivery and ROI trajectory.
              </div>
            </div>

            <div className="rounded-lg border-l-4 border-purple-500 bg-white p-4">
              <div className="mb-2 font-semibold text-purple-900">
                <span className="font-bold">If/Then framing:</span> If approved → trajectory sustained. If not → ROI stalls.
              </div>
            </div>
          </div>
        </div>

        {/* Closing Echo Line (Verbatim Cadence) */}
        <div className="mb-6 rounded-lg border-l-4 border-indigo-600 bg-indigo-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">🔚</span>
            <span className="text-xs font-bold uppercase tracking-wide text-indigo-800">Closing Echo Line</span>
          </div>
          <p className="font-mono text-base font-semibold leading-relaxed text-indigo-900">
            "Momentum is strong. ROI is visible. One decision this quarter secures delivery and advantage. That's the lever in front of you today."
          </p>
        </div>

        {/* Anchor Continuity Note */}
        <div className="rounded-lg border-2 border-red-500 bg-red-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-xl">⚓</span>
            <span className="text-xs font-bold uppercase tracking-wide text-red-800">Anchor Continuity</span>
          </div>
          <p className="text-sm font-semibold text-red-900">
            Repeat "Momentum is strong. ROI is visible." on Slide 1 and Slide 3 to bookend the narrative.
          </p>
        </div>
      </section>

      {/* Delivery Notes */}
      <section className="rounded-lg border-2 border-slate-600 bg-white p-6 shadow-lg">
        <h2 className="mb-4 flex items-center gap-2 text-xl font-bold text-slate-900">
          <span className="text-2xl">💡</span>
          Delivery Notes
        </h2>
        <div className="space-y-4">
          <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
            <div className="mb-2 text-sm font-bold text-blue-900">Cadence Control</div>
            <div className="text-sm text-blue-800">
              Use short declarative lines. Mark pauses (short vs. long) to let metrics land. 
              <span className="font-semibold"> Avoid filler words</span> — silence is your ally.
            </div>
          </div>

          <div className="rounded-lg border border-purple-200 bg-purple-50 p-4">
            <div className="mb-2 text-sm font-bold text-purple-900">Flexibility Cues</div>
            <div className="text-sm text-purple-800">
              Embedded in <span className="italic">italics</span> — deploy only if needed. 
              <span className="font-semibold"> Don't preemptively address objections</span> that haven't been raised.
            </div>
          </div>

          <div className="rounded-lg border border-green-200 bg-green-50 p-4">
            <div className="mb-2 text-sm font-bold text-green-900">Continuity Anchor</div>
            <div className="text-sm text-green-800">
              Repeat <span className="font-semibold">"Momentum is strong. ROI is visible."</span> on Slide 1 and Slide 3 
              to bookend the narrative. This creates <span className="font-semibold">psychological closure</span>.
            </div>
          </div>
        </div>
      </section>

      {/* Anticipated Q&A */}
      <section className="rounded-lg border-2 border-indigo-600 bg-white p-6 shadow-lg">
        <h2 className="mb-4 flex items-center gap-2 text-xl font-bold text-slate-900">
          <span className="text-2xl">❓</span>
          Anticipated Q&A
        </h2>
        <div className="space-y-4">
          <div className="rounded-lg border-l-4 border-blue-500 bg-blue-50 p-4">
            <div className="mb-2 font-semibold text-blue-900">Q: Why Legal specifically?</div>
            <div className="text-sm text-blue-800">
              <span className="font-semibold">A:</span> "Non‑substitutable, directly tied to Q3 delivery. 
              Automation has eased load elsewhere — Legal is the one exception where human judgment is irreplaceable."
            </div>
          </div>

          <div className="rounded-lg border-l-4 border-amber-500 bg-amber-50 p-4">
            <div className="mb-2 font-semibold text-amber-900">Q: Timeline risk if we wait?</div>
            <div className="text-sm text-amber-800">
              <span className="font-semibold">A:</span> "Aligned with budget cycles to avoid drift. 
              Q3 is when registry launches — if we start Q3 behind schedule, ROI gains stall immediately."
            </div>
          </div>

          <div className="rounded-lg border-l-4 border-purple-500 bg-purple-50 p-4">
            <div className="mb-2 font-semibold text-purple-900">Q: Could alternative support work?</div>
            <div className="text-sm text-purple-800">
              <span className="font-semibold">A:</span> "Automation eased load elsewhere; Legal is the one exception. 
              We've exhausted process optimization — this is about <span className="font-semibold">capacity, not efficiency</span>."
            </div>
          </div>

          <div className="rounded-lg border-l-4 border-green-500 bg-green-50 p-4">
            <div className="mb-2 font-semibold text-green-900">Q: What if board defers decision?</div>
            <div className="text-sm text-green-800">
              <span className="font-semibold">A:</span> "Q3 registry at risk. ROI trajectory stalls. 
              Competitive positioning advantage erodes. That's the <span className="font-semibold">binary outcome</span> we're presenting today."
            </div>
          </div>
        </div>
      </section>

      {/* Hybrid Script Advantages */}
      <section className="rounded-lg border-2 border-teal-600 bg-gradient-to-br from-teal-50 to-cyan-50 p-6">
        <h2 className="mb-4 flex items-center gap-2 text-xl font-bold text-teal-900">
          <span className="text-2xl">🎭</span>
          Why This Hybrid Approach Works
        </h2>
        <div className="grid gap-4 md:grid-cols-2">
          <div className="rounded-lg border border-teal-200 bg-white p-4">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xl">📝</span>
              <span className="text-sm font-bold text-teal-900">Verbatim Cadence Benefits</span>
            </div>
            <ul className="space-y-1 text-xs text-teal-800">
              <li>• <span className="font-semibold">Anchor phrases stick</span> - Board members remember exact wording</li>
              <li>• <span className="font-semibold">Confidence in delivery</span> - You know the "money lines" cold</li>
              <li>• <span className="font-semibold">Consistent messaging</span> - Same core narrative every time</li>
              <li>• <span className="font-semibold">Practiced rhythm</span> - Pauses and pacing become natural</li>
            </ul>
          </div>

          <div className="rounded-lg border border-cyan-200 bg-white p-4">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xl">🔄</span>
              <span className="text-sm font-bold text-cyan-900">Adaptability Cues Benefits</span>
            </div>
            <ul className="space-y-1 text-xs text-cyan-800">
              <li>• <span className="font-semibold">Read the room</span> - Deploy emphasis based on board energy</li>
              <li>• <span className="font-semibold">Respond to skepticism</span> - Pre-scripted clarifications ready</li>
              <li>• <span className="font-semibold">Avoid over-explaining</span> - Only use cues if challenged</li>
              <li>• <span className="font-semibold">Natural conversation</span> - Doesn't sound overly rehearsed</li>
            </ul>
          </div>
        </div>

        <div className="mt-4 rounded-lg border-2 border-teal-400 bg-teal-100 p-4">
          <div className="text-sm font-semibold text-teal-900">
            🎯 The Balance: Discipline meets flexibility
          </div>
          <div className="mt-2 text-xs text-teal-800">
            You're not reading a script (robotic) or winging it (risky). You have <span className="font-semibold">memorized anchor phrases</span> 
            that provide structure, with <span className="font-semibold">contextual cues</span> that let you adapt to board dynamics in real-time. 
            This is the <span className="font-semibold">professional presenter's sweet spot</span>.
          </div>
        </div>
      </section>

      {/* Practice Recommendations */}
      <section className="rounded-lg border-2 border-purple-600 bg-white p-6 shadow-lg">
        <h2 className="mb-4 flex items-center gap-2 text-xl font-bold text-slate-900">
          <span className="text-2xl">🎯</span>
          Practice Recommendations
        </h2>
        <div className="space-y-3">
          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-purple-600 text-sm font-bold text-white">
              1
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Memorize Anchor Phrases First</div>
              <div className="text-xs text-slate-600">
                Focus on opening lines, closing echo, and anchor continuity. These must be verbatim.
              </div>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-purple-600 text-sm font-bold text-white">
              2
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Practice Core Points as Bullet Summaries</div>
              <div className="text-xs text-slate-600">
                Don't memorize word-for-word. Know the metric (6→2, 78%→85%) and the insight (non-substitutable, pinpointed).
              </div>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-purple-600 text-sm font-bold text-white">
              3
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Role-Play "If Challenged" Scenarios</div>
              <div className="text-xs text-slate-600">
                Have a colleague play skeptical board member. Practice deploying flexibility cues naturally.
              </div>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-amber-600 text-sm font-bold text-white">
              4
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Record and Listen for Over-Explanation</div>
              <div className="text-xs text-slate-600">
                Watch for tendency to use ALL flexibility cues. Only deploy when board signals need for clarification.
              </div>
            </div>
          </div>
        </div>

        <div className="mt-4 rounded-lg bg-purple-50 p-3">
          <div className="text-xs text-purple-900">
            <span className="font-semibold">✓ Ready when:</span> You can deliver anchor phrases verbatim without looking, 
            summarize core points naturally with correct metrics, and deploy flexibility cues only when prompted.
          </div>
        </div>
      </section>

      {/* Navigation Footer */}
      <div className="rounded-lg border bg-slate-50 p-4">
        <div className="mb-2 text-xs font-semibold text-slate-600">Related Resources</div>
        <div className="flex flex-wrap gap-3 text-xs">
          <a href="/docs/exec-overlay/slides" className="font-medium text-blue-600 hover:underline">
            ← Back to Visual Slides
          </a>
          <a href="/docs/exec-overlay/slides/script-dry-run" className="font-medium text-blue-600 hover:underline">
            → 90-Second Dry Run
          </a>
          <a href="/docs/exec-overlay/slides/script" className="font-medium text-blue-600 hover:underline">
            → Detailed Script
          </a>
          <a href="/docs/exec-overlay/action-brief" className="font-medium text-blue-600 hover:underline">
            → Board Action Brief
          </a>
        </div>
      </div>
    </main>
  );
}
