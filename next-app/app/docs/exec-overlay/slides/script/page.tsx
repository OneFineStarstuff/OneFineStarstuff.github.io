export const metadata = { title: 'Speaker Script - Board Presentation' } as const;

export default function SpeakerScriptPage() {
  return (
    <main className="mx-auto max-w-5xl space-y-8 p-6">
      {/* Page Header */}
      <div className="rounded-lg border-2 border-purple-600 bg-gradient-to-r from-purple-600 to-indigo-700 p-6 shadow-xl">
        <h1 className="mb-2 text-3xl font-bold text-white">
          Speaker Script for Board Presentation
        </h1>
        <div className="flex items-center gap-4 text-sm text-purple-100">
          <span>🎤 5-Minute Executive Slot</span>
          <span>•</span>
          <span>3 Slides</span>
          <span>•</span>
          <span>~90 seconds per slide</span>
        </div>
      </div>

      {/* Timing Overview */}
      <div className="rounded-lg border-2 border-slate-300 bg-gradient-to-br from-slate-50 to-slate-100 p-5">
        <div className="mb-3 text-center text-sm font-bold uppercase tracking-wide text-slate-700">
          Timing Breakdown
        </div>
        <div className="flex items-center justify-between">
          <div className="flex-1 text-center">
            <div className="mb-1 text-2xl font-bold text-green-700">90s</div>
            <div className="text-xs text-slate-600">Slide 1</div>
            <div className="text-xs text-slate-500">Trajectory & Value</div>
          </div>
          <div className="text-2xl text-slate-400">→</div>
          <div className="flex-1 text-center">
            <div className="mb-1 text-2xl font-bold text-amber-700">90s</div>
            <div className="text-xs text-slate-600">Slide 2</div>
            <div className="text-xs text-slate-500">Capacity & Risks</div>
          </div>
          <div className="text-2xl text-slate-400">→</div>
          <div className="flex-1 text-center">
            <div className="mb-1 text-2xl font-bold text-red-700">90s</div>
            <div className="text-xs text-slate-600">Slide 3</div>
            <div className="text-xs text-slate-500">Decision & Action</div>
          </div>
          <div className="text-2xl text-slate-400">→</div>
          <div className="flex-1 text-center">
            <div className="mb-1 text-2xl font-bold text-blue-700">60s</div>
            <div className="text-xs text-slate-600">Buffer</div>
            <div className="text-xs text-slate-500">Q&A / Closing</div>
          </div>
        </div>
      </div>

      {/* Slide 1 Script */}
      <section className="rounded-xl border-4 border-green-600 bg-white p-8 shadow-2xl">
        <div className="mb-6 flex items-center justify-between border-b-2 border-green-600 pb-4">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wide text-green-700">Slide 1 of 3</div>
            <h2 className="text-2xl font-bold text-slate-900">Trajectory & Value</h2>
            <div className="mt-1 text-xs text-slate-600">Governance as Enterprise Capability</div>
          </div>
          <div className="rounded-full bg-green-600 px-4 py-2 text-sm font-bold text-white">
            90 seconds
          </div>
        </div>

        {/* Opening Hook */}
        <div className="mb-4 rounded-lg border-l-4 border-green-600 bg-green-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">🎯</span>
            <span className="text-xs font-bold uppercase tracking-wide text-green-800">Opening Hook</span>
          </div>
          <p className="text-base font-semibold italic text-green-900">
            "We've moved governance from a compliance requirement into a strategic capability — and the results are already visible."
          </p>
        </div>

        {/* Main Points */}
        <div className="mb-4 space-y-3">
          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-green-600 text-sm font-bold text-white">
              1
            </div>
            <div className="flex-1">
              <div className="mb-1 text-xs font-semibold text-green-700">ESTABLISH TRANSFORMATION</div>
              <p className="text-sm text-slate-800">
                "Our trajectory shows systematic progression: <span className="font-semibold">principles → framework → operations</span>."
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-green-600 text-sm font-bold text-white">
              2
            </div>
            <div className="flex-1">
              <div className="mb-1 text-xs font-semibold text-green-700">QUANTIFY ROI</div>
              <p className="text-sm text-slate-800">
                "Most importantly, the ROI is clear: risk incidents reduced from <span className="font-semibold">six to two annually</span>, 
                and efficiency improved from <span className="font-semibold">78% to 85%</span>. Governance is now creating measurable business value."
              </p>
            </div>
          </div>
        </div>

        {/* Visual Cues */}
        <div className="mb-4 rounded-lg bg-slate-100 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">👁️</span>
            <span className="text-xs font-bold uppercase tracking-wide text-slate-600">Visual Cues on Slide</span>
          </div>
          <ul className="space-y-1 text-xs text-slate-700">
            <li className="flex items-start gap-2">
              <span className="text-green-600">▸</span>
              <span>Point to trajectory arc showing completed stages (✓)</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-600">▸</span>
              <span>Gesture to ROI cards with progress bars (6→2, 78%→85%)</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-600">▸</span>
              <span>Pause at "measurable business value" for emphasis</span>
            </li>
          </ul>
        </div>

        {/* Delivery Notes */}
        <div className="rounded-lg bg-blue-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">💡</span>
            <span className="text-xs font-bold uppercase tracking-wide text-blue-800">Delivery Notes</span>
          </div>
          <ul className="space-y-1 text-xs text-blue-900">
            <li>• <span className="font-semibold">Tone:</span> Confident and evidence-based</li>
            <li>• <span className="font-semibold">Pace:</span> Steady with emphasis on numbers (6→2, 78%→85%)</li>
            <li>• <span className="font-semibold">Body language:</span> Open gestures toward slide visuals</li>
            <li>• <span className="font-semibold">Eye contact:</span> Scan board members during "measurable business value"</li>
          </ul>
        </div>

        {/* Transition */}
        <div className="mt-4 rounded-sm border-t-2 border-green-200 bg-green-50 px-4 py-2">
          <div className="text-xs font-semibold text-green-800">Transition to Slide 2:</div>
          <p className="text-xs italic text-green-700">
            "With that momentum established, let me show you where we need to focus attention..."
          </p>
        </div>
      </section>

      {/* Slide 2 Script */}
      <section className="rounded-xl border-4 border-amber-600 bg-white p-8 shadow-2xl">
        <div className="mb-6 flex items-center justify-between border-b-2 border-amber-600 pb-4">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wide text-amber-700">Slide 2 of 3</div>
            <h2 className="text-2xl font-bold text-slate-900">Capacity & Risks</h2>
            <div className="mt-1 text-xs text-slate-600">Pinpointing Bottlenecks, Not Broad Restructuring</div>
          </div>
          <div className="rounded-full bg-amber-600 px-4 py-2 text-sm font-bold text-white">
            90 seconds
          </div>
        </div>

        {/* Main Points */}
        <div className="mb-4 space-y-3">
          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-amber-600 text-sm font-bold text-white">
              1
            </div>
            <div className="flex-1">
              <div className="mb-1 text-xs font-semibold text-amber-700">CONTEXT: BROAD PROGRESS</div>
              <p className="text-sm text-slate-800">
                "Across core functions, automation has strengthened <span className="font-semibold">Risk and Compliance</span>, 
                but <span className="font-semibold text-red-700">Legal and Regulatory capacity is deteriorating</span>."
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-amber-600 text-sm font-bold text-white">
              2
            </div>
            <div className="flex-1">
              <div className="mb-1 text-xs font-semibold text-amber-700">NARROW THE ISSUE</div>
              <p className="text-sm text-slate-800">
                "This isn't a broad organizational issue — <span className="font-semibold">it's a specific bottleneck</span>."
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-red-600 text-sm font-bold text-white">
              3
            </div>
            <div className="flex-1">
              <div className="mb-1 text-xs font-semibold text-red-700">CONNECT TO MILESTONE</div>
              <p className="text-sm text-slate-800">
                "If unaddressed, it <span className="font-semibold text-red-700">jeopardizes Q3 registry operationalization</span>. 
                That directly impacts both delivery and the ROI trajectory we've established."
              </p>
            </div>
          </div>
        </div>

        {/* Visual Cues */}
        <div className="mb-4 rounded-lg bg-slate-100 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">👁️</span>
            <span className="text-xs font-bold uppercase tracking-wide text-slate-600">Visual Cues on Slide</span>
          </div>
          <ul className="space-y-1 text-xs text-slate-700">
            <li className="flex items-start gap-2">
              <span className="text-amber-600">▸</span>
              <span>Gesture to traffic light grid showing 🟡 and 🟢 statuses first</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-red-600">▸</span>
              <span>Point directly to 🔴 Legal & Regulatory line when saying "deteriorating"</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-red-600">▸</span>
              <span>Pause at red milestone risk alert: "Q3 registry operationalization"</span>
            </li>
          </ul>
        </div>

        {/* Delivery Notes */}
        <div className="rounded-lg bg-blue-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">💡</span>
            <span className="text-xs font-bold uppercase tracking-wide text-blue-800">Delivery Notes</span>
          </div>
          <ul className="space-y-1 text-xs text-blue-900">
            <li>• <span className="font-semibold">Tone:</span> Factual but concerned (not alarmist)</li>
            <li>• <span className="font-semibold">Pace:</span> Slow down at "specific bottleneck" and "Q3 jeopardizes"</li>
            <li>• <span className="font-semibold">Body language:</span> Shift from open gestures to focused pointing</li>
            <li>• <span className="font-semibold">Eye contact:</span> Hold gaze when saying "directly impacts ROI trajectory"</li>
          </ul>
        </div>

        {/* Critical Emphasis */}
        <div className="mb-4 rounded-lg border-2 border-red-600 bg-red-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-xl">⚠️</span>
            <span className="text-xs font-bold uppercase tracking-wide text-red-800">Critical Emphasis Point</span>
          </div>
          <p className="text-sm font-semibold text-red-900">
            Use voice modulation on "specific bottleneck" — this differentiates from broad restructuring requests 
            and signals targeted intervention.
          </p>
        </div>

        {/* Transition */}
        <div className="rounded-sm border-t-2 border-amber-200 bg-amber-50 px-4 py-2">
          <div className="text-xs font-semibold text-amber-800">Transition to Slide 3:</div>
          <p className="text-xs italic text-amber-700">
            "So what's the board decision that keeps us on track? It's focused and time-bound..."
          </p>
        </div>
      </section>

      {/* Slide 3 Script */}
      <section className="rounded-xl border-4 border-red-600 bg-white p-8 shadow-2xl">
        <div className="mb-6 flex items-center justify-between border-b-2 border-red-600 pb-4">
          <div>
            <div className="text-sm font-semibold uppercase tracking-wide text-red-700">Slide 3 of 3</div>
            <h2 className="text-2xl font-bold text-slate-900">Decision & Action</h2>
            <div className="mt-1 text-xs text-slate-600">Single Board Ask</div>
          </div>
          <div className="rounded-full bg-red-600 px-4 py-2 text-sm font-bold text-white">
            90 seconds
          </div>
        </div>

        {/* Opening Synthesis */}
        <div className="mb-4 rounded-lg border-l-4 border-red-600 bg-red-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">⚖️</span>
            <span className="text-xs font-bold uppercase tracking-wide text-red-800">Opening Synthesis</span>
          </div>
          <p className="text-base font-semibold italic text-red-900">
            "Momentum is strong, ROI is visible, and our trajectory depends on one decision this quarter."
          </p>
        </div>

        {/* Main Points */}
        <div className="mb-4 space-y-3">
          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-red-600 text-sm font-bold text-white">
              1
            </div>
            <div className="flex-1">
              <div className="mb-1 text-xs font-semibold text-red-700">STATE THE ASK</div>
              <p className="text-sm text-slate-800">
                "The ask is precise: <span className="font-semibold text-red-700">approve targeted resourcing for Legal capacity in Q2</span>."
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-red-600 text-sm font-bold text-white">
              2
            </div>
            <div className="flex-1">
              <div className="mb-1 text-xs font-semibold text-red-700">BINARY OUTCOME</div>
              <p className="text-sm text-slate-800">
                "If approved, <span className="font-semibold text-green-700">Q3 delivery and ROI sustainability are secured</span>. 
                If not, <span className="font-semibold text-red-700">the trajectory stalls</span>."
              </p>
            </div>
          </div>
        </div>

        {/* Visual Cues */}
        <div className="mb-4 rounded-lg bg-slate-100 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">👁️</span>
            <span className="text-xs font-bold uppercase tracking-wide text-slate-600">Visual Cues on Slide</span>
          </div>
          <ul className="space-y-1 text-xs text-slate-700">
            <li className="flex items-start gap-2">
              <span className="text-red-600">▸</span>
              <span>Point to intervention arrow: Legal Bottleneck → Q2 Action → Q3 On Track</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-red-600">▸</span>
              <span>Gesture to "Approve Q2 Resourcing" callout when stating ask</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-red-600">▸</span>
              <span>Use hand gesture showing binary outcome (approved ✓ / not approved ✗)</span>
            </li>
          </ul>
        </div>

        {/* Delivery Notes */}
        <div className="mb-4 rounded-lg bg-blue-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-lg">💡</span>
            <span className="text-xs font-bold uppercase tracking-wide text-blue-800">Delivery Notes</span>
          </div>
          <ul className="space-y-1 text-xs text-blue-900">
            <li>• <span className="font-semibold">Tone:</span> Decisive and clear (not pleading)</li>
            <li>• <span className="font-semibold">Pace:</span> Slow and deliberate on "one decision this quarter"</li>
            <li>• <span className="font-semibold">Body language:</span> Stand still, minimal movement (conveys confidence)</li>
            <li>• <span className="font-semibold">Eye contact:</span> Sweep across all board members during binary outcome</li>
          </ul>
        </div>

        {/* Power Close */}
        <div className="mb-4 rounded-lg border-2 border-red-600 bg-gradient-to-br from-red-50 to-orange-50 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-xl">🎯</span>
            <span className="text-xs font-bold uppercase tracking-wide text-red-800">Power Close Technique</span>
          </div>
          <p className="mb-2 text-sm font-semibold text-red-900">
            After stating the binary outcome, pause for 2-3 seconds.
          </p>
          <p className="text-xs text-red-800">
            This silence creates space for board members to mentally commit to the decision. 
            Don't fill the silence — let the weight of "trajectory stalls" resonate.
          </p>
        </div>

        {/* Closing Statement */}
        <div className="rounded-sm border-t-2 border-red-200 bg-red-50 px-4 py-2">
          <div className="text-xs font-semibold text-red-800">Closing (if time permits):</div>
          <p className="text-xs italic text-red-700">
            "Happy to take questions on the specifics of Legal capacity or Q3 registry dependencies."
          </p>
        </div>
      </section>

      {/* Q&A Preparation */}
      <section className="rounded-lg border-2 border-blue-600 bg-white p-6 shadow-lg">
        <h2 className="mb-4 flex items-center gap-2 text-xl font-bold text-slate-900">
          <span className="text-2xl">❓</span>
          Anticipated Board Questions & Responses
        </h2>
        
        <div className="space-y-4">
          <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
            <div className="mb-2 font-semibold text-blue-900">Q: "How much will Legal resourcing cost?"</div>
            <p className="text-sm text-blue-800">
              <span className="font-semibold">A:</span> "We're requesting [specific FTE count or budget figure] for Q2 through Q4. 
              This is offset by the 67% reduction in risk incidents, which represents [quantified savings] in potential exposure."
            </p>
          </div>

          <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
            <div className="mb-2 font-semibold text-blue-900">Q: "Why can't we wait until Q3 to address this?"</div>
            <p className="text-sm text-blue-800">
              <span className="font-semibold">A:</span> "Q3 is when registry operationalization launches. Legal capacity is already deteriorating, 
              so waiting would mean starting Q3 behind schedule. Q2 approval allows us to onboard and ramp before the critical Q3 milestone."
            </p>
          </div>

          <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
            <div className="mb-2 font-semibold text-blue-900">Q: "Is this a permanent headcount increase or temporary?"</div>
            <p className="text-sm text-blue-800">
              <span className="font-semibold">A:</span> "We're proposing [temporary/contract/permanent] to address the Q2-Q4 bottleneck. 
              We'll reassess in Q4 based on actual capacity needs and governance maturity at that point."
            </p>
          </div>

          <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
            <div className="mb-2 font-semibold text-blue-900">Q: "What if Legal capacity improves on its own?"</div>
            <p className="text-sm text-blue-800">
              <span className="font-semibold">A:</span> "The trend is deteriorating, not improving, and predictive indicators show this will worsen without intervention. 
              Waiting creates risk to the ROI gains we've already secured — that's not a bet we'd recommend."
            </p>
          </div>
        </div>
      </section>

      {/* Rehearsal Checklist */}
      <section className="rounded-lg border-2 border-purple-600 bg-gradient-to-br from-purple-50 to-indigo-50 p-6 shadow-lg">
        <h2 className="mb-4 flex items-center gap-2 text-xl font-bold text-purple-900">
          <span className="text-2xl">✅</span>
          Pre-Presentation Rehearsal Checklist
        </h2>
        
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <h3 className="mb-2 text-sm font-bold text-purple-800">Technical Preparation</h3>
            <ul className="space-y-1 text-xs text-purple-900">
              <li className="flex items-start gap-2">
                <span>☐</span>
                <span>Review all three slides in sequence</span>
              </li>
              <li className="flex items-start gap-2">
                <span>☐</span>
                <span>Practice 90-90-90 second timing with timer</span>
              </li>
              <li className="flex items-start gap-2">
                <span>☐</span>
                <span>Rehearse transitions between slides 3 times</span>
              </li>
              <li className="flex items-start gap-2">
                <span>☐</span>
                <span>Test pointer/clicker with slides</span>
              </li>
              <li className="flex items-start gap-2">
                <span>☐</span>
                <span>Have backup PDF ready (tech failure contingency)</span>
              </li>
            </ul>
          </div>

          <div>
            <h3 className="mb-2 text-sm font-bold text-purple-800">Content Preparation</h3>
            <ul className="space-y-1 text-xs text-purple-900">
              <li className="flex items-start gap-2">
                <span>☐</span>
                <span>Memorize opening hook and power close verbatim</span>
              </li>
              <li className="flex items-start gap-2">
                <span>☐</span>
                <span>Know ROI numbers cold (6→2, 78%→85%)</span>
              </li>
              <li className="flex items-start gap-2">
                <span>☐</span>
                <span>Prepare specific Legal resourcing cost figures</span>
              </li>
              <li className="flex items-start gap-2">
                <span>☐</span>
                <span>Review anticipated questions and responses</span>
              </li>
              <li className="flex items-start gap-2">
                <span>☐</span>
                <span>Have Board Action Brief printed for follow-up</span>
              </li>
            </ul>
          </div>
        </div>

        <div className="mt-4 rounded-lg border border-purple-300 bg-white p-3">
          <p className="text-xs font-semibold text-purple-900">
            💡 <span className="underline">Pro Tip:</span> Record yourself presenting all three slides. Watch playback focusing on 
            filler words ("um," "uh"), pacing, and whether you're reading slides vs. telling the story.
          </p>
        </div>
      </section>

      {/* Navigation Footer */}
      <div className="rounded-lg border bg-slate-50 p-4">
        <div className="mb-2 text-xs font-semibold text-slate-600">Related Resources</div>
        <div className="flex flex-wrap gap-3 text-xs">
          <a href="/docs/exec-overlay/slides" className="font-medium text-blue-600 hover:underline">
            ← Back to Visual Slides
          </a>
          <a href="/docs/exec-overlay/action-brief" className="font-medium text-blue-600 hover:underline">
            → Board Action Brief (Backup)
          </a>
          <a href="/docs/exec-overlay/board-pack" className="font-medium text-blue-600 hover:underline">
            → Board Pack (Detailed Data)
          </a>
          <a href="/governance" className="font-medium text-blue-600 hover:underline">
            → Governance Cockpit
          </a>
        </div>
      </div>
    </main>
  );
}
