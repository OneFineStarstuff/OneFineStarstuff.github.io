export const metadata = { title: '90-Second Dry Run Script - Board Presentation' } as const;

export default function DryRunScriptPage() {
  return (
    <main className="mx-auto max-w-5xl space-y-8 p-6">
      {/* Page Header */}
      <div className="rounded-lg border-2 border-indigo-600 bg-gradient-to-r from-indigo-600 via-purple-700 to-pink-700 p-6 shadow-xl">
        <h1 className="mb-2 text-3xl font-bold text-white">
          90-Second Dry Run Transcript
        </h1>
        <div className="text-sm text-indigo-100">
          Natural cadence · Strategic pauses · Rhythm markers · Adaptability built-in
        </div>
      </div>

      {/* Key Features Banner */}
      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border-2 border-blue-300 bg-blue-50 p-4 text-center">
          <div className="mb-2 text-2xl">⏱️</div>
          <div className="text-xs font-bold text-blue-900">Exact 90-Second Delivery</div>
          <div className="mt-1 text-xs text-blue-700">Tested timing with natural pauses</div>
        </div>
        <div className="rounded-lg border-2 border-purple-300 bg-purple-50 p-4 text-center">
          <div className="mb-2 text-2xl">🎯</div>
          <div className="text-xs font-bold text-purple-900">Anchor Phrases Repeated</div>
          <div className="mt-1 text-xs text-purple-700">Front-loaded for stickiness</div>
        </div>
        <div className="rounded-lg border-2 border-green-300 bg-green-50 p-4 text-center">
          <div className="mb-2 text-2xl">🔄</div>
          <div className="text-xs font-bold text-green-900">Pivot Points Built-In</div>
          <div className="mt-1 text-xs text-green-700">Adapt to room energy on the fly</div>
        </div>
      </div>

      {/* Complete 90-Second Transcript */}
      <section className="rounded-xl border-4 border-indigo-600 bg-white p-8 shadow-2xl">
        <div className="mb-6 border-b-2 border-indigo-600 pb-4">
          <h2 className="text-2xl font-bold text-slate-900">Complete 90-Second Transcript</h2>
          <div className="mt-1 text-sm text-slate-600">
            All three slides · Natural delivery · Pause markers included
          </div>
        </div>

        {/* Slide 1 Transcript */}
        <div className="mb-8 rounded-lg border-2 border-green-500 bg-green-50 p-6">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="rounded-full bg-green-600 px-3 py-1 text-xs font-bold text-white">
                Slide 1
              </div>
              <span className="text-sm font-bold text-green-900">Trajectory & Value</span>
            </div>
            <span className="text-xs text-green-700">~30 seconds</span>
          </div>

          <div className="space-y-3 font-mono text-sm leading-relaxed text-slate-800">
            <p>
              <span className="font-bold text-green-700">"Momentum is strong. ROI is visible.</span>{' '}
              <span className="italic text-slate-500">[pause]</span>
            </p>
            <p>
              In the past year, we've moved from principles … to framework … to operations.{' '}
              <span className="italic text-slate-500">[short pause]</span>
            </p>
            <p>
              The results are clear: risk incidents reduced from six … to two annually.
              Efficiency improved from seventy‑eight percent … to eighty‑five percent.{' '}
              <span className="italic text-slate-500">[long pause]</span>
            </p>
            <p>
              <span className="rounded bg-yellow-200 px-1 font-semibold">These are business performance numbers, not governance abstractions.</span>{' '}
              <span className="italic text-slate-500">[pause]</span>
            </p>
          </div>
        </div>

        {/* Slide 2 Transcript */}
        <div className="mb-8 rounded-lg border-2 border-amber-500 bg-amber-50 p-6">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="rounded-full bg-amber-600 px-3 py-1 text-xs font-bold text-white">
                Slide 2
              </div>
              <span className="text-sm font-bold text-amber-900">Capacity & Risks</span>
            </div>
            <span className="text-xs text-amber-700">~30 seconds</span>
          </div>

          <div className="space-y-3 font-mono text-sm leading-relaxed text-slate-800">
            <p>
              Most functions are improving. One bottleneck is emerging.{' '}
              <span className="italic text-slate-500">[pause]</span>
            </p>
            <p>
              Risk and Compliance capacity is stabilizing through automation.{' '}
              <span className="italic text-slate-500">[short pause]</span>
            </p>
            <p>
              <span className="font-bold text-red-700">But Legal is a non‑substitutable bottleneck.</span>{' '}
              <span className="italic text-slate-500">[pause]</span>
            </p>
            <p>
              If left unaddressed, it directly jeopardizes Q3 registry operationalization.{' '}
              <span className="italic text-slate-500">[long pause]</span>
            </p>
            <p>
              <span className="rounded bg-yellow-200 px-1 font-semibold">This isn't systemic weakness — it's a pinpointed constraint.</span>{' '}
              <span className="italic text-slate-500">[pause]</span>
            </p>
          </div>
        </div>

        {/* Slide 3 Transcript */}
        <div className="rounded-lg border-2 border-red-500 bg-red-50 p-6">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="rounded-full bg-red-600 px-3 py-1 text-xs font-bold text-white">
                Slide 3
              </div>
              <span className="text-sm font-bold text-red-900">Decision & Action</span>
            </div>
            <span className="text-xs text-red-700">~30 seconds</span>
          </div>

          <div className="space-y-3 font-mono text-sm leading-relaxed text-slate-800">
            <p>
              <span className="font-bold text-red-700">One decision. One quarter. One lever.</span>{' '}
              <span className="italic text-slate-500">[pause]</span>
            </p>
            <p>
              If resourcing is approved … Q3 delivery is secured.{' '}
              <span className="italic text-slate-500">[short pause]</span>
            </p>
            <p>
              <span className="font-bold text-red-700">If not … ROI trajectory stalls.</span>{' '}
              <span className="italic text-slate-500">[long pause]</span>
            </p>
            <p>
              <span className="font-bold text-indigo-700">Momentum is strong. ROI is visible.</span>{' '}
              <span className="italic text-slate-500">[pause]</span>
            </p>
            <p>
              That's the lever in front of you today.{' '}
              <span className="italic text-slate-500">[close]</span>
            </p>
          </div>
        </div>
      </section>

      {/* Pause Legend */}
      <section className="rounded-lg border-2 border-slate-300 bg-slate-50 p-6">
        <h2 className="mb-4 text-lg font-bold text-slate-900">Pause Duration Guide</h2>
        <div className="grid gap-3 md:grid-cols-3">
          <div className="rounded-lg border border-slate-200 bg-white p-3">
            <div className="mb-1 text-xs font-bold text-slate-700">[pause]</div>
            <div className="text-xs text-slate-600">~1 second - Natural breath</div>
          </div>
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-3">
            <div className="mb-1 text-xs font-bold text-amber-800">[short pause]</div>
            <div className="text-xs text-amber-700">~1.5 seconds - Allow absorption</div>
          </div>
          <div className="rounded-lg border border-red-200 bg-red-50 p-3">
            <div className="mb-1 text-xs font-bold text-red-800">[long pause]</div>
            <div className="text-xs text-red-700">~2-3 seconds - Note-taking time</div>
          </div>
        </div>
      </section>

      {/* Anchor Phrases (Repeated for Stickiness) */}
      <section className="rounded-lg border-2 border-purple-600 bg-gradient-to-br from-purple-50 to-indigo-50 p-6">
        <h2 className="mb-4 flex items-center gap-2 text-lg font-bold text-purple-900">
          <span className="text-2xl">⚓</span>
          Anchor Phrases (Repeated for Stickiness)
        </h2>
        <div className="space-y-3">
          <div className="rounded-lg border border-purple-200 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-purple-900">
              "Momentum is strong. ROI is visible."
            </div>
            <div className="text-xs text-purple-700">
              <span className="font-semibold">Used:</span> Opening (Slide 1) + Closing (Slide 3)
              <br />
              <span className="font-semibold">Purpose:</span> Bookend framing - establishes credibility, then reinforces urgency
            </div>
          </div>

          <div className="rounded-lg border border-purple-200 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-purple-900">
              "One [decision/bottleneck/quarter/lever]"
            </div>
            <div className="text-xs text-purple-700">
              <span className="font-semibold">Used:</span> Slide 2 ("One bottleneck") + Slide 3 ("One decision. One quarter. One lever.")
              <br />
              <span className="font-semibold">Purpose:</span> Emphasizes focused, targeted intervention (not broad restructuring)
            </div>
          </div>

          <div className="rounded-lg border border-purple-200 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-purple-900">
              "Q3 registry operationalization"
            </div>
            <div className="text-xs text-purple-700">
              <span className="font-semibold">Used:</span> Slide 2 (risk connection) + Slide 3 (secured outcome)
              <br />
              <span className="font-semibold">Purpose:</span> Concrete milestone everyone can visualize
            </div>
          </div>
        </div>
      </section>

      {/* Pivot Points for Room Energy Adaptation */}
      <section className="rounded-lg border-2 border-green-600 bg-white p-6 shadow-lg">
        <h2 className="mb-4 flex items-center gap-2 text-lg font-bold text-slate-900">
          <span className="text-2xl">🔄</span>
          Pivot Points for Room Energy Adaptation
        </h2>
        <div className="space-y-4">
          <div className="rounded-lg border-l-4 border-blue-500 bg-blue-50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <span className="font-bold text-blue-900">
                "These are business performance numbers, not governance abstractions."
              </span>
              <span className="rounded-full bg-blue-600 px-2 py-1 text-xs font-bold text-white">
                Slide 1
              </span>
            </div>
            <div className="space-y-2 text-xs text-blue-800">
              <div>
                <span className="font-semibold">If room is skeptical:</span> EMPHASIZE this line with slower pace and eye contact
              </div>
              <div>
                <span className="font-semibold">If room is engaged:</span> Keep natural pace, move forward confidently
              </div>
              <div className="mt-2 rounded bg-white p-2 text-blue-900">
                💡 <span className="font-semibold">Why it works:</span> Preempts "this is just governance theater" objection
              </div>
            </div>
          </div>

          <div className="rounded-lg border-l-4 border-amber-500 bg-amber-50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <span className="font-bold text-amber-900">
                "This isn't systemic weakness — it's a pinpointed constraint."
              </span>
              <span className="rounded-full bg-amber-600 px-2 py-1 text-xs font-bold text-white">
                Slide 2
              </span>
            </div>
            <div className="space-y-2 text-xs text-amber-800">
              <div>
                <span className="font-semibold">If room fears broad restructuring:</span> EMPHASIZE "pinpointed" with hand gesture (single point)
              </div>
              <div>
                <span className="font-semibold">If room is receptive:</span> Keep as reassurance statement, don't belabor
              </div>
              <div className="mt-2 rounded bg-white p-2 text-amber-900">
                💡 <span className="font-semibold">Why it works:</span> Differentiates targeted resourcing from org-wide change
              </div>
            </div>
          </div>

          <div className="rounded-lg border-l-4 border-red-500 bg-red-50 p-4">
            <div className="mb-2 flex items-center justify-between">
              <span className="font-bold text-red-900">
                "If not … ROI trajectory stalls."
              </span>
              <span className="rounded-full bg-red-600 px-2 py-1 text-xs font-bold text-white">
                Slide 3
              </span>
            </div>
            <div className="space-y-2 text-xs text-red-800">
              <div>
                <span className="font-semibold">If room needs urgency:</span> Add 2-3 second silence after "stalls" - let consequence sink in
              </div>
              <div>
                <span className="font-semibold">If room is already convinced:</span> Keep pause shorter (1 second), move to close
              </div>
              <div className="mt-2 rounded bg-white p-2 text-red-900">
                💡 <span className="font-semibold">Why it works:</span> Binary outcome creates decision pressure without sounding desperate
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Rhythm Analysis */}
      <section className="rounded-lg border-2 border-indigo-600 bg-gradient-to-br from-indigo-50 to-purple-50 p-6">
        <h2 className="mb-4 flex items-center gap-2 text-lg font-bold text-indigo-900">
          <span className="text-2xl">🎵</span>
          Rhythm & Cadence Analysis
        </h2>
        <div className="space-y-4">
          <div className="rounded-lg border border-indigo-200 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-indigo-900">Triple Structure Pattern</div>
            <div className="text-xs text-indigo-800">
              <span className="font-semibold">Slide 1:</span> "Momentum is strong. ROI is visible. [pause]" — Establishes credibility with staccato declaration
              <br />
              <span className="font-semibold">Slide 2:</span> "Most functions improving. One bottleneck emerging." — Creates contrast (many vs. one)
              <br />
              <span className="font-semibold">Slide 3:</span> "One decision. One quarter. One lever." — Triple "one" hammers focus
            </div>
          </div>

          <div className="rounded-lg border border-indigo-200 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-indigo-900">Ellipsis Pacing (…)</div>
            <div className="text-xs text-indigo-800">
              Used to slow delivery naturally without sounding robotic:
              <br />
              • "principles … to framework … to operations" — Allows directors to visualize stages
              <br />
              • "from six … to two annually" — Creates anticipation before the win
              <br />
              • "If approved … Q3 secured. If not … trajectory stalls." — Binary outcome with built-in pause
            </div>
          </div>

          <div className="rounded-lg border border-indigo-200 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-indigo-900">Front-Loaded Power Words</div>
            <div className="text-xs text-indigo-800">
              Opening sentences use strong verbs and outcomes first:
              <br />
              • <span className="font-semibold">"Momentum is strong"</span> (not "We have strong momentum")
              <br />
              • <span className="font-semibold">"ROI is visible"</span> (not "We can see the ROI")
              <br />
              • <span className="font-semibold">"One bottleneck is emerging"</span> (not "There's a bottleneck")
            </div>
          </div>
        </div>
      </section>

      {/* Practice Workflow */}
      <section className="rounded-lg border-2 border-green-600 bg-white p-6 shadow-lg">
        <h2 className="mb-4 flex items-center gap-2 text-lg font-bold text-slate-900">
          <span className="text-2xl">🎯</span>
          Practice Workflow for 90-Second Delivery
        </h2>
        <div className="space-y-3">
          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-green-600 text-sm font-bold text-white">
              1
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Read Aloud 3 Times (No Timing)</div>
              <div className="text-xs text-slate-600">
                Focus on natural flow, honor the ellipsis pauses, don't rush. Get comfortable with rhythm.
              </div>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-green-600 text-sm font-bold text-white">
              2
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Record with Timer (Target: 85-95 seconds)</div>
              <div className="text-xs text-slate-600">
                Use phone voice recorder. Aim for 90 seconds ±5. Listen for filler words ("um," "uh," "so").
              </div>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-green-600 text-sm font-bold text-white">
              3
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Practice Pivot Points</div>
              <div className="text-xs text-slate-600">
                Deliberately emphasize/downplay the highlighted pivot phrases. Practice both versions.
              </div>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-green-600 text-sm font-bold text-white">
              4
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Deliver Standing with Slides</div>
              <div className="text-xs text-slate-600">
                Full rehearsal standing up, advancing slides. Check if you're looking at slides vs. telling the story.
              </div>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-amber-600 text-sm font-bold text-white">
              5
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Final Check: Anchor Phrases</div>
              <div className="text-xs text-slate-600">
                Can you recall the three anchor phrases without looking? "Momentum/ROI," "One," "Q3 registry."
              </div>
            </div>
          </div>
        </div>

        <div className="mt-4 rounded-lg bg-green-50 p-3">
          <div className="text-xs text-green-900">
            <span className="font-semibold">✓ Ready to present when:</span> You can deliver in 85-95 seconds without script,
            hit all anchor phrases naturally, and adapt pivot points based on imagined room energy.
          </div>
        </div>
      </section>

      {/* Emergency Shortcuts */}
      <section className="rounded-lg border-2 border-red-600 bg-red-50 p-6">
        <h2 className="mb-4 flex items-center gap-2 text-lg font-bold text-red-900">
          <span className="text-2xl">⚡</span>
          Emergency Shortcuts (If Time is Cut Short)
        </h2>
        <div className="space-y-3">
          <div className="rounded-lg border border-red-300 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-red-900">60-Second Version (Ultra Compressed)</div>
            <div className="space-y-2 text-xs text-red-800">
              <p><span className="font-semibold">Slide 1:</span> "Momentum strong, ROI visible. Six to two incidents, 78% to 85% efficiency."</p>
              <p><span className="font-semibold">Slide 2:</span> "Legal is a non-substitutable bottleneck jeopardizing Q3 registry."</p>
              <p><span className="font-semibold">Slide 3:</span> "One decision: Q2 resourcing. If approved, Q3 secured. If not, stalls."</p>
            </div>
          </div>

          <div className="rounded-lg border border-amber-300 bg-amber-50 p-4">
            <div className="mb-2 text-sm font-bold text-amber-900">30-Second Version (Absolute Minimum)</div>
            <div className="text-xs text-amber-800">
              "Governance ROI is visible: six to two risk incidents annually. Legal bottleneck jeopardizes Q3 registry.
              Board decision required: approve Q2 resourcing to secure delivery."
            </div>
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
          <a href="/docs/exec-overlay/slides/script" className="font-medium text-blue-600 hover:underline">
            → Detailed Script (Full Version)
          </a>
          <a href="/docs/exec-overlay/action-brief" className="font-medium text-blue-600 hover:underline">
            → Board Action Brief
          </a>
          <a href="/governance" className="font-medium text-blue-600 hover:underline">
            → Governance Cockpit
          </a>
        </div>
      </div>
    </main>
  );
}
