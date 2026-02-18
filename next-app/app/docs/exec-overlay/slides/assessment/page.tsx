export const metadata = { title: 'Executive Communication Assessment' } as const;

export default function ExecutiveAssessmentPage() {
  return (
    <main className="mx-auto max-w-5xl space-y-8 p-6">
      {/* Page Header */}
      <div className="rounded-lg border-2 border-amber-600 bg-gradient-to-r from-amber-600 via-orange-600 to-red-600 p-6 shadow-xl">
        <h1 className="mb-2 text-3xl font-bold text-white">
          Executive Communication Assessment
        </h1>
        <div className="text-sm text-amber-100">
          Dry Run Transcript Analysis · Board Presentation Evaluation · Strategic Refinements
        </div>
      </div>

      {/* Executive Commentary Banner */}
      <div className="rounded-lg border-2 border-green-500 bg-gradient-to-br from-green-50 to-emerald-50 p-6 shadow-lg">
        <div className="mb-3 flex items-center gap-2">
          <span className="text-3xl">✅</span>
          <div>
            <div className="text-lg font-bold text-green-900">Executive Verdict</div>
            <div className="text-sm text-green-700">Communication strategy validated for board delivery</div>
          </div>
        </div>
        <p className="text-base font-semibold italic leading-relaxed text-green-900">
          "This dry run transcript is excellent. It has the discipline of cadence and the flexibility of pivot points, 
          which is exactly what you need in a boardroom setting."
        </p>
      </div>

      {/* Transcript Analysis */}
      <section className="rounded-xl border-2 border-indigo-600 bg-white p-8 shadow-2xl">
        <h2 className="mb-6 text-2xl font-bold text-slate-900">
          Dry Run Transcript Analysis
        </h2>

        <div className="space-y-6">
          {/* Opening Sequence Analysis */}
          <div className="rounded-lg border-l-4 border-blue-500 bg-blue-50 p-5">
            <h3 className="mb-3 text-lg font-semibold text-blue-900">Opening Sequence Effectiveness</h3>
            <p className="mb-3 text-sm leading-relaxed text-blue-800">
              The opening sequence establishes governance transformation as <span className="font-semibold">measurable business capability</span> rather 
              than compliance activity. The progression narrative from principles through framework to operations creates immediate comprehension of 
              organizational advancement while the specific metrics regarding risk incident reduction and efficiency improvement translate governance 
              implementation into familiar business performance indicators.
            </p>
            <div className="rounded bg-blue-100 p-3 text-xs text-blue-900">
              <span className="font-semibold">Strategic insight:</span> The emphasis on "business performance numbers, not governance abstractions" 
              directly addresses potential board skepticism about governance value measurement.
            </div>
          </div>

          {/* Capacity Analysis Section */}
          <div className="rounded-lg border-l-4 border-amber-500 bg-amber-50 p-5">
            <h3 className="mb-3 text-lg font-semibold text-amber-900">Capacity Analysis Structure</h3>
            <p className="mb-3 text-sm leading-relaxed text-amber-800">
              The capacity analysis section effectively isolates the resource allocation requirement through focused problem identification. 
              The distinction between improving functions and the specific Legal capacity constraint enables <span className="font-semibold">targeted discussion 
              rather than comprehensive organizational restructuring debates</span>. The "non-substitutable bottleneck" framing provides clear rationale 
              for concentrated investment while acknowledging that automation solutions have addressed capacity constraints in other functional areas.
            </p>
            <div className="rounded bg-amber-100 p-3 text-xs text-amber-900">
              <span className="font-semibold">Strategic insight:</span> The contrast between systemic organizational weakness and pinpointed constraint 
              prevents broad organizational capability questioning that could derail resource allocation approval.
            </div>
          </div>

          {/* Decision Segment Analysis */}
          <div className="rounded-lg border-l-4 border-red-500 bg-red-50 p-5">
            <h3 className="mb-3 text-lg font-semibold text-red-900">Decision Segment Impact</h3>
            <p className="mb-3 text-sm leading-relaxed text-red-800">
              The decision segment creates compelling urgency through conditional framing that directly connects board action to implementation outcomes. 
              The "one decision, one quarter, one lever" formulation simplifies executive evaluation while emphasizing the concentrated nature of resource 
              requirements. The <span className="font-semibold">repetition of anchor phrases</span> from the opening provides narrative continuity that 
              reinforces core messaging about governance momentum and measurable value creation.
            </p>
            <div className="rounded bg-red-100 p-3 text-xs text-red-900">
              <span className="font-semibold">Strategic insight:</span> The bookend framing (opening and closing with identical anchor phrases) 
              creates psychological closure that directors will echo back in discussion.
            </div>
          </div>

          {/* Pause Structure Analysis */}
          <div className="rounded-lg border-l-4 border-purple-500 bg-purple-50 p-5">
            <h3 className="mb-3 text-lg font-semibold text-purple-900">Pause Structure Effectiveness</h3>
            <p className="mb-3 text-sm leading-relaxed text-purple-800">
              The pause structure accommodates board member note-taking while enabling presenter control over information flow and emphasis points. 
              The differentiation between short and long pauses provides natural transition markers that support board comprehension without extending 
              presentation beyond time constraints. The rhythm enables directors to <span className="font-semibold">process quantitative information and 
              strategic implications</span> without requiring extended technical discussion.
            </p>
            <div className="rounded bg-purple-100 p-3 text-xs text-purple-900">
              <span className="font-semibold">Technical note:</span> Strategic silence is as important as spoken content in executive communication.
            </div>
          </div>

          {/* Pivot Point Strategy */}
          <div className="rounded-lg border-l-4 border-green-500 bg-green-50 p-5">
            <h3 className="mb-3 text-lg font-semibold text-green-900">Pivot Point Strategy</h3>
            <p className="mb-3 text-sm leading-relaxed text-green-800">
              The pivot point identification within the transcript demonstrates understanding of board dynamics and potential resistance patterns. 
              The embedded emphasis opportunities regarding business performance measurement and constraint specificity provide 
              <span className="font-semibold"> strategic responses to common concerns</span> without disrupting presentation flow or requiring 
              extensive preparation for every possible inquiry.
            </p>
            <div className="rounded bg-green-100 p-3 text-xs text-green-900">
              <span className="font-semibold">Adaptability principle:</span> Deploy emphasis levers based on room energy, not preemptively.
            </div>
          </div>
        </div>

        {/* Overall Assessment */}
        <div className="mt-6 rounded-lg border-2 border-indigo-500 bg-indigo-50 p-5">
          <h3 className="mb-3 text-lg font-semibold text-indigo-900">Overall Assessment</h3>
          <p className="text-sm leading-relaxed text-indigo-800">
            This delivery approach successfully transforms comprehensive governance framework development into focused executive communication that 
            enables <span className="font-semibold">rapid board evaluation and resource allocation approval</span> within established meeting time 
            constraints while maintaining analytical rigor necessary for informed decision-making.
          </p>
        </div>
      </section>

      {/* Strengths Identified */}
      <section className="rounded-xl border-2 border-green-600 bg-white p-8 shadow-2xl">
        <h2 className="mb-6 flex items-center gap-2 text-2xl font-bold text-slate-900">
          <span className="text-3xl">⭐</span>
          What Makes This Especially Strong
        </h2>

        <div className="space-y-4">
          <div className="rounded-lg border border-green-200 bg-green-50 p-5">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xl">⚓</span>
              <span className="text-base font-bold text-green-900">Anchor Phrases</span>
            </div>
            <p className="mb-2 text-sm text-green-800">
              Repeating <span className="font-semibold">"Momentum is strong. ROI is visible."</span> at the open and close creates a memorable bookend. 
              Directors will likely <span className="font-semibold">echo that line back in discussion</span>.
            </p>
            <div className="rounded bg-white p-3 text-xs italic text-green-700">
              Psychological closure: When directors repeat your exact phrasing in deliberation, you've achieved message penetration.
            </div>
          </div>

          <div className="rounded-lg border border-blue-200 bg-blue-50 p-5">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xl">🎵</span>
              <span className="text-base font-bold text-blue-900">Cadence Control</span>
            </div>
            <p className="mb-2 text-sm text-blue-800">
              The short declarative sentences, broken by pauses, give <span className="font-semibold">weight to each point</span>. 
              It feels authoritative without being rushed.
            </p>
            <div className="rounded bg-white p-3 text-xs italic text-blue-700">
              Tempo management: Silence between ideas signals importance and allows directors to absorb quantitative data.
            </div>
          </div>

          <div className="rounded-lg border border-purple-200 bg-purple-50 p-5">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xl">🔄</span>
              <span className="text-base font-bold text-purple-900">Pivot Points</span>
            </div>
            <p className="mb-2 text-sm text-purple-800">
              Lines like <span className="font-semibold">"These are business performance numbers, not governance abstractions"</span> and 
              <span className="font-semibold"> "This isn't systemic weakness — it's a pinpointed constraint"</span> are 
              <span className="font-semibold"> optional emphasis levers</span> you can deploy depending on the room's energy.
            </p>
            <div className="rounded bg-white p-3 text-xs italic text-purple-700">
              Adaptive messaging: Don't use all pivot points preemptively—deploy only when board signals skepticism or confusion.
            </div>
          </div>

          <div className="rounded-lg border border-red-200 bg-red-50 p-5">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xl">⚖️</span>
              <span className="text-base font-bold text-red-900">Binary Framing</span>
            </div>
            <p className="mb-2 text-sm text-red-800">
              The If/Then structure on Slide 3 is <span className="font-semibold">crisp and forces clarity</span>: 
              approve resourcing → trajectory sustained; don't approve → ROI stalls. 
              <span className="font-semibold">Boards respond well to that kind of decision logic</span>.
            </p>
            <div className="rounded bg-white p-3 text-xs italic text-red-700">
              Decision forcing: Binary outcomes eliminate ambiguity and accelerate board decision-making.
            </div>
          </div>

          <div className="rounded-lg border border-amber-200 bg-amber-50 p-5">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xl">⏱️</span>
              <span className="text-base font-bold text-amber-900">Time Discipline</span>
            </div>
            <p className="mb-2 text-sm text-amber-800">
              90 seconds is <span className="font-semibold">just enough to land the message</span> without inviting drift into technical detail.
            </p>
            <div className="rounded bg-white p-3 text-xs italic text-amber-700">
              Constraint breeds clarity: Tight time limits force presenter to distill to essential strategic points.
            </div>
          </div>
        </div>
      </section>

      {/* Refinements for Live Delivery */}
      <section className="rounded-xl border-2 border-orange-600 bg-white p-8 shadow-2xl">
        <h2 className="mb-6 flex items-center gap-2 text-2xl font-bold text-slate-900">
          <span className="text-3xl">🎯</span>
          Refinements for Live Delivery
        </h2>

        <div className="space-y-4">
          <div className="rounded-lg border-l-4 border-blue-500 bg-blue-50 p-5">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xl">⏸️</span>
              <span className="text-base font-bold text-blue-900">Vary Pause Lengths</span>
            </div>
            <p className="mb-3 text-sm text-blue-800">
              Mark <span className="font-semibold">[short pause]</span> vs. <span className="font-semibold">[long pause]</span> more explicitly 
              so you can control rhythm and avoid sounding mechanical.
            </p>
            <div className="rounded bg-white p-4">
              <div className="mb-2 text-xs font-semibold text-blue-900">Practice technique:</div>
              <ul className="space-y-1 text-xs text-blue-800">
                <li>• <span className="font-semibold">[pause]</span> = Count "one thousand" in your head (~1 second)</li>
                <li>• <span className="font-semibold">[short pause]</span> = Count "one thousand, two thousand" (~1.5 seconds)</li>
                <li>• <span className="font-semibold">[long pause]</span> = Count "one thousand, two thousand, three thousand" (~2-3 seconds)</li>
              </ul>
            </div>
          </div>

          <div className="rounded-lg border-l-4 border-purple-500 bg-purple-50 p-5">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xl">👉</span>
              <span className="text-base font-bold text-purple-900">Gesture Anchors</span>
            </div>
            <p className="mb-3 text-sm text-purple-800">
              When you say <span className="font-semibold">"One decision. One quarter. One lever."</span> count them off on your fingers. 
              It <span className="font-semibold">reinforces memorability</span>.
            </p>
            <div className="rounded bg-white p-4">
              <div className="mb-2 text-xs font-semibold text-purple-900">Execution:</div>
              <div className="text-xs text-purple-800">
                Hold up index finger for "One decision," add middle finger for "One quarter," add ring finger for "One lever." 
                <span className="font-semibold"> Visual reinforcement</span> makes abstract concepts concrete.
              </div>
            </div>
          </div>

          <div className="rounded-lg border-l-4 border-red-500 bg-red-50 p-5">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-xl">🔚</span>
              <span className="text-base font-bold text-red-900">Closing Cadence</span>
            </div>
            <p className="mb-3 text-sm text-red-800">
              After <span className="font-semibold">"That's the lever in front of you today"</span>, 
              <span className="font-semibold"> let silence hang for a beat</span>. It gives the board space to feel the weight of the ask 
              before discussion begins.
            </p>
            <div className="rounded bg-white p-4">
              <div className="mb-2 text-xs font-semibold text-red-900">Power close technique:</div>
              <div className="text-xs text-red-800">
                After final statement, maintain eye contact, hold position for 2-3 seconds. 
                <span className="font-semibold"> Don't rush to Q&A</span> — let the decision weight settle. 
                Then say "I'm ready for questions" to transition.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Board Psychology Insights */}
      <section className="rounded-xl border-2 border-teal-600 bg-gradient-to-br from-teal-50 to-cyan-50 p-8 shadow-xl">
        <h2 className="mb-6 flex items-center gap-2 text-2xl font-bold text-teal-900">
          <span className="text-3xl">🧠</span>
          Board Psychology Insights
        </h2>

        <div className="space-y-4">
          <div className="rounded-lg border border-teal-200 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-teal-900">Why Directors Echo Your Phrasing</div>
            <p className="text-xs text-teal-800">
              When you repeat <span className="font-semibold">"Momentum is strong. ROI is visible."</span> at opening and closing, 
              you create a <span className="font-semibold">cognitive anchor</span>. Directors who agree with your proposal will unconsciously 
              adopt your exact language in their support statements. Listen for this during board deliberation — it signals message penetration.
            </p>
          </div>

          <div className="rounded-lg border border-cyan-200 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-cyan-900">Binary Framing Accelerates Decisions</div>
            <p className="text-xs text-cyan-800">
              Boards operate more efficiently with <span className="font-semibold">clear yes/no choices</span>. 
              "If approved → trajectory sustained. If not → ROI stalls." removes middle-ground ambiguity that can lead to 
              "let's table this for more study" deferrals. <span className="font-semibold">Decision forcing</span> is a strategic tool.
            </p>
          </div>

          <div className="rounded-lg border border-blue-200 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-blue-900">Silence Creates Decision Space</div>
            <p className="text-xs text-blue-800">
              Most presenters fear silence and rush to fill it. <span className="font-semibold">Professional communicators use silence strategically</span>. 
              After your closing line, 2-3 seconds of silence lets directors mentally commit to supporting your ask before discussion begins. 
              It's a <span className="font-semibold">subtle pressure technique</span> that increases approval likelihood.
            </p>
          </div>

          <div className="rounded-lg border border-purple-200 bg-white p-4">
            <div className="mb-2 text-sm font-bold text-purple-900">Quantitative Anchors Build Credibility</div>
            <p className="text-xs text-purple-800">
              "6 → 2 incidents" and "78% → 85% efficiency" are <span className="font-semibold">concrete, verifiable claims</span>. 
              Even if directors don't remember the exact numbers, they remember "there were numbers" which signals rigor. 
              <span className="font-semibold">Quantification = credibility</span> in board environments.
            </p>
          </div>
        </div>
      </section>

      {/* Next Steps */}
      <section className="rounded-lg border-2 border-indigo-600 bg-white p-6 shadow-lg">
        <h2 className="mb-4 flex items-center gap-2 text-xl font-bold text-slate-900">
          <span className="text-2xl">🚀</span>
          Recommended Next Steps
        </h2>
        <div className="space-y-3">
          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-indigo-600 text-sm font-bold text-white">
              1
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Practice with Timer</div>
              <div className="text-xs text-slate-600">
                Deliver the dry run script 3 times with a stopwatch. Target 85-95 seconds. Adjust pause lengths to hit timing naturally.
              </div>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-indigo-600 text-sm font-bold text-white">
              2
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Record and Critique</div>
              <div className="text-xs text-slate-600">
                Video yourself delivering to slides. Watch for: eye contact vs. slide reading, filler words, rushed sections, and whether 
                gesture anchors feel natural.
              </div>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-indigo-600 text-sm font-bold text-white">
              3
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Role-Play Board Scenarios</div>
              <div className="text-xs text-slate-600">
                Have a colleague play skeptical director. Practice deploying pivot points ("business performance numbers, not abstractions") 
                only when challenged. Don't overuse them.
              </div>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-amber-600 text-sm font-bold text-white">
              4
            </div>
            <div className="flex-1">
              <div className="mb-1 text-sm font-semibold text-slate-800">Prepare Board Materials</div>
              <div className="text-xs text-slate-600">
                Print Board Action Brief as backup. Have emergency 60-second version ready in case time is cut. 
                Confirm specific Legal resourcing numbers (FTE count, budget) for Q&A.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Navigation Footer */}
      <div className="rounded-lg border bg-slate-50 p-4">
        <div className="mb-2 text-xs font-semibold text-slate-600">Related Resources</div>
        <div className="flex flex-wrap gap-3 text-xs">
          <a href="/docs/exec-overlay/slides/script-hybrid" className="font-medium text-blue-600 hover:underline">
            ← Hybrid Script
          </a>
          <a href="/docs/exec-overlay/slides/script-dry-run" className="font-medium text-blue-600 hover:underline">
            → 90-Second Dry Run
          </a>
          <a href="/docs/exec-overlay/slides" className="font-medium text-blue-600 hover:underline">
            → Visual Slides
          </a>
          <a href="/docs/exec-overlay/action-brief" className="font-medium text-blue-600 hover:underline">
            → Board Action Brief
          </a>
        </div>
      </div>
    </main>
  );
}
