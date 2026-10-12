import { useState } from 'react';
import {
  BookOpen,
  Check,
  ChevronDown,
  Clock,
  ExternalLink,
  FileText,
  Globe,
  Layers,
  Search,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import CodeBlock from '../components/CodeBlock';
import DetailDrawer from '../components/DetailDrawer';
import ExpandableSection from '../components/ExpandableSection';
import MetricCard from '../components/MetricCard';
import PageHeader from '../components/PageHeader';
import ProgressBar from '../components/ProgressBar';
import StatusBadge from '../components/StatusBadge';
import {
  EPOCH_TIMELINE_MILESTONES,
  TLA_MODULES,
  TREATY_FRAMEWORKS_DETAILED,
  getInvariantDetails,
} from '../data/constitutionalData';
import { CONSTITUTIONAL_INVARIANTS, GOVERNANCE_PHASES, INFINITY_PILLARS } from '../data/gienData';
import { truncateHash } from '../data/helpers';
import type { ConstitutionalInvariant } from '../types';

export default function Constitutional() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedInvariant, setSelectedInvariant] = useState<ConstitutionalInvariant | null>(null);
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

  const toggleRow = (id: string) => {
    setExpandedRows((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const filteredInvariants = CONSTITUTIONAL_INVARIANTS.filter((ci) => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return true;
    return (
      ci.id.toLowerCase().includes(q) ||
      ci.name.toLowerCase().includes(q) ||
      ci.statement.toLowerCase().includes(q) ||
      ci.tlaSpecRef.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-8 pb-12">
      <PageHeader
        title="Constitutional Invariants & Treaty Framework"
        subtitle="Formal verification of non-negotiable governance invariants (CI-001..CI-024) and supranational treaty architecture."
        crumbs={[{ label: 'GIEN Mesh', to: '/' }, { label: 'Constitutional Invariants' }]}
        actions={
          <div className="flex items-center gap-2">
            <StatusBadge variant="PROVED" label="24 / 24 INVARIANTS PROVED" />
            <StatusBadge variant="VERIFIED" label="APALACHE / TLC VALIDATED" />
          </div>
        }
      />

      {/* Overview Metric Summary */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Active Invariants"
          value="24 / 24"
          status="PROVED"
          footer={<span className="font-mono text-[11px] text-gray-400">100% Formal Verification</span>}
        />
        <MetricCard
          label="Verification Engine"
          value="Apalache v1.35"
          status="VERIFIED"
          footer={<span className="font-mono text-[11px] text-gray-400">TLC 2.08 Model Checker</span>}
        />
        <MetricCard
          label="Treaty Jurisdictions"
          value="41 States"
          status="COMPLIANT"
          footer={<span className="font-mono text-[11px] text-gray-400">CFE-1.0 Signatories</span>}
        />
        <MetricCard
          label="Current Epoch Phase"
          value="Phase VI-δ"
          status="NOMINAL"
          footer={<span className="font-mono text-[11px] text-gray-400">2026-2028 Consolidation</span>}
        />
      </div>

      {/* SECTION 1 — CONSTITUTIONAL INVARIANTS PANEL */}
      <section className="rounded-xl border border-gray-700 bg-gray-800/40 p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-700/80 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-gray-100 flex items-center gap-2">
              <ShieldCheck size={18} className="text-cyan-400" />
              Section 1 — Constitutional Invariants Catalog (CI-001 .. CI-024)
            </h2>
            <p className="text-xs text-gray-400 mt-0.5">
              Formally proved TLA+ assertions holding across all epoch phase transitions.
            </p>
          </div>

          {/* Search Filter */}
          <div className="relative min-w-[240px]">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by CI ID, name, statement..."
              className="w-full rounded-lg border border-gray-700 bg-gray-900 pl-8 pr-3 py-1.5 text-xs text-gray-100 placeholder-gray-500 focus:border-indigo-500 focus:outline-none"
            />
          </div>
        </div>

        {/* Invariants List */}
        <div className="space-y-2.5">
          {filteredInvariants.length === 0 ? (
            <p className="p-4 text-center text-xs text-gray-400">
              No constitutional invariants found matching &quot;{searchQuery}&quot;.
            </p>
          ) : (
            filteredInvariants.map((ci) => {
              const isExpanded = !!expandedRows[ci.id];
              return (
                <div
                  key={ci.id}
                  className="rounded-lg border border-gray-700/80 bg-gray-900/60 overflow-hidden transition-colors hover:border-gray-600"
                >
                  <div className="p-3.5 flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-3 flex-1 min-w-[280px]">
                      <button
                        type="button"
                        onClick={() => toggleRow(ci.id)}
                        className="p-1 rounded text-gray-400 hover:text-gray-200 hover:bg-gray-800"
                        aria-label="Toggle invariant row details"
                      >
                        <ChevronDown size={16} className={`transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                      </button>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-cyan-400">{ci.id}</span>
                          <span className="text-xs font-semibold text-gray-100">{ci.name}</span>
                        </div>
                        <p className="text-xs text-gray-300 mt-0.5 line-clamp-1">{ci.statement}</p>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <StatusBadge variant={ci.tlaProofStatus} label={ci.tlaProofStatus} />
                      <StatusBadge variant={ci.verificationStatus} label={ci.verificationStatus} />
                      <span className="font-mono text-[11px] text-gray-400 px-2 py-0.5 rounded bg-gray-950 border border-gray-800">
                        {truncateHash(ci.proofHash, 8, 4)}
                      </span>
                      <button
                        type="button"
                        onClick={() => setSelectedInvariant(ci)}
                        className="inline-flex items-center gap-1 text-[11px] font-mono text-indigo-300 hover:text-indigo-200 px-2 py-1 rounded bg-indigo-950/60 border border-indigo-900/80"
                      >
                        Details <ExternalLink size={10} />
                      </button>
                    </div>
                  </div>

                  {/* Expanded Content */}
                  {isExpanded && (
                    <div className="border-t border-gray-800 bg-gray-950/80 p-4 text-xs space-y-3">
                      <div>
                        <span className="text-[10px] font-mono uppercase text-gray-500 block">Formal Statement</span>
                        <p className="text-gray-200 mt-0.5 font-sans leading-relaxed">{ci.statement}</p>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        <div>
                          <span className="text-[10px] font-mono uppercase text-gray-500 block">TLA+ Spec Ref</span>
                          <code className="font-mono text-cyan-300 text-[11px]">{ci.tlaSpecRef}</code>
                        </div>
                        <div>
                          <span className="text-[10px] font-mono uppercase text-gray-500 block">Last Verified</span>
                          <span className="font-mono text-gray-300">{ci.lastVerified}</span>
                        </div>
                        <div>
                          <span className="text-[10px] font-mono uppercase text-gray-500 block">Full Proof Hash</span>
                          <code className="font-mono text-gray-400 text-[10px] break-all">{ci.proofHash}</code>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-gray-800/80">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono uppercase text-gray-500">Epochs:</span>
                          {ci.epochs.map((ep) => (
                            <span
                              key={ep}
                              className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-950/80 text-indigo-300 border border-indigo-900/60"
                            >
                              {ep}
                            </span>
                          ))}
                        </div>

                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-mono uppercase text-gray-500">Regulatory Mappings:</span>
                          {ci.regulatoryMappings.map((rm) => (
                            <span
                              key={rm}
                              className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-900/60"
                            >
                              {rm}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </section>

      {/* SECTION 2 — TLA+ SPECIFICATION VIEWER */}
      <section>
        <ExpandableSection
          title="Section 2 — TLA+ Formal Specification Viewer (Apalache & TLC Verified)"
          subtitle="Executable formal specification modules governing quorum, systemic risk ceilings, and authority bounds."
          defaultOpen={true}
          badge={<StatusBadge variant="PROVED" label="3 / 3 MODULES PROVED" />}
        >
          <div className="space-y-6">
            {TLA_MODULES.map((mod) => (
              <div key={mod.id} className="space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2 bg-gray-900 p-3 rounded-t-lg border border-gray-700">
                  <div>
                    <h3 className="text-xs font-mono font-bold text-cyan-300 flex items-center gap-2">
                      <Terminal size={14} /> {mod.filename} — {mod.name}
                    </h3>
                    <p className="text-[11px] text-gray-400 font-mono mt-0.5">Theorem: {mod.theorem}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-gray-400 bg-gray-950 px-2 py-1 rounded border border-gray-800">
                      {mod.checkerInfo}
                    </span>
                    <StatusBadge variant={mod.proofStatus} />
                  </div>
                </div>
                <CodeBlock code={mod.code} language="tla" maxHeight="max-h-72" />
              </div>
            ))}
          </div>
        </ExpandableSection>
      </section>

      {/* SECTION 3 — TREATY FRAMEWORK ARCHITECTURE */}
      <section className="space-y-4">
        <div className="border-b border-gray-700 pb-2">
          <h2 className="text-sm font-semibold text-gray-100 flex items-center gap-2">
            <Globe size={18} className="text-cyan-400" />
            Section 3 — Treaty Framework Architecture & Supranational Accords
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Supranational binding treaties, protocol specifications, and cross-border enforcement mechanics.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {TREATY_FRAMEWORKS_DETAILED.map((tf) => (
            <div
              key={tf.id}
              className={`rounded-xl p-5 space-y-4 border ${
                tf.isTreatyGrade
                  ? 'border-cyan-500/40 bg-gray-800/60 shadow-lg shadow-cyan-950/20'
                  : 'border-gray-700 bg-gray-800/40'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">{tf.id}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                      v{tf.version}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-gray-100 mt-1">{tf.name}</h3>
                </div>
                <StatusBadge variant="VERIFIED" label="RATIFIED" />
              </div>

              <p className="text-xs text-gray-300 leading-relaxed">{tf.scope}</p>

              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono bg-gray-900/60 p-2.5 rounded-lg border border-gray-700/60">
                <div>
                  <span className="text-gray-400 block">Ratification:</span>
                  <span className="text-gray-200">{tf.ratificationDate}</span>
                </div>
                <div>
                  <span className="text-gray-400 block">Jurisdictions:</span>
                  <span className="text-cyan-300">{tf.jurisdictionCount} Sovereign States</span>
                </div>
                {tf.filingRef && (
                  <div className="col-span-2">
                    <span className="text-gray-400 block">Filing Reference:</span>
                    <span className="text-indigo-300 break-all">{tf.filingRef}</span>
                  </div>
                )}
              </div>

              <div>
                <span className="text-[10px] font-mono uppercase text-gray-400 block font-semibold mb-1">
                  Enforcement Mechanism:
                </span>
                <p className="text-xs text-gray-300 bg-gray-900/40 p-2 rounded border border-gray-800">
                  {tf.enforcementMechanism}
                </p>
              </div>

              <div>
                <span className="text-[10px] font-mono uppercase text-gray-400 block font-semibold mb-1">
                  Key Treaty Obligations:
                </span>
                <ul className="space-y-1 text-xs text-gray-300">
                  {tf.keyObligations.map((ob, idx) => (
                    <li key={idx} className="flex items-start gap-1.5">
                      <Check size={14} className="text-cyan-400 shrink-0 mt-0.5" />
                      <span>{ob}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {tf.amendmentHistory.length > 0 && (
                <div className="border-t border-gray-700/60 pt-3">
                  <span className="text-[10px] font-mono uppercase text-gray-400 block font-semibold mb-1.5">
                    Amendment History:
                  </span>
                  <div className="space-y-1.5">
                    {tf.amendmentHistory.map((ah, i) => (
                      <div key={i} className="text-[11px] text-gray-400 flex items-baseline justify-between gap-2">
                        <span className="font-mono text-cyan-300 shrink-0">{ah.date}</span>
                        <span className="truncate text-gray-300">{ah.title}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* SECTION 4 — GOVERNANCE EPOCH TIMELINE */}
      <section className="rounded-xl border border-gray-700 bg-gray-800/40 p-5 space-y-4">
        <div className="border-b border-gray-700 pb-2">
          <h2 className="text-sm font-semibold text-gray-100 flex items-center gap-2">
            <Clock size={18} className="text-indigo-400" />
            Section 4 — Governance Epoch Timeline (2026 → 2100+)
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Scaled horizontal transition timeline from Phase VI-δ planetary mesh through Ω-GAR terminal dissolution.
          </p>
        </div>

        {/* Hand-Rolled Scaled SVG Timeline */}
        <div className="overflow-x-auto bg-gray-950 p-4 rounded-lg border border-gray-800">
          <svg viewBox="0 0 960 180" className="w-full h-auto min-w-[760px]" role="img" aria-label="Governance epoch timeline">
            {/* Year Scale Base Line */}
            <line x1={30} y1={70} x2={930} y2={70} stroke="#374151" strokeWidth={3} />

            {/* Render Epoch Segments */}
            {(() => {
              const startYear = 2026;
              const endYear = 2100;
              const totalYears = endYear - startYear;
              const px = (year: number) => 30 + ((Math.min(year, endYear) - startYear) / totalYears) * (930 - 30);

              return EPOCH_TIMELINE_MILESTONES.map((ep) => {
                const x1 = px(ep.yearStart);
                const x2 = px(ep.yearEnd);
                const midX = (x1 + x2) / 2;

                return (
                  <g key={ep.phaseId}>
                    {/* Segment Line */}
                    <line x1={x1} y1={70} x2={x2} y2={70} stroke={ep.color} strokeWidth={6} strokeLinecap="round" />

                    {/* Point Marker */}
                    <circle cx={x1} cy={70} r={5} fill={ep.color} />
                    <circle cx={x1} cy={70} r={9} fill="none" stroke={ep.color} strokeOpacity={0.4} />

                    {/* Phase ID above */}
                    <text x={x1} y={48} fill={ep.color} fontSize={11} fontWeight="bold" textAnchor="middle" fontFamily="monospace">
                      {ep.phaseId}
                    </text>
                    <text x={x1} y={32} fill="#9ca3af" fontSize={9} textAnchor="middle" fontFamily="monospace">
                      {ep.yearStart}
                    </text>

                    {/* Milestone text below */}
                    <text x={midX} y={96} fill="#e5e7eb" fontSize={9.5} fontWeight="500" textAnchor="middle">
                      {ep.name}
                    </text>
                    {ep.milestones[0] && (
                      <text x={midX} y={114} fill="#9ca3af" fontSize={8.5} textAnchor="middle" fontFamily="monospace">
                        {ep.milestones[0]}
                      </text>
                    )}
                  </g>
                );
              });
            })()}
          </svg>
        </div>
      </section>

      {/* SECTION 5 — LONG-HORIZON ARCHITECTURE */}
      <section className="space-y-3">
        <div className="border-b border-gray-700 pb-2">
          <h2 className="text-sm font-semibold text-gray-100 flex items-center gap-2">
            <Layers size={18} className="text-violet-400" />
            Section 5 — Long-Horizon Architecture Phase Cards
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Sequential phase configurations across planetary, off-world, multiversal, and terminal dissolution eras.
          </p>
        </div>

        {/* Scrollable Horizontal Row */}
        <div className="flex gap-4 overflow-x-auto pb-4 pt-1 snap-x">
          {GOVERNANCE_PHASES.map((ph) => (
            <div
              key={ph.id}
              className="min-w-[300px] max-w-[340px] flex-shrink-0 snap-start rounded-xl border border-gray-700 bg-gray-800/60 p-4 space-y-3 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm font-bold text-violet-300">Phase {ph.id}</span>
                  <span className="font-mono text-xs text-gray-400 px-2 py-0.5 rounded bg-gray-900 border border-gray-700">
                    {ph.epoch}
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-gray-100 mt-1">{ph.name}</h3>

                <div className="mt-3 space-y-2 text-xs">
                  <div>
                    <span className="text-[10px] font-mono uppercase text-gray-400 block font-semibold">
                      Objectives:
                    </span>
                    <ul className="list-disc list-inside space-y-0.5 text-gray-300 mt-0.5">
                      {ph.objectives.map((obj, i) => (
                        <li key={i}>{obj}</li>
                      ))}
                    </ul>
                  </div>

                  <div>
                    <span className="text-[10px] font-mono uppercase text-gray-400 block font-semibold">
                      Treaty Frameworks:
                    </span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {ph.treatyFrameworks.map((tf) => (
                        <span key={tf} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-900">
                          {tf}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-gray-700/60 flex items-center justify-between text-[11px] font-mono text-gray-400">
                <span>Active Invariants: {ph.invariantsActive}</span>
                <span className="text-indigo-300">{ph.pillarStatus}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* SECTION 6 — INFINITY PILLAR READINESS DASHBOARD */}
      <section className="rounded-xl border border-gray-700 bg-gray-800/40 p-5 space-y-4">
        <div className="border-b border-gray-700 pb-2">
          <h2 className="text-sm font-semibold text-gray-100 flex items-center gap-2">
            <BookOpen size={18} className="text-emerald-400" />
            Section 6 — Infinity Pillar Readiness Dashboard (IP-I .. IP-VII)
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Evaluates readiness scores, active prerequisites, and sealing status for all seven core governance pillars.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {INFINITY_PILLARS.map((p) => (
            <div key={p.id} className="rounded-xl border border-gray-700 bg-gray-800/60 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-bold text-indigo-400">{p.id}</span>
                <StatusBadge variant={p.status} />
              </div>

              <div>
                <h3 className="text-sm font-semibold text-gray-100">{p.name}</h3>
                <p className="text-xs text-gray-300 mt-0.5">{p.description}</p>
              </div>

              <div className="pt-1">
                <ProgressBar value={p.readinessScore} label="Pillar Readiness Score" />
              </div>

              <div className="border-t border-gray-700/60 pt-2 text-xs">
                <span className="text-[10px] font-mono uppercase text-gray-400 block font-semibold mb-1">
                  Prerequisites:
                </span>
                <ul className="space-y-1 text-gray-300 font-mono text-[11px]">
                  {p.prerequisites.map((pre, idx) => (
                    <li key={idx} className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                      <span>{pre}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* DETAIL DRAWER FOR INVARIANT DETAIL VIEW */}
      {selectedInvariant && (
        <DetailDrawer
          open={!!selectedInvariant}
          onClose={() => setSelectedInvariant(null)}
          title={`Constitutional Invariant Detail: ${selectedInvariant.id}`}
          subtitle={selectedInvariant.name}
        >
          {(() => {
            const details = getInvariantDetails(selectedInvariant.id);
            return (
              <div className="space-y-5 text-xs">
                <div className="space-y-1">
                  <span className="text-[10px] font-mono uppercase text-gray-400 font-semibold">Formal Statement:</span>
                  <p className="p-3 rounded-lg border border-gray-700 bg-gray-950 text-gray-200 leading-relaxed font-sans">
                    {selectedInvariant.statement}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-3 font-mono bg-gray-900 p-3 rounded-lg border border-gray-800">
                  <div>
                    <span className="text-gray-400 text-[10px] block">Proof Status:</span>
                    <StatusBadge variant={selectedInvariant.tlaProofStatus} />
                  </div>
                  <div>
                    <span className="text-gray-400 text-[10px] block">Verification Status:</span>
                    <StatusBadge variant={selectedInvariant.verificationStatus} />
                  </div>
                  <div className="col-span-2">
                    <span className="text-gray-400 text-[10px] block">Last Verified Timestamp:</span>
                    <span className="text-gray-200">{selectedInvariant.lastVerified}</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] font-mono uppercase text-gray-400 font-semibold">
                    Cryptographic Proof Hash:
                  </span>
                  <code className="block font-mono text-[11px] p-2.5 rounded bg-gray-950 text-cyan-300 border border-gray-800 break-all">
                    {selectedInvariant.proofHash}
                  </code>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] font-mono uppercase text-gray-400 font-semibold">
                    TLA+ Formal Specification Module Snippet:
                  </span>
                  <CodeBlock code={details.tlaSnippet} language="tla" maxHeight="max-h-64" />
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] font-mono uppercase text-gray-400 font-semibold">Verification Audit Trail:</span>
                  <p className="p-3 rounded-lg border border-gray-700/80 bg-gray-900/60 text-gray-300 leading-relaxed">
                    {details.detailHistory}
                  </p>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] font-mono uppercase text-gray-400 font-semibold">Regulatory Mappings:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedInvariant.regulatoryMappings.map((m) => (
                      <span
                        key={m}
                        className="px-2.5 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono text-[11px]"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            );
          })()}
        </DetailDrawer>
      )}
    </div>
  );
}
