import { useState } from 'react';
import { BookOpen, Radio, ScrollText } from 'lucide-react';
import ExpandableSection from '../components/ExpandableSection';
import PageHeader from '../components/PageHeader';
import ProgressBar from '../components/ProgressBar';
import StatusBadge from '../components/StatusBadge';
import TaggedDocument from '../components/TaggedDocument';
import { GOVERNANCE_PHASES, INFINITY_PILLARS } from '../data/gienData';
import { FICTIONAL_NOTICE } from '../data/extendedData';

const ARTIFACTS = [
  {
    id: 'GIEN-UNIFIED-CODEX-OMEGA',
    status: 'DRAFT',
    summary: 'Unified post-dissolution codex consolidating the 24 constitutional invariants, treaty chains and corpus manifest for successor-epoch activation.',
    sections: ['Preamble and epoch scope', 'Invariant consolidation (CI-001–CI-024)', 'Treaty continuity chains', 'Corpus manifest and beacon signatures', 'Successor legitimacy conditions'],
  },
  {
    id: 'GIEN-EPITAPH-OMEGA',
    status: 'STANDBY',
    summary: 'Dissolution declaration: preserves legacy, certifies non-interference and records the terminal governance state of the mesh.',
    sections: ['Dissolution declaration', 'Legacy preservation commitments', 'Constitutional continuity provisions', 'Audit trail handover'],
  },
  {
    id: 'GIEN-INVOCATION-OMEGA',
    status: 'ACTIVE',
    summary: 'Successor-epoch activation protocol: governance handoff procedures, quorum attestations and treaty continuity execution.',
    sections: ['Activation protocol', 'Handoff choreography', 'Quorum and ZK-vote attestation', 'Treaty continuity execution'],
  },
];

export default function LongHorizon() {
  const [phaseId, setPhaseId] = useState(GOVERNANCE_PHASES[0].id);
  const phase = GOVERNANCE_PHASES.find((p) => p.id === phaseId) ?? GOVERNANCE_PHASES[0];

  return (
    <div>
      <PageHeader
        title="Long-Horizon Architecture — Phases VI-δ → XIII and Ω-GAR"
        subtitle="Constitutional and governance synthesis across epochs 2026–2035 and 2035–2100+"
        crumbs={[{ label: 'Home', to: '/dashboard' }, { label: 'Long Horizon' }]}
      />

      <section className="mb-6">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-gray-400">Phase sequence</h2>
        <div className="flex gap-3 overflow-x-auto pb-2">
          {GOVERNANCE_PHASES.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => setPhaseId(p.id)}
              aria-pressed={p.id === phaseId}
              className={`min-w-[190px] rounded-lg border p-3 text-left transition-colors ${
                p.id === phaseId
                  ? 'border-indigo-500 bg-indigo-500/10'
                  : 'border-gray-700 bg-gray-800/40 hover:border-gray-600'
              }`}
            >
              <p className="font-mono text-xs text-indigo-300">{p.id}</p>
              <p className="mt-1 text-sm font-semibold text-gray-100">{p.name}</p>
              <p className="mt-1 font-mono text-[11px] text-gray-500">{p.epoch}</p>
            </button>
          ))}
        </div>

        <div className="mt-3 rounded-lg border border-gray-700 bg-gray-800/50 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-semibold text-gray-100">
              {phase.id} — {phase.name}
            </h3>
            <StatusBadge variant={phase.id === 'VI-δ' ? 'NOMINAL' : 'PENDING'} label={phase.epoch} />
          </div>
          <ul className="mt-3 grid gap-1.5 text-xs text-gray-300 sm:grid-cols-3">
            {phase.objectives.map((o) => (
              <li key={o} className="rounded border border-gray-700/70 bg-gray-900/50 px-2.5 py-1.5">{o}</li>
            ))}
          </ul>
          <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
            <span className="rounded bg-gray-700/60 px-2 py-0.5 text-gray-300">{phase.invariantsActive} invariants active</span>
            {phase.treatyFrameworks.map((t) => (
              <span key={t} className="rounded bg-cyan-500/10 px-2 py-0.5 font-mono text-cyan-300">{t}</span>
            ))}
            <span className="rounded bg-violet-500/10 px-2 py-0.5 text-violet-300">{phase.pillarStatus}</span>
          </div>
        </div>
      </section>

      <section className="mb-6">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-gray-400">
          <BookOpen size={14} /> Infinity Pillar readiness
        </h2>
        <div className="grid gap-3 md:grid-cols-2">
          {INFINITY_PILLARS.map((p) => (
            <div key={p.id} className="rounded-lg border border-gray-700 bg-gray-800/50 p-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="font-mono text-[11px] text-indigo-400">{p.id}</p>
                  <h3 className="text-sm font-semibold text-gray-100">{p.name}</h3>
                </div>
                <StatusBadge variant={p.status} />
              </div>
              <p className="mt-1.5 text-xs text-gray-400">{p.description}</p>
              <div className="mt-3">
                <ProgressBar value={p.readinessScore} label="Readiness" />
              </div>
              <ul className="mt-2 space-y-1 text-[11px] text-gray-500">
                {p.prerequisites.map((pr) => (
                  <li key={pr}>· {pr}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </section>

      <section className="mb-6">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-gray-400">
          <Radio size={14} /> Eternal Corpus Transmission Protocol
        </h2>
        <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-4">
          <div className="grid gap-3 sm:grid-cols-3">
            {[
              { id: 'beacon-north', label: 'Beacon North (terrestrial)', status: 'ACTIVE', latency: '42 s' },
              { id: 'beacon-orbit', label: 'Beacon Orbit (L2 relay)', status: 'STANDBY', latency: '18 min' },
              { id: 'beacon-deep', label: 'Beacon Deep (interstellar)', status: 'STANDBY', latency: '4.1 yr' },
            ].map((b) => (
              <div key={b.id} className="rounded border border-gray-700/70 bg-gray-900/50 p-3">
                <p className="text-xs text-gray-300">{b.label}</p>
                <p className="mt-1 font-mono text-[11px] text-gray-500">latency {b.latency}</p>
                <div className="mt-2">
                  <StatusBadge variant={b.status === 'ACTIVE' ? 'ACTIVE' : 'PENDING'} label={b.status} />
                </div>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-gray-400">
            Corpus sealing requires ≥ 3 independent channels (CI-008). Beacon Signature design: <span className="font-mono text-violet-300">INTERSTELLAR</span>; redundancy factor 3; FIPS 204 signatures on every beacon frame.
          </p>
        </div>
      </section>

      <section>
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-gray-400">
          <ScrollText size={14} /> Successor-epoch codex artefacts
        </h2>
        <div className="space-y-3">
          {ARTIFACTS.map((a) => (
            <ExpandableSection key={a.id} title={a.id} subtitle={a.summary} badge={<StatusBadge variant={a.status} label={a.status} />}>
              <TaggedDocument
                compact
                title={`${a.id} — structural outline`}
                abstract={a.summary}
              >
                <ul className="space-y-1 text-xs text-gray-300">
                  {a.sections.map((s) => (
                    <li key={s}>· {s}</li>
                  ))}
                </ul>
                <p className="text-[11px] text-gray-500">
                  Sealing requires ratification by ≥ 67% of the supervisory college (CI-005) and Merkle-anchored PQC signature before transmission.
                </p>
              </TaggedDocument>
            </ExpandableSection>
          ))}
        </div>
      </section>

      <p className="mt-5 text-[11px] text-gray-500">{FICTIONAL_NOTICE}</p>
    </div>
  );
}
