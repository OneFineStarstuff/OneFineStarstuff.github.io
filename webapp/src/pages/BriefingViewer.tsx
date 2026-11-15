import { useState } from 'react';
import { ShieldCheck, FileLock, Drill, Scale, GitBranch } from 'lucide-react';
import { DOSSIER_318 } from '../data/dossier-2026-318';
import { EVIDENCE_318 } from '../data/evidence-2026-318';
import { validateEvidenceContract } from '../lib/evidence';
import { EvidenceIndexId, Role } from '../types/gien';
import BandBadge from '../components/BandBadge';
import RoleSelector from '../components/RoleSelector';
import EvidenceDrawer from '../components/EvidenceDrawer';
import MerkleInspector from '../components/MerkleInspector';

const CONTRACT = validateEvidenceContract(EVIDENCE_318);

interface Props { role: Role; onRoleChange: (r: Role) => void; }

export default function BriefingViewer({ role, onRoleChange }: Props) {
  const d = DOSSIER_318;
  const [openDrill, setOpenDrill] = useState<number | null>(null);
  const [openEvidence, setOpenEvidence] = useState<EvidenceIndexId | null>(null);
  const showHashes = role === 'engineer';
  const showNotes = role !== 'supervisor';

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-bold">Daily Supervisory Brief — {d.dossierId}</h1>
        <RoleSelector role={role} onChange={onRoleChange} />
      </div>

      <section className="rounded-lg border border-slate-200 dark:border-slate-700 p-4">
        <h2 className="flex items-center gap-2 font-semibold mb-2"><FileLock size={18} /> Sealed archive</h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-sm">
          <dt className="font-medium">Evaluation window</dt><dd>{d.window}</dd>
          <dt className="font-medium">Work package</dt><dd>{d.workPackage}</dd>
          <dt className="font-medium">Artefacts sealed</dt><dd>{d.artefacts} / {d.artefacts} (SHA-384 digests)</dd>
          <dt className="font-medium">Merkle root</dt>
          <dd className="font-mono text-xs break-all">{showHashes ? d.merkleRoot : d.merkleRoot.slice(0, 18) + '… (unseal as Governance Engineer)'}</dd>
        </dl>
        {showHashes && (
          <ul className="mt-3 space-y-1 text-xs font-mono">
            {d.signatures.map((s) => (
              <li key={s.algorithm}><span className="font-sans font-semibold">{s.algorithm}:</span> {s.value}</li>
            ))}
          </ul>
        )}
      </section>

      <section className="rounded-lg border border-slate-200 dark:border-slate-700 p-4">
        <h2 className="flex items-center gap-2 font-semibold mb-3"><ShieldCheck size={18} /> Systemic-risk telemetry</h2>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">
          Rows with an evidence link open the WP-096-contract evidence drawer; the evidence quote age tile
          has no drawer (its index id is outside the WP-096 contract enum).
        </p>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left border-b border-slate-200 dark:border-slate-700">
              <th className="py-1.5 pr-3">Index</th><th className="pr-3">Value</th><th className="pr-3">24h</th><th className="pr-3">Band</th><th className="pr-3">Evidence</th>
              {showNotes && <th className="pr-3">Note</th>}
            </tr>
          </thead>
          <tbody>
            {d.indices.map((ix) => (
              <tr key={ix.key} className="border-b border-slate-100 dark:border-slate-800">
                <td className="py-1.5 pr-3 font-medium">{ix.label}</td>
                <td className="pr-3 font-mono">{ix.value}</td>
                <td className="pr-3 font-mono">{ix.delta}</td>
                <td className="pr-3"><BandBadge band={ix.band} /></td>
                <td className="pr-3">
                  {ix.evidenceId ? (
                    <button
                      className="text-xs underline underline-offset-2 hover:font-semibold"
                      aria-haspopup="dialog"
                      onClick={() => setOpenEvidence(ix.evidenceId!)}
                    >
                      Open drawer
                    </button>
                  ) : (
                    <span className="text-xs text-slate-400">—</span>
                  )}
                </td>
                {showNotes && <td className="pr-3 text-slate-600 dark:text-slate-300">{ix.note}</td>}
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="rounded-lg border border-slate-200 dark:border-slate-700 p-4">
        <h2 className="flex items-center gap-2 font-semibold mb-3"><Drill size={18} /> Drills & replays</h2>
        <ul className="space-y-2">
          {d.drills.map((dr, i) => (
            <li key={dr.name}>
              <button
                className="w-full text-left px-3 py-2 rounded-md border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800"
                aria-expanded={openDrill === i}
                onClick={() => setOpenDrill(openDrill === i ? null : i)}
              >
                <span className="font-medium">{dr.name}</span> — {dr.outcome}
              </button>
              {openDrill === i && <p className="px-3 py-2 text-sm text-slate-600 dark:text-slate-300">{dr.note}</p>}
            </li>
          ))}
        </ul>
      </section>

      <section className="rounded-lg border border-slate-200 dark:border-slate-700 p-4">
        <h2 className="flex items-center gap-2 font-semibold mb-3"><Scale size={18} /> Regulatory alignment (17 regimes, all GREEN)</h2>
        <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-sm list-disc list-inside">
          {d.regimes.map((r) => <li key={r}>{r}</li>)}
        </ul>
        <p className="mt-3 text-sm">{d.continuityProtocols}. Alert level: {d.alertLevel}.</p>
      </section>

      <MerkleInspector />

      {openEvidence && (
        <EvidenceDrawer
          payload={EVIDENCE_318[openEvidence]}
          schemaErrors={CONTRACT.report[openEvidence] ?? []}
          role={role}
          onClose={() => setOpenEvidence(null)}
        />
      )}
      <p className="flex items-center gap-1.5 text-xs text-slate-400">
        <GitBranch size={12} /> Evidence contract: {Object.keys(EVIDENCE_318).length} payloads, {CONTRACT.ok ? 'all conforming to' : 'deviations from'} the WP-096 evidence-drawer schema.
      </p>
    </div>
  );
}
