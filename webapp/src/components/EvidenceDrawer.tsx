import { useEffect } from 'react';
import { X, CheckCircle2, AlertTriangle } from 'lucide-react';
import { EvidencePayload, Role } from '../types/gien';
import BandBadge from './BandBadge';

interface Props {
  payload: EvidencePayload;
  schemaErrors: string[];
  role: Role;
  onClose: () => void;
}

export default function EvidenceDrawer({ payload, schemaErrors, role, onClose }: Props) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);

  const showHashes = role === 'engineer';
  const redact = (s: string) => (showHashes ? s : s.slice(0, 18) + '… (unseal as Governance Engineer)');

  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true" aria-label={'Evidence: ' + payload.index.name}>
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <aside className="relative h-full w-full max-w-md overflow-y-auto bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-700 p-5 space-y-5">
        <div className="flex items-start justify-between gap-3">
          <h2 className="text-lg font-bold">{payload.index.name}</h2>
          <button onClick={onClose} aria-label="Close evidence drawer" className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800">
            <X size={18} />
          </button>
        </div>

        <p className={'inline-flex items-center gap-1.5 text-xs font-medium px-2 py-1 rounded ' +
          (schemaErrors.length === 0
            ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
            : 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200')}>
          {schemaErrors.length === 0 ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
          WP-096 schema check: {schemaErrors.length === 0 ? 'PASS' : schemaErrors.length + ' deviation(s)'}
        </p>

        <section>
          <h3 className="text-sm font-semibold mb-1">Semantics</h3>
          <p className="text-sm text-slate-600 dark:text-slate-300">{payload.index.semantics}</p>
        </section>

        <section>
          <h3 className="text-sm font-semibold mb-1">Current reading</h3>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            <dt className="text-slate-500 dark:text-slate-400">Value</dt>
            <dd className="font-mono">{payload.current.value} {payload.current.unit}</dd>
            <dt className="text-slate-500 dark:text-slate-400">Band</dt>
            <dd><BandBadge band={payload.current.band} /></dd>
            {payload.current.delta_24h !== undefined && (
              <>
                <dt className="text-slate-500 dark:text-slate-400">24 h Δ</dt>
                <dd className="font-mono">{payload.current.delta_24h > 0 ? '+' : ''}{payload.current.delta_24h}</dd>
              </>
            )}
            <dt className="text-slate-500 dark:text-slate-400">Window</dt>
            <dd className="font-mono text-xs">{payload.current.window_id}</dd>
            {payload.current.epoch_trend && (
              <>
                <dt className="text-slate-500 dark:text-slate-400">Epoch trend</dt>
                <dd className="text-xs">{payload.current.epoch_trend}</dd>
              </>
            )}
          </dl>
          {payload.series?.inline && (
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              Series: {payload.series.inline.join(' → ')}{payload.series.notes ? ' — ' + payload.series.notes : ''}
            </p>
          )}
        </section>

        <section>
          <h3 className="text-sm font-semibold mb-1">Contributing controls</h3>
          <ul className="space-y-1 text-sm">
            {payload.controls.map((c) => (
              <li key={c.control_id}>
                <span className="font-mono font-medium">{c.control_id}</span>{' '}
                <span className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800">{c.layer}</span>
                {c.regimes && <span className="text-slate-500 dark:text-slate-400 text-xs"> · {c.regimes.join(', ')}</span>}
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h3 className="text-sm font-semibold mb-1">Sealed artifacts</h3>
          <ul className="space-y-2 text-sm">
            {payload.artifacts.map((a, i) => (
              <li key={i} className="rounded border border-slate-200 dark:border-slate-700 p-2">
                <p className="font-medium">{a.type}</p>
                <p className="font-mono text-xs">{a.dossier_id}</p>
                <p className="font-mono text-xs break-all">digest {redact(a.digest)}</p>
                <p className="font-mono text-xs break-all">root {redact(a.merkle_root)}</p>
                {a.path && <p className="text-xs text-slate-500 dark:text-slate-400">{a.path}</p>}
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h3 className="text-sm font-semibold mb-1">Verification</h3>
          <p className="text-sm">
            Root recomputable in this static fixture:{' '}
            <span className={payload.verification.root_recomputable ? 'text-green-700 dark:text-green-400' : 'text-amber-700 dark:text-amber-400'}>
              {String(payload.verification.root_recomputable)}
            </span>
          </p>
          {payload.verification.walkthrough_steps && (
            <p className="text-xs text-slate-500 dark:text-slate-400">Walkthrough steps: {payload.verification.walkthrough_steps}</p>
          )}
          {payload.verification.notes && <p className="text-xs text-slate-500 dark:text-slate-400">{payload.verification.notes}</p>}
        </section>

        <p className="text-xs text-slate-500 dark:text-slate-400 italic">
          Fictional simulation: all values, controls, digests, and roots shown are simulated artefacts.
        </p>
      </aside>
    </div>
  );
}
