import { useState } from 'react';
import { GitBranch, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react';
import { DOSSIER_318 } from '../data/dossier-2026-318';
import { EVIDENCE_318 } from '../data/evidence-2026-318';
import { recomputeMerkleRoot, sha384Hex } from '../lib/evidence';

interface Result {
  leafCount: number;
  levels: number;
  recomputed: string;
  sealed: string;
  match: boolean;
  error?: string;
}

export default function MerkleInspector() {
  const [status, setStatus] = useState<'idle' | 'running' | 'done'>('idle');
  const [result, setResult] = useState<Result | null>(null);

  async function run() {
    setStatus('running');
    try {
      const ids = Object.keys(EVIDENCE_318).sort();
      const leaves = await Promise.all(ids.map((id) => sha384Hex(JSON.stringify(EVIDENCE_318[id]))));
      const { root, levels } = await recomputeMerkleRoot(leaves);
      const sealed = DOSSIER_318.merkleRoot;
      setResult({ leafCount: leaves.length, levels, recomputed: root, sealed, match: root === sealed });
    } catch (e) {
      setResult({ leafCount: 0, levels: 0, recomputed: '', sealed: DOSSIER_318.merkleRoot, match: false, error: String(e) });
    }
    setStatus('done');
  }

  return (
    <section className="rounded-lg border border-slate-200 dark:border-slate-700 p-4">
      <h2 className="flex items-center gap-2 font-semibold mb-2"><GitBranch size={18} /> Merkle inspector</h2>
      <p className="text-sm text-slate-600 dark:text-slate-300 mb-3">
        Recomputes SHA-384 leaf digests over the 12 evidence payloads in-browser and derives a binary
        Merkle root. Honesty note: the static fixture carries the sealed archive root but not the WORM
        leaf set, so a root MISMATCH is the expected, truthful outcome here (verification.root_recomputable
        = false in every evidence payload). Full recomputation requires WORM ledger access.
      </p>
      <button
        onClick={run}
        disabled={status === 'running'}
        className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-600 text-sm font-medium hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-50"
      >
        {status === 'running' ? <Loader2 size={14} className="animate-spin" /> : <GitBranch size={14} />}
        Recompute fixture Merkle tree
      </button>
      {status === 'done' && result && (
        <div className="mt-3 space-y-1 text-sm">
          {result.error ? (
            <p className="text-amber-700 dark:text-amber-400"><AlertTriangle size={14} className="inline" /> {result.error}</p>
          ) : (
            <>
              <p className="text-green-700 dark:text-green-400"><CheckCircle2 size={14} className="inline" /> Leaf recomputation: {result.leafCount}/{result.leafCount} SHA-384 digests derived; tree depth {result.levels}.</p>
              <p className="font-mono text-xs break-all">Fixture-derived root: {result.recomputed}</p>
              <p className="font-mono text-xs break-all">Sealed WORM root: {result.sealed}</p>
              <p className={result.match ? 'text-green-700 dark:text-green-400' : 'text-amber-700 dark:text-amber-400'}>
                {result.match ? 'Root comparison: MATCH.' : 'Root comparison: MISMATCH — expected in the static demo (no WORM leaf set in the corpus); not a defect of the sealed values.'}
              </p>
            </>
          )}
        </div>
      )}
    </section>
  );
}
