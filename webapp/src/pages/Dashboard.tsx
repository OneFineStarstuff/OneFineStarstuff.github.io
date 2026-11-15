import { Link } from 'react-router-dom';
import { ArrowRight, Landmark, ShieldCheck } from 'lucide-react';
import { DOSSIER_318 } from '../data/dossier-2026-318';
import { Role } from '../types/gien';

interface Props { role: Role; }

export default function Dashboard({ role }: Props) {
  const d = DOSSIER_318;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Executive Summary — GIEN Supervisory Console</h1>
      <p className="text-sm text-slate-600 dark:text-slate-300">
        Rendering layer over the daily dossier corpus. Current fixture: {d.dossierId} ({d.window}).
      </p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-lg border border-green-300 dark:border-green-700 p-4">
          <p className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">Systemic risk</p>
          <p className="text-2xl font-bold font-mono">G-SRI {d.indices[1].value}</p>
          <p className="text-sm text-slate-600 dark:text-slate-300">New epoch low; 31st improving window of the last 32; lowest weekly close of Epoch I.</p>
        </div>
        <div className="rounded-lg border border-green-300 dark:border-green-700 p-4">
          <p className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">Attestation</p>
          <p className="text-2xl font-bold font-mono">TEE 52/52</p>
          <p className="text-sm text-slate-600 dark:text-slate-300">99.6% density (record held); ZTAI-02 31st closed window at 100%.</p>
        </div>
        <div className="rounded-lg border border-green-300 dark:border-green-700 p-4">
          <p className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">zkML pipeline</p>
          <p className="text-2xl font-bold font-mono">98.9%</p>
          <p className="text-sm text-slate-600 dark:text-slate-300">Record; p99 4.0 s; DI 0.910 (floor 0.800); Stage C day 17.</p>
        </div>
      </div>
      <div className="flex gap-4">
        <Link to="/briefing" className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-slate-900 text-white dark:bg-white dark:text-slate-900 font-medium">
          Open the daily brief <ArrowRight size={16} />
        </Link>
        <span className="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-slate-300 dark:border-slate-600 text-sm">
          <ShieldCheck size={16} /> {d.continuityProtocols}
        </span>
        <span className="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-slate-300 dark:border-slate-600 text-sm">
          <Landmark size={16} /> Alert level: {d.alertLevel}
        </span>
      </div>
      {role === 'educational' && (
        <p className="text-sm text-slate-600 dark:text-slate-300">
          Learning path: start with the daily brief, then open an evidence drawer on any index to see how it
          maps to control domains and a sealed artefact, and run the Merkle inspector.
        </p>
      )}
    </div>
  );
}
