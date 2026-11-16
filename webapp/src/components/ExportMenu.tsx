import { useEffect, useRef, useState } from 'react';
import { Braces, Download, FileSpreadsheet, FileText } from 'lucide-react';
import { Role } from '../types/gien';
import {
  buildComplianceDataset,
  buildDrillsDataset,
  downloadBlob,
  downloadPdf,
  toCsv,
  toJson,
  ExportDataset
} from '../lib/export';

interface Props {
  role: Role;
  dataset: 'compliance' | 'drills';
}

/**
 * M4 (WP-110): role-gated export menu (PDF / CSV / JSON) for the compliance
 * matrix and drills register. Exports are renderings of the sealed dossier
 * corpus, never evidence; the disclaimer travels with every format.
 */
export default function ExportMenu({ role, dataset }: Props) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onClick);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onClick);
    };
  }, [open]);

  const build = (): ExportDataset =>
    dataset === 'compliance' ? buildComplianceDataset(role) : buildDrillsDataset(role);

  const run = async (kind: 'pdf' | 'csv' | 'json') => {
    setOpen(false);
    setBusy(true);
    try {
      const ds = build();
      if (kind === 'csv') downloadBlob(ds.name + '.csv', 'text/csv;charset=utf-8', toCsv(ds));
      else if (kind === 'json') downloadBlob(ds.name + '.json', 'application/json;charset=utf-8', toJson(ds));
      else await downloadPdf(ds);
    } finally {
      setBusy(false);
    }
  };

  const itemClass =
    'w-full text-left px-3 py-2 text-sm inline-flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-700';

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Export this view"
        onClick={() => setOpen(!open)}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-600 text-sm font-medium whitespace-nowrap"
      >
        <Download size={14} /> Export{busy ? '…' : ''}
      </button>
      {open && (
        <div
          role="menu"
          aria-label="Export formats"
          className="absolute right-0 z-10 mt-1 w-60 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-lg py-1"
        >
          <button role="menuitem" onClick={() => run('pdf')} className={itemClass}>
            <FileText size={14} /> PDF (regulator-style)
          </button>
          <button role="menuitem" onClick={() => run('csv')} className={itemClass}>
            <FileSpreadsheet size={14} /> CSV
          </button>
          <button role="menuitem" onClick={() => run('json')} className={itemClass}>
            <Braces size={14} /> JSON
          </button>
          <p className="px-3 py-2 text-xs text-slate-500 dark:text-slate-400">
            {role === 'supervisor'
              ? 'Supervisor export: bands and outcomes only.'
              : 'Full notes included for this role.'}{' '}
            Simulated data; exports are renderings, not evidence.
          </p>
        </div>
      )}
    </div>
  );
}
