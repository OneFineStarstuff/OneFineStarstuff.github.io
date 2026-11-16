/**
 * M4 (WP-110): regulator-ready export utilities for the GIEN supervisory console.
 * CSV and JSON are produced natively; PDF uses jsPDF, lazy-loaded so the core
 * bundle keeps working without it.
 *
 * Honesty model: exports are renderings of the sealed dossier corpus and carry
 * the fictional-simulation disclaimer plus the sealed Merkle root reference.
 * They are NOT evidence: every conformance claim in a regulator-ready export
 * must link an artefact digest (WP-096 evidence contract).
 *
 * Role-gating: supervisor exports carry bands and outcomes only; engineer and
 * educational exports add the full notes from the sealed corpus.
 */
import { REGIMES, CATALOG_REV } from '../data/regimes';
import { DRILLS } from '../data/drills';
import { Role } from '../types/gien';

export const EXPORT_DISCLAIMER =
  'Fictional governance simulation. GIEN, Omni-Sentinel and all indices, drills, filings, ' +
  'signatures and Merkle roots shown are simulated artefacts and do not describe real systems. ' +
  'Rendering of the sealed dossier corpus; not itself evidence.';

/** Sealed corpus provenance for the compliance matrix and drills register (WP-108 data). */
const SOURCE_DOSSIER = 'GIEN-DOSSIER-2026-320';
const SOURCE_MERKLE_ROOT = '0x8f2c41d7a96e3b50c4d8f1a6e2b97c05d3e84a61f7b20c9d5e1a3846b0c7f29d';

export interface ExportDataset {
  /** File stem without extension, e.g. gien-compliance-2026-320. */
  name: string;
  title: string;
  columns: string[];
  rows: string[][];
  meta: Record<string, string>;
  disclaimer: string;
}

function roleNote(role: Role): string {
  if (role === 'supervisor') return 'bands and outcomes only';
  if (role === 'engineer') return 'full notes (Governance Engineer)';
  return 'full notes (Educational)';
}

export function buildComplianceDataset(role: Role): ExportDataset {
  const columns = ['Regime', 'Kind', 'OSCAL 1.1.2', 'OPA-Rego', 'Band', 'Note'];
  const rows = REGIMES.map((r) => [
    r.name,
    r.kind,
    r.oscal,
    r.opa,
    r.band,
    role === 'supervisor' ? r.band + ' - bands and outcomes only' : r.note
  ]);
  return {
    name: 'gien-compliance-2026-320',
    title: 'GIEN Compliance Matrix - ' + REGIMES.length + ' regimes (OSCAL 1.1.2 / OPA-Rego)',
    columns,
    rows,
    meta: {
      'Catalog rev': CATALOG_REV,
      'Sealed corpus': SOURCE_DOSSIER + ' (compliance matrix and drills register)',
      'Sealed Merkle root': SOURCE_MERKLE_ROOT,
      'Export role': roleNote(role)
    },
    disclaimer: EXPORT_DISCLAIMER
  };
}

export function buildDrillsDataset(role: Role): ExportDataset {
  const columns = ['Drill', 'Date', 'Mode', 'Outcome', 'Convergence', 'Target', 'Replay determinism', 'Band', 'Note'];
  const rows = DRILLS.map((d) => [
    d.id + ' ' + d.name,
    d.date,
    d.mode,
    d.outcome,
    d.convergence || '-',
    d.target,
    d.replayDeterminism,
    d.band,
    d.note
  ]);
  return {
    name: 'gien-drills-2026-320',
    title: 'GIEN Supervisory Digital Twin - Drills Register',
    columns,
    rows,
    meta: {
      'Sealed corpus': SOURCE_DOSSIER + ' (compliance matrix and drills register)',
      'Sealed Merkle root': SOURCE_MERKLE_ROOT,
      'Export role': roleNote(role)
    },
    disclaimer: EXPORT_DISCLAIMER
  };
}

/** CSV field with formula-injection guard (=, +, -, @, tab prefixes get a leading quote). */
function csvField(v: string): string {
  const s = String(v);
  const guarded = /^[=+\-@\t]/.test(s) ? "'" + s : s;
  return /[",\n]/.test(guarded) ? '"' + guarded.replace(/"/g, '""') + '"' : guarded;
}

export function toCsv(ds: ExportDataset): string {
  const lines = [ds.columns.map(csvField).join(',')];
  for (const row of ds.rows) lines.push(row.map(csvField).join(','));
  return lines.join('\r\n') + '\r\n';
}

export function toJson(ds: ExportDataset): string {
  const records = ds.rows.map((row) => {
    const o: Record<string, string> = {};
    ds.columns.forEach((c, i) => {
      o[c] = row[i];
    });
    return o;
  });
  return (
    JSON.stringify(
      {
        export: ds.name,
        title: ds.title,
        meta: ds.meta,
        columns: ds.columns,
        records,
        disclaimer: ds.disclaimer
      },
      null,
      2
    ) + '\n'
  );
}

export function downloadBlob(filename: string, mime: string, content: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Regulator-style PDF via lazy-loaded jsPDF: banner, metadata, wrapped table, disclaimer. */
export async function downloadPdf(ds: ExportDataset): Promise<void> {
  const { jsPDF } = await import('jspdf');
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const pw = doc.internal.pageSize.getWidth();
  const ph = doc.internal.pageSize.getHeight();
  const margin = 40;
  const usable = pw - 2 * margin;
  let y = margin;

  const ensure = (h: number) => {
    if (y + h > ph - margin) {
      doc.addPage();
      y = margin;
    }
  };

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.text('TOP SECRET // SUPERVISORY EYES ONLY', pw / 2, y, { align: 'center' });
  y += 20;
  doc.setFontSize(14);
  doc.text(ds.title, margin, y, { maxWidth: usable });
  y += 20;

  doc.setFont('courier', 'normal');
  doc.setFontSize(9);
  Object.keys(ds.meta).forEach((k) => {
    ensure(12);
    doc.text(k + ': ' + ds.meta[k], margin, y, { maxWidth: usable });
    y += 12;
  });
  y += 6;

  const weights = ds.columns.map((c, i) =>
    Math.max(c.length, ...ds.rows.map((r) => (r[i] || '').length), 8)
  );
  const capped = weights.map((w) => Math.min(w, 60));
  const total = capped.reduce((a, b) => a + b, 0);
  const widths = capped.map((w) => (w / total) * usable);

  const drawRow = (cells: string[], bold: boolean) => {
    doc.setFont('courier', bold ? 'bold' : 'normal');
    doc.setFontSize(8);
    const wrapped = cells.map((c, i) => doc.splitTextToSize(c || '', widths[i] - 4)) as string[][];
    const lineCount = Math.max(...wrapped.map((w) => w.length));
    const rowH = lineCount * 10 + 6;
    ensure(rowH);
    let x = margin;
    wrapped.forEach((lines, i) => {
      lines.forEach((ln, j) => doc.text(ln, x, y + j * 10));
      x += widths[i];
    });
    y += rowH;
    doc.setDrawColor(200);
    doc.line(margin, y - 3, pw - margin, y - 3);
  };

  drawRow(ds.columns, true);
  for (const row of ds.rows) drawRow(row, false);

  y += 10;
  doc.setFont('helvetica', 'italic');
  doc.setFontSize(8);
  const disc = doc.splitTextToSize(ds.disclaimer, usable) as string[];
  disc.forEach((ln) => {
    ensure(11);
    doc.text(ln, margin, y);
    y += 11;
  });

  doc.save(ds.name + '.pdf');
}
