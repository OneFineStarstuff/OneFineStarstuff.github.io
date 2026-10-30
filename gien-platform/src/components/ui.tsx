import React from 'react';
import type { Severity } from '../types';
import { useRole } from '../contexts';

export function Watermark() {
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider px-2 py-1 rounded border border-amber-400/50 bg-amber-50 text-amber-800 dark:bg-amber-950/50 dark:text-amber-300">
      FICTIONAL / SIMULATION
    </span>
  );
}

export function StatusBadge({ status }: { status: Severity }) {
  const map: Record<Severity, string> = {
    GREEN: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800',
    AMBER: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border-amber-300 dark:border-amber-800',
    RED: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300 border-red-300 dark:border-red-800',
    CRITICAL: 'bg-fuchsia-100 text-fuchsia-900 dark:bg-fuchsia-950 dark:text-fuchsia-300 border-fuchsia-400 dark:border-fuchsia-800',
  };
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${map[status]}`}>{status}</span>;
}

export function Page({ title, subtitle, children, fictional = true }: { title: string; subtitle?: string; children: React.ReactNode; fictional?: boolean }) {
  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <header className="border-b border-slate-200 dark:border-slate-800 pb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          {subtitle && <p className="text-sm text-slate-500 dark:text-slate-400 mt-1 max-w-3xl">{subtitle}</p>}
        </div>
        {fictional && <Watermark />}
      </header>
      {fictional && (
        <section role="note" aria-label="Evidence status" className="rounded-md border border-amber-300 bg-amber-50 dark:bg-amber-950/30 px-4 py-3 text-sm text-amber-950 dark:text-amber-100">
          <strong>DEMONSTRATION DATA — NOT ASSESSED.</strong> Preloaded metrics, control-domain states, attestation counts, alerts and compliance summaries are synthetic fixtures. No current operational evidence is connected to this frontend. The role/layer selectors are presentation controls, not authentication or authorization; the emergency-stop affordance is simulation-only.
        </section>
      )}
      {children}
    </div>
  );
}

export function Disclosure({ min, children }: { min: 'executive' | 'engineering' | 'crypto'; children: React.ReactNode }) {
  const { layer } = useRole();
  const order = { executive: 0, engineering: 1, crypto: 2 };
  if (order[layer] < order[min]) return null;
  return <>{children}</>;
}

export function Card({ title, action, children }: { title?: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
      {(title || action) && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-800">
          {title && <h3 className="font-medium text-sm">{title}</h3>}
          {action}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}

export function RiskGauge({ value, thresholds, label }: { value: number; thresholds: { amber: number; red: number; critical: number }; label: string }) {
  const R = 80;
  const total = Math.PI * R;
  const v = Math.max(0, Math.min(1, value));
  const arc = (a: number, b: number, color: string) => (
    <path d={`M 20 100 A ${R} ${R} 0 0 1 180 100`} stroke={color} strokeWidth={12} fill="none"
      strokeDasharray={`${(b - a) * total} ${total}`} strokeDashoffset={-a * total} />
  );
  const color = v >= thresholds.critical ? '#dc2626' : v >= thresholds.red ? '#f97316' : v >= thresholds.amber ? '#f59e0b' : '#10b981';
  const angle = Math.PI * (1 - v);
  const nx = 100 + R * Math.cos(angle);
  const ny = 100 - R * Math.sin(angle);
  return (
    <svg viewBox="0 0 200 120" role="img" aria-label={`${label}: ${v.toFixed(2)}`} className="w-full">
      <title>{`${label} — ${v.toFixed(2)}`}</title>
      {arc(0, thresholds.amber, '#10b981')}
      {arc(thresholds.amber, thresholds.red, '#f59e0b')}
      {arc(thresholds.red, thresholds.critical, '#f97316')}
      {arc(thresholds.critical, 1, '#dc2626')}
      <line x1={100} y1={100} x2={nx} y2={ny} stroke={color} strokeWidth={3} />
      <circle cx={100} cy={100} r={5} fill={color} />
      <text x={100} y={118} textAnchor="middle" className="fill-current text-sm font-mono">{v.toFixed(2)}</text>
    </svg>
  );
}

export function Sparkline({ data, width = 160, height = 36, color }: { data: number[]; width?: number; height?: number; color?: string }) {
  const max = Math.max(...data, 0.001), min = Math.min(...data, 0);
  const span = max - min || 1;
  const step = width / Math.max(1, data.length - 1);
  const d = data.map((v, i) => `${i === 0 ? 'M' : 'L'} ${i * step} ${height - ((v - min) / span) * height}`).join(' ');
  return (
    <svg width={width} height={height} role="img" aria-label="24h trend">
      <title>24-hour trend</title>
      <path d={d} fill="none" stroke={color || '#3b82f6'} strokeWidth={1.75} />
    </svg>
  );
}

export function ComplianceProgressBar({ value, total }: { value: number; total: number }) {
  const pct = total === 0 ? 0 : Math.min(100, (value / total) * 100);
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
        <div className="h-full bg-emerald-500 transition-all duration-500" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-slate-500 w-16 text-right">{value}/{total}</span>
    </div>
  );
}

export function download(filename: string, content: string, mime = 'text/plain') {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

export function toCsv(rows: Record<string, string | number | boolean>[]): string {
  if (rows.length === 0) return '';
  const headers = Object.keys(rows[0]);
  const cell = (value: string | number | boolean): string => {
    let text = String(value ?? '');
    // Spreadsheet cells beginning with formula operators are treated as text.
    if (typeof value === 'string' && /^[\t\r\n ]*[=+\-@]/.test(text)) text = "'" + text;
    return `"${text.replace(/"/g, '""')}"`;
  };
  const body = rows.map(r => headers.map(h => cell(r[h] ?? '')).join(','));
  return [headers.map(cell).join(','), ...body].join('\r\n');
}
