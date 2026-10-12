import type { ReactNode } from 'react';

export type BadgeVariant =
  | 'NOMINAL' | 'ELEVATED' | 'CRITICAL' | 'SAFEGUARD'
  | 'COMPLIANT' | 'PARTIAL' | 'NON_COMPLIANT' | 'PENDING' | 'NOT_APPLICABLE'
  | 'VERIFIED' | 'SEALED'
  | 'ACTIVE' | 'STANDBY' | 'DEGRADED'
  | 'PROVED' | 'UNPROVED' | 'COUNTEREXAMPLE'
  | 'WATCH' | 'CONTAINED';

const VARIANT_CLASSES: Record<BadgeVariant, string> = {
  NOMINAL: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  ELEVATED: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  SAFEGUARD: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  COMPLIANT: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  PARTIAL: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  NON_COMPLIANT: 'bg-red-500/15 text-red-400 border-red-500/30',
  PENDING: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  NOT_APPLICABLE: 'bg-gray-600/15 text-gray-400 border-gray-600/30',
  VERIFIED: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  SEALED: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
  ACTIVE: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  STANDBY: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  DEGRADED: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  PROVED: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  UNPROVED: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  COUNTEREXAMPLE: 'bg-red-500/15 text-red-400 border-red-500/30',
  WATCH: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  CONTAINED: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
};

const VARIANT_LABELS: Partial<Record<BadgeVariant, string>> = {
  NON_COMPLIANT: 'NON-COMPLIANT',
  COUNTEREXAMPLE: 'COUNTEREXAMPLE FOUND',
};

export function isBadgeVariant(s: string): s is BadgeVariant {
  return s in VARIANT_CLASSES;
}

export default function StatusBadge({ variant, label, className = '' }: {
  variant: BadgeVariant | string;
  label?: string;
  className?: string;
}) {
  const key = variant.toUpperCase().replace(/-/g, '_').replace(/ /g, '_');
  const v: BadgeVariant = isBadgeVariant(key) ? key : 'NOT_APPLICABLE';
  return (
    <span
      role="status"
      aria-label={label ?? v}
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-wide ${VARIANT_CLASSES[v]} ${className}`}
    >
      {label ?? VARIANT_LABELS[v] ?? v.replace(/_/g, '-')}
    </span>
  );
}

// Small helper used across pages for label/value pair layout
export function KV({ label, value, mono = false }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1">
      <span className="text-xs text-gray-400">{label}</span>
      <span className={`text-xs text-gray-100 ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  );
}
