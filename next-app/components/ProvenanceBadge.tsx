"use client";
export function ProvenanceBadge({ meta }: { meta: { name?: string; model?: string; version?: string; layer?: string; latencyMs?: number } }) {
  const label = `${meta.layer ?? 'surface'} • ${meta.name ?? meta.model ?? 'model'} ${meta.version ?? ''}`;
  const color = (meta.layer ?? 'surface') === 'surface' ? '#38A169' : '#1A237E';
  return (
    <span role="status" aria-label={`Model ${label}`} className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs text-slate-700">
      <span className="h-2 w-2 rounded-full" style={{ background: color }} />
      {label}
      {meta.latencyMs != null && <span className="text-slate-500">• {meta.latencyMs}ms</span>}
    </span>
  );
}
