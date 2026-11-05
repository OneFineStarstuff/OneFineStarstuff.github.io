import { useMemo } from 'react';
import type { AttestationNode, Phase } from '../types';

export function AttestationHeatmap({ nodes }: { nodes: AttestationNode[] }) {
  const cols = 12;
  const size = 22;
  const rows = Math.ceil(nodes.length / cols);
  return (
    <svg width={cols * size + 20} height={rows * size + 20} role="img" aria-label="Attestation heatmap">
      <title>Attestation density heatmap (72 nodes)</title>
      {nodes.map((n, i) => {
        const x = (i % cols) * size + 10;
        const y = Math.floor(i / cols) * size + 10;
        const fill = n.valid ? '#10b981' : '#f59e0b';
        return (
          <g key={n.id}>
            <rect x={x} y={y} width={size - 3} height={size - 3} rx={3} fill={fill} opacity={n.valid ? 0.9 : 0.6}>
              <title>{`${n.id} · ${n.region} · ${n.algorithm} · ${n.valid ? 'valid' : 'pending'}`}</title>
            </rect>
          </g>
        );
      })}
    </svg>
  );
}

export function MerkleChainVisualizer({ leaves = 8 }: { leaves?: number }) {
  const w = 640;
  const step = w / leaves;
  const yLeaf = 90, yParents = 40, yRoot = 15;
  const parents = leaves / 2;
  const pStep = w / parents;
  const rnd = (i: number) => `sha3-512:${(i * 131 + 7).toString(16).padStart(6, '0')}…`;
  return (
    <svg viewBox={`0 0 ${w} 120`} className="w-full" role="img" aria-label="Merkle DAG">
      <title>Merkle-DAG audit chain — 8 leaves, 4 parents, 1 root</title>
      {Array.from({ length: leaves }).map((_, i) => (
        <g key={`l${i}`}>
          <circle cx={i * step + step / 2} cy={yLeaf} r={8} fill="#3b82f6"><title>{rnd(i)}</title></circle>
          <line x1={i * step + step / 2} y1={yLeaf - 8} x2={Math.floor(i / 2) * pStep + pStep / 2} y2={yParents + 8} stroke="#94a3b8" strokeWidth={1} />
        </g>
      ))}
      {Array.from({ length: parents }).map((_, i) => (
        <g key={`p${i}`}>
          <circle cx={i * pStep + pStep / 2} cy={yParents} r={8} fill="#0ea5e9"><title>{rnd(i + 100)}</title></circle>
          <line x1={i * pStep + pStep / 2} y1={yParents - 8} x2={w / 2} y2={yRoot + 8} stroke="#94a3b8" strokeWidth={1} />
        </g>
      ))}
      <circle cx={w / 2} cy={yRoot} r={10} fill="#10b981"><title>Root: sha3-512:62af…d18c</title></circle>
    </svg>
  );
}

export function EpochTimeline({ phases, activeId }: { phases: Phase[]; activeId?: string }) {
  return (
    <div className="space-y-3">
      {phases.map(p => (
        <div key={p.id} className={`flex items-center gap-3 rounded-md border p-3 ${activeId === p.id ? 'border-emerald-400 bg-emerald-50 dark:bg-emerald-950/30' : 'border-slate-200 dark:border-slate-800'}`}>
          <div className="w-32 shrink-0">
            <div className="font-medium text-sm">{p.name}</div>
            <div className="text-xs text-slate-500">{p.epoch}</div>
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <div className="flex-1 h-2 bg-slate-200 dark:bg-slate-800 rounded overflow-hidden">
                <div className="h-full bg-sky-500 transition-all" style={{ width: `${p.readiness}%` }} />
              </div>
              <span className="text-xs font-mono">{p.readiness}%</span>
            </div>
            <div className="text-xs text-slate-500">Maturity L{p.maturity} · {p.objectives.length} objectives</div>
          </div>
        </div>
      ))}
    </div>
  );
}

export function FrameworkGraph({ names }: { names: string[] }) {
  const size = 520;
  const cx = size / 2, cy = size / 2, r = 200;
  const angles = useMemo(() => names.map((_, i) => (2 * Math.PI * i) / names.length - Math.PI / 2), [names.length]);
  return (
    <svg viewBox={`0 0 ${size} ${size}`} className="w-full max-w-2xl" role="img" aria-label="Framework graph">
      <title>Global governance framework relationships</title>
      {angles.map((a, i) => (
        <line key={`e${i}`} x1={cx} y1={cy} x2={cx + r * Math.cos(a)} y2={cy + r * Math.sin(a)} stroke="#cbd5e1" strokeWidth={1} />
      ))}
      <circle cx={cx} cy={cy} r={26} fill="#0f172a" className="dark:fill-slate-100" />
      <text x={cx} y={cy + 4} textAnchor="middle" className="fill-white dark:fill-slate-900 text-xs font-mono">GIEN</text>
      {angles.map((a, i) => {
        const x = cx + r * Math.cos(a);
        const y = cy + r * Math.sin(a);
        return (
          <g key={`n${i}`}>
            <circle cx={x} cy={y} r={9} fill="#0ea5e9" />
            <text x={x} y={y - 14} textAnchor="middle" className="fill-current text-[10px]">{names[i].slice(0, 12)}</text>
          </g>
        );
      })}
    </svg>
  );
}

export function ParityBars({ items }: { items: { label: string; capability: number; control: number }[] }) {
  return (
    <div className="space-y-3">
      {items.map(({ label, capability, control }) => {
        const gap = capability - control;
        return (
          <div key={label}>
            <div className="flex justify-between text-xs mb-1"><span>{label}</span><span className="font-mono">gap {gap > 0 ? '+' : ''}{gap.toFixed(2)}</span></div>
            <div className="relative h-2 rounded bg-slate-200 dark:bg-slate-800 overflow-hidden">
              <div className="absolute inset-y-0 left-0 bg-sky-500" style={{ width: `${capability * 100}%` }} />
              <div className="absolute inset-y-0 left-0 bg-emerald-500/70" style={{ width: `${control * 100}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
