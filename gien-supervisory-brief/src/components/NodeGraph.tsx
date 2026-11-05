// Pure-SVG node graph: nodes positioned in a circle, edges drawn between pairs.

export interface GraphNode {
  id: string;
  label: string;
  value: number; // 0..1, drives radius
  status: 'NOMINAL' | 'ELEVATED' | 'CRITICAL' | 'SAFEGUARD' | string;
}

export interface GraphEdge {
  from: string;
  to: string;
  weight?: number; // 0..1 correlation
}

const STATUS_FILL: Record<string, string> = {
  NOMINAL: '#10b981',
  ELEVATED: '#f59e0b',
  CRITICAL: '#ef4444',
  SAFEGUARD: '#a78bfa',
};

export default function NodeGraph({
  nodes,
  edges,
  size = 460,
  height,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  size?: number;
  height?: number;
}) {
  const h = height ?? size;
  const cx = size / 2;
  const cy = h / 2;
  const R = Math.min(size, h) / 2 - 56;
  const pos = (i: number): [number, number] => {
    const a = (Math.PI * 2 * i) / nodes.length - Math.PI / 2;
    return [cx + R * Math.cos(a), cy + R * Math.sin(a)];
  };
  const idx = new Map(nodes.map((n, i) => [n.id, i]));

  return (
    <svg viewBox={`0 0 ${size} ${h}`} className="max-w-full" role="img" aria-label="Node graph visualization">
      {edges.map((e, i) => {
        const a = idx.get(e.from);
        const b = idx.get(e.to);
        if (a === undefined || b === undefined) return null;
        const [x1, y1] = pos(a);
        const [x2, y2] = pos(b);
        return (
          <line
            key={i}
            x1={x1}
            y1={y1}
            x2={x2}
            y2={y2}
            stroke="#4b5563"
            strokeWidth={0.8 + (e.weight ?? 0.4) * 2}
            strokeOpacity={0.25 + (e.weight ?? 0.4) * 0.5}
          />
        );
      })}
      {nodes.map((n, i) => {
        const [x, y] = pos(i);
        const r = 7 + n.value * 16;
        const fill = STATUS_FILL[n.status] ?? '#6b7280';
        return (
          <g key={n.id}>
            <circle cx={x} cy={y} r={r + 4} fill={fill} opacity={0.15} />
            <circle cx={x} cy={y} r={r} fill={fill} />
            <text x={x} y={y + r + 14} fontSize={9.5} fill="#9ca3af" textAnchor="middle" fontFamily="ui-monospace, monospace">
              {n.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
