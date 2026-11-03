// Pure-SVG radar / spider chart for normalized 0-1 risk indices.
export default function RadarChart({
  axes,
  values,
  size = 320,
}: {
  axes: string[];
  values: number[]; // each 0..1
  size?: number;
}) {
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 44;
  const n = axes.length;
  const angle = (i: number) => (Math.PI * 2 * i) / n - Math.PI / 2;
  const pt = (i: number, v: number): [number, number] => [
    cx + r * v * Math.cos(angle(i)),
    cy + r * v * Math.sin(angle(i)),
  ];
  const ring = (v: number) => axes.map((_, i) => pt(i, v).join(',')).join(' ');
  const dataPoly = values.map((v, i) => pt(i, Math.min(1, Math.max(0, v))).join(',')).join(' ');

  return (
    <svg viewBox={`0 0 ${size} ${size}`} className="max-w-full" role="img" aria-label="Risk indices radar chart">
      {[0.25, 0.5, 0.75, 1].map((v) => (
        <polygon key={v} points={ring(v)} fill="none" stroke="#374151" strokeWidth={1} />
      ))}
      {axes.map((_, i) => {
        const [px, py] = pt(i, 1);
        return <line key={i} x1={cx} y1={cy} x2={px} y2={py} stroke="#374151" strokeWidth={1} />;
      })}
      <polygon points={dataPoly} fill="#6366f1" fillOpacity={0.25} stroke="#818cf8" strokeWidth={1.5} />
      {values.map((v, i) => {
        const [px, py] = pt(i, Math.min(1, Math.max(0, v)));
        return <circle key={i} cx={px} cy={py} r={2.5} fill="#818cf8" />;
      })}
      {axes.map((label, i) => {
        const [px, py] = pt(i, 1.18);
        return (
          <text
            key={label}
            x={px}
            y={py}
            textAnchor={Math.abs(px - cx) < 8 ? 'middle' : px > cx ? 'start' : 'end'}
            dominantBaseline="middle"
            fontSize={10}
            fill="#9ca3af"
            fontFamily="ui-monospace, monospace"
          >
            {label}
          </text>
        );
      })}
    </svg>
  );
}
