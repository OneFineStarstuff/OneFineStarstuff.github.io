export interface TimelineEvent {
  at: string; // e.g. "08:00"
  label: string;
  state: 'DONE' | 'PENDING' | 'ACTIVE' | 'FAILED';
}

// Pure-SVG horizontal timeline (00:00 -> 23:59 style or arbitrary event list).
export default function TimelineVisualization({
  events,
  startHour = 0,
  endHour = 24,
  height = 120,
}: {
  events: TimelineEvent[];
  startHour?: number;
  endHour?: number;
  height?: number;
}) {
  const width = 960;
  const y = 40;
  const span = endHour - startHour;
  const px = (hour: number) => 24 + (hour - startHour) * ((width - 48) / span);
  const colorOf = (s: TimelineEvent['state']) =>
    s === 'DONE' ? '#10b981' : s === 'ACTIVE' ? '#a78bfa' : s === 'FAILED' ? '#ef4444' : '#3b82f6';

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${width} ${height}`} className="min-w-[720px]" role="img" aria-label="Supervisory cycle timeline">
        <line x1={px(startHour)} y1={y} x2={px(endHour)} y2={y} stroke="#374151" strokeWidth={2} />
        {[0, 3, 6, 9, 12, 15, 18, 21, 23.983].map((h) => (
          <g key={h}>
            <line x1={px(h)} y1={y - 5} x2={px(h)} y2={y + 5} stroke="#4b5563" strokeWidth={1} />
            <text x={px(h)} y={y + 18} fontSize={9} fill="#6b7280" textAnchor="middle" fontFamily="ui-monospace, monospace">
              {`${String(Math.floor(h)).padStart(2, '0')}:00`}
            </text>
          </g>
        ))}
        {events.map((e) => {
          const hour = parseFloat(e.at.split(':')[0]) + parseFloat(e.at.split(':')[1]) / 60;
          const x = px(Math.min(Math.max(hour, startHour), endHour));
          const c = colorOf(e.state);
          const up = e.at === '23:59'; // stack the last event label above
          return (
            <g key={`${e.at}-${e.label}`}>
              <circle cx={x} cy={y} r={5} fill={c} />
              <circle cx={x} cy={y} r={9} fill="none" stroke={c} strokeOpacity={0.4} />
              <text
                x={x}
                y={up ? y - 28 : y + 34}
                fontSize={9.5}
                fill={c}
                textAnchor="middle"
                fontFamily="ui-monospace, monospace"
              >
                {e.at}
              </text>
              <text
                x={x}
                y={up ? y - 16 : y + 46}
                fontSize={9}
                fill="#9ca3af"
                textAnchor="middle"
              >
                {e.label.length > 26 ? `${e.label.slice(0, 26)}…` : e.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
