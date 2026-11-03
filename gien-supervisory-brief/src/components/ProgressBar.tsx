export default function ProgressBar({
  value,
  threshold,
  label,
  color,
}: {
  value: number; // 0-100
  threshold?: number; // 0-100 marker position
  label?: string;
  color?: string; // tailwind bar class, defaults to indigo
}) {
  const clamped = Math.min(100, Math.max(0, value));
  const bar = color ?? (clamped >= 90 ? 'bg-emerald-500' : clamped >= 70 ? 'bg-indigo-500' : 'bg-amber-500');
  return (
    <div>
      {label && (
        <div className="mb-1 flex justify-between text-xs text-gray-400">
          <span>{label}</span>
          <span className="font-mono">{clamped.toFixed(0)}%</span>
        </div>
      )}
      <div className="relative h-2.5 w-full overflow-hidden rounded-full bg-gray-700">
        <div className={`h-full rounded-full ${bar}`} style={{ width: `${clamped}%` }} />
        {typeof threshold === 'number' && (
          <div className="absolute top-0 h-full w-0.5 bg-red-400" style={{ left: `${threshold}%` }} title={`threshold ${threshold}%`} />
        )}
      </div>
    </div>
  );
}
