import { useId } from 'react';

interface Props {
  label: string;
  values: number[];
  unit?: string;
}

/**
 * A5 (WP-114): accessible sparkline. No animation (motion safety), no
 * Math.random (A1), role="img" with a full text summary for screen readers.
 */
export default function Sparkline({ label, values, unit = '' }: Props) {
  const titleId = useId();
  if (!values.length) return null;
  const w = 120;
  const h = 32;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = Math.max(max - min, 1e-9);
  const points = values
    .map((v, i) => ((i / Math.max(values.length - 1, 1)) * w).toFixed(1) + ',' + (h - ((v - min) / span) * (h - 4) - 2).toFixed(1))
    .join(' ');
  const summary = label + ': ' + values.length + ' points, ranging ' + min + unit + ' to ' + max + unit;
  return (
    <svg width={w} height={h} viewBox={'0 0 ' + w + ' ' + h} role="img" aria-labelledby={titleId}>
      <title id={titleId}>{summary}</title>
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}
