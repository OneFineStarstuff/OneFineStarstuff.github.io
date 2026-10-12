import { TrendingDown, TrendingUp } from 'lucide-react';
import type { ReactNode } from 'react';
import StatusBadge from './StatusBadge';

export default function MetricCard({
  label,
  value,
  unit = '',
  trend,
  threshold,
  status,
  footer,
}: {
  label: string;
  value: string | number;
  unit?: string;
  trend?: number;
  threshold?: string;
  status?: string;
  footer?: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-800/60 p-4">
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs font-medium uppercase tracking-wider text-gray-400">{label}</p>
        {status && <StatusBadge variant={status} />}
      </div>
      <p className="mt-2 font-mono text-2xl font-semibold text-gray-50">
        {value}
        <span className="ml-1 text-sm text-gray-400">{unit}</span>
      </p>
      <div className="mt-1 flex items-center gap-3 text-xs">
        {typeof trend === 'number' && (
          <span className={`inline-flex items-center gap-0.5 font-medium ${trend >= 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
            {trend >= 0 ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
            {trend >= 0 ? '+' : ''}
            {trend}
          </span>
        )}
        {threshold && <span className="text-gray-500">threshold {threshold}</span>}
      </div>
      {footer && <div className="mt-2 border-t border-gray-700/60 pt-2 text-xs text-gray-400">{footer}</div>}
    </div>
  );
}
