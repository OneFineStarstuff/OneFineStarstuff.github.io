import { ChevronDown } from 'lucide-react';
import { useState, type ReactNode } from 'react';

export default function ExpandableSection({
  title,
  subtitle,
  defaultOpen = false,
  badge,
  children,
}: {
  title: string;
  subtitle?: string;
  defaultOpen?: boolean;
  badge?: ReactNode;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="overflow-hidden rounded-lg border border-gray-700 bg-gray-800/40" aria-expanded={open}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition-colors hover:bg-gray-800/80"
        aria-label={`${open ? 'Collapse' : 'Expand'} ${title}`}
      >
        <span className="flex flex-1 flex-col">
          <span className="text-sm font-semibold text-gray-100">{title}</span>
          {subtitle && <span className="mt-0.5 text-xs text-gray-400">{subtitle}</span>}
        </span>
        <span className="flex items-center gap-2">
          {badge}
          <ChevronDown size={16} className={`text-gray-400 transition-transform ${open ? 'rotate-180' : ''}`} />
        </span>
      </button>
      {open && <div className="border-t border-gray-700/70 px-4 py-4">{children}</div>}
    </section>
  );
}
