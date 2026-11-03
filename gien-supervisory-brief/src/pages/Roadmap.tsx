import { useMemo, useState } from 'react';
import { CalendarClock } from 'lucide-react';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import { ROADMAP } from '../data/extendedData';
import { FICTIONAL_NOTICE } from '../data/extendedData';

const KINDS = ['ALL', 'REAL', 'FICTIONAL'] as const;

export default function Roadmap() {
  const [kind, setKind] = useState<(typeof KINDS)[number]>('ALL');

  const milestones = useMemo(
    () => ROADMAP.filter((m) => kind === 'ALL' || m.kind === kind).sort((a, b) => a.date.localeCompare(b.date)),
    [kind]
  );

  const years = useMemo(() => {
    const grouped = new Map<string, typeof milestones>();
    milestones.forEach((m) => {
      const y = m.date.slice(0, 4);
      grouped.set(y, [...(grouped.get(y) ?? []), m]);
    });
    return Array.from(grouped.entries());
  }, [milestones]);

  return (
    <div>
      <PageHeader
        title="Regulatory Roadmap"
        subtitle="Obligation dates across real frameworks and fictional GIEN instruments"
        crumbs={[{ label: 'Home', to: '/dashboard' }, { label: 'Roadmap' }]}
      />

      <div className="mb-4 flex items-center gap-2">
        <div className="flex items-center gap-1 rounded-md border border-gray-700 p-0.5">
          {KINDS.map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => setKind(k)}
              aria-pressed={kind === k}
              className={`rounded px-2.5 py-1 text-[11px] ${kind === k ? 'bg-indigo-500 text-white' : 'text-gray-400 hover:text-gray-200'}`}
            >
              {k}
            </button>
          ))}
        </div>
        <span className="rounded bg-violet-500/10 px-2 py-1 text-[11px] text-violet-300">
          Fictional instruments are labelled and are not real obligations
        </span>
      </div>

      <div className="space-y-6">
        {years.map(([year, items]) => (
          <section key={year}>
            <h2 className="mb-2 font-mono text-sm text-indigo-300">{year}</h2>
            <ol className="relative space-y-3 border-l border-gray-700 pl-4">
              {items.map((m) => (
                <li key={m.id} className="relative">
                  <span className="absolute -left-[21px] top-2 h-2 w-2 rounded-full bg-indigo-500" aria-hidden="true" />
                  <div className="rounded-lg border border-gray-700 bg-gray-800/50 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h3 className="text-sm font-semibold text-gray-100">{m.title}</h3>
                      <div className="flex items-center gap-2">
                        <StatusBadge variant={m.kind === 'FICTIONAL' ? 'SEALED' : 'VERIFIED'} label={m.kind} />
                        <StatusBadge variant={m.status === 'COMPLETE' ? 'COMPLIANT' : m.status === 'ACTIVE' ? 'ELEVATED' : 'PENDING'} label={m.status} />
                      </div>
                    </div>
                    <p className="mt-1 text-xs text-gray-400">{m.detail}</p>
                    <p className="mt-1.5 flex items-center gap-1 font-mono text-[11px] text-gray-500">
                      <CalendarClock size={11} /> {m.date} · {m.framework}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          </section>
        ))}
      </div>

      <p className="mt-5 text-[11px] text-gray-500">{FICTIONAL_NOTICE}</p>
    </div>
  );
}
