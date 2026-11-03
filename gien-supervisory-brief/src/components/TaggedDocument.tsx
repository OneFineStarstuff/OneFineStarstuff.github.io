import type { ReactNode } from 'react';

// Renders the regulator-ready <title> / <abstract> / <content> tagged document
// structure as visible monospace section headers over the document body.
export default function TaggedDocument({
  title,
  abstract,
  children,
  compact = false,
}: {
  title: string;
  abstract: string;
  children: ReactNode;
  compact?: boolean;
}) {
  return (
    <article className={`rounded-lg border border-gray-700 bg-gray-800/40 print-plain ${compact ? 'p-4' : 'p-6'}`}>
      <header className="font-mono text-[11px] font-bold uppercase tracking-widest text-indigo-400">
        &lt;title&gt;
      </header>
      <h1 className="mt-1 text-lg font-semibold text-gray-50">{title}</h1>
      <div className="my-3 border-t border-dashed border-gray-700" />
      <header className="font-mono text-[11px] font-bold uppercase tracking-widest text-indigo-400">
        &lt;abstract&gt;
      </header>
      <p className="mt-1 text-sm leading-relaxed text-gray-300">{abstract}</p>
      <div className="my-3 border-t border-dashed border-gray-700" />
      <header className="font-mono text-[11px] font-bold uppercase tracking-widest text-indigo-400">
        &lt;content&gt;
      </header>
      <div className="mt-2 space-y-3 text-sm leading-relaxed text-gray-200">{children}</div>
    </article>
  );
}
