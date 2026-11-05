import { X } from 'lucide-react';
import { useEffect, type ReactNode } from 'react';

export default function DetailDrawer({
  open,
  onClose,
  title,
  subtitle,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    globalThis.addEventListener('keydown', onKey);
    return () => globalThis.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex justify-end no-print" role="dialog" aria-modal="true" aria-label={title}>
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <aside className="relative flex h-full w-full max-w-xl flex-col overflow-y-auto border-l border-gray-700 bg-gray-900 shadow-2xl">
        <header className="sticky top-0 flex items-start justify-between gap-4 border-b border-gray-700 bg-gray-900 px-5 py-4">
          <div>
            <h2 className="text-base font-semibold text-gray-100">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-gray-400">{subtitle}</p>}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close detail drawer"
            className="rounded-md border border-gray-700 p-1.5 text-gray-400 hover:bg-gray-800 hover:text-gray-200"
          >
            <X size={16} />
          </button>
        </header>
        <div className="flex-1 px-5 py-4">{children}</div>
      </aside>
    </div>
  );
}
