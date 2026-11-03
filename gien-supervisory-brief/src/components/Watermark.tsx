import { useSearchParams } from 'react-router-dom';

// Fictional/simulation watermark applied to every page and to exported artefacts.
export const WATERMARK_TEXT = 'FICTIONAL / SIMULATION';
export const WATERMARK_NOTE =
  'GIEN governance universe scenario data. Not a real regulatory filing, assessment, or forecast.';

export interface WatermarkProvenance {
  watermark: string;
  note: string;
  generated_at: string;
  filing_reference: string;
}

export function watermarkProvenance(filingReference: string): WatermarkProvenance {
  return {
    watermark: WATERMARK_TEXT,
    note: WATERMARK_NOTE,
    generated_at: new Date().toISOString(),
    filing_reference: filingReference,
  };
}

// Visible page watermark: compact ribbon plus a repeating diagonal faint overlay.
export default function Watermark({ compact = false }: { compact?: boolean }) {
  return (
    <div aria-hidden="true" className="pointer-events-none select-none">
      <div
        className={
          compact
            ? 'mb-3 inline-flex items-center gap-2 rounded border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 text-[10px] font-semibold tracking-widest text-violet-300'
            : 'mb-4 flex items-center justify-between gap-3 rounded border border-violet-500/30 bg-violet-500/10 px-3 py-1.5 text-[10px] font-semibold tracking-widest text-violet-300'
        }
      >
        <span>{WATERMARK_TEXT}</span>
        {!compact && <span className="hidden font-normal tracking-normal text-violet-300/70 md:inline">{WATERMARK_NOTE}</span>}
      </div>
    </div>
  );
}

// Helper used by export buttons so CSV/JSON artefacts carry provenance.
export function withWatermarkRow<T extends Record<string, unknown>>(rows: T[], filingReference: string): Array<T & { watermark?: string }> {
  return rows.map((r, i) => (i === 0 ? { ...r, watermark: `${WATERMARK_TEXT} — ${filingReference}` } : r));
}

// Utility: keep query params (role/layer) intact when navigating programmatically.
export function usePreservedParams(): (path: string) => string {
  const [params] = useSearchParams();
  return (path: string) => {
    const qs = params.toString();
    return qs ? `${path}?${qs}` : path;
  };
}
