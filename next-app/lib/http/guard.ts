/**
 * Request-hardening helpers (closes DASH-03 / DASH-08).
 *  - Enforce a body-size cap before parsing JSON (unbounded body = DoS surface).
 *  - Parse JSON safely (never throw to the caller; return null on bad input).
 *  - Sanitize values before they are embedded in SSE `data:` frames (log/stream
 *    injection via newlines).
 */

export const MAX_BODY_BYTES = 16 * 1024; // 16 KiB is ample for chat/consent/intent

export type ReadResult<T> = { ok: true; data: T } | { ok: false; status: number; error: string };

/** Read + size-cap + JSON-parse a request body. */
export async function readJson<T = unknown>(
  req: Request,
  maxBytes: number = MAX_BODY_BYTES,
): Promise<ReadResult<T>> {
  const lenHeader = req.headers.get('content-length');
  if (lenHeader && Number(lenHeader) > maxBytes) {
    return { ok: false, status: 413, error: 'payload too large' };
  }
  let text: string;
  try {
    text = await req.text();
  } catch {
    return { ok: false, status: 400, error: 'unreadable body' };
  }
  if (text.length > maxBytes) {
    return { ok: false, status: 413, error: 'payload too large' };
  }
  if (!text) return { ok: false, status: 400, error: 'empty body' };
  try {
    return { ok: true, data: JSON.parse(text) as T };
  } catch {
    return { ok: false, status: 400, error: 'invalid json' };
  }
}

/** Strip CR/LF and control chars so a value can't forge SSE frames or log lines. */
export function sanitizeForStream(s: string, maxLen = 8_000): string {
  return s.replace(/[\r\n\u0000-\u001f\u007f]/g, ' ').slice(0, maxLen);
}
