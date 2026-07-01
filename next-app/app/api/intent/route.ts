import { getPrincipal, UNAUTHORIZED } from '@/lib/auth/session';
import { readJson } from '@/lib/http/guard';

export const runtime = 'nodejs';

/**
 * Classify message intent. Hardened per DASH-08: authenticated, size-capped
 * body, and explicit validation of `message`. The classifier regex is linear
 * (no catastrophic backtracking).
 */
export async function POST(req: Request) {
  const principal = getPrincipal(req);
  if (!principal) return UNAUTHORIZED();

  const body = await readJson<{ message?: unknown }>(req);
  if (!body.ok) return new Response(JSON.stringify({ error: body.error }), { status: body.status });

  const message = body.data.message;
  if (typeof message !== 'string') {
    return new Response(JSON.stringify({ error: 'message required' }), { status: 400 });
  }

  const intent = /simulate|prove|optimize|model/i.test(message) ? 'analytical' : 'casual';
  return new Response(JSON.stringify({ intent }), {
    headers: { 'content-type': 'application/json' },
  });
}
