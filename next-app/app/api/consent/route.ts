import { NextRequest } from 'next/server';
import { appendConsentEvent, exportConsent } from '@/lib/privacy/consentLedger';
import { getPrincipal, canAccessSubject, UNAUTHORIZED, FORBIDDEN } from '@/lib/auth/session';
import { readJson } from '@/lib/http/guard';

export const runtime = 'nodejs';

const VALID_ACTIONS = ['persist_on', 'persist_off', 'export'] as const;
type Action = (typeof VALID_ACTIONS)[number];

/**
 * POST consent action.
 *
 * SECURITY (DASH-02 fixed): the subject identity is taken from the AUTHENTICATED
 * principal, never from the request body. Client-supplied `userId`/`sessionId`
 * are ignored for identity. A consent event therefore cannot be forged for
 * another subject.
 */
export async function POST(req: NextRequest) {
  const principal = getPrincipal(req);
  if (!principal) return UNAUTHORIZED();

  const body = await readJson<{ action?: string; sessionId?: string }>(req);
  if (!body.ok) return new Response(JSON.stringify({ error: body.error }), { status: body.status });

  const { action, sessionId } = body.data;
  if (!action || !VALID_ACTIONS.includes(action as Action)) {
    return new Response(JSON.stringify({ error: 'bad action' }), { status: 400 });
  }

  // userId is bound to the authenticated principal — not caller-controlled.
  const ev = await appendConsentEvent({
    userId: principal.userId,
    sessionId: typeof sessionId === 'string' ? sessionId : undefined,
    action: action as Action,
    ts: new Date().toISOString() as unknown as string,
  });
  return Response.json(ev);
}

/**
 * GET consent export.
 *
 * SECURITY (DASH-01 fixed): defaults to the authenticated principal's own
 * record. A different `?userId=` is honored ONLY if the principal owns it or
 * holds the `dpo` role; otherwise 403. No more IDOR over arbitrary subjects.
 */
export async function GET(req: NextRequest) {
  const principal = getPrincipal(req);
  if (!principal) return UNAUTHORIZED();

  const { searchParams } = new URL(req.url);
  const requested = searchParams.get('userId') ?? principal.userId;
  if (!canAccessSubject(principal, requested)) return FORBIDDEN();

  const data = await exportConsent(requested);
  return Response.json(data);
}
