import { NextRequest } from 'next/server';
import { appendConsentEvent, exportConsent } from '@/lib/privacy/consentLedger';

export const runtime = 'nodejs';

type ConsentAction = 'persist_on' | 'persist_off' | 'export';

/**
 * Handles POST requests to process consent actions.
 *
 * This endpoint is demo-only until an authenticated server-side identity
 * provider is connected. Do not accept client-selected user IDs as identities.
 */
export async function POST(req: NextRequest) {
  let payload: unknown;
  try {
    payload = await req.json();
  } catch {
    return new Response('invalid JSON body', { status: 400 });
  }

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return new Response('invalid request body', { status: 400 });
  }

  const body = payload as Record<string, unknown>;
  const userId = body.userId === undefined ? 'demo' : body.userId;
  const sessionId = body.sessionId;
  const action = body.action;

  if (userId !== 'demo') {
    return new Response('authenticated identity is not configured; only demo records are supported', { status: 403 });
  }

  if (action !== 'persist_on' && action !== 'persist_off' && action !== 'export') {
    return new Response('bad action', { status: 400 });
  }

  if (sessionId !== undefined && (typeof sessionId !== 'string' || sessionId.length > 128)) {
    return new Response('invalid sessionId', { status: 400 });
  }

  const consentAction: ConsentAction = action;
  const ev = await appendConsentEvent({
    userId: 'demo',
    ...(typeof sessionId === 'string' ? { sessionId } : {}),
    action: consentAction,
    ts: new Date().toISOString()
  });
  return Response.json(ev);
}

/**
 * Handles GET requests and returns consent data for the demo user.
 */
export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const userId = searchParams.get('userId') ?? 'demo';
  if (userId !== 'demo') {
    return new Response('authenticated identity is not configured; only demo records are supported', { status: 403 });
  }
  const data = await exportConsent('demo');
  return Response.json(data);
}
