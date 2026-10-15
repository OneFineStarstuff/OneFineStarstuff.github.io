import type { NextRequest } from 'next/server';
import { appendConsentEvent, exportConsent } from '@/lib/privacy/consentLedger';
import type { ConsentAction } from '@/lib/privacy/consentLedger';

export const runtime = 'nodejs';

const CONSENT_ACTIONS = ['persist_on', 'persist_off', 'export'] as const;

/** Type guard for the supported user-consent actions. */
function isConsentAction(value: unknown): value is ConsentAction {
  return CONSENT_ACTIONS.some((action) => action === value);
}

/**
 * Handles POST requests to process user consent actions.
 *
 * The body is treated as untrusted input. User and session identifiers must be
 * strings, and the action must be one of the supported consent actions.
 */
export async function POST(req: NextRequest) {
  let body: unknown;

  try {
    body = await req.json();
  } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return Response.json({ error: 'Expected a JSON object' }, { status: 400 });
  }

  const payload = body as Record<string, unknown>;
  const userId = payload.userId === undefined ? 'demo' : payload.userId;
  const sessionId = payload.sessionId;
  const action = payload.action;

  if (typeof userId !== 'string' || userId.trim().length === 0) {
    return Response.json({ error: 'userId must be a non-empty string' }, { status: 400 });
  }

  if (sessionId !== undefined && typeof sessionId !== 'string') {
    return Response.json({ error: 'sessionId must be a string when provided' }, { status: 400 });
  }

  if (!isConsentAction(action)) {
    return Response.json({ error: 'Unsupported consent action' }, { status: 400 });
  }

  const ev = await appendConsentEvent({
    userId,
    ...(typeof sessionId === 'string' ? { sessionId } : {}),
    action,
    ts: new Date().toISOString(),
  });

  return Response.json(ev);
}

/**
 * Handles GET requests and returns consent data for a user.
 */
export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const userId = searchParams.get('userId') ?? 'demo';
  const data = await exportConsent(userId);
  return Response.json(data);
}
