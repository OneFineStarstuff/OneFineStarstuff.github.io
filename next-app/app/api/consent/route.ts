import { NextRequest } from 'next/server';
import { appendConsentEvent, exportConsent, type ConsentAction } from '@/lib/privacy/consentLedger';

export const runtime = 'nodejs';

const CONSENT_ACTIONS = ['persist_on', 'persist_off', 'export'] as const;

function isConsentAction(value: unknown): value is ConsentAction {
  return typeof value === 'string' && (CONSENT_ACTIONS as readonly string[]).includes(value);
}

/**
 * Handles POST requests to process user consent actions.
 *
 * This function extracts the userId, sessionId, and action from the request body.
 * It validates the action against a predefined list and returns a 400 response for invalid actions.
 * If the action is valid, it appends a consent event using the appendConsentEvent function and returns the result as a JSON response.
 *
 * @param req - The NextRequest object containing the request data.
 */
export async function POST(req: NextRequest) {
  const body: unknown = await req.json();
  const record = body && typeof body === 'object' ? body as Record<string, unknown> : {};
  const userId = typeof record.userId === 'string' && record.userId.length > 0 ? record.userId : 'demo';
  const sessionId = typeof record.sessionId === 'string' ? record.sessionId : undefined;
  if (!isConsentAction(record.action)) return new Response('bad action', { status: 400 });
  const ev = await appendConsentEvent({ userId, sessionId, action: record.action, ts: new Date().toISOString() });
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
