import { NextRequest } from 'next/server';
import { appendConsentEvent, exportConsent } from '@/lib/privacy/consentLedger';

export const runtime = 'nodejs';

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
  const { userId = 'demo', sessionId, action } = await req.json();
  if (!['persist_on','persist_off','export'].includes(action)) return new Response('bad action', { status: 400 });
  const ev = await appendConsentEvent({ userId, sessionId, action, ts: new Date().toISOString() as any });
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
