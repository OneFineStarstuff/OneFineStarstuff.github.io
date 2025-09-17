import { NextRequest } from 'next/server';
import { appendConsentEvent, exportConsent } from '@/lib/privacy/consentLedger';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
  const { userId = 'demo', sessionId, action } = await req.json();
  if (!['persist_on','persist_off','export'].includes(action)) return new Response('bad action', { status: 400 });
  const ev = await appendConsentEvent({ userId, sessionId, action, ts: new Date().toISOString() as any });
  return Response.json(ev);
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const userId = searchParams.get('userId') ?? 'demo';
  const data = await exportConsent(userId);
  return Response.json(data);
}
