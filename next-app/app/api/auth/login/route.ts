import { NextRequest } from 'next/server';
import { mintToken } from '@/lib/auth/session';
import { readJson } from '@/lib/http/guard';

export const runtime = 'nodejs';

/**
 * Demo login: issues a signed `sentinel_session` cookie so the rest of the
 * dashboard's authenticated routes are end-to-end demonstrable.
 *
 * THIS IS A DEMO STUB. It does NOT verify a password — in production this is
 * replaced by the institution's IdP/OIDC flow. The token-minting contract
 * (mintToken) and the verification path (getPrincipal) are the real, tested parts.
 */
export async function POST(req: NextRequest) {
  const body = await readJson<{ userId?: unknown; roles?: unknown }>(req);
  if (!body.ok) return new Response(JSON.stringify({ error: body.error }), { status: body.status });

  const userId = body.data.userId;
  if (typeof userId !== 'string' || userId.length === 0 || userId.length > 128) {
    return new Response(JSON.stringify({ error: 'userId required' }), { status: 400 });
  }
  const roles = Array.isArray(body.data.roles)
    ? (body.data.roles.filter((r) => typeof r === 'string') as string[])
    : [];

  const ttlMs = 3_600_000; // 1h
  const token = mintToken(userId, ttlMs, roles);

  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const cookie =
    `sentinel_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; ` +
    `Max-Age=${Math.floor(ttlMs / 1000)}${secure}`;

  return new Response(JSON.stringify({ ok: true, userId, roles, expiresInMs: ttlMs }), {
    status: 200,
    headers: { 'content-type': 'application/json', 'set-cookie': cookie },
  });
}
