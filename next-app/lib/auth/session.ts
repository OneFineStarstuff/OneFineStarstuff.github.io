import crypto from 'crypto';

/**
 * Minimal, dependency-free server-side session/auth helper.
 *
 * SECURITY MODEL (closes DASH-01/02/03):
 *  - The authenticated principal is derived ONLY from a server-verified token.
 *    Client-supplied identity fields (body `userId`, query `?userId=`) are NEVER
 *    trusted for authorization.
 *  - Tokens are HMAC-signed `userId.expiryMs.sig` triples. In production this is
 *    replaced by the institution's IdP/OIDC session; the contract (return a
 *    verified principal or null) stays the same.
 *
 * Token format:  base64url(userId).<expiryEpochMs>.<hmac_sha256_hex>
 * Secret:        process.env.SENTINEL_SESSION_SECRET (required outside tests)
 */

export type Principal = { userId: string; roles: string[] };

const TEST_SECRET = 'test-only-session-secret-do-not-use-in-prod';

function secret(): string {
  const s = process.env.SENTINEL_SESSION_SECRET;
  if (s && s.length >= 16) return s;
  if (process.env.NODE_ENV === 'production') {
    throw new Error('SENTINEL_SESSION_SECRET is not set or too short');
  }
  return TEST_SECRET; // dev/test only
}

function b64url(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url');
}
function unb64url(s: string): string {
  return Buffer.from(s, 'base64url').toString('utf8');
}

/** Mint a signed session token. Used by tests and by a real login handler. */
export function mintToken(userId: string, ttlMs = 3_600_000, roles: string[] = []): string {
  const expiry = Date.now() + ttlMs;
  const payload = `${b64url(userId)}.${expiry}.${b64url(JSON.stringify(roles))}`;
  const sig = crypto.createHmac('sha256', secret()).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

/** Verify a token; returns the principal or null. Constant-time signature check. */
export function verifyToken(token: string | null | undefined): Principal | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 4) return null;
  const [uB64, expStr, rolesB64, sig] = parts;
  const payload = `${uB64}.${expStr}.${rolesB64}`;
  const expected = crypto.createHmac('sha256', secret()).update(payload).digest('hex');
  // constant-time compare (lengths must match for timingSafeEqual)
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  const expiry = Number(expStr);
  if (!Number.isFinite(expiry) || Date.now() > expiry) return null;
  try {
    const userId = unb64url(uB64);
    const roles = JSON.parse(unb64url(rolesB64)) as string[];
    if (!userId) return null;
    return { userId, roles: Array.isArray(roles) ? roles : [] };
  } catch {
    return null;
  }
}

/**
 * Extract the authenticated principal from a request.
 * Order: `Authorization: Bearer <token>` header, then `sentinel_session` cookie.
 */
export function getPrincipal(req: Request): Principal | null {
  const auth = req.headers.get('authorization');
  if (auth?.startsWith('Bearer ')) {
    const p = verifyToken(auth.slice(7).trim());
    if (p) return p;
  }
  const cookie = req.headers.get('cookie') ?? '';
  const m = cookie.match(/(?:^|;\s*)sentinel_session=([^;]+)/);
  if (m) return verifyToken(decodeURIComponent(m[1]));
  return null;
}

/** Authorization: a principal may access a subject's record if it owns it or is a DPO. */
export function canAccessSubject(p: Principal, subjectUserId: string): boolean {
  return p.userId === subjectUserId || p.roles.includes('dpo');
}

export const UNAUTHORIZED = () =>
  new Response(JSON.stringify({ error: 'unauthorized' }), {
    status: 401,
    headers: { 'content-type': 'application/json' },
  });

export const FORBIDDEN = () =>
  new Response(JSON.stringify({ error: 'forbidden' }), {
    status: 403,
    headers: { 'content-type': 'application/json' },
  });
