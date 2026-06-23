import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { RateLimiter, clientKey } from '@/lib/http/rateLimit';

/**
 * Edge middleware (DASH-06): per-client rate limiting on API routes.
 *
 * Note: a module-level limiter is per-instance; on serverless this is best-effort
 * and must be backed by Redis/Upstash in production. It is sufficient as a
 * defense-in-depth control and is unit-tested via lib/http/rateLimit.ts.
 */
const limiter = new RateLimiter(120, 60_000); // 120 req/min/client on /api/*

export function middleware(req: NextRequest) {
  const { allowed, remaining, resetMs } = limiter.check(clientKey(req));
  if (!allowed) {
    return new NextResponse(JSON.stringify({ error: 'rate_limited' }), {
      status: 429,
      headers: {
        'content-type': 'application/json',
        'retry-after': String(Math.ceil(resetMs / 1000)),
        'x-ratelimit-remaining': '0',
      },
    });
  }
  const res = NextResponse.next();
  res.headers.set('x-ratelimit-remaining', String(remaining));
  return res;
}

export const config = {
  matcher: ['/api/:path*'],
};
