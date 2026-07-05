/**
 * Minimal fixed-window in-memory rate limiter (DASH-06).
 *
 * Pure + testable: the store is injectable so tests don't depend on time/global
 * state. In production replace the store with Redis/Upstash (the interface is the
 * same: read count for (key, windowStart), increment, expire).
 *
 * This is a defense-in-depth control for a demo dashboard, not a DDoS solution.
 */
export type RateLimitResult = { allowed: boolean; remaining: number; resetMs: number };

type Bucket = { count: number; windowStart: number };

export class RateLimiter {
  private buckets = new Map<string, Bucket>();
  constructor(
    private readonly limit = 60,
    private readonly windowMs = 60_000,
    private readonly now: () => number = () => Date.now(),
  ) {}

  check(key: string): RateLimitResult {
    const t = this.now();
    const b = this.buckets.get(key);
    if (!b || t - b.windowStart >= this.windowMs) {
      this.buckets.set(key, { count: 1, windowStart: t });
      return { allowed: true, remaining: this.limit - 1, resetMs: this.windowMs };
    }
    b.count += 1;
    const allowed = b.count <= this.limit;
    return {
      allowed,
      remaining: Math.max(0, this.limit - b.count),
      resetMs: this.windowMs - (t - b.windowStart),
    };
  }

  /** Best-effort cleanup of expired buckets (call periodically in prod). */
  sweep(): void {
    const t = this.now();
    for (const [k, b] of this.buckets) {
      if (t - b.windowStart >= this.windowMs) this.buckets.delete(k);
    }
  }
}

/** Derive a client key from forwarded headers (best-effort in edge/runtime). */
export function clientKey(req: Request): string {
  const xff = req.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  return req.headers.get('x-real-ip') ?? 'unknown';
}
