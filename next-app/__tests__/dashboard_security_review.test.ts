import { describe, test, expect } from 'vitest'
import { preFilter, postModerate } from '../lib/safety/pipeline'
import { mintToken, verifyToken, getPrincipal, canAccessSubject } from '../lib/auth/session'
import { readJson, sanitizeForStream, MAX_BODY_BYTES } from '../lib/http/guard'
import { RateLimiter } from '../lib/http/rateLimit'
import { hashEvent, signHash, verifyEvent } from '../lib/privacy/consentLedger'
import fs from 'fs'
import path from 'path'

/**
 * Evidence for DASHBOARD_SECURITY_REVIEW.md.
 *
 * The original turn-3 tests pinned the VULNERABLE behaviour. After remediation
 * (DASH-01/02/03/05/08) these assert the FIXED behaviour, so the tests now fail
 * if a regression reintroduces a finding.
 */
describe('Dashboard security remediations (DASH-01/02/03/05/08)', () => {
  // ---- Auth helper (underpins DASH-01/02/03 fixes) ----
  test('session token round-trips and yields a verified principal', () => {
    const tok = mintToken('alice', 60_000, ['dpo'])
    const p = verifyToken(tok)
    expect(p?.userId).toBe('alice')
    expect(p?.roles).toContain('dpo')
  })

  test('tampered or expired tokens are rejected', () => {
    expect(verifyToken('garbage')).toBeNull()
    expect(verifyToken(null)).toBeNull()
    const tok = mintToken('bob', 60_000)
    expect(verifyToken(tok.slice(0, -2) + 'ff')).toBeNull() // bad signature
    const expired = mintToken('bob', -1)
    expect(verifyToken(expired)).toBeNull() // already expired
  })

  test('getPrincipal reads Bearer header and cookie; ignores nothing else', () => {
    const tok = mintToken('carol')
    const viaHeader = getPrincipal(new Request('http://x/', { headers: { authorization: `Bearer ${tok}` } }))
    expect(viaHeader?.userId).toBe('carol')
    const viaCookie = getPrincipal(new Request('http://x/', { headers: { cookie: `sentinel_session=${tok}` } }))
    expect(viaCookie?.userId).toBe('carol')
    expect(getPrincipal(new Request('http://x/'))).toBeNull()
  })

  // ---- DASH-01: IDOR fixed — authz on subject access ----
  test('DASH-01: a principal cannot access another subject unless DPO', () => {
    const alice = verifyToken(mintToken('alice'))!
    const dpo = verifyToken(mintToken('officer', 60_000, ['dpo']))!
    expect(canAccessSubject(alice, 'alice')).toBe(true)
    expect(canAccessSubject(alice, 'bob')).toBe(false) // no IDOR
    expect(canAccessSubject(dpo, 'bob')).toBe(true) // DPO override
  })

  // ---- DASH-02: consent route binds identity to the principal, not the body ----
  test('DASH-02: consent route no longer trusts body userId', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'app', 'api', 'consent', 'route.ts'), 'utf8')
    expect(src).toMatch(/getPrincipal/)
    expect(src).toMatch(/principal\.userId/)
    expect(src).not.toMatch(/userId\s*=\s*['"]demo['"]/) // old body-default removed
  })

  // ---- DASH-03: chat route authn + body cap + GET text-gen removed ----
  test('DASH-03: chat route requires auth, caps body, has no GET handler', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'app', 'api', 'chat', 'stream', 'route.ts'), 'utf8')
    expect(src).toMatch(/getPrincipal/)
    expect(src).toMatch(/readJson/)
    expect(src).not.toMatch(/export function GET/) // unauthenticated GET text-gen removed
  })

  // ---- DASH-05: moderation block is ENFORCED, not just logged ----
  test('DASH-05: postModerate blocks unsafe content', () => {
    expect(postModerate('here is some violent illegal advice').action).toBe('block')
  })
  test('DASH-05: chat route branches on a block decision', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'app', 'api', 'chat', 'stream', 'route.ts'), 'utf8')
    expect(src).toMatch(/post\.action\s*===\s*['"]block['"]/) // enforcement branch present
    expect(src).toMatch(/blocked by the safety policy/)
  })

  // ---- DASH-03/08: request guard behaviour ----
  test('readJson enforces size cap and rejects bad json', async () => {
    const big = new Request('http://x/', {
      method: 'POST',
      headers: { 'content-length': String(MAX_BODY_BYTES + 1) },
      body: 'x'.repeat(MAX_BODY_BYTES + 1),
    })
    const r1 = await readJson(big)
    expect(r1.ok).toBe(false)
    if (!r1.ok) expect(r1.status).toBe(413)

    const bad = new Request('http://x/', { method: 'POST', body: 'not json' })
    const r2 = await readJson(bad)
    expect(r2.ok).toBe(false)
    if (!r2.ok) expect(r2.status).toBe(400)

    const good = new Request('http://x/', { method: 'POST', body: JSON.stringify({ a: 1 }) })
    const r3 = await readJson<{ a: number }>(good)
    expect(r3.ok).toBe(true)
    if (r3.ok) expect(r3.data.a).toBe(1)
  })

  test('sanitizeForStream strips newlines/control chars (no SSE injection)', () => {
    expect(sanitizeForStream('a\r\nevent: evil', 100)).not.toMatch(/[\r\n]/)
  })

  // ---- DASH-04: risk scores labelled synthetic ----
  test('DASH-04: risk scores route flags synthetic data', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'app', 'api', 'risk', 'scores', 'route.ts'), 'utf8')
    expect(src).toMatch(/synthetic:\s*true/)
    expect(src).toMatch(/DEMO DATA/)
  })

  // ---- DASH-06: security headers + rate limiting ----
  test('DASH-06: next.config sets CSP and hardening headers', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'next.config.js'), 'utf8')
    expect(src).toMatch(/Content-Security-Policy/)
    expect(src).toMatch(/X-Content-Type-Options/)
    expect(src).toMatch(/Strict-Transport-Security/)
  })
  test('DASH-06: rate limiter blocks past the window limit', () => {
    let t = 0
    const rl = new RateLimiter(3, 1000, () => t)
    expect(rl.check('ip').allowed).toBe(true) // 1
    expect(rl.check('ip').allowed).toBe(true) // 2
    expect(rl.check('ip').allowed).toBe(true) // 3
    expect(rl.check('ip').allowed).toBe(false) // 4 -> blocked
    t = 1001 // window rolls over
    expect(rl.check('ip').allowed).toBe(true)
  })

  // ---- DASH-07: consent ledger signature ----
  test('DASH-07: consent events are signed and tamper-evident', () => {
    const ev = { userId: 'alice', action: 'persist_on' as const, ts: '2026-01-01T00:00:00Z' }
    const hash = hashEvent(ev)
    const signed = { ...ev, hash, sig: signHash(hash) }
    expect(verifyEvent(signed)).toBe(true)
    // tamper the action -> hash no longer matches -> verification fails
    expect(verifyEvent({ ...signed, action: 'persist_off' as const })).toBe(false)
    // tamper the signature -> fails
    expect(verifyEvent({ ...signed, sig: signed.sig.slice(0, -2) + 'ff' })).toBe(false)
    // missing sig -> fails
    expect(verifyEvent({ ...ev, hash })).toBe(false)
  })
  test('DASH-07: consent ledger fails closed (no silent new chain)', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'lib', 'privacy', 'consentLedger.ts'), 'utf8')
    expect(src).not.toMatch(/catch\s*\([^)]*\)\s*\{\s*console\.error/) // old swallow removed
    expect(src).toMatch(/integrity violation/)
  })

  // ---- Positive control: preFilter still redacts secrets ----
  test('preFilter flags sensitive tokens for redaction', () => {
    expect(preFilter('my ssn is 123').action).toBe('revise')
    expect(preFilter('hello world').action).toBe('allow')
  })
})
