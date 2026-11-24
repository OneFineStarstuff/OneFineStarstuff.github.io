import { describe, test, expect } from 'vitest'
import { preFilter, postModerate } from '../lib/safety/pipeline'
import fs from 'fs'
import path from 'path'

/**
 * Runnable evidence for DASHBOARD_SECURITY_REVIEW.md.
 *
 * These tests do not assert "the code is good"; they pin the CURRENT behaviour so
 * the security findings are falsifiable and regression-tracked. When a finding is
 * remediated, the corresponding test should be updated to assert the fixed behaviour.
 */
describe('Dashboard security findings (falsifiable evidence)', () => {
  // DASH-05: the moderation pipeline CAN decide to block...
  test('DASH-05: postModerate returns block for unsafe content', () => {
    const ev = postModerate('here is some violent illegal advice')
    expect(ev.action).toBe('block')
    expect(ev.reason).toBe('unsafe_content')
  })

  // ...but the stream handler computes `post` only into metadata and streams the
  // reply regardless. We assert the structural gap directly against source so the
  // finding cannot silently drift.
  test('DASH-05: chat stream handler does not branch on a block decision', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'app', 'api', 'chat', 'stream', 'route.ts'),
      'utf8',
    )
    // `post` is attached to meta...
    expect(src).toMatch(/post\s*[},]/)
    // ...but there is no enforcement branch. If this assertion fails, someone added
    // enforcement — update this test to assert the new (correct) behaviour.
    expect(src).not.toMatch(/post\.action\s*===\s*['"]block['"]/)
  })

  // DASH-02: until authentication exists, consent writes are restricted to demo identity.
  test('DASH-02: consent POST rejects caller-selected non-demo identities', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'app', 'api', 'consent', 'route.ts'),
      'utf8',
    )
    expect(src).toMatch(/const userId = body\.userId === undefined \? ['"]demo['"] : body\.userId/)
    expect(src).toMatch(/if \(userId !== ['"]demo['"]\)/)
    expect(src).toMatch(/userId: ['"]demo['"]/)
    expect(src).not.toMatch(/appendConsentEvent\(\{\s*userId,/)
  })

  // DASH-01: consent export is constrained to the demo ledger until authz is configured.
  test('DASH-01: consent GET rejects non-demo IDs and exports only demo records', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'app', 'api', 'consent', 'route.ts'),
      'utf8',
    )
    expect(src).toMatch(/if \(userId !== ['"]demo['"]\)/)
    expect(src).toMatch(/exportConsent\(['"]demo['"]\)/)
    expect(src).not.toMatch(/exportConsent\(userId\)/)
  })

  // Positive control: preFilter still redacts obvious secrets (kept behaviour).
  test('preFilter flags sensitive tokens for redaction', () => {
    expect(preFilter('my ssn is 123').action).toBe('revise')
    expect(preFilter('hello world').action).toBe('allow')
  })
})
