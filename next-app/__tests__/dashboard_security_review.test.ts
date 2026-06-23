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

  // DASH-02: consent write trusts caller-supplied identity (no session binding).
  test('DASH-02: consent POST reads userId from the request body', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'app', 'api', 'consent', 'route.ts'),
      'utf8',
    )
    expect(src).toMatch(/userId\s*=\s*['"]demo['"]/) // default + body-sourced identity
  })

  // DASH-01: consent export takes userId straight from the query string (IDOR).
  test('DASH-01: consent GET derives userId from query string, not session', () => {
    const src = fs.readFileSync(
      path.join(__dirname, '..', 'app', 'api', 'consent', 'route.ts'),
      'utf8',
    )
    expect(src).toMatch(/searchParams\.get\(['"]userId['"]\)/)
  })

  // Positive control: preFilter still redacts obvious secrets (kept behaviour).
  test('preFilter flags sensitive tokens for redaction', () => {
    expect(preFilter('my ssn is 123').action).toBe('revise')
    expect(preFilter('hello world').action).toBe('allow')
  })
})
