import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { handleRequest, isValidReportingWindow, readConfiguration } from '../src/server.mjs';

const NOW = new Date('2026-10-28T14:45:00.000Z');
const WINDOW_START = '2026-10-27T09:00:00.000Z';
const WINDOW_END = '2026-10-28T09:00:00.000Z';
const TOKEN = 'gien-test-access-token-123';

function env(overrides = {}) {
  return {
    NODE_ENV: 'test',
    GIEN_OIDC_INTROSPECTION_URL: 'https://identity.example.test/introspect',
    GIEN_OIDC_CLIENT_ID: 'gien-evidence-test-client',
    GIEN_OIDC_CLIENT_SECRET: 'client-secret-for-tests-000000000000',
    GIEN_EVIDENCE_PROVIDER_URL: 'https://evidence.example.test/v1/systemic-risk',
    GIEN_EVIDENCE_PROVIDER_TOKEN: 'provider-token-for-tests-000000000000',
    GIEN_AUDIT_SINK_URL: 'https://audit.example.test/v1/events',
    GIEN_AUDIT_SINK_HMAC_SECRET: 'audit-hmac-secret-for-tests-000000000000',
    GIEN_ALLOWED_ORIGINS: 'http://localhost:4173',
    GIEN_UPSTREAM_TIMEOUT_MS: '3000',
    GIEN_MAX_SNAPSHOT_AGE_MS: '300000',
    ...overrides,
  };
}

function liveSnapshot(overrides = {}) {
  return {
    schemaVersion: 'gien.evidence.snapshot.v1',
    tenantId: 'tenant-alpha',
    generatedAt: '2026-10-28T14:44:00.000Z',
    window: { start: WINDOW_START, end: WINDOW_END },
    source: { id: 'metrics-prod-eu-01', kind: 'live', version: 'adapter-1.2.0' },
    metrics: [{
      id: 'S_sys',
      label: 'System-wide systemic stress composite',
      value: 0.22,
      delta: -0.01,
      sourceKind: 'live',
      assessmentStatus: 'ASSESSED',
      evidenceRefs: ['evidence://gien/snapshot/2026-10-28/S_sys'],
      observedAt: '2026-10-28T08:58:00.000Z',
      methodVersion: 's-sys-2.1',
    }],
    ...overrides,
  };
}

function mockFetch(options = {}) {
  const calls = [];
  const opts = {
    active: true,
    scope: 'openid profile gien:evidence:read',
    subject: 'user-123',
    tenantId: 'tenant-alpha',
    snapshot: liveSnapshot(),
    auditPersisted: true,
    auditReceiptId: 'audit-receipt-001',
    providerStatus: 200,
    auditStatus: 200,
    ...options,
  };
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    calls.push({ url: url.toString(), init });
    if (url.hostname === 'identity.example.test') {
      const body = new URLSearchParams(init.body);
      assert.equal(body.get('token'), TOKEN);
      assert.match(init.headers.Authorization, /^Basic /);
      return new Response(JSON.stringify({
        active: opts.active,
        sub: opts.subject,
        tenant_id: opts.tenantId,
        scope: opts.scope,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url.hostname === 'evidence.example.test') {
      assert.equal(init.headers['X-GIEN-Tenant-ID'], opts.tenantId);
      assert.equal(url.searchParams.get('windowStart'), WINDOW_START);
      assert.equal(url.searchParams.get('windowEnd'), WINDOW_END);
      return new Response(JSON.stringify(opts.snapshot), {
        status: opts.providerStatus,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url.hostname === 'audit.example.test') {
      const event = JSON.parse(init.body);
      const expected = 'sha256=' + createHmac('sha256', env().GIEN_AUDIT_SINK_HMAC_SECRET).update(init.body).digest('hex');
      assert.equal(init.headers['X-GIEN-Audit-Signature'], expected);
      assert.equal(event.eventType, 'gien.evidence.read');
      assert.equal(event.tenantId, opts.tenantId);
      return new Response(JSON.stringify({
        persisted: opts.auditPersisted,
        receiptId: opts.auditReceiptId,
        eventId: opts.auditEventId ?? event.eventId,
        snapshotDigest: opts.auditSnapshotDigest ?? event.snapshotDigest,
      }), { status: opts.auditStatus, headers: { 'content-type': 'application/json' } });
    }
    throw new Error('Unexpected outbound URL: ' + url.toString());
  };
  return { fetchImpl, calls };
}

function request(path = '', options = {}) {
  const url = 'https://api.example.test/v1/evidence/systemic-risk?windowStart=' +
    encodeURIComponent(WINDOW_START) + '&windowEnd=' + encodeURIComponent(WINDOW_END) + path;
  return new Request(url, {
    method: 'GET',
    headers: options.headers ?? { Authorization: 'Bearer ' + TOKEN },
  });
}

async function assertErrorResponse(response, status, code) {
  assert.equal(response.status, status);
  const payload = await response.json();
  assert.equal(payload.error.code, code);
  return payload;
}

async function assertNoSnapshotError(response, status, code) {
  const payload = await assertErrorResponse(response, status, code);
  assert.equal('snapshot' in payload, false);
}

async function assertInvalidSnapshot(snapshot, envOverrides = {}) {
  const { fetchImpl, calls } = mockFetch({ snapshot });
  const response = await handleRequest(request(), { env: env(envOverrides), fetchImpl, now: () => NOW });
  await assertErrorResponse(response, 502, 'EVIDENCE_SNAPSHOT_INVALID');
  assert.equal(calls.length, 2);
}
test('configuration is fail-closed when a required dependency is missing', () => {
  assert.equal(readConfiguration(env({ GIEN_AUDIT_SINK_URL: '' })), null);
});

test('only completed 24-hour UTC windows aligned to 09:00 are accepted', () => {
  assert.equal(isValidReportingWindow(WINDOW_START, WINDOW_END, NOW), true);
  assert.equal(isValidReportingWindow(WINDOW_START, '2026-10-28T10:00:00.000Z', NOW), false);
  assert.equal(isValidReportingWindow(WINDOW_START, '2026-10-29T09:00:00.000Z', NOW), false);
  assert.equal(isValidReportingWindow('2026-10-27T08:00:00.000Z', WINDOW_END, NOW), false);
});

test('unconfigured service returns 503 and never calls upstream services', async () => {
  const { fetchImpl, calls } = mockFetch();
  const response = await handleRequest(request(), {
    env: env({ GIEN_EVIDENCE_PROVIDER_TOKEN: '' }),
    fetchImpl,
    now: () => NOW,
  });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error.code, 'EVIDENCE_API_NOT_CONFIGURED');
  assert.equal(calls.length, 0);
});

test('missing bearer token is rejected before upstream access', async () => {
  const { fetchImpl, calls } = mockFetch();
  const response = await handleRequest(request('', { headers: {} }), {
    env: env(), fetchImpl, now: () => NOW,
  });
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, 'AUTHENTICATION_REQUIRED');
  assert.equal(calls.length, 0);
});

test('disallowed browser origin is rejected before upstream access', async () => {
  const { fetchImpl, calls } = mockFetch();
  const response = await handleRequest(request('', {
    headers: { Authorization: 'Bearer ' + TOKEN, Origin: 'https://attacker.example' },
  }), { env: env(), fetchImpl, now: () => NOW });
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error.code, 'ORIGIN_NOT_ALLOWED');
  assert.equal(calls.length, 0);
});

test('invalid reporting window is rejected before token introspection', async () => {
  const { fetchImpl, calls } = mockFetch();
  const response = await handleRequest(
    new Request('https://api.example.test/v1/evidence/systemic-risk?windowStart=' +
      encodeURIComponent(WINDOW_START) + '&windowEnd=2026-10-28T10%3A00%3A00.000Z', {
      headers: { Authorization: 'Bearer ' + TOKEN },
    }),
    { env: env(), fetchImpl, now: () => NOW },
  );
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, 'INVALID_REPORTING_WINDOW');
  assert.equal(calls.length, 0);
});

test('inactive token is rejected and no provider or audit request is sent', async () => {
  const { fetchImpl, calls } = mockFetch({ active: false });
  const response = await handleRequest(request(), { env: env(), fetchImpl, now: () => NOW });
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, 'ACCESS_TOKEN_INVALID');
  assert.equal(calls.length, 1);
});

test('missing evidence-read scope is rejected before provider access', async () => {
  const { fetchImpl, calls } = mockFetch({ scope: 'openid profile' });
  const response = await handleRequest(request(), { env: env(), fetchImpl, now: () => NOW });
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error.code, 'INSUFFICIENT_SCOPE');
  assert.equal(calls.length, 1);
});

test('synthetic measurements cannot be presented as assessed evidence', async () => {
  const bad = liveSnapshot();
  bad.metrics[0].sourceKind = 'synthetic';
  await assertInvalidSnapshot(bad);
});

test('a synthetic snapshot source cannot wrap metrics marked assessed', async () => {
  const contradictory = liveSnapshot({ source: { id: 'demo-provider', kind: 'synthetic', version: 'fixture-1' } });
  await assertInvalidSnapshot(contradictory);
});

test('evidence is released only after a signed audit request receives a durable receipt', async () => {
  const { fetchImpl, calls } = mockFetch();
  const response = await handleRequest(request(), { env: env(), fetchImpl, now: () => NOW });
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.snapshot.schemaVersion, 'gien.evidence.snapshot.v1');
  assert.equal(payload.snapshot.metrics[0].assessmentStatus, 'ASSESSED');
  assert.equal(payload.audit.persisted, true);
  assert.equal(payload.audit.receiptId, 'audit-receipt-001');
  assert.equal(payload.audit.eventId, payload.requestId);
  assert.equal(payload.audit.snapshotDigest, payload.snapshotDigest);
  assert.match(payload.snapshotDigest, /^sha384:[a-f0-9]{96}$/);
  assert.equal(calls.length, 3);
});

test('audit receipt for a different event or digest is rejected', async () => {
  const { fetchImpl } = mockFetch({ auditEventId: 'another-event-id' });
  const response = await handleRequest(request(), { env: env(), fetchImpl, now: () => NOW });
  await assertNoSnapshotError(response, 503, 'AUDIT_RECEIPT_INVALID');
});

test('audit sink failure returns no metric values to the caller', async () => {
  const { fetchImpl } = mockFetch({ auditPersisted: false });
  const response = await handleRequest(request(), { env: env(), fetchImpl, now: () => NOW });
  await assertNoSnapshotError(response, 503, 'AUDIT_RECEIPT_INVALID');
});

test('empty evidence snapshots are rejected instead of implying zero risk', async () => {
  const empty = liveSnapshot({ metrics: [] });
  await assertInvalidSnapshot(empty);
});

test('stale source snapshots are rejected instead of being returned as current', async () => {
  const stale = liveSnapshot({ generatedAt: '2026-10-28T14:00:00.000Z' });
  await assertInvalidSnapshot(stale, { GIEN_MAX_SNAPSHOT_AGE_MS: '60000' });
});
