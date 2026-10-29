import { createServer as createHttpServer } from 'node:http';
import { Buffer } from 'node:buffer';
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import process from 'node:process';

export const EVIDENCE_ROUTE = '/v1/evidence/systemic-risk';
const SCHEMA_VERSION = 'gien.evidence.snapshot.v1';
const ALLOWED_SOURCE_KINDS = new Set(['live', 'external-attested', 'synthetic', 'replay', 'pending']);
const ALLOWED_ASSESSMENT_STATES = new Set([
  'ASSESSED', 'NOT_ASSESSED', 'STALE', 'CONFLICTED', 'INVALID', 'EVIDENCE_PENDING', 'SIMULATED',
]);
const MAX_UPSTREAM_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 3000;

function isoUtc(value) {
  if (typeof value !== 'string') return false;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.toISOString() === value;
}

function validUrl(raw, production) {
  try {
    const value = new URL(raw);
    if (value.protocol === 'https:') return value;
    if (!production && value.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(value.hostname)) return value;
  } catch {
    // Invalid operator configuration must fail closed.
  }
  return null;
}

function readAllowedOrigins(env) {
  const raw = String(env.GIEN_ALLOWED_ORIGINS ?? '').trim();
  if (!raw) return [];
  const origins = [];
  for (const item of raw.split(',')) {
    const value = item.trim();
    if (!value) continue;
    try {
      const parsed = new URL(value);
      if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== value) return null;
      origins.push(parsed.origin);
    } catch {
      return null;
    }
  }
  return [...new Set(origins)];
}

export function readConfiguration(env = process.env) {
  const production = env.NODE_ENV === 'production';
  const origins = readAllowedOrigins(env);
  const required = [
    'GIEN_OIDC_INTROSPECTION_URL',
    'GIEN_OIDC_CLIENT_ID',
    'GIEN_OIDC_CLIENT_SECRET',
    'GIEN_EVIDENCE_PROVIDER_URL',
    'GIEN_EVIDENCE_PROVIDER_TOKEN',
    'GIEN_AUDIT_SINK_URL',
    'GIEN_AUDIT_SINK_HMAC_SECRET',
  ];
  if (origins === null || origins.length === 0) return null;
  if (required.some((key) => !String(env[key] ?? '').trim())) return null;
  if (String(env.GIEN_OIDC_CLIENT_SECRET).length < 16) return null;
  if (String(env.GIEN_EVIDENCE_PROVIDER_TOKEN).length < 24) return null;
  if (String(env.GIEN_AUDIT_SINK_HMAC_SECRET).length < 32) return null;

  const introspectionUrl = validUrl(env.GIEN_OIDC_INTROSPECTION_URL, production);
  const providerUrl = validUrl(env.GIEN_EVIDENCE_PROVIDER_URL, production);
  const auditSinkUrl = validUrl(env.GIEN_AUDIT_SINK_URL, production);
  if (!introspectionUrl || !providerUrl || !auditSinkUrl) return null;

  const timeoutCandidate = Number(env.GIEN_UPSTREAM_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS);
  const timeoutMs = Number.isFinite(timeoutCandidate) && timeoutCandidate >= 500 && timeoutCandidate <= 10000
    ? Math.floor(timeoutCandidate)
    : DEFAULT_TIMEOUT_MS;

  const maxAgeCandidate = Number(env.GIEN_MAX_SNAPSHOT_AGE_MS ?? 300000);
  const maxSnapshotAgeMs = Number.isFinite(maxAgeCandidate) && maxAgeCandidate >= 1000 && maxAgeCandidate <= 900000
    ? Math.floor(maxAgeCandidate)
    : 300000;

  return {
    introspectionUrl,
    clientId: String(env.GIEN_OIDC_CLIENT_ID),
    clientSecret: String(env.GIEN_OIDC_CLIENT_SECRET),
    providerUrl,
    providerToken: String(env.GIEN_EVIDENCE_PROVIDER_TOKEN),
    auditSinkUrl,
    auditHmacSecret: String(env.GIEN_AUDIT_SINK_HMAC_SECRET),
    allowedOrigins: origins,
    timeoutMs,
    maxSnapshotAgeMs,
  };
}

function latestCompletedCutoff(now) {
  const cutoff = new Date(Date.UTC(
    now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 9, 0, 0, 0,
  ));
  if (now.getTime() < cutoff.getTime()) cutoff.setUTCDate(cutoff.getUTCDate() - 1);
  return cutoff;
}

export function isValidReportingWindow(startValue, endValue, now = new Date()) {
  if (!isoUtc(startValue) || !isoUtc(endValue)) return false;
  const start = new Date(startValue);
  const end = new Date(endValue);
  if (start.getUTCHours() !== 9 || start.getUTCMinutes() !== 0 || start.getUTCSeconds() !== 0 || start.getUTCMilliseconds() !== 0) return false;
  if (end.getUTCHours() !== 9 || end.getUTCMinutes() !== 0 || end.getUTCSeconds() !== 0 || end.getUTCMilliseconds() !== 0) return false;
  if (end.getTime() - start.getTime() !== 24 * 60 * 60 * 1000) return false;
  if (end.getTime() > latestCompletedCutoff(now).getTime()) return false;
  return true;
}

function makeResponse(request, status, payload, requestId, env = process.env, extraHeaders = {}) {
  const headers = new Headers({
    'Cache-Control': 'no-store, max-age=0',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Request-ID': requestId,
    ...extraHeaders,
  });
  headers.set('Vary', 'Origin');
  const origin = request.headers.get('origin');
  const allowedOrigins = readAllowedOrigins(env);
  if (origin && allowedOrigins && allowedOrigins.includes(origin)) {
    headers.set('Access-Control-Allow-Origin', origin);
  }
  return Response.json(payload, { status, headers });
}

function errorResponse(request, status, code, message, requestId, env, extraHeaders = {}) {
  return makeResponse(request, status, { error: { code, message }, requestId }, requestId, env, extraHeaders);
}

async function readJsonLimited(response, maxBytes = MAX_UPSTREAM_BYTES) {
  const declaredLength = Number(response.headers.get('content-length') ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) throw new Error('upstream_payload_too_large');
  if (!response.body) throw new Error('upstream_payload_empty');

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      total += result.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error('upstream_payload_too_large');
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

function hasControlCharacters(value) {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function validShortString(value, max = 256) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= max && !hasControlCharacters(value);
}

function validateSnapshot(raw, principal, start, end, now, maxSnapshotAgeMs) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  if (raw.schemaVersion !== SCHEMA_VERSION) return null;
  if (raw.tenantId !== principal.tenantId) return null;
  if (!raw.window || raw.window.start !== start || raw.window.end !== end) return null;
  if (!isoUtc(raw.generatedAt)) return null;

  const generatedAtMs = new Date(raw.generatedAt).getTime();
  if (generatedAtMs > now.getTime() + 10000 || now.getTime() - generatedAtMs > maxSnapshotAgeMs) return null;
  if (!raw.source || !validShortString(raw.source.id) || !validShortString(raw.source.version)) return null;
  if (!ALLOWED_SOURCE_KINDS.has(raw.source.kind)) return null;
  if (!Array.isArray(raw.metrics) || raw.metrics.length === 0 || raw.metrics.length > 100) return null;

  if (raw.source.kind === 'synthetic' && raw.metrics.some((metric) => metric?.assessmentStatus === 'ASSESSED')) return null;

  const seenIds = new Set();
  const metrics = [];
  for (const metric of raw.metrics) {
    if (!metric || typeof metric !== 'object' || Array.isArray(metric)) return null;
    if (!validShortString(metric.id, 128) || !validShortString(metric.label, 256) || seenIds.has(metric.id)) return null;
    seenIds.add(metric.id);
    if (!ALLOWED_SOURCE_KINDS.has(metric.sourceKind) || !ALLOWED_ASSESSMENT_STATES.has(metric.assessmentStatus)) return null;

    const valueValid = metric.value === null || (typeof metric.value === 'number' && Number.isFinite(metric.value) && metric.value >= 0 && metric.value <= 1);
    const deltaValid = metric.delta === null || (typeof metric.delta === 'number' && Number.isFinite(metric.delta));
    if (!valueValid || !deltaValid) return null;

    if (!Array.isArray(metric.evidenceRefs) || metric.evidenceRefs.length > 100) return null;
    if (!metric.evidenceRefs.every((ref) => validShortString(ref, 512))) return null;
    if (metric.observedAt !== null && !isoUtc(metric.observedAt)) return null;
    if (metric.methodVersion !== null && !validShortString(metric.methodVersion, 128)) return null;

    if (metric.assessmentStatus === 'ASSESSED') {
      if (metric.sourceKind !== 'live' && metric.sourceKind !== 'external-attested') return null;
      if (metric.value === null || metric.evidenceRefs.length === 0 || !metric.observedAt || !metric.methodVersion) return null;
      const observedAt = new Date(metric.observedAt).getTime();
      if (observedAt < new Date(start).getTime() || observedAt > new Date(end).getTime()) return null;
    }
    if (metric.assessmentStatus === 'NOT_ASSESSED' || metric.assessmentStatus === 'EVIDENCE_PENDING') {
      if (metric.value !== null) return null;
    }
    if (metric.sourceKind === 'synthetic' && !['SIMULATED', 'NOT_ASSESSED', 'EVIDENCE_PENDING'].includes(metric.assessmentStatus)) return null;
    if (metric.assessmentStatus === 'SIMULATED' && metric.sourceKind !== 'synthetic') return null;

    metrics.push({
      id: metric.id,
      label: metric.label,
      value: metric.value,
      delta: metric.delta,
      sourceKind: metric.sourceKind,
      assessmentStatus: metric.assessmentStatus,
      evidenceRefs: metric.evidenceRefs,
      observedAt: metric.observedAt,
      methodVersion: metric.methodVersion,
    });
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    tenantId: raw.tenantId,
    generatedAt: raw.generatedAt,
    window: { start, end },
    source: { id: raw.source.id, kind: raw.source.kind, version: raw.source.version },
    metrics,
  };
}

async function fetchJson(fetchImpl, url, options, timeoutMs) {
  const response = await fetchImpl(url, { ...options, signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) return { ok: false, status: response.status, value: null };
  try {
    return { ok: true, status: response.status, value: await readJsonLimited(response) };
  } catch {
    return { ok: false, status: response.status, value: null };
  }
}

export async function handleRequest(request, options = {}) {
  const env = options.env ?? process.env;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const nowFn = options.now ?? (() => new Date());
  const requestId = randomUUID();
  const url = new URL(request.url);

  if (request.method === 'GET' && url.pathname === '/healthz') {
    return makeResponse(request, 200, { status: 'ok', service: 'gien-evidence-api' }, requestId, env);
  }

  if (request.method === 'GET' && url.pathname === '/readyz') {
    const ready = readConfiguration(env) !== null;
    return ready
      ? makeResponse(request, 200, { status: 'ready' }, requestId, env)
      : errorResponse(request, 503, 'EVIDENCE_API_NOT_CONFIGURED', 'Evidence API dependencies are not configured.', requestId, env);
  }

  if (url.pathname !== EVIDENCE_ROUTE) {
    return errorResponse(request, 404, 'NOT_FOUND', 'Route not found.', requestId, env);
  }

  const config = readConfiguration(env);
  if (!config) {
    return errorResponse(request, 503, 'EVIDENCE_API_NOT_CONFIGURED', 'Evidence API dependencies are not configured.', requestId, env);
  }

  const origin = request.headers.get('origin');
  if (origin && !config.allowedOrigins.includes(origin)) {
    return errorResponse(request, 403, 'ORIGIN_NOT_ALLOWED', 'Request origin is not allowed.', requestId, env);
  }

  if (request.method === 'OPTIONS') {
    const headers = new Headers({
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Vary': 'Origin',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Max-Age': '600',
      'X-Request-ID': requestId,
    });
    if (origin) headers.set('Access-Control-Allow-Origin', origin);
    return new Response(null, { status: 204, headers });
  }

  if (request.method !== 'GET') {
    return errorResponse(request, 405, 'METHOD_NOT_ALLOWED', 'Only GET is supported.', requestId, env, { Allow: 'GET, OPTIONS' });
  }

  const windowStart = url.searchParams.get('windowStart');
  const windowEnd = url.searchParams.get('windowEnd');
  const now = nowFn();
  if (!isValidReportingWindow(windowStart, windowEnd, now)) {
    return errorResponse(request, 400, 'INVALID_REPORTING_WINDOW', 'Provide a completed 24-hour UTC window whose start and end are at 09:00 UTC.', requestId, env);
  }

  const authorization = request.headers.get('authorization') ?? '';
  const bearer = /^Bearer ([-A-Za-z0-9._~+/=]{8,8192})$/.exec(authorization);
  if (!bearer) {
    return errorResponse(request, 401, 'AUTHENTICATION_REQUIRED', 'A valid bearer access token is required.', requestId, env, { 'WWW-Authenticate': 'Bearer' });
  }

  let introspection;
  try {
    const basic = Buffer.from(config.clientId + ':' + config.clientSecret).toString('base64');
    const result = await fetchJson(fetchImpl, config.introspectionUrl, {
      method: 'POST',
      headers: {
        Authorization: 'Basic ' + basic,
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams({ token: bearer[1], token_type_hint: 'access_token' }).toString(),
    }, config.timeoutMs);
    if (!result.ok) {
      return errorResponse(request, 503, 'IDENTITY_PROVIDER_UNAVAILABLE', 'Token verification is temporarily unavailable.', requestId, env);
    }
    introspection = result.value;
  } catch {
    return errorResponse(request, 503, 'IDENTITY_PROVIDER_UNAVAILABLE', 'Token verification is temporarily unavailable.', requestId, env);
  }

  if (!introspection || introspection.active !== true) {
    return errorResponse(request, 401, 'ACCESS_TOKEN_INVALID', 'Access token is inactive or invalid.', requestId, env, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
  }
  const subject = validShortString(introspection.sub, 255) ? introspection.sub : null;
  const tenantId = validShortString(introspection.tenant_id, 128) ? introspection.tenant_id : null;
  const scopeValues = Array.isArray(introspection.scope)
    ? introspection.scope
    : (typeof introspection.scope === 'string' ? introspection.scope.split(/\s+/) : []);
  if (!subject || !tenantId) {
    return errorResponse(request, 401, 'ACCESS_TOKEN_CLAIMS_INVALID', 'Token lacks the required principal or tenant claims.', requestId, env);
  }
  if (!scopeValues.includes('gien:evidence:read')) {
    return errorResponse(request, 403, 'INSUFFICIENT_SCOPE', 'The caller lacks the required evidence-read scope.', requestId, env);
  }

  const providerUrl = new URL(config.providerUrl);
  providerUrl.searchParams.set('windowStart', windowStart);
  providerUrl.searchParams.set('windowEnd', windowEnd);

  let upstream;
  try {
    const result = await fetchJson(fetchImpl, providerUrl, {
      method: 'GET',
      headers: {
        Authorization: 'Bearer ' + config.providerToken,
        Accept: 'application/json',
        'X-GIEN-Tenant-ID': tenantId,
        'X-GIEN-Request-ID': requestId,
      },
    }, config.timeoutMs);
    if (!result.ok) {
      return errorResponse(request, 502, 'EVIDENCE_PROVIDER_UNAVAILABLE', 'Evidence provider did not return a valid response.', requestId, env);
    }
    upstream = result.value;
  } catch {
    return errorResponse(request, 502, 'EVIDENCE_PROVIDER_UNAVAILABLE', 'Evidence provider did not return a valid response.', requestId, env);
  }

  const snapshot = validateSnapshot(upstream, { subject, tenantId }, windowStart, windowEnd, now, config.maxSnapshotAgeMs);
  if (!snapshot) {
    return errorResponse(request, 502, 'EVIDENCE_SNAPSHOT_INVALID', 'Evidence provider response failed schema, provenance, tenant, freshness, or assessment validation.', requestId, env);
  }

  const snapshotDigest = 'sha384:' + createHash('sha384').update(JSON.stringify(snapshot)).digest('hex');
  const auditEvent = {
    schemaVersion: 'gien.audit.event.v1',
    eventId: requestId,
    eventType: 'gien.evidence.read',
    occurredAt: now.toISOString(),
    actorId: subject,
    tenantId,
    resourceType: 'systemic-risk-snapshot',
    sourceId: snapshot.source.id,
    sourceVersion: snapshot.source.version,
    window: snapshot.window,
    snapshotDigest,
    metrics: snapshot.metrics.map((metric) => ({
      id: metric.id,
      sourceKind: metric.sourceKind,
      assessmentStatus: metric.assessmentStatus,
      evidenceReferenceCount: metric.evidenceRefs.length,
    })),
  };
  const auditBody = JSON.stringify(auditEvent);
  const signature = 'sha256=' + createHmac('sha256', config.auditHmacSecret).update(auditBody).digest('hex');

  let auditReceipt;
  try {
    const auditResponse = await fetchImpl(config.auditSinkUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'X-GIEN-Audit-Signature': signature,
        'Idempotency-Key': requestId,
      },
      body: auditBody,
      signal: AbortSignal.timeout(config.timeoutMs),
    });
    if (!auditResponse.ok) {
      return errorResponse(request, 503, 'AUDIT_SINK_UNAVAILABLE', 'The required audit receipt could not be obtained; evidence was not released.', requestId, env);
    }
    const result = await readJsonLimited(auditResponse, 64 * 1024);
    if (
      !result ||
      result.persisted !== true ||
      !validShortString(result.receiptId, 256) ||
      result.eventId !== requestId ||
      result.snapshotDigest !== snapshotDigest
    ) {
      return errorResponse(request, 503, 'AUDIT_RECEIPT_INVALID', 'The required audit receipt did not bind to this event and snapshot; evidence was not released.', requestId, env);
    }
    auditReceipt = {
      persisted: true,
      receiptId: result.receiptId,
      eventId: requestId,
      snapshotDigest,
    };
  } catch {
    return errorResponse(request, 503, 'AUDIT_SINK_UNAVAILABLE', 'The required audit receipt could not be obtained; evidence was not released.', requestId, env);
  }

  return makeResponse(request, 200, {
    requestId,
    snapshot,
    snapshotDigest,
    audit: auditReceipt,
  }, requestId, env);
}

export function createServer(options = {}) {
  return createHttpServer(async (incoming, outgoing) => {
    const headers = new Headers();
    for (const [name, value] of Object.entries(incoming.headers)) {
      if (typeof value === 'string') headers.set(name, value);
    }
    // Do not trust Host to construct an internal request URL.
    const request = new Request('http://gien.internal' + (incoming.url || '/'), {
      method: incoming.method || 'GET',
      headers,
    });
    try {
      const response = await handleRequest(request, options);
      outgoing.statusCode = response.status;
      response.headers.forEach((value, name) => outgoing.setHeader(name, value));
      if (response.body) {
        outgoing.end(Buffer.from(await response.arrayBuffer()));
      } else {
        outgoing.end();
      }
    } catch {
      outgoing.statusCode = 500;
      outgoing.setHeader('Content-Type', 'application/json');
      outgoing.setHeader('Cache-Control', 'no-store');
      outgoing.end(JSON.stringify({ error: { code: 'INTERNAL_ERROR', message: 'Internal server error.' } }));
    }
  });
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : '';
if (invokedPath === import.meta.url) {
  const port = Number(process.env.PORT ?? 8080);
  const server = createServer();
  server.listen(port, '0.0.0.0', () => {
    process.stdout.write('GIEN Evidence API listening on port ' + port + '\n');
  });
  const stop = () => server.close(() => process.exit(0));
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}
