export type EvidenceSourceKind = 'live' | 'external-attested' | 'synthetic' | 'replay' | 'pending';
export type EvidenceAssessmentStatus =
  | 'ASSESSED'
  | 'NOT_ASSESSED'
  | 'STALE'
  | 'CONFLICTED'
  | 'INVALID'
  | 'EVIDENCE_PENDING'
  | 'SIMULATED';

export interface EvidenceMetric {
  id: string;
  label: string;
  value: number | null;
  delta: number | null;
  sourceKind: EvidenceSourceKind;
  assessmentStatus: EvidenceAssessmentStatus;
  evidenceRefs: string[];
  observedAt: string | null;
  methodVersion: string | null;
}

export interface EvidenceSnapshot {
  schemaVersion: 'gien.evidence.snapshot.v1';
  tenantId: string;
  generatedAt: string;
  window: { start: string; end: string };
  source: { id: string; kind: EvidenceSourceKind; version: string };
  metrics: EvidenceMetric[];
}

export interface EvidenceReadResult {
  requestId: string;
  snapshot: EvidenceSnapshot;
  snapshotDigest: string;
  audit: { persisted: true; receiptId: string; eventId: string };
}

export class EvidenceApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly requestId?: string;

  constructor(code: string, message: string, status: number, requestId?: string) {
    super(message);
    this.name = 'EvidenceApiError';
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function endpointUrl(): URL {
  const configuredBase = import.meta.env.VITE_GIEN_EVIDENCE_API_URL?.trim();
  if (!configuredBase) {
    throw new EvidenceApiError(
      'EVIDENCE_API_NOT_CONFIGURED',
      'No GIEN evidence API URL is configured. Synthetic fixtures remain the only available data.',
      503,
    );
  }

  let base: URL;
  try {
    base = new URL(configuredBase);
  } catch {
    throw new EvidenceApiError('EVIDENCE_API_URL_INVALID', 'The GIEN evidence API URL is invalid.', 503);
  }

  const localHttp = base.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(base.hostname) && import.meta.env.DEV;
  if (base.protocol !== 'https:' && !localHttp) {
    throw new EvidenceApiError('EVIDENCE_API_HTTPS_REQUIRED', 'The GIEN evidence API must use HTTPS outside local development.', 503);
  }

  const endpoint = new URL('/v1/evidence/systemic-risk', base);
  return endpoint;
}

function validateReadResult(
  payload: unknown,
  expectedWindow: { start: string; end: string },
): EvidenceReadResult {
  if (!isRecord(payload) || !isRecord(payload.snapshot) || !isRecord(payload.audit)) {
    throw new EvidenceApiError('EVIDENCE_RESPONSE_INVALID', 'The evidence API response has an invalid shape.', 502);
  }

  const snapshot = payload.snapshot;
  const audit = payload.audit;
  const window = snapshot.window;
  if (
    snapshot.schemaVersion !== 'gien.evidence.snapshot.v1' ||
    typeof snapshot.tenantId !== 'string' ||
    typeof snapshot.generatedAt !== 'string' ||
    !isRecord(window) ||
    window.start !== expectedWindow.start ||
    window.end !== expectedWindow.end ||
    !isRecord(snapshot.source) ||
    !Array.isArray(snapshot.metrics) ||
    typeof payload.requestId !== 'string' ||
    typeof payload.snapshotDigest !== 'string' ||
    !/^sha384:[a-f0-9]{96}$/.test(payload.snapshotDigest) ||
    audit.persisted !== true ||
    typeof audit.receiptId !== 'string' ||
    audit.receiptId.length === 0 ||
    typeof audit.eventId !== 'string'
  ) {
    throw new EvidenceApiError('EVIDENCE_RESPONSE_INVALID', 'The evidence response failed contract validation.', 502);
  }

  for (const metric of snapshot.metrics) {
    if (
      !isRecord(metric) ||
      typeof metric.id !== 'string' ||
      typeof metric.label !== 'string' ||
      !['ASSESSED', 'NOT_ASSESSED', 'STALE', 'CONFLICTED', 'INVALID', 'EVIDENCE_PENDING', 'SIMULATED'].includes(String(metric.assessmentStatus)) ||
      !['live', 'external-attested', 'synthetic', 'replay', 'pending'].includes(String(metric.sourceKind)) ||
      !Array.isArray(metric.evidenceRefs)
    ) {
      throw new EvidenceApiError('EVIDENCE_RESPONSE_INVALID', 'A metric failed contract validation.', 502);
    }
    if (metric.assessmentStatus === 'ASSESSED') {
      if (
        metric.sourceKind !== 'live' && metric.sourceKind !== 'external-attested'
      ) {
        throw new EvidenceApiError('EVIDENCE_RESPONSE_INVALID', 'Synthetic or replay data cannot be marked assessed.', 502);
      }
      if (
        typeof metric.value !== 'number' ||
        !Number.isFinite(metric.value) ||
        metric.value < 0 ||
        metric.value > 1 ||
        metric.evidenceRefs.length === 0 ||
        typeof metric.observedAt !== 'string' ||
        typeof metric.methodVersion !== 'string'
      ) {
        throw new EvidenceApiError('EVIDENCE_RESPONSE_INVALID', 'An assessed metric is missing required evidence fields.', 502);
      }
    }
  }

  return payload as unknown as EvidenceReadResult;
}

/**
 * Reads an authenticated, tenant-scoped snapshot from the separately deployed
 * GIEN Evidence API. Callers must supply the approved OIDC access-token provider.
 * This function has no synthetic fallback and requires the API's durable audit
 * receipt before it returns the data to the UI.
 */
export async function readEvidenceSnapshot(input: {
  windowStart: string;
  windowEnd: string;
  getAccessToken: () => Promise<string | null>;
  signal?: AbortSignal;
}): Promise<EvidenceReadResult> {
  if (!input.windowStart || !input.windowEnd) {
    throw new EvidenceApiError('REPORTING_WINDOW_REQUIRED', 'An explicit reporting window is required.', 400);
  }

  const endpoint = endpointUrl();
  const accessToken = await input.getAccessToken();
  if (!accessToken || accessToken.trim().length < 8) {
    throw new EvidenceApiError(
      'ACCESS_TOKEN_UNAVAILABLE',
      'The approved identity provider did not supply an access token. No live request was made.',
      401,
    );
  }

  endpoint.searchParams.set('windowStart', input.windowStart);
  endpoint.searchParams.set('windowEnd', input.windowEnd);

  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer ' + accessToken,
      },
      cache: 'no-store',
      credentials: 'omit',
      ...(input.signal ? { signal: input.signal } : {}),
    });
  } catch {
    throw new EvidenceApiError('EVIDENCE_API_UNAVAILABLE', 'The evidence API could not be reached.', 503);
  }

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const errorObject = isRecord(body) && isRecord(body.error) ? body.error : {};
    const code = typeof errorObject.code === 'string' ? errorObject.code : 'EVIDENCE_API_ERROR';
    const message = typeof errorObject.message === 'string' ? errorObject.message : 'The evidence API request failed.';
    const requestId = isRecord(body) && typeof body.requestId === 'string' ? body.requestId : undefined;
    throw new EvidenceApiError(code, message, response.status, requestId);
  }

  return validateReadResult(body, { start: input.windowStart, end: input.windowEnd });
}
