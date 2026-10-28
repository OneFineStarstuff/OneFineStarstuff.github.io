# GIEN Evidence API boundary and integration gate

**Status:** Service scaffold implemented on `gien/evidence-contract-p0`; not deployed, not configured with a real identity provider, evidence provider or audit sink.

## Why this is a separate service

The repository's `backend/` currently describes a different Turning Wheel application, while `next-app/` includes a static Pages deployment workflow and pre-existing unauthenticated routes. The GIEN evidence service is therefore added as a standalone Node 20 service rather than grafted onto an unrelated backend or assumed serverless runtime.

## New service

- Source: `gien-evidence-api/src/server.mjs`
- Contract tests: `gien-evidence-api/test/server.test.mjs`
- Runtime: Node 20+, built-in HTTP/fetch/crypto; no third-party runtime dependencies
- Endpoint: `GET /v1/evidence/systemic-risk?windowStart=...&windowEnd=...`
- Readiness: `GET /readyz`
- Process health: `GET /healthz`

The route requires token introspection with an active principal, `gien:evidence:read` scope and `tenant_id`; it uses a server-held provider credential, checks snapshot schema/window/freshness/metric lineage, computes a SHA-384 snapshot digest, sends a HMAC-SHA-256 authenticated audit event, and releases the snapshot only after receiving an explicit `persisted: true` audit receipt. No token or service secret is shipped to the browser.

## Frontend boundary

`gien-platform/src/services/evidenceApi.ts` defines an authenticated API adapter. It accepts an access-token callback supplied by the approved identity-provider integration and requires `VITE_GIEN_EVIDENCE_API_URL`. It never supplies a default token, creates an identity, derives authorization from the URL role selector, or falls back to synthetic fixtures when the API fails.

The adapter is deliberately not wired into the current telemetry screen because no approved OIDC client/session adapter is configured in the repository. The screen remains explicitly synthetic until that dependency exists.

## Required operational steps

1. Configure a real OIDC introspection endpoint and least-privilege client credentials.
2. Configure a tenant-aware evidence provider with authenticated, versioned records.
3. Configure an audit sink that verifies the request HMAC, stores append-only/durable events with idempotency, and issues a receipt only after durable persistence.
4. Configure exact CORS origins and HTTPS endpoints; never expose server credentials under a `VITE_` variable.
5. Deploy the standalone service to a server-capable runtime, set readiness checks, secrets and timeouts, and record rollback/owner information.
6. Connect the approved frontend auth provider to `readEvidenceSnapshot`.
7. Add end-to-end tests against a non-production identity/provider/audit environment and verify tenant isolation, audit receipt behavior and export lineage.

The service tests use mocked upstreams. They validate local fail-closed behavior but do not establish the availability, persistence guarantees or assurance of external services.

## Not claimed

This does not complete RBAC for the entire GIEN application, create a production OIDC client, deploy the API, persist audit events itself, sign metric source records, independently verify source signatures, or create a regulator-accepted submission pipeline. Any metric without a valid current assessment remains `NOT_ASSESSED`.
