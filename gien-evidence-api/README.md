# GIEN Evidence API

**Status: implementation scaffold; not deployed or configured for production.** The service is deliberately fail-closed. It does not generate risk measurements or use the frontend's seeded fixtures as source data.

## Endpoint

The machine-readable contract is in [openapi.yaml](./openapi.yaml) (OpenAPI 3.1). The runtime and integration tests enforce the security- and evidence-relevant invariants from this schema.

`GET /v1/evidence/systemic-risk?windowStart=<ISO-UTC>&windowEnd=<ISO-UTC>`

The request requires an OAuth2/OIDC bearer access token. The identity provider's token-introspection response must return:

- `active: true`
- a non-empty `sub`
- a non-empty `tenant_id`
- a `scope` containing `gien:evidence:read`

The service derives tenant scope from that verified principal. It does not accept a tenant ID from the browser as authority.

Windows must be completed 24-hour UTC intervals aligned at 09:00 UTC; the end must not be later than the most recently completed 09:00 UTC cutoff.

## Fail-closed request pipeline

1. Validate configuration and reporting window; reject unsupported origins.
2. Introspect the bearer token with the configured OIDC service.
3. Call the fixed evidence-provider endpoint with a server-held provider token and tenant ID derived from the introspected principal.
4. Validate the response schema, tenant, exact window, source metadata, freshness and each metric's assessment semantics.
5. Compute a SHA-384 digest over the validated snapshot.
6. Send a HMAC-SHA-256 authenticated audit event to the configured audit sink.
7. Release metric values only if the sink returns `persisted: true` and a non-empty `receiptId`.

This confirms an upstream audit-sink receipt, not that the sink is independently certified or immutable. The sink must verify the signature, persist an append-only record, enforce idempotency on the event ID, and return the receipt only after persistence.

## Required server-only environment variables

| Variable | Purpose |
|---|---|
| `GIEN_OIDC_INTROSPECTION_URL` | Trusted token-introspection endpoint |
| `GIEN_OIDC_CLIENT_ID` / `GIEN_OIDC_CLIENT_SECRET` | Server credentials for introspection |
| `GIEN_EVIDENCE_PROVIDER_URL` | Fixed snapshot-provider endpoint |
| `GIEN_EVIDENCE_PROVIDER_TOKEN` | Server-to-server provider credential |
| `GIEN_AUDIT_SINK_URL` | Durable audit receiver |
| `GIEN_AUDIT_SINK_HMAC_SECRET` | At least 32 characters; shared only with the audit receiver |
| `GIEN_ALLOWED_ORIGINS` | Comma-separated exact browser origins; no wildcard |
| `GIEN_UPSTREAM_TIMEOUT_MS` | Optional, 500–10000 ms; defaults to 3000 |
| `GIEN_MAX_SNAPSHOT_AGE_MS` | Optional, 1000–900000 ms; defaults to 300000 |
| `PORT` | Optional listening port; defaults to 8080 |

In production, all upstream URLs must use HTTPS. Do not prefix server secrets with `VITE_` or `NEXT_PUBLIC_`, and do not commit them to source control.

## Response contract

A successful response contains:

- `snapshot.schemaVersion = "gien.evidence.snapshot.v1"`
- tenant-bound `snapshot.tenantId`
- exact `snapshot.window.start/end`
- source identity/version and bounded metric records
- `snapshotDigest` in `sha384:<96 lowercase hex characters>` form
- an `audit` receipt with `persisted: true`, `receiptId`, and `eventId`

Each assessed metric must include a non-null value in [0,1], `sourceKind` of `live` or `external-attested`, an observation timestamp inside the requested reporting window, a method version, and at least one evidence reference. Synthetic measurements are never accepted with an `ASSESSED` status. Missing or pending assessments must have a null value.

## Status codes

- `200`: validated snapshot released after audit receipt
- `400`: invalid reporting window
- `401`: absent, inactive, or invalid principal token
- `403`: disallowed origin or missing scope
- `404`: unknown route
- `405`: unsupported method
- `502`: provider unavailable or invalid/stale snapshot
- `503`: dependency configuration, identity provider, or audit sink unavailable

Every response is `Cache-Control: no-store` and includes an `X-Request-ID`.

## Local checks

```bash
cd gien-evidence-api
npm run check
npm test
npm start
```

The service can be started locally only after valid test/development dependencies are configured. The test suite uses mocked upstreams and does not claim to verify a real OIDC provider, evidence store, or audit sink.

## Integration boundary

The Vite frontend's `readEvidenceSnapshot` adapter accepts an access-token callback and requires `VITE_GIEN_EVIDENCE_API_URL`. It is an interface only until the application integrates its approved identity provider. No token storage, stub token, fixture fallback, or automatic role escalation is provided.
