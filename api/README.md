# GIEN Governance Telemetry API

Schema-first telemetry service for the GIEN supervisory platform. Zero runtime dependencies (Node 20 + TypeScript, `node:http` only).

- **WP-089** — WP-087 rollout phase P1: OpenAPI 3.1 schema of record (`openapi.json`), approved baseline snapshot (`snapshots/openapi.baseline.json`), schema drift gate with four-eyes override, schema-derived types, seeded deterministic server, 16 tests.
- **WP-091** — WP-087 rollout phase P2: broker-less consumer-driven contract testing and can-i-deploy promotion gates.

Fictional governance-simulation artefact: all data is simulated and seeded from the sealed GIEN-DOSSIER-2026-308 baselines.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run validate` | Structural validation of `openapi.json` (WP-087 C1) |
| `npm run gate` | Schema drift gate vs the approved baseline; `GIEN_APPROVE_BREAKING=1` applies the four-eyes override |
| `npm run build` | Type-check and build to `dist/` |
| `npm test` | Unit tests (drift-gate drills, payload shape tests, pact + promotion-gate drills) |
| `npm run verify:pacts` | Replays every consumer pact in `pacts/` against the built server and records verification results keyed by spec digest |
| `npm run can-i-deploy -- --environment production [--record-deployment]` | Promotion gate: PASS only if the drift gate is GREEN (or APPROVED) and every registered consumer has a fresh PASS verification for the exact spec digest being promoted |
| `npm start` | Serve on `PORT` (default 4183) |

## Contract-testing model (P2)

The checked-in `pacts/` directory, `deployments/verifications.json`, and `deployments/records.json` are the broker. A promotion is only permitted when:

1. the schema drift gate is GREEN against the approved baseline snapshot (or APPROVED via `GIEN_APPROVE_BREAKING=1` after second-reviewer sign-off), and
2. every consumer pact has a PASS verification record whose SHA-256 spec digest matches exactly the candidate spec. Stale digests block promotion.

Verification records are written by `npm run verify:pacts` after a full replay against the live built server; deployment records are appended (idempotently, per environment + digest) by `--record-deployment`. In enterprise mode these ledgers are WORM-committed with ML-DSA-87 sealing.

## Consumers

- `gien-platform-dashboard` (`pacts/gien-dashboard.pact.json`) — the gien-platform supervisory SPA.
