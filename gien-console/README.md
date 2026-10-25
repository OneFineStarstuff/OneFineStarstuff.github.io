# GIEN Governance Console — First Vertical Slice

This is an isolated Vite + React + TypeScript implementation for the fictional GIEN supervisory console. It is intentionally separate from the existing `frontend/`, `backend/` and `next-app/` projects.

## Included in this first slice

- Evidence-qualified dashboard with persistent `DEMONSTRATION DATA` labeling.
- Risk-index register and a Recharts time-series visualization.
- D3-rendered fairness heatmap using synthetic example data.
- Compliance matrix that keeps `NOT ASSESSED` distinct from a compliance conclusion.
- Alert history with JSON/CSV export and CSV-formula escaping.
- RAG provenance and submission-package readiness views with evidence gaps exposed.
- Theme toggle, route navigation, toast notification provider and responsive layouts.
- Unit tests for telemetry classification and export-safety helpers.

## Run locally

The repository commits `package-lock.json` for reproducible installation. From this directory:

```bash
npm ci
npm run typecheck
npm test
npm run build
npm run dev
```

The lockfile uses npm lockfile version 3 and currently contains 340 package entries. The entry count and file digest change whenever dependency resolution changes; use the checked-in `package-lock.json` as the source of truth rather than a historical checksum. CI installs from this committed lockfile with `npm ci`; it only generates a temporary lockfile if none is present. When changing dependencies intentionally, update and review both `package.json` and `package-lock.json`, then rerun the production dependency audit, tests, type-check and production build.

## Versioning

This is an additive, separately scoped application. The intended semantic-version classification for this feature is minor (`+semver: minor`); it is not a release or deployment approval. The console remains a draft until current-head CI and quality/security gates are cleared.

## Security and evidence boundaries

- All telemetry in this slice is synthetic; no live data connector is configured.
- The UI does not authorize regulatory decisions or make a legal-conformity determination.
- Client-side CSV/JSON export is a demonstration utility and is not an immutable or server-audited export.
- No emergency-stop action is exposed until an authenticated backend intervention controller can verify runtime acknowledgement.
- OPA/Rego enforcement, server-side role checks, authenticated evidence storage, and externally verified TEE/zk-proof evidence are future integration gates, not implemented capabilities.
