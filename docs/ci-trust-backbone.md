# CI trust backbone and knowledge backbone (A1-A8, B7) - WP-114

Delivery plan with concrete drop-in files and acceptance checks. Every artefact here is a
fictional governance simulation scaffold; the honesty and determinism rules are real engineering.

## A1: ESLint no-math-random rule
Drop-in: lint/eslint.gien.cjs + webapp/src/lib/random.ts.
Acceptance: npx eslint --no-eslintrc -c lint/eslint.gien.cjs "webapp/src/**/*.{ts,tsx}" flags every
Math.random occurrence; after migration, zero Math.random usages remain in webapp/src.

## A2: watermark Playwright invariant
Drop-in: tests/e2e/watermark.spec.ts (+ tests/e2e/playwright.config.ts).
Acceptance: every routed page renders the classification banner "TOP SECRET // SUPERVISORY EYES ONLY"
and the fictional-simulation footer; the test fails on any new route missing either.

## A3: p(doom) Playwright invariant
Drop-in: tests/e2e/pdoom.spec.ts.
Acceptance: the rendered p(doom) value parses as a percentage and is <= the bands.json greenBelow
threshold for p(doom); the test imports webapp/src/data/bands.json so the invariant re-binds when
the shared thresholds change. Never hardcode the threshold in the test.

## A4: reproducible build gate
Drop-in: scripts/reproducible-build.sh.
Acceptance: in a clean CI workspace the script prints "REPRODUCIBLE: <sha256-of-hashlist>" and exits 0;
any timestamp or nondeterminism in bundler output flips it to NON_REPRODUCIBLE and blocks the release
job. If the bundler injects timestamps, fix the bundler config rather than the gate.

## A5: Sparkline accessibility fix
Drop-in: webapp/src/components/Sparkline.tsx.
Acceptance: sparklines expose role="img" with a text summary label (series name, points, range),
carry a <title>, use no animation, and zero critical violations remain on the telemetry page scan.

## A6: OPA bundle pinning
Drop-in: scripts/opa_pin.sh + scripts/opa-pinned.sha256 (fill from the official OPA checksums page
at pin time; fail-closed while empty). Acceptance: the pinned OPA release is verified by checksum,
the bundle builds from compliance/, and its checksum is printed for the CI job summary; an
unverified or unpinned bundle fails the job.

## A7: Delta_OSCAL diff for EU AI Act and DORA
Drop-in: scripts/oscal_diff.mjs.
Acceptance: snapshot the operational catalog twice; the script prints per-regime delta lines
(+/- controls, rev change) for EU AI Act and DORA, exits 0 with no drift and 2 on unexpected
drift, feeding the daily dossier Delta_OSCAL field.

## B7: knowledge backbone
Drop-in: GLOSSARY.md, CONSTITUTION.md, compliance/crosswalk.yaml, schemas/crosswalk.schema.json,
scripts/validate_crosswalk.mjs.
Acceptance: npm i -D yaml ajv, then node scripts/validate_crosswalk.mjs exits 0 on the valid
crosswalk; CI runs it on every compliance/ change; GLOSSARY.md and CONSTITUTION.md are published
at repo root and cited from the dossier footer sources.

## Sequencing
A1 + A5 first (immediate lint/a11y signal), A2 + A3 next (npm i -D @playwright/test), A4 + A6 as CI
jobs, then A7 + B7 feeding the dossier Delta_OSCAL and knowledge citations.