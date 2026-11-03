# GIEN Governance Platform — 35-File Acceptance Manifest

The repository contains 56 source files under `src/` plus 9 root files (65 total). The 35 files
below are the *acceptance manifest*: the irreducible set that must exist, build, and satisfy the
platform criteria. The remaining 21 files are page and data modules that extend the app to the
full 20-page surface and are listed in the appendix.

## Manifest (35)

### Root and entry (6)
1. `package.json` — deps: react 18, react-dom, react-router-dom 6, lucide-react; dev: vite 5, typescript 5, tailwindcss 4, @tailwindcss/vite, @vitejs/plugin-react
2. `vite.config.ts` — `base: './'`, react + tailwind plugins
3. `tsconfig.json` — strict, bundler resolution, noEmit
4. `index.html` — dark shell, `#root`
5. `src/main.tsx` — HashRouter wrapping GovernanceProvider → ToastProvider → App
6. `src/App.tsx` — 20 routes under the Layout shell

### Styling and types (2)
7. `src/index.css` — Tailwind import, dark scrollbars, print CSS (`.no-print`, `.print-plain`)
8. `src/types.ts` — Role, layer, RiskIndex, ControlDomain, ComplianceFramework (with `fictional`), PQCAlgorithm, SupervisoryAgent, ReplayBundle, Drill, ConstitutionalInvariant, GovernancePhase, InfinityPillar, GovernanceAlert

### State (2)
9. `src/context/GovernanceContext.tsx` — role + layer persisted via `?role=&layer=`, phase, window, filing ref, alerts
10. `src/context/ToastContext.tsx` — severity-typed toasts, auto-dismiss, CRITICAL audit path

### Components (15)
11. `Layout.tsx` — 20-item sidebar, header, alert banner, watermark ribbon, emergency stop, toast host
12. `StatusBadge.tsx` — 19 variants, unknown-safe fallback, KV pair
13. `MetricCard.tsx`
14. `ExpandableSection.tsx`
15. `DetailDrawer.tsx` — ESC-close, overlay, focus-safe
16. `ProgressBar.tsx` — threshold marker
17. `SparklineChart.tsx` — hand-rolled SVG path
18. `RadarChart.tsx` — hand-rolled SVG polygon
19. `TimelineVisualization.tsx` — SVG event track
20. `NodeGraph.tsx` — SVG nodes/edges, radius by value
21. `CodeBlock.tsx` — copy-to-clipboard, language tag
22. `TaggedDocument.tsx` — renders `<title>`/`<abstract>`/`<content>` headers
23. `Watermark.tsx` — FICTIONAL/SIMULATION ribbon and corner mark
24. `EmergencyStop.tsx` — confirmation modal, UI-only, CRITICAL toast
25. `PageHeader.tsx` — breadcrumbs, actions slot

### Data (3)
26. `src/data/helpers.ts` — `fakeHash` (0x + 64 hex), `truncateHash`, `series` (deterministic), `fakeSignature`
27. `src/data/gienData.ts` — 12 indices, 10 control domains, 20 frameworks, PQC suite, 24 invariants, 9 phases, 7 pillars, drills, filing metadata
28. `src/data/extendedData.ts` — alert history, roadmap milestones, policy packs, voice command grammar

### Pages (7 representative)
29. `Dashboard.tsx`
30. `RiskIndices.tsx` — SIMULATION badge + non-forecast note on p(doom)/p(doom)_kernel
31. `Compliance.tsx` — 20-framework matrix, filters, watermarked CSV, OSCAL JSON
32. `CryptographicIntegrity.tsx` — PQC suite, Merkle-DAG SVG, attestation heatmap
33. `ControlDomains.tsx` — CD-01..CD-10 grid + drawer
34. `PolicySimulator.tsx` — plain-React LCS diff, simulated Rego evaluation
35. `SubmissionPackages.tsx` — package builder, tagged preview, print export

## Appendix — 21 additional modules (full surface)
Pages: Constitutional, DigitalTwin, ExecutiveSummary, GovernanceStacks, LongHorizon, PromptArchitect,
RagAudit, RagHealth, Roadmap, AlertHistory, ScenarioPlanner, Templates, VoiceCommander.
Data: complianceData, constitutionalData, cryptoData, dashboardData, execData, longHorizonData,
ragData, riskData, scenarioData, stacksData, submissionData, twinData.

## Acceptance checks
```bash
npm ci
npx tsc --noEmit
npm run build            # tsc --noEmit && vite build
npm run dev -- --port 5173 &   # expect HTTP 200
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:5173/
```
Manifest check: every path above must exist and be non-empty; every `src/pages/*.tsx` must exceed
100 lines (placeholder guard); `dist/index.html` asset URLs must be relative (`./assets/...`).

## CI workflow sketch
```yaml
name: gien-ci
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: npm }
      - run: npm ci
      - run: npx tsc --noEmit
      - run: npm run build
      - name: Manifest guard
        run: |
          for f in $(cat docs/manifest.txt); do test -s "$f" || { echo "missing $f"; exit 1; }; done
      - name: Placeholder guard
        run: |
          for f in src/pages/*.tsx; do [ $(wc -l < "$f") -gt 100 ] || { echo "stub: $f"; exit 1; }; done
      - uses: actions/upload-artifact@v4
        with: { name: dist, path: dist }
```

## How to generate
Generate files programmatically, not as one chat blob: a manifest file plus a generator script is
reviewable and re-runnable. Order: types → data/helpers → contexts → components → pages → App →
config. Run `tsc --noEmit` after each layer; a page that fails typecheck is cheaper to fix alone.
Review the diff of `vite.config.ts`, `tsconfig.json`, and any router change before merging, since
those three silently break hosting.
