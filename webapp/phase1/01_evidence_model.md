# 01 — Evidence Model

## The evidence chain (core invariant)

Every number displayed anywhere in the application resolves through one chain:

```
index → band (threshold table) → contributing OSCAL controls → sealed artifacts → Merkle root
```

A displayed value that cannot complete this chain is a defect, not a data point. The chain is the contract between the telemetry layer and the compliance layer: telemetry owns values and bands; compliance owns control mappings; the evidence store owns artifacts and roots.

## 12-index band table (simulation-calibrated defaults)

| Index | Semantics | GREEN | AMBER | RED | Notes |
| --- | --- | --- | --- | --- | --- |
| p(doom) | Ensemble existential-risk estimate | < 0.50% | 0.50–1.00% | > 1.00% | Band edges are pp of estimated probability |
| p(doom)_kernel | Kernel-density estimate | < 0.50% | 0.50–1.00% | > 1.00% | Shown alongside the ensemble estimate |
| S_sys | Systemic composite | < 0.25 | 0.25–0.40 | > 0.40 | Headline systemic-risk gauge |
| G-SRI | Global systemic risk index (0–100) | < 30 | 30–40 | > 40 | Critical threshold 40 per the scoring engine |
| C-SRI | Compliance-side risk | < 30 | 30–40 | > 40 | |
| A-SRI | Alignment-side risk | < 30 | 30–40 | > 40 | |
| P-SRI | Propagation risk | < 30 | 30–40 | > 40 | |
| CGR-I | Constitutional-grade readiness | < 30 | 30–40 | > 40 | Inverse semantics: readiness deficit |
| CCR-I | Cryptographic governance readiness | < 30 | 30–40 | > 40 | Collateral tie-outs reference this index |
| G-SRI-VII | Galactic-readiness band (simulation) | < 30 | 30–40 | > 40 | Phase VII fictional layer |
| Δ_drift | Autonomous supervisory agent drift | < 1.0σ | 1.0–2.0σ | > 2.0σ | Trajectory matters as much as level |
| Δ_OSCAL | Control-catalog drift | +0 controls, nominal | unexplained change | missing control | Diff of catalog revisions |

Bands are defaults for the simulation calibration; a deploying institution tunes per-appetite in a single config that version-controls with the catalog. Two clocks apply: daily windows for fast indices; the slow-frequency Ω-GAR panel (CESI, UCSI, UCI, CDS, Infinity Pillar) for long-horizon synthesis — never mixed on one axis.

## Evidence-drawer contract

Each index tile opens a drawer whose payload validates against `evidence-drawer.schema.json`:

1. **current**: value, unit, band, 24h delta, window id (GIEN-DOSSIER-YYYY-DDD).
2. **series**: 30-day reference (URL or inline array), plus epoch-trend summary.
3. **controls**: contributing OSCAL control ids (resolve into the compliance matrix).
4. **artifacts**: sealed references — dossier id, artifact type, SHA-384 digest, Merkle root, and a verification hint (recompute path).
5. **verification**: `root_recomputable` flag and the recomputation walkthrough step count.

The drawer is the single UI surface regulators use to move from "trust us" to "recompute it". Drawers must render identically from the static briefing page (embedded JSON) and the live console (API) — one source of truth, two renderings.

## Hash format conventions (audit standard)

- All digests: `0x` + 64 lowercase hex characters, consistent across every occurrence within a document.
- Merkle roots: single root per window; supersession chains record the superseded root explicitly.
- Window ids: `GIEN-DOSSIER-YYYY-DDD` (day-of-year numbering), one sealed window per day at 09:00 UTC.
