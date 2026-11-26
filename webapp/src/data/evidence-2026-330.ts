import { EvidenceIndexId, EvidencePayload } from '../types/gien';
import { DOSSIER_330 } from './dossier-2026-330';

// Evidence payloads for the WP-096 evidence-drawer contract, sealed dossier-330 values.
// Honesty rules: the per-artefact WORM leaf digests are NOT part of the static corpus,
// so each payload references the sealed archive itself (digest = archive seal) and
// declares root_recomputable: false. The evidence quote age tile has no drawer:
// its index id is outside the WP-096 contract enum.
const ROOT = DOSSIER_330.merkleRoot;
const D = DOSSIER_330.dossierId;

const ARTIFACT = {
  type: 'sealed-dossier-corpus',
  dossier_id: D,
  digest: ROOT,
  merkle_root: ROOT,
  path: 'GIEN_Daily_Dossier_2026-11-26.md'
};

const VERIFICATION = {
  root_recomputable: false,
  walkthrough_steps: 4,
  notes: 'Static fixture: leaf-level recomputation only. The WORM leaf set is not exposed in the daily corpus, so the sealed root cannot be recomputed in-browser; the Merkle inspector reports this honestly.'
};

function ev(
  id: EvidenceIndexId,
  name: string,
  semantics: string,
  value: number,
  unit: string,
  delta: number,
  trend: string,
  controls: { control_id: string; regimes: string[] }[],
  series?: { inline: number[]; notes: string }
): EvidencePayload {
  return {
    index: { id, name, semantics },
    current: { value, unit, band: 'GREEN', delta_24h: delta, window_id: D, epoch_trend: trend },
    ...(series ? { series } : {}),
    controls: controls.map((c) => ({ ...c, layer: 'simulation' as const })),
    artifacts: [ARTIFACT],
    verification: VERIFICATION
  };
}

const R_NIST = 'NIST AI RMF 1.0';
const R_EU = 'EU AI Act';
const R_SR11 = 'SR 11-7';
const R_ISO = 'ISO/IEC 42001';

export const EVIDENCE_330: Record<EvidenceIndexId, EvidencePayload> = {
  s_sys: ev('s_sys', 'Systemic risk (S_sys)', 'Composite systemic-risk index of the GIEN mesh; sub-0.200 is the supervisory comfort band.', 0.167, 'index', -0.001, 'New epoch low; close series 0.171 -> 0.167.', [
    { control_id: 'CD-02', regimes: [R_NIST, R_SR11] },
    { control_id: 'CD-01', regimes: [R_ISO] }
  ], { inline: [0.171, 0.170, 0.169, 0.168, 0.167], notes: 'Daily closes 2026-11-22 -> 2026-11-26 (GIEN-DOSSIER-2026-326 -> -330).' }),
  g_sri: ev('g_sri', 'Global systemic risk index', 'Headline global systemic-risk index across all ten control domains.', 25.0, 'index', -0.1, 'New epoch low; 42nd improving window of the last 43.', [
    { control_id: 'CD-02', regimes: [R_NIST, R_SR11] },
    { control_id: 'CD-07', regimes: [R_EU] }
  ], { inline: [25.4, 25.3, 25.2, 25.1, 25.0], notes: 'Daily closes 2026-11-22 -> 2026-11-26 (GIEN-DOSSIER-2026-326 -> -330).' }),
  c_sri: ev('c_sri', 'Compliance-side risk', 'Risk contribution from compliance and crosswalk posture.', 15.4, 'index', -0.1, 'Steady drift down.', [
    { control_id: 'CD-06', regimes: [R_EU, R_ISO] },
    { control_id: 'CD-02', regimes: [R_NIST] }
  ]),
  g_sri_vii: ev('g_sri_vii', 'Phase VII readiness band', 'Galactic-phase (Phase VII) readiness risk band.', 27.6, 'index', -0.1, 'Steady improvement.', [
    { control_id: 'CD-10', regimes: ['Interstellar AI Governance Accord'] },
    { control_id: 'CD-02', regimes: [R_NIST] }
  ]),
  a_sri: ev('a_sri', 'Alignment-side risk', 'Risk contribution from model-alignment assurance.', 18.6, 'index', -0.1, 'Steady.', [
    { control_id: 'CD-04', regimes: [R_EU, R_NIST] },
    { control_id: 'CD-02', regimes: [R_SR11] }
  ]),
  p_sri: ev('p_sri', 'Propagation risk', 'Risk contribution from deployment and propagation surfaces.', 13.9, 'index', -0.1, 'Steady.', [
    { control_id: 'CD-08', regimes: [R_ISO, 'DORA'] },
    { control_id: 'CD-02', regimes: [R_NIST] }
  ]),
  cgr_i: ev('cgr_i', 'Constitutional-grade readiness', 'Readiness of the constitutional governance layer (CFE-1.0 / SGR-028).', 18.4, 'index', -0.1, 'Steady.', [
    { control_id: 'CD-01', regimes: ['Galactic Treaty Framework'] },
    { control_id: 'CD-02', regimes: [R_NIST] }
  ]),
  ccr_i: ev('ccr_i', 'Cryptographic governance readiness', 'Readiness of the PQC / WORM ledger cryptographic stack.', 17.0, 'index', -0.1, 'Steady.', [
    { control_id: 'CD-05', regimes: ['SEC Rule 17a-4'] },
    { control_id: 'CD-02', regimes: [R_NIST] }
  ]),
  p_doom: ev('p_doom', 'Ensemble p(doom)', 'Ensemble estimate of catastrophic-outcome probability from the SDT scenario library.', 0.12, '%', -0.01, 'New epoch low; close series 0.16% -> 0.12%.', [
    { control_id: 'CD-02', regimes: [R_NIST] },
    { control_id: 'CD-10', regimes: ['Galactic Treaty Framework'] }
  ], { inline: [0.16, 0.15, 0.14, 0.13, 0.12], notes: 'Daily closes 2026-11-22 -> 2026-11-26 (GIEN-DOSSIER-2026-326 -> -330).' }),
  p_doom_kernel: ev('p_doom_kernel', 'Kernel density p(doom)', 'Kernel-density estimate of catastrophic-outcome probability.', 0.05, '%', 0, 'Epoch low held.', [
    { control_id: 'CD-02', regimes: [R_NIST] },
    { control_id: 'CD-10', regimes: ['Galactic Treaty Framework'] }
  ]),
  drift: ev('drift', 'Delta_drift', 'Autonomous supervisory agent drift within the Sentinel v2.4 auto-throttle envelope.', 0.0, 'sigma', 0, '29th consecutive centered window.', [
    { control_id: 'CD-09', regimes: [R_ISO] },
    { control_id: 'CD-02', regimes: [R_NIST] }
  ]),
  oscal_drift: ev('oscal_drift', 'Delta_OSCAL', 'Control-count drift in the OSCAL 1.1.2 catalog crosswalk.', 0, 'controls', 0, 'Catalog rev 1165 steady-state; no control-dictionary deltas.', [
    { control_id: 'CD-06', regimes: [R_EU, R_ISO] },
    { control_id: 'CD-01', regimes: [R_NIST] }
  ])
};
