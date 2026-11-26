import { SealedDossier } from '../types/gien';

// Sealed fixture: GIEN-DOSSIER-2026-330 (window 2026-11-25 09:00 UTC -> 2026-11-26 09:00 UTC).
// Source of truth: the daily dossier corpus (WP-125, PR #284, merged 0e19dad2);
// values must match the sealed dossier exactly.
export const DOSSIER_330: SealedDossier = {
  dossierId: 'GIEN-DOSSIER-2026-330',
  workPackage: 'WP-125 (PR #284, merged 0e19dad2)',
  window: '2026-11-25 09:00 UTC -> 2026-11-26 09:00 UTC (Thursday: no DRILL scheduled; DRILL-055 Cobalt-Trellis live week remains CLOSED with the reference mark confirmed at 3 m 08 s / 3 m 07 s; 2nd full window under the confirmed mark; zk-STARK Stage C build day 29; compute governance BASELINE whole window)',
  merkleRoot: '0x92d702ceea2725eada1d0f6650e53826ffb2d59a078db209288c717664234237',
  artefacts: 26,
  signatures: [
    { algorithm: 'ML-DSA-87 (FIPS 204)', value: '0xa753bca7fff6eb33521cbff362212c696c8891f78bad645da337e9ff54b035ed' },
    { algorithm: 'Falcon-1024', value: '0x3fc217f438661afdd3cc2841cc9fcd7623b2f3c520e8eaefab1c3de270eed588' },
    { algorithm: 'SLH-DSA (FIPS 205)', value: '0x9ff131c885d8cb26de1174db3d843b62087b190e12d1e70c546bfd106c94930d' }
  ],
  indices: [
    { key: 'S_sys', label: 'Systemic risk (S_sys)', value: '0.167', delta: '-0.001', band: 'GREEN', note: 'New epoch low.', evidenceId: 's_sys' },
    { key: 'G-SRI', label: 'Global systemic risk index', value: '25.0', delta: '-0.1', band: 'GREEN', note: 'New epoch low; 42nd improving window of the last 43.', evidenceId: 'g_sri' },
    { key: 'C-SRI', label: 'Compliance-side risk', value: '15.4', delta: '-0.1', band: 'GREEN', note: 'Containment-side composite.', evidenceId: 'c_sri' },
    { key: 'G-SRI-VII', label: 'Phase VII readiness band', value: '27.6', delta: '-0.1', band: 'GREEN', note: 'Verification-and-integrity sub-index.', evidenceId: 'g_sri_vii' },
    { key: 'A-SRI', label: 'Alignment-side risk', value: '18.6', delta: '-0.1', band: 'GREEN', note: 'Alignment sub-index.', evidenceId: 'a_sri' },
    { key: 'P-SRI', label: 'Propagation risk', value: '13.9', delta: '-0.1', band: 'GREEN', note: 'Privacy sub-index.', evidenceId: 'p_sri' },
    { key: 'CGR-I', label: 'Constitutional-grade readiness', value: '18.4', delta: '-0.1', band: 'GREEN', note: 'Compute governance risk index.', evidenceId: 'cgr_i' },
    { key: 'CCR-I', label: 'Cryptographic governance readiness', value: '17.0', delta: '-0.1', band: 'GREEN', note: 'Constitutional compliance risk index.', evidenceId: 'ccr_i' },
    { key: 'p(doom)', label: 'Ensemble p(doom)', value: '0.12%', delta: '-0.01 pp', band: 'GREEN', note: 'New epoch low.', evidenceId: 'p_doom' },
    { key: 'p(doom)_kernel', label: 'Kernel density p(doom)', value: '0.05%', delta: '0.00 pp', band: 'GREEN', note: 'Epoch low held.', evidenceId: 'p_doom_kernel' },
    { key: 'DRIFT', label: 'Delta_drift', value: '0.0 sigma', delta: '0.0 sigma', band: 'GREEN', note: '29th consecutive centered window.', evidenceId: 'drift' },
    { key: 'OSCAL', label: 'Delta_OSCAL', value: '+0 controls (rev 1165)', delta: 'nominal', band: 'GREEN', note: 'Catalog rev 1165 steady-state, no control-dictionary deltas.', evidenceId: 'oscal_drift' },
    { key: 'QUOTE', label: 'Evidence quote age', value: '12 h max', delta: 'within floor', band: 'GREEN', note: 'Freshest sealed exhibit quote 12 h old; inside the 24 h floor.' }
  ],
  domains: [
    { id: '01', name: 'Constitutional Attestation', status: 'GREEN', note: '44th consecutive GREEN window.' },
    { id: '02', name: 'Containment Envelope', status: 'GREEN', note: 'Steady.' },
    { id: '03', name: 'Compute Governance', status: 'GREEN', note: 'BASELINE whole window; second consecutive drill-free window with zero ELEVATED excursions.' },
    { id: '04', name: 'Evidence & Sealing', status: 'GREEN', note: '26/26 artefacts sealed.' },
    { id: '05', name: 'Identity & Keys', status: 'GREEN', note: 'vkFMv3 fleet rotation steady; no rotation debt outstanding.' },
    { id: '06', name: 'Model Provenance', status: 'GREEN', note: 'zkML records held (99.5%, p99 3.4 s).' },
    { id: '07', name: 'Data & Retrieval Integrity', status: 'GREEN', note: 'Bit-identical replay discipline in force.' },
    { id: '08', name: 'Cross-Border Custody', status: 'GREEN', note: 'Steady.' },
    { id: '09', name: 'Market Conduct & Fairness', status: 'GREEN', note: 'DI 0.922 compliant.' },
    { id: '10', name: 'Long-Horizon Stewardship', status: 'GREEN', note: 'Omega-GAR steady.' }
  ],
  drills: [
    { name: 'DRILL-055 (Cobalt-Trellis, live week CLOSED)', outcome: 'CONFIRMED', note: 'Live-execution week of 2026-11-23-11-26 closed with the reference mark confirmed at 3 m 08 s / 3 m 07 s (binding <= 3 m 08 s; 3 m 04 s stretch); all Panel 13-15 replays this window were executed against the confirmed band.' },
    { name: 'REPLAY-RB-2026-330', outcome: 'BIT-IDENTICAL', note: 'Panels 13-15 replay determinism 1,490 checks, 100% bit-identical; ASA drift +0.01 sigma contained; kill-switch heartbeats 5/5 nominal (median 1.6 s).' }
  ],
  regimes: [
    'EU AI Act (incl. Digital Omnibus (EU) 2026/1744 deferral tracking)', 'NIST AI RMF 1.0 / AI 600-1 (GenAI profile)', 'ISO/IEC 42001 (AIMS)',
    'Basel III/IV', 'SR 11-7', 'SR 26-2', 'DORA', 'NIS2', 'GDPR', 'MAS/HKMA FEAT', 'FCA SMCR & Consumer Duty',
    'HKMA Fintech 2030 AI2', 'SEC Rule 17a-4', 'FCRA/ECOA', 'ICGC/GASO', 'Interstellar AI Governance Accord', 'Galactic Treaty Framework'
  ],
  continuityProtocols: 'CP-001..CP-010 all GREEN (43rd consecutive window)',
  alertLevel: 'GREEN (EL-1); compute governance BASELINE throughout the window',
  omegaGar: { cesi: '0.555', ucsi: '0.725', uci: '0.751', cds: '0.109', infinityPillar: '99%' }
};
