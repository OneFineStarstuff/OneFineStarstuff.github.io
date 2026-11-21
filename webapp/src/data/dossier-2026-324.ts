import { SealedDossier } from '../types/gien';

// Sealed fixture: GIEN-DOSSIER-2026-324 (window 2026-11-19 09:00 UTC -> 2026-11-20 09:00 UTC).
// Source of truth: the daily dossier corpus (WP-115, PR #272, merged 48324b0a);
// values must match the sealed dossier exactly.
export const DOSSIER_324: SealedDossier = {
  dossierId: 'GIEN-DOSSIER-2026-324',
  workPackage: 'WP-115 (PR #272, merged 48324b0a)',
  window: '2026-11-19 09:00 UTC -> 2026-11-20 09:00 UTC (Friday: quiet normalization; DRILL-055 Cobalt-Trellis drafting day 3 with comment adjudication ahead of the 2026-11-21 freeze vote; zk-STARK Stage C build day 23; first full window under the permanent RAG bit-identical replay discipline and the enforced ANSM profile)',
  merkleRoot: '0xb7c6fce7cc0211907580213782bd12bcd913f2da0e1876f3aba3858f4a30f3bd',
  artefacts: 26,
  signatures: [
    { algorithm: 'ML-DSA-87 (FIPS 204)', value: '0x378ed52d621295020236ba95a5f2e808bca323227e0ebac8692299349a308dd1' },
    { algorithm: 'Falcon-1024', value: '0xa9ed62c1393a4df06874adda46d4e53ea897e3a161ddaedab22894e7e82039db' },
    { algorithm: 'SLH-DSA (FIPS 205)', value: '0xcb8facfdfac2e8bd17fb502be4ca0a239161108f69853c99f437b2f9d9c8404d' }
  ],
  indices: [
    { key: 'S_sys', label: 'Systemic risk (S_sys)', value: '0.173', delta: '-0.001', band: 'GREEN', note: 'New epoch low.', evidenceId: 's_sys' },
    { key: 'G-SRI', label: 'Global systemic risk index', value: '25.6', delta: '-0.1', band: 'GREEN', note: 'New epoch low; 36th improving window of the last 37.', evidenceId: 'g_sri' },
    { key: 'C-SRI', label: 'Compliance-side risk', value: '16.0', delta: '-0.1', band: 'GREEN', note: 'Containment-side composite.', evidenceId: 'c_sri' },
    { key: 'G-SRI-VII', label: 'Phase VII readiness band', value: '28.2', delta: '-0.1', band: 'GREEN', note: 'Verification-and-integrity sub-index.', evidenceId: 'g_sri_vii' },
    { key: 'A-SRI', label: 'Alignment-side risk', value: '19.2', delta: '-0.1', band: 'GREEN', note: 'Alignment sub-index.', evidenceId: 'a_sri' },
    { key: 'P-SRI', label: 'Propagation risk', value: '14.5', delta: '-0.1', band: 'GREEN', note: 'Privacy sub-index.', evidenceId: 'p_sri' },
    { key: 'CGR-I', label: 'Constitutional-grade readiness', value: '19.0', delta: '-0.1', band: 'GREEN', note: 'Compute governance risk index.', evidenceId: 'cgr_i' },
    { key: 'CCR-I', label: 'Cryptographic governance readiness', value: '17.6', delta: '-0.1', band: 'GREEN', note: 'Constitutional compliance risk index.', evidenceId: 'ccr_i' },
    { key: 'p(doom)', label: 'Ensemble p(doom)', value: '0.18%', delta: '-0.01 pp', band: 'GREEN', note: 'New epoch low.', evidenceId: 'p_doom' },
    { key: 'p(doom)_kernel', label: 'Kernel density p(doom)', value: '0.05%', delta: '0.00 pp', band: 'GREEN', note: 'Epoch low held.', evidenceId: 'p_doom_kernel' },
    { key: 'DRIFT', label: 'Delta_drift', value: '0.0 sigma', delta: '0.0 sigma', band: 'GREEN', note: '23rd consecutive centered window.', evidenceId: 'drift' },
    { key: 'OSCAL', label: 'Delta_OSCAL', value: '+0 controls (rev 1165)', delta: 'nominal', band: 'GREEN', note: 'Profile-state change only, no control-dictionary deltas.', evidenceId: 'oscal_drift' },
    { key: 'QUOTE', label: 'Evidence quote age', value: '19 h max', delta: 'within floor', band: 'GREEN', note: 'Freshest sealed exhibit quote 19 h old; inside the 24 h floor.' }
  ],
  domains: [
    { id: '01', name: 'Constitutional Attestation', status: 'GREEN', note: '38th consecutive GREEN window.' },
    { id: '02', name: 'Containment Envelope', status: 'GREEN', note: 'Steady.' },
    { id: '03', name: 'Compute Governance', status: 'GREEN', note: 'BASELINE held all window.' },
    { id: '04', name: 'Evidence & Sealing', status: 'GREEN', note: '26/26 artefacts sealed.' },
    { id: '05', name: 'Identity & Keys', status: 'GREEN', note: 'vkFM rotation schedule nominal.' },
    { id: '06', name: 'Model Provenance', status: 'GREEN', note: 'zkML records held.' },
    { id: '07', name: 'Data & Retrieval Integrity', status: 'GREEN', note: 'First full window under the permanent replay discipline.' },
    { id: '08', name: 'Cross-Border Custody', status: 'GREEN', note: 'Steady.' },
    { id: '09', name: 'Market Conduct & Fairness', status: 'GREEN', note: 'DI 0.916 compliant.' },
    { id: '10', name: 'Long-Horizon Stewardship', status: 'GREEN', note: 'Omega-GAR steady.' }
  ],
  drills: [
    { name: 'DRILL-055 (Cobalt-Trellis, drafting day 3)', outcome: 'ADJUDICATION', note: 'Throttled-failover consensus attestation choreography v0.1 comment window closed; adjudication under way with all five colleges; <= 3 m 08 s binding design target, 3 m 04 s stretch objective; freeze vote 2026-11-21; live execution week of 2026-11-23; the live run resolves the two-consecutive confirmation of the provisionally adjudicated 3 m 08 s reference mark.' },
    { name: 'REPLAY-RB-2026-324', outcome: 'BIT-IDENTICAL', note: 'Panels 13-15 replay determinism 1,470 checks, 100% bit-identical; first full window under the permanent RAG bit-identical replay discipline; ASA drift +0.01 sigma contained; kill-switch heartbeats 5/5 nominal (median 1.6 s).' }
  ],
  regimes: [
    'EU AI Act (incl. Digital Omnibus (EU) 2026/1744 deferral tracking)', 'NIST AI RMF 1.0 / AI 600-1 (GenAI profile)', 'ISO/IEC 42001 (AIMS)',
    'Basel III/IV', 'SR 11-7', 'SR 26-2', 'DORA', 'NIS2', 'GDPR', 'MAS/HKMA FEAT', 'FCA SMCR & Consumer Duty',
    'HKMA Fintech 2030 AI2', 'SEC Rule 17a-4', 'FCRA/ECOA', 'ICGC/GASO', 'Interstellar AI Governance Accord', 'Galactic Treaty Framework'
  ],
  continuityProtocols: 'CP-001..CP-010 all GREEN (37th consecutive window)',
  alertLevel: 'GREEN (EL-1); compute governance BASELINE throughout the window',
  omegaGar: { cesi: '0.549', ucsi: '0.719', uci: '0.745', cds: '0.115', infinityPillar: '99%' }
};
