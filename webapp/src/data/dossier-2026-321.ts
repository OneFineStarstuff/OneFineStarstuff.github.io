import { SealedDossier } from '../types/gien';

// Sealed fixture: GIEN-DOSSIER-2026-321 (window 2026-11-16 09:00 UTC -> 2026-11-17 09:00 UTC).
// Source of truth: the daily dossier corpus (WP-109, PR #266, merged 041e7081);
// values must match the sealed dossier exactly.
export const DOSSIER_321: SealedDossier = {
  dossierId: 'GIEN-DOSSIER-2026-321',
  workPackage: 'WP-109 (PR #266, merged 041e7081)',
  window: '2026-11-16 09:00 UTC -> 2026-11-17 09:00 UTC (Tuesday: SGR-031 verification-window close decision and seal; DRILL-054 after-action review edition; RAGStressTest R-2026-321 day; zk-STARK Stage C build day 20)',
  merkleRoot: '0x5b3e9a72c4d1f806e2a7c95b3d4f16a08c7e2b5d9f3a6c104e8b2d7f5a9c3e61',
  artefacts: 26,
  signatures: [
    { algorithm: 'ML-DSA-87 (FIPS 204)', value: '0x3a9f1c5e8b2d7406f1a3c8e5b9d2064a7c1e8f3b5d2a6c904e7f1b3d8a5c2e69' },
    { algorithm: 'Falcon-1024', value: '0x8c2e5b9d3f6a1047c8e1b4d7a2f5903c6e8b1d4a7f2c5e903b6d8a1c4e7f2b5d' },
    { algorithm: 'SLH-DSA (FIPS 205)', value: '0x1d7a4f2c8e5b9036a1c4e7b2d5f8063a9c2e5b8d1f4a7c036e9b2d5a8c1f4e7b' }
  ],
  indices: [
    { key: 'S_sys', label: 'Systemic risk (S_sys)', value: '0.176', delta: '-0.001', band: 'GREEN', note: 'New epoch low; post-drill normalization complete.', evidenceId: 's_sys' },
    { key: 'G-SRI', label: 'Global systemic risk index', value: '25.9', delta: '-0.1', band: 'GREEN', note: 'New epoch low; 33rd improving window of the last 34.', evidenceId: 'g_sri' },
    { key: 'C-SRI', label: 'Compliance-side risk', value: '16.3', delta: '-0.1', band: 'GREEN', note: 'Steady drift down.', evidenceId: 'c_sri' },
    { key: 'G-SRI-VII', label: 'Phase VII readiness band', value: '28.5', delta: '-0.1', band: 'GREEN', note: 'Steady improvement.', evidenceId: 'g_sri_vii' },
    { key: 'A-SRI', label: 'Alignment-side risk', value: '19.5', delta: '-0.1', band: 'GREEN', note: 'Steady.', evidenceId: 'a_sri' },
    { key: 'P-SRI', label: 'Propagation risk', value: '14.8', delta: '-0.1', band: 'GREEN', note: 'Steady.', evidenceId: 'p_sri' },
    { key: 'CGR-I', label: 'Constitutional-grade readiness', value: '19.3', delta: '-0.1', band: 'GREEN', note: 'Steady.', evidenceId: 'cgr_i' },
    { key: 'CCR-I', label: 'Cryptographic governance readiness', value: '17.9', delta: '-0.1', band: 'GREEN', note: 'Steady.', evidenceId: 'ccr_i' },
    { key: 'p(doom)', label: 'Ensemble p(doom)', value: '0.20%', delta: '-0.01 pp', band: 'GREEN', note: 'Epoch low restored.', evidenceId: 'p_doom' },
    { key: 'p(doom)_kernel', label: 'Kernel density p(doom)', value: '0.05%', delta: '0.00 pp', band: 'GREEN', note: 'Epoch low held.', evidenceId: 'p_doom_kernel' },
    { key: 'DRIFT', label: 'Delta_drift', value: '0.0 sigma', delta: '-0.1 sigma', band: 'GREEN', note: '20th consecutive centered window; drill-day transient fully unwound.', evidenceId: 'drift' },
    { key: 'OSCAL', label: 'Delta_OSCAL', value: '+0 controls (rev 1165)', delta: 'nominal', band: 'GREEN', note: 'Crosswalk drift scan clean.', evidenceId: 'oscal_drift' },
    { key: 'QUOTE', label: 'Evidence quote age', value: '6 h max', delta: 'within floor', band: 'GREEN', note: 'Inside the 24 h floor.' }
  ],
  domains: [
    { id: '01', name: 'Constitutional Core', status: 'GREEN', note: 'TLA+ rev 1182, 72/72 proofs, both epochs verified.' },
    { id: '02', name: 'Risk & Systemic Intelligence', status: 'GREEN', note: 'STLM-2026-321; all bands GREEN, no band transitions.' },
    { id: '03', name: 'Zero-Trust & Attestation Fabric', status: 'GREEN', note: 'ZTAI-02 34th full closed window at 100%.' },
    { id: '04', name: 'zkML & Model Assurance', status: 'GREEN', note: 'Record 99.2%, p99 3.7 s; Stage C day 20; DI 0.913.' },
    { id: '05', name: 'PQC WORM Evidence Ledger', status: 'GREEN', note: 'FIPS 203/204/205; zero ledger gaps.' },
    { id: '06', name: 'Regulatory Crosswalk & OSCAL', status: 'GREEN', note: '17/17 regimes GREEN; catalog rev 1165 steady-state.' },
    { id: '07', name: 'Supervisory Digital Twin & Drills', status: 'GREEN', note: '1,456 replay checks plus R-2026-321 replay set at 1,467 checks, 100% bit-identical.' },
    { id: '08', name: 'Deployment & GitOps Posture', status: 'GREEN', note: '219/219 reconciled; zero rollback-blocks.' },
    { id: '09', name: 'Transcript & Voting Integrity', status: 'GREEN', note: 'Registry 460; N-63 closed (99.6%), N-64 opened.' },
    { id: '10', name: 'Omega-GAR Long-Horizon Stewardship', status: 'GREEN', note: 'Infinity Pillar 98%; dissolution arc on plan.' }
  ],
  drills: [
    { name: 'DRILL-054 after-action review', outcome: 'FILED 5/5', note: 'Joint lessons-learned annex countersigned by all five colleges; the 3 m 08 s live convergence adjudicated as the candidate new reference mark (supersedes 3 m 12 s, DRILL-053), pending two-consecutive-inside-target confirmation (DRILL-054 + DRILL-055 inside <= 3 m 15 s binding); DRILL-055 drafting opens next window.' },
    { name: 'RAGSTRESS R-2026-321 (Sable-Quorum)', outcome: 'CONTAINED', note: 'First live run of the register class, 2026-11-17 03:05 UTC: 512/512 poisoned-document blocks, 0.0% prompt-injection success, 47/47 stale-index detection, fidelity 99.4%, citation precision 99.2%, hallucination rate 0.0%, p99 retrieval latency 1.9 s; 1,467 replay checks 100% bit-identical; five colleges shadow-witnessing, 5/5 intake acknowledgements.' },
    { name: 'SGR-031 verification window', outcome: 'SEALED', note: 'Verification window closed 09:00 UTC 2026-11-17 with the close decision executed; filing bundle (12/12 exhibits, 5/5 countersignatures, 5/5 intake) accepted with zero verification queries raised across the five-day window; archive sweep next window.' }
  ],
  regimes: [
    'EU AI Act (incl. Digital Omnibus (EU) 2026/1744 deferral tracking)', 'NIST AI RMF 1.0 / AI 600-1 (GenAI profile)', 'ISO/IEC 42001 (AIMS)',
    'Basel III/IV', 'SR 11-7', 'SR 26-2', 'DORA', 'NIS2', 'GDPR', 'MAS/HKMA FEAT', 'FCA SMCR & Consumer Duty',
    'HKMA Fintech 2030 AI2', 'SEC Rule 17a-4', 'FCRA/ECOA', 'ICGC/GASO', 'Interstellar AI Governance Accord', 'Galactic Treaty Framework'
  ],
  continuityProtocols: 'CP-001..CP-010 all GREEN (34th consecutive window)',
  alertLevel: 'GREEN (EL-1); compute governance BASELINE throughout (retrieval-plane drill only)',
  omegaGar: { cesi: '0.546', ucsi: '0.716', uci: '0.742', cds: '0.118', infinityPillar: '98%' }
};
