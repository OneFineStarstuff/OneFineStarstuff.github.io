import { SealedDossier } from '../types/gien';

// Sealed fixture: GIEN-DOSSIER-2026-318 (window 2026-11-13 09:00 UTC -> 2026-11-14 09:00 UTC).
// Source of truth: the daily dossier corpus (WP-104, PR #258, merged 1cce4695);
// values must match the sealed dossier exactly.
export const DOSSIER_318: SealedDossier = {
  dossierId: 'GIEN-DOSSIER-2026-318',
  workPackage: 'WP-104 (PR #258, merged 1cce4695)',
  window: '2026-11-13 09:00 UTC -> 2026-11-14 09:00 UTC (Saturday — weekly aggregation edition; DRILL-054 freeze-vote day; SGR-031 verification-window day 3)',
  merkleRoot: '0x1cccef5860e29dce513e0d877b4c2ad620235ba0aae82105b319674612e97dc2',
  artefacts: 26,
  signatures: [
    { algorithm: 'ML-DSA-87 (FIPS 204)', value: '0x4f7a2c9e1b8d6350a9e4c1f7b3d8e2069c5a1f8d3b7e9c4026d8a3f1e5c7b9d2' },
    { algorithm: 'Falcon-1024', value: '0x8b1d5f3a7c9e2046d3f8b5a1c7e9d4038a2f6c1b9e5d7a3406f9c2b8d1e5a7f3' },
    { algorithm: 'SLH-DSA (FIPS 205)', value: '0x2e9c7b1a5f3d8064c9b2e7a5d1f8c3067b4a9d2e1f5c8b3704a9d6f2c8e1b5a7' }
  ],
  indices: [
    { key: 'S_sys', label: 'Systemic risk (S_sys)', value: '0.177', delta: '-0.001', band: 'GREEN', note: 'New epoch low.', evidenceId: 's_sys' },
    { key: 'G-SRI', label: 'Global systemic risk index', value: '26.0', delta: '-0.1', band: 'GREEN', note: 'New epoch low; 31st improving window of the last 32.', evidenceId: 'g_sri' },
    { key: 'C-SRI', label: 'Compliance-side risk', value: '16.4', delta: '-0.1', band: 'GREEN', note: 'Steady drift down.', evidenceId: 'c_sri' },
    { key: 'G-SRI-VII', label: 'Phase VII readiness band', value: '28.6', delta: '-0.1', band: 'GREEN', note: 'Galactic readiness.', evidenceId: 'g_sri_vii' },
    { key: 'A-SRI', label: 'Alignment-side risk', value: '19.6', delta: '-0.1', band: 'GREEN', note: 'Steady.', evidenceId: 'a_sri' },
    { key: 'P-SRI', label: 'Propagation risk', value: '14.9', delta: '-0.1', band: 'GREEN', note: 'Steady.', evidenceId: 'p_sri' },
    { key: 'CGR-I', label: 'Constitutional-grade readiness', value: '19.4', delta: '-0.1', band: 'GREEN', note: 'Steady.', evidenceId: 'cgr_i' },
    { key: 'CCR-I', label: 'Cryptographic governance readiness', value: '18.0', delta: '-0.1', band: 'GREEN', note: 'Steady.', evidenceId: 'ccr_i' },
    { key: 'p(doom)', label: 'Ensemble p(doom)', value: '0.20%', delta: '0.00 pp', band: 'GREEN', note: 'Epoch low held.', evidenceId: 'p_doom' },
    { key: 'p(doom)_kernel', label: 'Kernel density p(doom)', value: '0.05%', delta: '0.00 pp', band: 'GREEN', note: 'Epoch low held.', evidenceId: 'p_doom_kernel' },
    { key: 'DRIFT', label: 'Delta_drift', value: '0.0 sigma', delta: '0.0 sigma', band: 'GREEN', note: '17th consecutive centered window.', evidenceId: 'drift' },
    { key: 'OSCAL', label: 'Delta_OSCAL', value: '+0 controls (rev 1165)', delta: 'nominal', band: 'GREEN', note: 'Crosswalk drift scan clean.', evidenceId: 'oscal_drift' },
    { key: 'QUOTE', label: 'Evidence quote age', value: '7 h max', delta: 'within floor', band: 'GREEN', note: 'Inside the 24 h floor.' }
  ],
  domains: [
    { id: '01', name: 'Constitutional Core', status: 'GREEN', note: 'TLA+ rev 1179, 72/72 proofs, both epochs verified.' },
    { id: '02', name: 'Risk & Systemic Intelligence', status: 'GREEN', note: 'STLM-2026-318; all bands GREEN, no transitions.' },
    { id: '03', name: 'Zero-Trust & Attestation Fabric', status: 'GREEN', note: 'ZTAI-02 31st full closed window at 100%.' },
    { id: '04', name: 'zkML & Model Assurance', status: 'GREEN', note: 'Record 98.9%, p99 4.0 s; Stage C day 17; DI 0.910.' },
    { id: '05', name: 'PQC WORM Evidence Ledger', status: 'GREEN', note: 'FIPS 203/204/205; zero ledger gaps.' },
    { id: '06', name: 'Regulatory Crosswalk & OSCAL', status: 'GREEN', note: '17/17 regimes GREEN; catalog rev 1165 steady-state.' },
    { id: '07', name: 'Supervisory Digital Twin & Drills', status: 'GREEN', note: '1,444 replay checks, 100% bit-identical.' },
    { id: '08', name: 'Deployment & GitOps Posture', status: 'GREEN', note: '219/219 reconciled; zero rollback-blocks.' },
    { id: '09', name: 'Transcript & Voting Integrity', status: 'GREEN', note: 'Registry 457; N-60 closed (99.6%), N-61 opened.' },
    { id: '10', name: 'Omega-GAR Long-Horizon Stewardship', status: 'GREEN', note: 'Infinity Pillar 98%; dissolution arc on plan.' }
  ],
  drills: [
    { name: 'DRILL-054 (freeze vote)', outcome: 'PASSED 5/5', note: 'Choreography v0.2 frozen with all college structured comments adjudicated; dry-run shadow-replay Sunday 2026-11-15; live execution week of 2026-11-16 (<= 3 m 15 s binding design target, 3 m 10 s stretch; reference mark 3 m 12 s, Umber-Beacon).' },
    { name: 'SGR-031 (verification window)', outcome: 'DAY 3 OF 5', note: 'College rota review on plan; filing bundle 12/12 exhibits, 5/5 countersignatures, 5/5 intake; zero verification queries to date; close target 2026-11-17.' },
    { name: 'REPLAY-RB-2026-318', outcome: 'BIT-IDENTICAL', note: '1,444 checks, 100% match, including the DRILL-054 adjudication and freeze-vote records.' }
  ],
  regimes: [
    'EU AI Act (incl. Digital Omnibus (EU) 2026/1744 deferral tracking)', 'NIST AI RMF 1.0 / AI 600-1 (GenAI profile)', 'ISO/IEC 42001 (AIMS)',
    'Basel III/IV', 'SR 11-7', 'SR 26-2', 'DORA', 'NIS2', 'GDPR', 'MAS/HKMA FEAT', 'FCA SMCR & Consumer Duty',
    'HKMA Fintech 2030 AI2', 'SEC Rule 17a-4', 'FCRA/ECOA', 'ICGC/GASO', 'Interstellar AI Governance Accord', 'Galactic Treaty Framework'
  ],
  continuityProtocols: 'CP-001..CP-010 all GREEN (31st consecutive window)',
  alertLevel: 'GREEN (EL-1); compute governance BASELINE held throughout the window',
  omegaGar: { cesi: '0.543', ucsi: '0.713', uci: '0.739', cds: '0.121', infinityPillar: '98%' }
};
