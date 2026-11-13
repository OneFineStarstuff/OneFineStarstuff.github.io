import { SealedDossier } from '../types/gien';

// Sealed fixture: GIEN-DOSSIER-2026-316 (window 2026-11-11 09:00 UTC -> 2026-11-12 09:00 UTC).
// Source of truth: the daily dossier corpus; values must match the sealed dossier exactly.
export const DOSSIER_316: SealedDossier = {
  dossierId: 'GIEN-DOSSIER-2026-316',
  workPackage: 'WP-101 (PR #253, merged 8859aa1c)',
  window: '2026-11-11 09:00 UTC -> 2026-11-12 09:00 UTC (Thursday — DRILL-053 AAR edition; DRILL-054 drafting opens; SGR-031 verification-window day 1)',
  merkleRoot: '0x1141bac4e3ac688a8d613d09d2b558d4ac38025d21a31f0aafe87d7e7bc05268',
  artefacts: 26,
  signatures: [
    { algorithm: 'ML-DSA-87 (FIPS 204)', value: '0x474d9a0da25f81753fb2a8181d37fc147f644657c4589efaccb3912a3e432e7e' },
    { algorithm: 'Falcon-1024', value: '0x14bb80369a76c5f26ef52315a0b308038ffac527f30b7ed47ddc0e9515c37e1f' },
    { algorithm: 'SLH-DSA (FIPS 205)', value: '0xc76f67c697f067f779b404b2582ababc1a239cc707c7aa867242033bd60fb12a' }
  ],
  indices: [
    { key: 'S_sys', label: 'Systemic risk (S_sys)', value: '0.179', delta: '-0.002', band: 'GREEN', note: 'New epoch low; post-drill normalization complete.' },
    { key: 'G-SRI', label: 'Global systemic risk index', value: '26.2', delta: '-0.2', band: 'GREEN', note: 'New epoch low; 29th improving window of the last 30.' },
    { key: 'C-SRI', label: 'Compliance-side risk', value: '16.6', delta: '-0.2', band: 'GREEN', note: 'Steady drift down.' },
    { key: 'G-SRI-VII', label: 'Phase VII readiness band', value: '28.8', delta: '-0.2', band: 'GREEN', note: 'Galactic readiness.' },
    { key: 'A-SRI', label: 'Alignment-side risk', value: '19.8', delta: '-0.2', band: 'GREEN', note: 'Steady.' },
    { key: 'P-SRI', label: 'Propagation risk', value: '15.1', delta: '-0.2', band: 'GREEN', note: 'Steady.' },
    { key: 'CGR-I', label: 'Constitutional-grade readiness', value: '19.6', delta: '-0.2', band: 'GREEN', note: 'Steady.' },
    { key: 'CCR-I', label: 'Cryptographic governance readiness', value: '18.2', delta: '-0.2', band: 'GREEN', note: 'Steady.' },
    { key: 'p(doom)', label: 'Ensemble p(doom)', value: '0.20%', delta: '-0.01 pp', band: 'GREEN', note: 'Epoch low restored.' },
    { key: 'p(doom)_kernel', label: 'Kernel density p(doom)', value: '0.05%', delta: '-0.01 pp', band: 'GREEN', note: 'Epoch low restored.' },
    { key: 'DRIFT', label: 'Delta_drift', value: '-0.1 sigma', delta: '-0.3 sigma', band: 'GREEN', note: '15th consecutive centered window.' },
    { key: 'OSCAL', label: 'Delta_OSCAL', value: '+0 controls (rev 1165)', delta: 'nominal', band: 'GREEN', note: 'Crosswalk drift scan clean.' },
    { key: 'QUOTE', label: 'Evidence quote age', value: '7 h max', delta: 'within floor', band: 'GREEN', note: 'Inside the 24 h floor.' }
  ],
  domains: [
    { id: '01', name: 'Constitutional Core', status: 'GREEN', note: 'TLA+ rev 1177, 72/72 proofs, both epochs verified.' },
    { id: '02', name: 'Risk & Systemic Intelligence', status: 'GREEN', note: 'STLM-2026-316; all bands GREEN, no transitions.' },
    { id: '03', name: 'Zero-Trust & Attestation Fabric', status: 'GREEN', note: 'ZTAI-02 29th full closed window at 100%.' },
    { id: '04', name: 'zkML & Model Assurance', status: 'GREEN', note: 'Record 98.7%, p99 4.2 s; Stage C day 15; DI 0.908.' },
    { id: '05', name: 'PQC WORM Evidence Ledger', status: 'GREEN', note: 'FIPS 203/204/205; zero ledger gaps.' },
    { id: '06', name: 'Regulatory Crosswalk & OSCAL', status: 'GREEN', note: '17/17 regimes GREEN; catalog rev 1165 steady-state.' },
    { id: '07', name: 'Supervisory Digital Twin & Drills', status: 'GREEN', note: '1,435 replay checks, 100% bit-identical.' },
    { id: '08', name: 'Deployment & GitOps Posture', status: 'GREEN', note: '219/219 reconciled; zero rollback-blocks.' },
    { id: '09', name: 'Transcript & Voting Integrity', status: 'GREEN', note: 'Registry 455; N-58 closed (99.6%), N-59 opened.' },
    { id: '10', name: 'Omega-GAR Long-Horizon Stewardship', status: 'GREEN', note: 'Infinity Pillar 98%; dissolution arc on plan.' }
  ],
  drills: [
    { name: 'DRILL-053 "Umber-Beacon" (AAR)', outcome: 'FILED / ADOPTED', note: '3 m 12 s convergence adopted as the new reference mark (supersedes 3 m 21 s, Cinder-Lattice); two-consecutive-inside-target condition satisfied.' },
    { name: 'DRILL-054 (drafting)', outcome: 'OPENED', note: 'Binding target <= 3 m 15 s carried from the adopted mark; 3 m 10 s stretch under comment; freeze-vote target 2026-11-14; live execution week of 2026-11-16.' },
    { name: 'REPLAY-RB-2026-316', outcome: 'BIT-IDENTICAL', note: '1,435 checks, 100% match, including the DRILL-053 AAR record.' }
  ],
  regimes: [
    'EU AI Act (incl. Digital Omnibus (EU) 2026/1744 deferral tracking)', 'NIST AI RMF 1.0 / AI 600-1 (GenAI profile)', 'ISO/IEC 42001 (AIMS)',
    'Basel III/IV', 'SR 11-7', 'SR 26-2', 'DORA', 'NIS2', 'GDPR', 'MAS/HKMA FEAT', 'FCA SMCR & Consumer Duty',
    'HKMA Fintech 2030 AI2', 'SEC Rule 17a-4', 'FCRA/ECOA', 'ICGC/GASO', 'Interstellar AI Governance Accord', 'Galactic Treaty Framework'
  ],
  continuityProtocols: 'CP-001..CP-010 all GREEN (29th consecutive window)',
  alertLevel: 'GREEN (EL-1); compute governance BASELINE held throughout the window',
  omegaGar: { cesi: '0.541', ucsi: '0.711', uci: '0.737', cds: '0.123', infinityPillar: '98%' }
};
