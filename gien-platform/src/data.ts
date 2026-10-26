import type { RiskIndex, AlertEvent, Framework, ControlDomain, Phase, AttestationNode } from './types';

function seeded(seed: number) {
  return () => {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function series(seed: number, base: number, n = 48, vol = 0.04): number[] {
  const r = seeded(seed);
  const out: number[] = [];
  let v = base;
  for (let i = 0; i < n; i++) {
    v += (r() - 0.5) * vol;
    v = Math.min(1, Math.max(0, v));
    out.push(v);
  }
  return out;
}

export const riskIndices: RiskIndex[] = [
  { id: 'S_sys', label: 'S_sys', value: 0.43, delta: -0.01, thresholds: { amber: 0.3, red: 0.6, critical: 0.85 }, series: series(1, 0.43), fictional: false, description: 'System-wide systemic stress composite' },
  { id: 'G-SRI', label: 'G-SRI', value: 0.32, delta: -0.01, thresholds: { amber: 0.3, red: 0.6, critical: 0.85 }, series: series(2, 0.32), fictional: false, description: 'Global Supervisory Risk Index' },
  { id: 'C-SRI', label: 'C-SRI', value: 0.28, delta: -0.01, thresholds: { amber: 0.3, red: 0.6, critical: 0.85 }, series: series(3, 0.28), fictional: false, description: 'Cyber/Compute Systemic Risk' },
  { id: 'CGR-I', label: 'CGR-I', value: 0.5, delta: -0.02, thresholds: { amber: 0.3, red: 0.6, critical: 0.85 }, series: series(4, 0.5), fictional: false, description: 'Constitutional Governance Risk' },
  { id: 'CCR-I', label: 'CCR-I', value: 0.17, delta: -0.01, thresholds: { amber: 0.3, red: 0.6, critical: 0.85 }, series: series(5, 0.17), fictional: false, description: 'Cross-Civilizational Coherence Risk' },
  { id: 'G-SRI-VII', label: 'G-SRI-VII', value: 0.36, delta: -0.01, thresholds: { amber: 0.3, red: 0.6, critical: 0.85 }, series: series(6, 0.36), fictional: false, description: 'Phase VII projection' },
  { id: 'A-SRI', label: 'A-SRI', value: 0.2, delta: -0.01, thresholds: { amber: 0.3, red: 0.6, critical: 0.85 }, series: series(7, 0.2), fictional: false, description: 'Autonomous Agent Systemic Risk' },
  { id: 'P-SRI', label: 'P-SRI', value: 0.27, delta: -0.01, thresholds: { amber: 0.3, red: 0.6, critical: 0.85 }, series: series(8, 0.27), fictional: false, description: 'Planetary-Scale Risk' },
  { id: 'p(doom)', label: 'p(doom)', value: 0.061, delta: -0.004, thresholds: { amber: 0.1, red: 0.3, critical: 0.6 }, series: series(9, 0.061), fictional: true, description: 'Narrative existential-risk telemetry — simulation field, not a forecast' },
  { id: 'p(doom)_kernel', label: 'p(doom)_kernel', value: 0.036, delta: -0.002, thresholds: { amber: 0.1, red: 0.3, critical: 0.6 }, series: series(10, 0.036), fictional: true, description: 'Kernel-level residual — simulation field' },
  { id: 'Δ_drift', label: 'Δ_drift', value: 0.01, delta: 0, thresholds: { amber: 0.2, red: 0.5, critical: 0.8 }, series: series(11, 0.01, 48, 0.02), fictional: false, description: 'Autonomous agent drift delta (5% budget)' },
  { id: 'Δ_OSCAL', label: 'Δ_OSCAL', value: 0, delta: 0, thresholds: { amber: 0.05, red: 0.2, critical: 0.5 }, series: series(12, 0.005, 48, 0.005), fictional: false, description: 'OSCAL compliance drift (no baseline change)' },
];

export const alerts: AlertEvent[] = [
  { id: 'a1', ts: '2026-10-26T04:18:00Z', severity: 'AMBER', source: 'SCP v3.0', message: 'Compliance bundle derivation exceeded SLA by 4 minutes', acknowledged: false },
  { id: 'a2', ts: '2026-10-26T02:05:00Z', severity: 'AMBER', source: 'OSCAL Waiver', message: 'HKMA AI² waiver renewed through 2027-01-31', acknowledged: true },
  { id: 'a3', ts: '2026-10-25T23:59:00Z', severity: 'GREEN', source: 'Archive Seal', message: '23:59 UTC cycle closure sealed', acknowledged: true },
  { id: 'a4', ts: '2026-10-25T18:00:00Z', severity: 'GREEN', source: 'Digital Twin', message: 'Panels 13-15 replayed byte-identically', acknowledged: true },
  { id: 'a5', ts: '2026-10-25T08:30:00Z', severity: 'GREEN', source: 'Ledger', message: 'Merkle root sha3-512:62af…d18c validated', acknowledged: true },
];

export const frameworks: Framework[] = [
  { id: 'eu-ai-act', name: 'EU AI Act', family: 'ai', status: 'COMPLIANT', controls: 142, total: 142, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'nist-ai-rmf', name: 'NIST AI RMF 1.0', family: 'ai', status: 'COMPLIANT', controls: 98, total: 98, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'nist-ai-600-1', name: 'NIST AI 600-1 (GenAI)', family: 'ai', status: 'COMPLIANT', controls: 61, total: 61, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'iso-42001', name: 'ISO/IEC 42001', family: 'ai', status: 'COMPLIANT', controls: 87, total: 87, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'basel', name: 'Basel III/IV', family: 'financial', status: 'COMPLIANT', controls: 54, total: 54, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'sr-11-7', name: 'SR 11-7', family: 'financial', status: 'COMPLIANT', controls: 44, total: 44, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'sr-26-2', name: 'SR 26-2', family: 'financial', status: 'COMPLIANT', controls: 29, total: 29, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'dora', name: 'DORA', family: 'operational', status: 'COMPLIANT', controls: 73, total: 73, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'nis2', name: 'NIS2', family: 'operational', status: 'COMPLIANT', controls: 51, total: 51, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'gdpr', name: 'GDPR', family: 'privacy', status: 'COMPLIANT', controls: 39, total: 39, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'fcra', name: 'FCRA / ECOA', family: 'financial', status: 'COMPLIANT', controls: 31, total: 31, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'mas-hkma', name: 'MAS/HKMA FEAT', family: 'financial', status: 'COMPLIANT', controls: 46, total: 46, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'fca-smcr', name: 'FCA SMCR / Consumer Duty', family: 'financial', status: 'COMPLIANT', controls: 38, total: 38, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'hkma-ai2', name: 'HKMA Fintech 2030 AI²', family: 'financial', status: 'PARTIAL', controls: 22, total: 27, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 1, lastAssessed: '2026-10-26' },
  { id: 'sec-17a4', name: 'SEC Rule 17a-4', family: 'financial', status: 'COMPLIANT', controls: 18, total: 18, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'icgc', name: 'ICGC / GASO', family: 'operational', status: 'COMPLIANT', controls: 27, total: 27, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'interstellar', name: 'Interstellar AI Governance Accord', family: 'fictional', status: 'PARTIAL', controls: 16, total: 18, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
  { id: 'galactic-treaty', name: 'Galactic Treaty Framework', family: 'fictional', status: 'PARTIAL', controls: 33, total: 40, oscalSsp: true, oscalAr: true, opaViolations: 0, opaWarnings: 0, lastAssessed: '2026-10-26' },
];

export const domains: ControlDomain[] = [
  { id: '01', name: 'Identity & Authority', status: 'GREEN', risk: 0.11, openRemediations: 0 },
  { id: '02', name: 'Policy & Constitutional Invariants', status: 'GREEN', risk: 0.13, openRemediations: 0 },
  { id: '03', name: 'Ledger Integrity', status: 'GREEN', risk: 0.08, openRemediations: 0 },
  { id: '04', name: 'Attestation Continuity', status: 'GREEN', risk: 0.14, openRemediations: 0 },
  { id: '05', name: 'Model & Agent Containment', status: 'GREEN', risk: 0.17, openRemediations: 0 },
  { id: '06', name: 'Data Provenance', status: 'GREEN', risk: 0.14, openRemediations: 0 },
  { id: '07', name: 'Compliance-as-Code', status: 'AMBER', risk: 0.24, openRemediations: 1 },
  { id: '08', name: 'Supply Chain / SBOM', status: 'GREEN', risk: 0.10, openRemediations: 0 },
  { id: '09', name: 'Telemetry & Observability', status: 'GREEN', risk: 0.07, openRemediations: 0 },
  { id: '10', name: 'Interstellar Interop', status: 'GREEN', risk: 0.12, openRemediations: 0 },
];

export const phases: Phase[] = [
  { id: 'VI-δ', name: 'Phase VI-δ', epoch: '2026–2028', readiness: 68, maturity: 3, objectives: ['Planetary mesh stabilization', 'GIEN-ZTAI-02 remediation completion', 'PQC migration to FIPS 203/204/205'], invariants: ['kill_switch', 'monotonic_ledger_append', 'quorum_preserving_authority'], milestones: [{ label: 'ZTAI-02 closed', done: true }, { label: 'PQC migration 78%', done: false }, { label: 'vkFMv3 propagated', done: true }] },
  { id: 'VII', name: 'Phase VII', epoch: '2028–2032', readiness: 62, maturity: 3, objectives: ['Galactic governance mesh expansion', 'G-SRI-VII activation', 'Router smoothing policy ratified'], invariants: ['epoch_boundary_atomic'], milestones: [{ label: 'G-SRI-VII ready', done: false }, { label: 'Router smoothing Q2 2027', done: false }] },
  { id: 'VIII-X', name: 'Phases VIII–X', epoch: '2032–2045', readiness: 31, maturity: 2, objectives: ['Interstellar Accord ratification', 'Infinity Pillar Level 5 deployment'], invariants: ['beacon_signature'], milestones: [{ label: 'Accord prep 31%', done: false }, { label: 'Infinity Pillar L3/5', done: true }] },
  { id: 'XI-XIII', name: 'Phases XI–XIII', epoch: '2045–2081', readiness: 14, maturity: 1, objectives: ['Multiversal governance synthesis', 'Galactic Treaty enforcement'], invariants: ['corpus_seal'], milestones: [{ label: 'Architecture drafted', done: true }] },
  { id: 'Ω-GAR', name: 'Phase Ω-GAR', epoch: '2081–2100+', readiness: 8, maturity: 1, objectives: ['Dissolution arc', 'UNIFIED-CODEX-OMEGA sealing', 'Eternal Corpus Transmission Protocol'], invariants: ['beacon_signature', 'corpus_seal'], milestones: [{ label: 'Protocol frozen', done: true }, { label: '2 open advisories', done: false }] },
];

export const attestationNodes: AttestationNode[] = Array.from({ length: 72 }, (_, i) => ({
  id: `node-${i.toString().padStart(3, '0')}`,
  region: ['Americas', 'EMEA', 'APAC', 'Orbital'][Math.floor(i / 18)],
  valid: (i * 7) % 11 !== 0,
  algorithm: (['ML-DSA-65', 'ML-DSA-87', 'SPHINCS+', 'Falcon', 'SLH-DSA'] as const)[i % 5],
  lastQuoteMin: i * 7,
}));

export function severityFor(v: number, t: { amber: number; red: number; critical: number }): 'GREEN' | 'AMBER' | 'RED' | 'CRITICAL' {
  if (v >= t.critical) return 'CRITICAL';
  if (v >= t.red) return 'RED';
  if (v >= t.amber) return 'AMBER';
  return 'GREEN';
}
