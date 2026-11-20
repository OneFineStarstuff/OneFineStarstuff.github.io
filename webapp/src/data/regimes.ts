import { Band } from '../types/gien';

/**
 * M3 (WP-108): compliance matrix data, rendered from the WP-096 OSCAL seed catalog
 * (OSCAL-SEED-GIEN-WEBAPP-1.0.0) and the sealed GIEN-DOSSIER-2026-320 -> -321 lineage.
 * All 17 regimes GREEN; operational catalog rev 1165 steady-state.
 * WP-116: the ANSM profile recorded as PROMOTED advisory -> enforced via the PROMO-R11
 * college adjudication (2026-11-19, 5/5, zero gate denies).
 * The webapp-side seed catalog remains outside the operational catalog.
 */
export type OscalStatus = 'validated' | 'pending' | 'deviation';

export interface RegimeStatus {
  name: string;
  kind: 'statutory' | 'prudential' | 'conduct' | 'treaty' | 'fictional-treaty';
  oscal: OscalStatus;
  opa: 'enforced' | 'advisory';
  band: Band;
  note: string;
}

export const CATALOG_REV = '1165';

export const REGIMES: RegimeStatus[] = [
  { name: 'EU AI Act (Arts. 15/17/22/35/51, Annex IV; Digital Omnibus (EU) 2026/1744 deferral tracking)', kind: 'statutory', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Annex IV technical documentation emitted per release.' },
  { name: 'NIST AI RMF 1.0 / AI 600-1 (GenAI profile)', kind: 'statutory', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Map + Measure + Manage gates in CI.' },
  { name: 'ISO/IEC 42001 AIMS', kind: 'statutory', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'AIMS scope covers the governance engine and webapp.' },
  { name: 'Basel III/IV', kind: 'prudential', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Model-risk capital linkage via SR 11-7 evidence.' },
  { name: 'SR 11-7', kind: 'prudential', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Independent validation + effective-challenge records gate deploys.' },
  { name: 'SR 26-2', kind: 'prudential', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Board-reporting artefacts sealed per window.' },
  { name: 'DORA', kind: 'prudential', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'ICT incident hooks wired to AlertHistory.' },
  { name: 'NIS2', kind: 'statutory', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Reporting timeline checks in the post-deploy stage.' },
  { name: 'GDPR', kind: 'statutory', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'PETs thresholds for CCaaS summarization; retention controls.' },
  { name: 'FCRA/ECOA', kind: 'conduct', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'DI floor 0.800 attested via zkML proofs.' },
  { name: 'MAS/HKMA FEAT + 2025 AI Risk Guidelines', kind: 'conduct', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Fairness, Ethics, Accountability, Transparency mapping.' },
  { name: 'FCA SMCR & Consumer Duty', kind: 'conduct', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Accountability roles mapped to certification records.' },
  { name: 'HKMA Fintech 2030 AI^2', kind: 'prudential', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Consumer protection + generative-AI controls.' },
  { name: 'SEC Rule 17a-4', kind: 'prudential', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'WORM Object Lock retention, zero ledger gaps.' },
  { name: 'ANSM (pharma marketing compliance)', kind: 'conduct', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Promoted advisory -> enforced via PROMO-R11 college adjudication (2026-11-19, 5/5, zero denies); profile under compliance/ansm/.' },
  { name: 'ICGC/GASO', kind: 'treaty', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Supervisory college rota and filing protocol alignment.' },
  { name: 'Interstellar AI Governance Accord', kind: 'fictional-treaty', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Fictional treaty instrument of the simulation.' },
  { name: 'Galactic Treaty Framework', kind: 'fictional-treaty', oscal: 'validated', opa: 'enforced', band: 'GREEN', note: 'Fictional treaty instrument of the simulation.' }
];
