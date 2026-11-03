// Extended fictional datasets for the executive, operations and governance pages.
// All values deterministic; watermark fields are attached on every export.

export const FICTIONAL_NOTICE =
  'FICTIONAL / SIMULATION — GIEN scenario data. Not a real regulatory filing, not investment or legal advice.';

export interface HistoryAlert {
  id: string;
  timestamp: string;
  severity: 'INFO' | 'ELEVATED' | 'CRITICAL';
  source: string;
  message: string;
  acknowledged: boolean;
  acknowledgedBy?: string;
}

export const ALERT_HISTORY: HistoryAlert[] = [
  { id: 'ALR-2026-11-03-014', timestamp: '2026-11-03T08:42:11Z', severity: 'ELEVATED', source: 'C-SRI', message: 'Contagion index 0.334 above 0.30 watch threshold; CB-04 throttling active.', acknowledged: false },
  { id: 'ALR-2026-11-03-013', timestamp: '2026-11-03T07:58:03Z', severity: 'INFO', source: 'SCP v3.0', message: '08:00 UTC archive transmission staged; 4.9 TB queued for supervisory college receipt.', acknowledged: true, acknowledgedBy: 'duty-officer-02' },
  { id: 'ALR-2026-11-03-012', timestamp: '2026-11-03T06:31:47Z', severity: 'ELEVATED', source: 'A-SRI', message: 'Agent recursion depth reached 7 (limit 6) during StaR-MoE re-optimization; containment applied.', acknowledged: true, acknowledgedBy: 'agent-ops-01' },
  { id: 'ALR-2026-11-03-011', timestamp: '2026-11-03T05:12:29Z', severity: 'INFO', source: 'Attestation', message: 'node-rtee-084 quote timeout (380 ms) isolated and re-verified; no ledger divergence.', acknowledged: true, acknowledgedBy: 'tee-ops-03' },
  { id: 'ALR-2026-11-03-010', timestamp: '2026-11-03T03:04:18Z', severity: 'INFO', source: 'OSCAL', message: 'Assessment-results bundle re-validated (1,504 controls); Δ_OSCAL 0.007 within tolerance.', acknowledged: true, acknowledgedBy: 'compliance-eng-01' },
  { id: 'ALR-2026-11-03-009', timestamp: '2026-11-03T01:47:55Z', severity: 'CRITICAL', source: 'GIEN-ZTAI-02', message: 'TEE memory boundary probe attempt blocked; compensating micro-isolation held.', acknowledged: true, acknowledgedBy: 'secops-01' },
  { id: 'ALR-2026-11-02-008', timestamp: '2026-11-02T22:19:02Z', severity: 'ELEVATED', source: 'StaR-MoE', message: 'Expert utilization σ 0.041; re-balance applied from Expert-12 to Expert-18.', acknowledged: true, acknowledgedBy: 'ml-ops-02' },
  { id: 'ALR-2026-11-02-007', timestamp: '2026-11-02T18:03:44Z', severity: 'INFO', source: 'PQC Ledger', message: 'Merkle root rotation verified across 8,020 RTEE nodes; ledger INTACT.', acknowledged: true, acknowledgedBy: 'ledger-ops-01' },
  { id: 'ALR-2026-11-02-006', timestamp: '2026-11-02T15:40:10Z', severity: 'ELEVATED', source: 'Supervisory College', message: 'SLA exception: bundle derivation exceeded 30-minute target by 6 minutes.', acknowledged: false },
  { id: 'ALR-2026-11-02-005', timestamp: '2026-11-02T11:22:37Z', severity: 'INFO', source: 'Digital Twin', message: 'Panel 13 replay bundle sealed; determinism verified across 1,024 nodes.', acknowledged: true, acknowledgedBy: 'twin-ops-01' },
  { id: 'ALR-2026-11-02-004', timestamp: '2026-11-02T09:15:51Z', severity: 'ELEVATED', source: 'zkML', message: 'Proof verification queue depth 1,240; drained within 42 s without liveness loss.', acknowledged: true, acknowledgedBy: 'proof-ops-02' },
  { id: 'ALR-2026-11-02-003', timestamp: '2026-11-02T06:02:12Z', severity: 'INFO', source: 'GitOps', message: 'Signed commit enforced; unsigned artifact rejected at admission (policy GITOPS-SIG-01).', acknowledged: true, acknowledgedBy: 'platform-01' },
  { id: 'ALR-2026-11-01-002', timestamp: '2026-11-01T21:44:09Z', severity: 'ELEVATED', source: 'Vault', message: 'Key rotation vkFMv2→vkFMv3 at 82%; two enclaves pending re-seal.', acknowledged: false },
  { id: 'ALR-2026-11-01-001', timestamp: '2026-11-01T11:10:00Z', severity: 'INFO', source: 'Constitution', message: '24/24 invariants re-proved (1.46e9 states); zero counterexamples.', acknowledged: true, acknowledgedBy: 'gov-eng-01' },
];

export interface RoadmapMilestone {
  id: string;
  date: string; // ISO date
  title: string;
  framework: string;
  detail: string;
  kind: 'REAL' | 'FICTIONAL';
  status: 'COMPLETE' | 'ACTIVE' | 'PLANNED';
}

export const ROADMAP: RoadmapMilestone[] = [
  { id: 'RM-01', date: '2018-05-25', title: 'GDPR applies', framework: 'GDPR', detail: 'Arts. 22 (automated decisions) and 35 (DPIA) anchor the individual-rights layer.', kind: 'REAL', status: 'COMPLETE' },
  { id: 'RM-02', date: '2023-01-26', title: 'NIST AI RMF 1.0 released', framework: 'NIST AI RMF', detail: 'GOVERN / MAP / MEASURE / MANAGE functions become the de facto US baseline.', kind: 'REAL', status: 'COMPLETE' },
  { id: 'RM-03', date: '2023-12-18', title: 'ISO/IEC 42001 published', framework: 'ISO/IEC 42001', detail: 'First certifiable AI management system standard (clauses 4–10).', kind: 'REAL', status: 'COMPLETE' },
  { id: 'RM-04', date: '2024-07-26', title: 'NIST AI 600-1 GenAI Profile', framework: 'NIST AI 600-1', detail: 'Twelve generative-AI risk areas with suggested actions.', kind: 'REAL', status: 'COMPLETE' },
  { id: 'RM-05', date: '2024-08-01', title: 'EU AI Act enters into force', framework: 'EU AI Act', detail: 'Regulation (EU) 2024/1689; obligations phase in through 2027.', kind: 'REAL', status: 'COMPLETE' },
  { id: 'RM-06', date: '2024-10-17', title: 'NIS2 transposition deadline', framework: 'NIS2', detail: 'Member-state transposition; incident reporting within 24h/72h.', kind: 'REAL', status: 'COMPLETE' },
  { id: 'RM-07', date: '2025-01-17', title: 'DORA applies', framework: 'DORA', detail: 'ICT risk, incident reporting, TLPT and third-party oversight.', kind: 'REAL', status: 'COMPLETE' },
  { id: 'RM-08', date: '2026-08-02', title: 'EU AI Act high-risk obligations (Annex III)', framework: 'EU AI Act', detail: 'Annex IV technical documentation, logging, human oversight, accuracy/robustness.', kind: 'REAL', status: 'COMPLETE' },
  { id: 'RM-09', date: '2026-08-02', title: 'CFE-1.0 ratified (fictional)', framework: 'CFE-1.0', detail: 'Constitutional Framework for Epochs; 24 invariants enter force.', kind: 'FICTIONAL', status: 'COMPLETE' },
  { id: 'RM-10', date: '2026-10-01', title: 'Protocol SGR-028 filing cadence begins (fictional)', framework: 'SGR-028', detail: 'Daily supervisory dossier with Merkle-anchored corpus manifest.', kind: 'FICTIONAL', status: 'COMPLETE' },
  { id: 'RM-11', date: '2027-08-02', title: 'EU AI Act Art. 6(1) high-risk obligations', framework: 'EU AI Act', detail: 'Full high-risk regime for product-safety components.', kind: 'REAL', status: 'PLANNED' },
  { id: 'RM-12', date: '2027-01-15', title: 'FIPS 205 full deployment target (fictional programme)', framework: 'NIST FIPS 205', detail: 'SLH-DSA coverage on secondary nodes to 100%.', kind: 'FICTIONAL', status: 'ACTIVE' },
  { id: 'RM-13', date: '2028-01-01', title: 'Phase VII entry gate (fictional)', framework: 'Galactic Treaty Framework', detail: 'G-SRI-VII < 0.50 sustainment for two quarters; beacon mesh buildout.', kind: 'FICTIONAL', status: 'PLANNED' },
  { id: 'RM-14', date: '2081-01-01', title: 'Phase Ω-GAR dissolution arc (fictional)', framework: 'CFE-1.0', detail: 'INVOCATION-OMEGA execution and non-interference verification.', kind: 'FICTIONAL', status: 'PLANNED' },
];

export interface PolicyRule {
  id: string;
  description: string;
  effect: 'allow' | 'deny';
  rego: string;
}

export interface PolicyPack {
  id: string;
  name: string;
  domain: string;
  baseline: string;
  proposed: string;
  rules: PolicyRule[];
}

export const POLICY_PACKS: PolicyPack[] = [
  {
    id: 'PQC-TRANSFER-GUARD',
    name: 'PQC Transfer Guard',
    domain: 'CD-03 Cryptographic Integrity',
    baseline: `package gien.crypto\n\n# baseline: ML-DSA-65 signatures required on transfers\ndefault allow := false\n\nallow {\n  input.transfer.signature_alg == "ML-DSA-65"\n  input.transfer.ledger_anchor == true\n}`,
    proposed: `package gien.crypto\n\n# proposed: accept the FIPS 204/205 suite, require WORM anchor\ndefault allow := false\n\nallowed_algs := {"ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s"}\n\nallow {\n  allowed_algs[input.transfer.signature_alg]\n  input.transfer.ledger_anchor == true\n  input.transfer.attestation_fresh_seconds <= 300\n}`,
    rules: [
      { id: 'PQC-01', description: 'Transfer signature algorithm must be in the approved PQC suite', effect: 'deny', rego: 'allowed_algs[input.transfer.signature_alg]' },
      { id: 'PQC-02', description: 'Transfer must be anchored to the WORM Merkle-DAG ledger', effect: 'deny', rego: 'input.transfer.ledger_anchor == true' },
      { id: 'PQC-03', description: 'RTEE attestation must be fresher than 300 seconds', effect: 'deny', rego: 'input.transfer.attestation_fresh_seconds <= 300' },
    ],
  },
  {
    id: 'AGENT-DELEGATION-LIMIT',
    name: 'Autonomous Agent Delegation Limit',
    domain: 'CD-07 Agent Oversight',
    baseline: `package gien.agents\n\n# baseline: recursion depth capped at 6\ndefault allow := false\n\nallow {\n  input.agent.recursion_depth <= 6\n  input.agent.human_in_loop == true\n}`,
    proposed: `package gien.agents\n\n# proposed: depth 5, mandatory intervention proof\ndefault allow := false\n\nallow {\n  input.agent.recursion_depth <= 5\n  input.agent.human_in_loop == true\n  input.agent.intervention_proof_verified == true\n}`,
    rules: [
      { id: 'AGT-01', description: 'Delegation recursion depth must not exceed 5', effect: 'deny', rego: 'input.agent.recursion_depth <= 5' },
      { id: 'AGT-02', description: 'Human-in-the-loop confirmation required', effect: 'deny', rego: 'input.agent.human_in_loop == true' },
      { id: 'AGT-03', description: 'Intervention Proof Verifier must attest the containment', effect: 'deny', rego: 'input.agent.intervention_proof_verified == true' },
    ],
  },
  {
    id: 'DPIA-EVIDENCE-GATE',
    name: 'DPIA Evidence Gate',
    domain: 'CD-06 Compliance Assurance',
    baseline: `package gien.privacy\n\n# baseline: DPIA on file is sufficient\ndefault allow := false\n\nallow {\n  input.processing.dpia_on_file == true\n}`,
    proposed: `package gien.privacy\n\n# proposed: machine-readable DPIA with zk attestation\ndefault allow := false\n\nallow {\n  input.processing.dpia_oscal_valid == true\n  input.processing.zk_attestation_verified == true\n  input.processing.art22_human_review == true\n}`,
    rules: [
      { id: 'DPIA-01', description: 'DPIA must validate against the OSCAL 1.1.2 profile', effect: 'deny', rego: 'input.processing.dpia_oscal_valid == true' },
      { id: 'DPIA-02', description: 'zk attestation of DPIA execution required', effect: 'deny', rego: 'input.processing.zk_attestation_verified == true' },
      { id: 'DPIA-03', description: 'Art. 22 automated-decision human review path present', effect: 'deny', rego: 'input.processing.art22_human_review == true' },
    ],
  },
];

export const VOICE_COMMANDS: { phrase: string; route: string; description: string }[] = [
  { phrase: 'open dashboard', route: '/dashboard', description: 'Daily supervisory brief' },
  { phrase: 'show risk indices', route: '/risk-indices', description: 'Systemic risk telemetry' },
  { phrase: 'open compliance matrix', route: '/compliance', description: 'Cross-jurisdictional matrix' },
  { phrase: 'cryptographic integrity', route: '/cryptographic-integrity', description: 'PQC ledger and attestation' },
  { phrase: 'digital twin panels', route: '/digital-twin', description: 'Panels 13–15 replays' },
  { phrase: 'open submission packages', route: '/submission-packages', description: 'Regulator package builder' },
  { phrase: 'long horizon architecture', route: '/long-horizon', description: 'Phases VII–XIII and Ω-GAR' },
  { phrase: 'policy simulator', route: '/policy-simulator', description: 'OPA/Rego policy diffing' },
  { phrase: 'alert history', route: '/alerts', description: 'Alert log and exports' },
];
