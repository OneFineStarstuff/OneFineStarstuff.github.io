import type { ComplianceStatus } from '../types';
import { FRAMEWORKS } from './gienData';
import { fakeHash } from './helpers';

export interface EvidenceArtefact {
  id: string;
  name: string;
  hash: string;
  timestamp: string;
  type: string;
}

export interface MatrixRow {
  id: string; // e.g., 'CD-01', 'CD-01.1'
  domainId: string; // parent control domain ID e.g. 'CD-01'
  name: string;
  description: string;
  isSubControl: boolean;
}

export interface MatrixCell {
  rowId: string;
  domainId: string;
  frameworkId: string;
  frameworkName: string;
  status: ComplianceStatus;
  frameworkArticleRef: string;
  oscalControlId: string;
  opaRegoSnippet: string;
  assessmentTimestamp: string;
  evidenceArtefacts: EvidenceArtefact[];
  remediationPlan?: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export const MATRIX_ROWS: MatrixRow[] = [
  { id: 'CD-01', domainId: 'CD-01', name: 'Constitutional Invariant Enforcement', description: 'TLA+-verified enforcement of CI-001..CI-024 across governance epochs.', isSubControl: false },
  { id: 'CD-01.1', domainId: 'CD-01', name: 'TLA+ Kernel Specification Proofs', description: 'Automated formal proofs for kernel safety invariants (CI-001..CI-008).', isSubControl: true },
  
  { id: 'CD-02', domainId: 'CD-02', name: 'AI Model Governance & Drift Containment', description: 'Model registry, drift telemetry and tiered containment for Sentinel model estate.', isSubControl: false },
  { id: 'CD-02.1', domainId: 'CD-02', name: 'StaR-MoE Policy & Routing Audit', description: 'Routing distribution stability and expert load balancing checks.', isSubControl: true },
  
  { id: 'CD-03', domainId: 'CD-03', name: 'Cryptographic Integrity & PQC Ledger', description: 'Post-quantum WORM Merkle-DAG audit ledger and FIPS 203/204/205 suite.', isSubControl: false },
  { id: 'CD-03.1', domainId: 'CD-03', name: 'ML-DSA-65 Signature Verification', description: 'FIPS 204 signature verification on all published governance attestation blocks.', isSubControl: true },
  
  { id: 'CD-04', domainId: 'CD-04', name: 'Zero-Trust Architecture & TEE Attestation', description: 'RTEE node attestation, zero-trust policy enforcement and root-of-trust coherence.', isSubControl: false },
  { id: 'CD-04.1', domainId: 'CD-04', name: 'vTPM Quote Quorum Verification', description: 'Hardware PCR measurement validation across distributed enclave cluster.', isSubControl: true },

  { id: 'CD-05', domainId: 'CD-05', name: 'Systemic Risk Monitoring & Telemetry', description: 'S_sys-class index computation, supervisory telemetry bus and threshold orchestration.', isSubControl: false },
  { id: 'CD-05.1', domainId: 'CD-05', name: 'Real-Time EWMA Smoothing Engine', description: 'Continuous 24h streaming calculation of G-SRI and C-SRI contagion metrics.', isSubControl: true },

  { id: 'CD-06', domainId: 'CD-06', name: 'Cross-Jurisdictional Compliance Assurance', description: 'OSCAL/OPA-Rego compliance-as-code mapping across 20 regulatory frameworks.', isSubControl: false },
  { id: 'CD-06.1', domainId: 'CD-06', name: 'OSCAL 1.1.2 SSP & Catalog Verification', description: 'Machine-readable System Security Plan validation against schema v1.1.2.', isSubControl: true },
  { id: 'CD-06.2', domainId: 'CD-06', name: 'Cross-Border Regulatory Mapping Engine', description: 'Automated harmonization of EU, Fed, DORA, and Asian-Pacific regulatory clauses.', isSubControl: true },

  { id: 'CD-07', domainId: 'CD-07', name: 'Autonomous Agent Oversight & Containment', description: 'Autonomous Supervisory Agent oversight, intervention proofs and kill-switch choreography.', isSubControl: false },
  { id: 'CD-07.1', domainId: 'CD-07', name: 'Kill-Switch Arbiter & Circuit Breaker', description: 'Sub-second agent quarantine and automated payload containment execution.', isSubControl: true },

  { id: 'CD-08', domainId: 'CD-08', name: 'Supervisory Digital Twin Operations', description: 'Digital Twin Panels 13-15, deterministic replay bundles and stress-test choreography.', isSubControl: false },

  { id: 'CD-09', domainId: 'CD-09', name: 'Incident Response & Vulnerability Management', description: 'Vulnerability lifecycle (incl. GIEN-ZTAI-02), incident notification and SLA handling.', isSubControl: false },
  { id: 'CD-09.1', domainId: 'CD-09', name: 'Zero-Day Vulnerability Remediation Pipeline', description: 'Rapid PQC patch signing and RTEE node update deployment timeline.', isSubControl: true },

  { id: 'CD-10', domainId: 'CD-10', name: 'Long-Horizon Governance & Treaty Compliance', description: 'Epoch 2026-2035 / 2035-2100+ obligations, Infinity Pillar and dissolution-arc readiness.', isSubControl: false },
  { id: 'CD-10.1', domainId: 'CD-10', name: 'Infinity Pillar Readiness Verification', description: 'Multi-generational pillar verification (IP-I through IP-VII) for inter-epoch transitions.', isSubControl: true },
];

export const OPA_REGO_TEMPLATES: Record<string, string> = {
  'CD-01': `package gien.cd01.invariants\n\ndefault allow = false\n\nallow {\n    input.invariant_id != ""\n    input.tla_proof_status == "PROVED"\n    input.merkle_root_valid == true\n}`,
  'CD-02': `package gien.cd02.model_drift\n\ndefault allow = false\n\nallow {\n    input.model_drift <= 0.05\n    input.fairness_gap <= 0.010\n    input.explainability_score >= 0.90\n    input.vtpm_attested == true\n}`,
  'CD-03': `package gien.cd03.pqc_ledger\n\ndefault allow = false\n\nallow {\n    input.algorithm in ["ML-DSA-65", "CRYSTALS-Dilithium", "CRYSTALS-Kyber"]\n    input.key_length >= 800\n    input.worm_immutable == true\n}`,
  'CD-04': `package gien.cd04.rtee_attestation\n\ndefault allow = false\n\nallow {\n    input.attestation_quote_valid == true\n    input.tpm_pcr_matched == true\n    input.firmware_signature == "ML-DSA-65"\n}`,
  'CD-05': `package gien.cd05.systemic_risk\n\ndefault allow = false\n\nallow {\n    input.s_sys <= 0.35\n    input.c_sri <= 0.30\n    input.telemetry_freshness_seconds <= 300\n}`,
  'CD-06': `package gien.cd06.jurisdiction_assurance\n\ndefault allow = false\n\nallow {\n    input.dpia_pack_complete == true\n    input.oscal_ssp_validated == true\n    input.cross_border_consent == true\n}`,
  'CD-07': `package gien.cd07.agent_containment\n\ndefault allow = false\n\nallow {\n    input.containment_status != "UNCONTAINED"\n    input.kill_switch_armed == true\n    input.drift_delta <= 0.05\n}`,
  'CD-08': `package gien.cd08.digital_twin\n\ndefault allow = false\n\nallow {\n    input.replay_deterministic == true\n    input.panel_sync_lag_ms <= 50\n    input.stress_test_passed == true\n}`,
  'CD-09': `package gien.cd09.incident_response\n\ndefault allow = false\n\nallow {\n    input.vulnerability_severity != "CRITICAL"\n    input.sla_breach == false\n    input.patch_attestation_hash != ""\n}`,
  'CD-10': `package gien.cd10.long_horizon\n\ndefault allow = false\n\nallow {\n    input.infinity_pillar_readiness >= 85\n    input.treaty_epoch == "2026-2035"\n    input.dissolution_arc_sealed == true\n}`,
};

const ARTICLE_REFS: Record<string, string[]> = {
  'eu-ai-act': ['Art. 6(2)', 'Art. 9', 'Art. 10', 'Art. 13', 'Art. 14', 'Art. 15', 'Art. 17', 'Art. 35 DPIA', 'Art. 51'],
  'nist-airmf': ['GOVERN 1.1', 'MAP 2.3', 'MEASURE 3.1', 'MANAGE 4.2'],
  'nist-600-1': ['GOVERN-1.2', 'MAP-2.1', 'MEASURE-3.4', 'MANAGE-GenAI-1'],
  'iso-42001': ['Clause 4.2', 'Clause 6.1', 'Clause 8.2', 'Clause 9.3', 'Clause 10.1'],
  'basel': ['Pillar 1 §12', 'Pillar 2 §4', 'Pillar 3 §9', 'FRTB §2', 'SA-CCR §5'],
  'sr-11-7': ['Model Dev §2', 'Validation §4', 'Governance §6'],
  'sr-26-2': ['Inventory §3', 'Controls §5', 'Validation §8'],
  'dora': ['Art. 5(1)', 'Art. 9(2)', 'Art. 12', 'Art. 21', 'Art. 33 TLPT'],
  'nis2': ['Art. 18', 'Art. 20', 'Art. 21(2)', 'Art. 23'],
  'gdpr': ['Art. 5(1)(a)', 'Art. 17', 'Art. 22(2)', 'Art. 25', 'Art. 35 DPIA'],
  'fcra-ecoa': ['FCRA §615(a)', 'ECOA Reg B §1002.9', 'Explainability §4'],
  'feat': ['Fairness §1', 'Ethics §2', 'Accountability §3', 'Transparency §4'],
  'fca': ['SMCR Rule 2', 'Consumer Duty Outcome 1', 'Outcome 4'],
  'hkma-ai2': ['AI² Pillar 1', 'Fintech 2030 Roadmap §3'],
  'sec-17a-4': ['Rule 17a-4(f)', 'WORM Storage §2'],
  'icgc-gaso': ['ICGC Art. 3', 'GASO Accord §7'],
  'interstellar-accord': ['Beacon Protocol §2', 'Corpus Transmission §5'],
  'galactic-treaty': ['Epoch Coverage §4', 'Dissolution Provision §9'],
  'cfe-1': ['§2 Kernel Invariants', '§5 Ledger Coherence', '§7 Invariant Engine'],
  'sgr-028': ['Protocol SGR-028 §4.1', '§9 p(doom) Telemetry', '§12 Filing'],
};

const OSCAL_SCHEMES: Record<string, string> = {
  'CD-01': 'au-3.1-rev5',
  'CD-01.1': 'au-3.1a-rev5',
  'CD-02': 'ai-01.2-rev5',
  'CD-02.1': 'ai-01.4-rev5',
  'CD-03': 'sc-13.1-pqc',
  'CD-03.1': 'sc-13.2-dsa',
  'CD-04': 'ac-02.4-tpm',
  'CD-04.1': 'ac-02.8-rtee',
  'CD-05': 'si-03.4-risk',
  'CD-05.1': 'si-03.6-ewma',
  'CD-06': 'cm-02.1-oscal',
  'CD-06.1': 'cm-02.4-ssp',
  'CD-06.2': 'cm-02.8-map',
  'CD-07': 'sa-04.2-agent',
  'CD-07.1': 'sa-04.6-arbiter',
  'CD-08': 'dr-06.1-twin',
  'CD-09': 'ir-04.3-vuln',
  'CD-09.1': 'ir-04.7-patch',
  'CD-10': 'gv-10.1-treaty',
  'CD-10.1': 'gv-10.4-pillar',
};

// Deterministically generated matrix cells
export function generateMatrixCells(): MatrixCell[] {
  const cells: MatrixCell[] = [];

  for (const row of MATRIX_ROWS) {
    const domainId = row.domainId;
    const opaRego = OPA_REGO_TEMPLATES[domainId] || OPA_REGO_TEMPLATES['CD-01'];
    const oscalBase = OSCAL_SCHEMES[row.id] || 'au-3.1';

    for (const fw of FRAMEWORKS) {
      const fwId = fw.id;
      const refList = ARTICLE_REFS[fwId] || ['Art. 1'];
      const hashIndex = (row.id.length * 7 + fwId.length * 13) % refList.length;
      const articleRef = refList[hashIndex];

      let status: ComplianceStatus = 'COMPLIANT';
      let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
      let remediationPlan: string | undefined = undefined;

      // SPECIFIC REQUIRED KNOWN GAPS:
      // 1. EU-AI-Act / CD-06 (and subcontrols CD-06.1, CD-06.2) -> PARTIAL
      if (fwId === 'eu-ai-act' && domainId === 'CD-06') {
        status = 'PARTIAL';
        riskLevel = 'HIGH';
        remediationPlan = 'Annex IV / Art. 35 DPIA evidence pack incomplete for StaR-MoE inference tier. Finalize DPIA assessment pack by Q4 2026.';
      }
      // 2. SR-26-2 / CD-02 (and subcontrols CD-02.1) -> PARTIAL
      else if (fwId === 'sr-26-2' && domainId === 'CD-02') {
        status = 'PARTIAL';
        riskLevel = 'HIGH';
        remediationPlan = 'AI model inventory reconciliation gap for 2 vTPM-scoped inference shards. Complete inventory audit before next supervisory window.';
      }
      // 3. Selective NOT_APPLICABLE for banking/consumer laws vs purely technical TEE/cryptographic domains
      else if ((fwId === 'fcra-ecoa' || fwId === 'fca') && (domainId === 'CD-03' || domainId === 'CD-04')) {
        status = 'NOT_APPLICABLE';
        riskLevel = 'LOW';
      }
      else if (fwId === 'sec-17a-4' && (domainId === 'CD-07' || domainId === 'CD-08')) {
        status = 'NOT_APPLICABLE';
        riskLevel = 'LOW';
      }
      else if ((fwId === 'galactic-treaty' || fwId === 'interstellar-accord') && (domainId === 'CD-09' || domainId === 'CD-04')) {
        status = 'NOT_APPLICABLE';
        riskLevel = 'LOW';
      }
      // 4. Selective PENDING cells
      else if (fwId === 'hkma-ai2' && row.id === 'CD-05.1') {
        status = 'PENDING';
        riskLevel = 'MEDIUM';
        remediationPlan = 'Pending cross-border APAC regional telemetry synchronization audit.';
      }
      else if (fwId === 'galactic-treaty' && row.id === 'CD-10.1') {
        status = 'PENDING';
        riskLevel = 'LOW';
        remediationPlan = 'Pre-expansion Phase VII galactic readiness gate verification in progress.';
      }
      // 5. Additional plausible PARTIAL gaps to align with framework gap counts
      else if (fwId === 'eu-ai-act' && row.id === 'CD-07.1') {
        status = 'PARTIAL';
        riskLevel = 'HIGH';
        remediationPlan = 'Art. 14 human oversight drill documentation review scheduled for 2026-10-15.';
      }
      else if (fwId === 'sr-11-7' && row.id === 'CD-02.1') {
        status = 'PARTIAL';
        riskLevel = 'MEDIUM';
        remediationPlan = 'StaR-MoE policy routing distribution validation report awaiting senior validator signoff.';
      }
      else if (fwId === 'sr-26-2' && row.id === 'CD-05') {
        status = 'PARTIAL';
        riskLevel = 'MEDIUM';
        remediationPlan = 'Model risk telemetry feed reconciliation with Fed SR 26-2 schema v2.';
      }

      // Evidence artefacts
      const seedBase = `${row.id}-${fwId}`;
      const evidenceArtefacts: EvidenceArtefact[] = [
        {
          id: `ev-${seedBase}-1`,
          name: `${fw.name} Compliance Attestation`,
          hash: fakeHash(`ev-attest-${seedBase}`),
          timestamp: '2026-10-10T08:15:00Z',
          type: 'WORM Attestation Log',
        },
        {
          id: `ev-${seedBase}-2`,
          name: `OSCAL Control Evidence (${articleRef})`,
          hash: fakeHash(`ev-oscal-${seedBase}`),
          timestamp: '2026-10-10T07:42:00Z',
          type: 'OSCAL Assessment Output',
        },
        {
          id: `ev-${seedBase}-3`,
          name: `OPA Policy Test Proof`,
          hash: fakeHash(`ev-opa-${seedBase}`),
          timestamp: '2026-10-10T06:30:00Z',
          type: 'OPA Rego Execution Trace',
        },
      ];

      cells.push({
        rowId: row.id,
        domainId: row.domainId,
        frameworkId: fwId,
        frameworkName: fw.name,
        status,
        frameworkArticleRef: articleRef,
        oscalControlId: oscalBase,
        opaRegoSnippet: opaRego,
        assessmentTimestamp: '2026-10-10T08:15:00Z',
        evidenceArtefacts,
        remediationPlan,
        riskLevel,
      });
    }
  }

  return cells;
}

export const MATRIX_CELLS = generateMatrixCells();

export function getCell(rowId: string, frameworkId: string): MatrixCell | undefined {
  return MATRIX_CELLS.find((c) => c.rowId === rowId && c.frameworkId === frameworkId);
}

// OSCAL 1.1.2 export JSON generator
export function generateOSCALBundleExport() {
  return {
    'oscal-version': '1.1.2',
    'system-security-plan': {
      uuid: 'c83d6f7a-84e1-4b12-9c1e-7f8931a40026',
      metadata: {
        title: 'GIEN Sentinel AI Governance System Security Plan',
        version: '2026.10.10-v2.4',
        'last-modified': '2026-10-10T08:15:00Z',
        'oscal-version': '1.1.2',
        remarks: 'Treaty-grade machine-readable compliance catalog for 20 frameworks.',
      },
      'import-profile': {
        href: 'https://gien.gov/profiles/sentinel-ai-governance-v2.4.json',
      },
      'control-implementation': {
        description: 'Implementation status of 10 Control Domains across 20 regulatory frameworks.',
        'implemented-requirements': MATRIX_CELLS.slice(0, 50).map((cell) => ({
          uuid: fakeHash(`oscal-uuid-${cell.rowId}-${cell.frameworkId}`).slice(2, 38),
          'control-id': cell.oscalControlId,
          status: { state: cell.status.toLowerCase() },
          'export-ref': cell.frameworkArticleRef,
          remarks: cell.remediationPlan ?? 'Fully validated via OPA-Rego engine.',
        })),
      },
    },
    'merkle-proof': {
      root: fakeHash('oscal-bundle-2026-10-10'),
      algorithm: 'ML-DSA-65',
      signature: fakeHash('oscal-mldsa65-sig-20261010'),
    },
  };
}
