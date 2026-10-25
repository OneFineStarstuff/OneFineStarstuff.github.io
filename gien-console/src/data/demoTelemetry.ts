import type {
  AlertRecord,
  ComplianceRecord,
  RagSourceRecord,
  RiskMetric
} from "../types/governance";

export const demoRiskMetrics: RiskMetric[] = [
  { id: "S_sys", name: "Systemic risk", value: 0.28, unit: "index", threshold: 0.35, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-001", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Synthetic sample; not a live system measurement." },
  { id: "G-SRI", name: "Global systemic risk", value: 0.32, unit: "index", threshold: 0.40, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-002", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Project-defined index; definition and validation remain pending." },
  { id: "C-SRI", name: "Cascade risk", value: 0.21, unit: "index", threshold: 0.30, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-003", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Synthetic sample; not independently validated." },
  { id: "CGR-I", name: "Control governance risk", value: 0.18, unit: "index", threshold: 0.25, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-004", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Project-defined index; inputs are illustrative." },
  { id: "CCR-I", name: "Containment coherence", value: 0.15, unit: "index", threshold: 0.20, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-005", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Synthetic sample; no operational attestation source is connected." },
  { id: "G-SRI-VII", name: "Governance risk VII", value: 0.40, unit: "index", threshold: 0.50, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-006", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Project-defined indicator; requires an approved methodology." },
  { id: "A-SRI", name: "Alignment risk", value: 0.31, unit: "index", threshold: 0.45, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-007", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Illustrative value; event and calibration definitions are pending." },
  { id: "P-SRI", name: "Propagation risk", value: 0.10, unit: "index", threshold: 0.15, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-008", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Project-defined indicator; values are not regulatory limits." },
  { id: "p(doom)", name: "Experimental risk probability", value: 0.0004, unit: "probability", threshold: 0.001, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-009", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Experimental concept; not a recognized regulatory metric or validated forecast." },
  { id: "p(doom)_kernel", name: "Kernel risk probability", value: 0.00005, unit: "probability", threshold: 0.0001, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-010", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Experimental concept; independent calibration and validation are absent." },
  { id: "Δ_drift", name: "Model drift", value: 0.025, unit: "delta", threshold: 0.05, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-011", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Illustrative delta; baseline and metric definitions require approval." },
  { id: "Δ_OSCAL", name: "OSCAL configuration drift", value: 0.009, unit: "delta", threshold: 0.02, thresholdDirection: "MAXIMUM", sourceStatus: "SYNTHETIC", sourceRef: "DEMO-RISK-012", observedAt: "2026-10-17T08:00:00Z", methodVersion: "demo-v1", limitation: "Illustrative comparison; no verified production baseline is connected." }
];

export const demoRiskTrend = [
  { time: "01:00", system: 0.31, cascade: 0.23, governance: 0.20 },
  { time: "03:00", system: 0.30, cascade: 0.22, governance: 0.19 },
  { time: "05:00", system: 0.29, cascade: 0.22, governance: 0.19 },
  { time: "07:00", system: 0.30, cascade: 0.21, governance: 0.18 },
  { time: "09:00", system: 0.28, cascade: 0.21, governance: 0.18 }
];

export const demoFairnessCells = [
  { group: "Group A", metric: "Selection rate", score: 0.82 },
  { group: "Group A", metric: "Recall", score: 0.78 },
  { group: "Group A", metric: "Precision", score: 0.85 },
  { group: "Group B", metric: "Selection rate", score: 0.77 },
  { group: "Group B", metric: "Recall", score: 0.74 },
  { group: "Group B", metric: "Precision", score: 0.80 },
  { group: "Group C", metric: "Selection rate", score: 0.79 },
  { group: "Group C", metric: "Recall", score: 0.73 },
  { group: "Group C", metric: "Precision", score: 0.81 }
];

export const demoAlerts: AlertRecord[] = [
  { id: "DEMO-ALERT-1042", title: "RAG source freshness review required", severity: "MEDIUM", state: "OPEN", occurredAt: "2026-10-17T07:42:00Z", owner: "Evidence Operations", sourceStatus: "SYNTHETIC", evidenceRef: "DEMO-EVD-2001" },
  { id: "DEMO-ALERT-1041", title: "Model drift evidence not connected", severity: "HIGH", state: "ACKNOWLEDGED", occurredAt: "2026-10-17T06:15:00Z", owner: "Model Risk", sourceStatus: "SYNTHETIC", evidenceRef: "DEMO-EVD-2002" },
  { id: "DEMO-ALERT-1040", title: "Quarterly control-owner review pending", severity: "LOW", state: "OPEN", occurredAt: "2026-10-17T03:20:00Z", owner: "Compliance", sourceStatus: "SYNTHETIC", evidenceRef: "DEMO-EVD-2003" }
];

export const demoComplianceRecords: ComplianceRecord[] = [
  { id: "CTRL-EU-001", framework: "EU AI Act", obligation: "Determine system classification and applicable provider/deployer obligations", owner: "Legal / AI Governance", assessment: "NOT ASSESSED", evidenceCount: 0, nextReview: "2026-10-24" },
  { id: "CTRL-NIST-001", framework: "NIST AI RMF 1.0", obligation: "Record governance ownership, risks and accountability", owner: "AI Risk", assessment: "EVIDENCE REQUIRED", evidenceCount: 0, nextReview: "2026-10-21" },
  { id: "CTRL-ISO-001", framework: "ISO/IEC 42001:2023", obligation: "Define AI management-system scope and risk-treatment evidence", owner: "Management System Owner", assessment: "NOT ASSESSED", evidenceCount: 0, nextReview: "2026-10-28" },
  { id: "CTRL-GDPR-001", framework: "GDPR", obligation: "Document processing purpose, lawful basis, retention and rights handling", owner: "Privacy", assessment: "IN REVIEW", evidenceCount: 1, nextReview: "2026-10-20" },
  { id: "CTRL-SEC-001", framework: "SEC Rule 17a-4", obligation: "Determine record-retention applicability and test retrieval", owner: "Records / Compliance", assessment: "NOT ASSESSED", evidenceCount: 0, nextReview: "2026-10-30" }
];

export const demoRagSources: RagSourceRecord[] = [
  { id: "DEMO-SRC-001", document: "AI system card", version: "0.3-demo", accessedAt: "2026-10-17T08:12:00Z", sourceStatus: "SYNTHETIC", citationCoverage: 0.92, accessDecision: "ALLOWED" },
  { id: "DEMO-SRC-002", document: "Control mapping workbook", version: "0.1-demo", accessedAt: "2026-10-17T07:55:00Z", sourceStatus: "SYNTHETIC", citationCoverage: 0.71, accessDecision: "PENDING" },
  { id: "DEMO-SRC-003", document: "Model validation summary", version: "pending", accessedAt: "2026-10-17T07:30:00Z", sourceStatus: "EVIDENCE_PENDING", citationCoverage: null, accessDecision: "PENDING" }
];
