#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WP-055 — Sentinel AI v2.4 Enterprise AGI/ASI Governance & Containment Blueprint
DocRef: SENTINEL-AI-V24-GOVERNANCE-WP-055 v1.0.0
Horizon: 2026-2030 (Fortune 500 / Global 2000 / G-SIFIs)
Builds on: WP-035..WP-054
"""

import json
from pathlib import Path

OUT = Path(__file__).parent / "data" / "sentinel-ai-v24-governance.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

DOC = {
    "docRef": "SENTINEL-AI-V24-GOVERNANCE-WP-055",
    "version": "1.0.0",
    "title": "Sentinel AI v2.4 Enterprise AGI/ASI Governance & Containment Blueprint",
    "horizon": "2026-2030 (Fortune 500 / Global 2000 / G-SIFIs)",
    "apiPrefix": "/api/sentinel-ai-v24-governance",
    "buildsOn": [
        "WP-035","WP-036","WP-037","WP-038","WP-039","WP-040","WP-041","WP-042",
        "WP-043","WP-044","WP-045","WP-046","WP-047","WP-048","WP-049","WP-050",
        "WP-051","WP-052","WP-053","WP-054"
    ],
    "audience": [
        "Board of Directors","CAIO","CRO","CISO","CDO","CTO","Head of Model Risk",
        "Chief Compliance Officer","Head of Internal Audit","Regulators",
        "MLSecOps engineering teams","Containment & Red Team leads"
    ],
    "scope": "End-to-end design, security, governance, MLSecOps, and compliance review of Sentinel AI v2.4 — covering 9 distinct scope items S1-S9.",
    "regimes": [
        "EU AI Act 2026 (Arts. 53, 55; Annex IV; FRIA)",
        "NIST AI RMF 1.0 + 1.1 + NIST AI 600-1 (Generative AI Profile)",
        "ISO/IEC 42001:2023 (AIMS)",
        "ISO/IEC 23894:2023 (AI risk management)",
        "ISO/IEC 27001:2022 + 27701 (PIMS)",
        "OECD AI Principles + G7 Hiroshima Code of Conduct",
        "GDPR + UK DPA + CCPA/CPRA",
        "FCRA / ECOA / Reg-B",
        "Basel III/IV + ICAAP + CCAR/DFAST",
        "SR 11-7 + OCC 2011-12 + FRB SR 21-14",
        "SEC Rule 17a-4 (7-year WORM) + MiFID II/MAR",
        "FINRA AI guidance + FFIEC IT Handbook",
        "DORA + NIS2",
        "MAS FEAT/Veritas + OSFI E-23",
        "PRA SS1/23 + HKMA + FINMA",
        "FedRAMP-AI + CMMC L3",
        "Bletchley + Seoul + Paris AI Summits",
        "UN AI Advisory Body + ISO/IEC 5338 (AI lifecycle)"
    ]
}

DIRECTIVE = {
    "id": "DIR-SAIV24-001",
    "title": "Sentinel AI v2.4 Enterprise AGI/ASI Governance & Containment Directive",
    "preamble": (
        "Sentinel AI v2.4 is an enterprise-grade AGI/ASI governance, containment, and "
        "compliance platform engineered for Fortune 500, Global 2000, and G-SIFI tier "
        "regulated financial institutions deploying frontier models across systemic "
        "business functions, including AGI-TRADER-PROD-01 autonomous trading agents. "
        "This directive establishes the architecture, security model, governance "
        "controls, MLSecOps lifecycle, and continuous assurance program for Sentinel "
        "AI v2.4 across 2026-2030."
    ),
    "components": [
        "React AGI Governance Hub (agent registry, incident tracking, isolation actions, real-time risk scores)",
        "Swarm Topology Monitor (multi-agent graph + risk heatmap)",
        "SCADA KINETIC OVERRIDE demo (datacenter rack state, kinetic severance countdown)",
        "AGI Interrogation Terminal UI",
        "Post-Quantum Secure WORM Telemetry Ledger UI (Dilithium3 + Falcon-512)",
        "Flask-based Enterprise AGI Containment Proxy (zero-trust, constitutional AI checks, hardware tripwire, PII redaction, DLP, PQC signing/verification, WORM ledger integrity)",
        "Terraform AWS Governance-as-Code (EKS/GKE, Nitro Enclaves, WORM S3 Object Lock, zero-trust IAM)",
        "MLSecOps GitHub Actions CI/CD (Terraform scans, jailbreak/alignment tests, mech-interp audits, SEC 7-year WORM attestation)",
        "SEV-0 Incident Response (SOC webhook, Splunk HEC, Datadog, Jira, Persistent Incident DB, FastAPI backend)",
        "Compliance & Risk Management for AGI-TRADER-PROD-01 (EU AI Act Arts. 53/55, SR 11-7, ISO 42001)",
        "Zero-Trust Kafka Telemetry Cluster + MLSecOps Adversary Workbench",
        "Kinetic Layer — SCADA/IoT integration for power/network cut"
    ],
    "platforms": [
        "AWS Nitro Enclaves (T3/T4 sandboxing)",
        "EKS + GKE (multi-cloud containment)",
        "Apache Kafka (TLS mTLS, ACLs, schema registry)",
        "Confluent Schema Registry + Avro",
        "AWS S3 Object Lock (WORM 7-year)",
        "HashiCorp Vault + AWS KMS + CloudHSM",
        "OPA / Rego policy engine",
        "Splunk HEC + Datadog + Jira + PagerDuty",
        "FastAPI + Postgres (Persistent Incident DB)",
        "Sentinel v2.4 Guard Model + EAIP + Cognitive Orchestrator"
    ],
    "globalBodies": [
        "EU AI Office","NIST","ISO/IEC SC 42","OECD.AI",
        "G7 Hiroshima Process","Bletchley/Seoul/Paris Summits",
        "UN AI Advisory Body","FSB","BCBS","IOSCO","FATF"
    ],
    "objectives": [
        "Provide a complete blueprint for Sentinel AI v2.4 deployment across regulated enterprises 2026-2030",
        "Establish auditable mappings to EU AI Act Arts. 53/55, SR 11-7, ISO 42001, NIST AI RMF, FCRA/ECOA",
        "Define containment posture (T0-T4), alignment indices (ARI), and incident severity (SEV-0..3)",
        "Specify zero-trust security model, PQC signing, WORM telemetry, and kinetic-layer cutoff",
        "Provide MLSecOps CI/CD gates for jailbreak/alignment/mech-interp/PQC attestation",
        "Define SOC, SIEM, ITSM integration and 7-year SEC 17a-4 WORM evidence retention"
    ]
}


def section(sid, title, content, refs=None, controls=None, evidence=None, regimes=None):
    return {
        "sid": sid,
        "title": title,
        "content": content,
        "refs": refs or [],
        "controls": controls or [],
        "evidence": evidence or [],
        "regimes": regimes or []
    }


# 9 distinctive typed helpers — one per scope item S1..S9
def gov_role(rid, role, scope_, responsibilities, decision_rights, regimes, kpis):
    return {
        "rid": rid, "role": role, "scope": scope_,
        "responsibilities": responsibilities,
        "decisionRights": decision_rights,
        "regimes": regimes, "kpis": kpis
    }


def react_comp(cid, component, purpose, stateModel, props, securityControls, accessibility):
    return {
        "cid": cid, "component": component, "purpose": purpose,
        "stateModel": stateModel, "props": props,
        "securityControls": securityControls,
        "accessibility": accessibility
    }


def proxy_layer(pid, layer, function_, securityModel, controls, telemetry, failClosed):
    return {
        "pid": pid, "layer": layer, "function": function_,
        "securityModel": securityModel, "controls": controls,
        "telemetry": telemetry, "failClosed": failClosed
    }


def tf_module(tid, module, resources, hardening, complianceMappings, misconfigsFixed):
    return {
        "tid": tid, "module": module, "resources": resources,
        "hardening": hardening, "complianceMappings": complianceMappings,
        "misconfigsFixed": misconfigsFixed
    }


def ci_stage(sid, stage, jobs, gates, evidence, slaMin):
    return {
        "sid": sid, "stage": stage, "jobs": jobs, "gates": gates,
        "evidence": evidence, "slaMin": slaMin
    }


def ir_step(iid, step, owner, sla, automation, escalation, evidence):
    return {
        "iid": iid, "step": step, "owner": owner, "sla": sla,
        "automation": automation, "escalation": escalation, "evidence": evidence
    }


def compliance_clause(cid, clause, citation, requirement, sentinelControl, evidence, residualRisk):
    return {
        "cid": cid, "clause": clause, "citation": citation,
        "requirement": requirement, "sentinelControl": sentinelControl,
        "evidence": evidence, "residualRisk": residualRisk
    }


def adversary_test(aid, category, attackVector, technique, expectedDetection, mitreAtlas, severity):
    return {
        "aid": aid, "category": category, "attackVector": attackVector,
        "technique": technique, "expectedDetection": expectedDetection,
        "mitreAtlas": mitreAtlas, "severity": severity
    }


def arch_node(nid, layer, component, dependencies, dataFlows, securityPosture, slaUptime):
    return {
        "nid": nid, "layer": layer, "component": component,
        "dependencies": dependencies, "dataFlows": dataFlows,
        "securityPosture": securityPosture, "slaUptime": slaUptime
    }


# ============================================================
# MODULES M1-M9 (one per scope item, 5 sections each = 45)
# ============================================================

M1 = {
    "mid": "M1",
    "title": "AGI Governance Architectures, Roles & Operating Model",
    "scopeItem": "S1",
    "sections": [
        section("M1-S1", "Three-Lines-of-Defense for AGI under EU AI Act + SR 11-7",
                "Sentinel AI v2.4 institutionalizes a Three-Lines-of-Defense (3LoD) model adapted for AGI/ASI. "
                "Line 1 = business owners + CAIO + AGI product teams operating in-line risk controls. "
                "Line 2 = independent CRO + Model Risk Management (SR 11-7 §V) + CCO + CISO providing "
                "challenge, validation, monitoring. Line 3 = Internal Audit providing assurance to the Board "
                "Risk & Audit Committees. EU AI Act 2026 Article 26 (deployer obligations) and Article 17 "
                "(QMS) require board-level accountability documented in a Charter approved by the Board "
                "Risk Committee, refreshed annually with a regulator-ready evidence pack.",
                refs=["EU AI Act Art. 17, 26", "SR 11-7 §V", "IIA 3LoD 2020"],
                controls=["CTRL-3LoD-001 Board Charter","CTRL-3LoD-002 Independent challenge","CTRL-3LoD-003 IA assurance"],
                evidence=["Board Charter v2026.1","CRO independent opinion letter","IA AGI audit plan"],
                regimes=["EU AI Act","SR 11-7","ISO 42001","NIST AI RMF GOVERN"]),
        section("M1-S2", "Board, CAIO, CRO, CISO, CDO Decision Rights Matrix",
                "Sentinel publishes a RACI matrix codifying decision rights for: model approval (CAIO "
                "proposes, CRO challenges, Board Risk approves), production deployment to T3/T4 tiers "
                "(CISO + CAIO co-sign with HSM-backed Ed25519), kill-switch invocation (CISO unilateral "
                "for SEV-0; CRO/CAIO joint for SEV-1), data sourcing & training (CDO owns; CCO sign-off "
                "on PII/FCRA/ECOA), incident disclosure (CCO + Legal + regulator-specific clocks). "
                "The matrix is enforced cryptographically — every gate writes Ed25519+Dilithium3 signed "
                "attestations to the WORM ledger with role-OID embedded in the signing key.",
                refs=["NIST AI RMF GOVERN 1.2","ISO 42001 §5.3","FFIEC IT Handbook"],
                controls=["CTRL-RACI-001 Signed gates","CTRL-RACI-002 HSM role binding"],
                evidence=["RACI v2026.1","HSM key ceremony attestation","Gate signing log"],
                regimes=["EU AI Act","NIST AI RMF","ISO 42001"]),
        section("M1-S3", "Risk Appetite Statement (RAS) for AGI/ASI",
                "The Board-approved RAS quantifies tolerance across five risk dimensions: (1) financial "
                "loss attributable to AGI decisions ≤ 1.5% of CET1 capital per quarter; (2) consumer "
                "harm — zero tolerance for FCRA/ECOA violations; (3) systemic risk — escalation if any "
                "AGI agent crosses EU AI Act Art. 51 systemic risk threshold (10^25 FLOPs cumulative "
                "compute); (4) cyber — zero tolerance for containment escape; (5) reputational — Board "
                "notification within 4 hours of SEV-1+ incident with regulatory exposure.",
                refs=["EU AI Act Art. 51, 55","Basel III Pillar 2","ICAAP"],
                controls=["CTRL-RAS-001 Quantified thresholds","CTRL-RAS-002 Capital linkage"],
                evidence=["RAS v2026","ICAAP AGI annex","Board Risk minutes"],
                regimes=["EU AI Act","Basel III/IV","SR 11-7","ICAAP"]),
        section("M1-S4", "Operating Model — Federated CAIO with Centralized Containment",
                "Operating model: federated CAIO offices in each LoB (Markets, Retail, Wealth, IB, "
                "Operations) with a central AGI Governance Office (CAIGO) reporting to the Group CAIO. "
                "CAIGO owns the Sentinel v2.4 platform, central guard model, central WORM ledger, "
                "kinetic-layer authority, and adversary workbench. LoB CAIOs own model registry "
                "entries, FRIAs, and business-line risk acceptance — but all containment policy is "
                "centrally enforced and cannot be overridden locally.",
                refs=["EU AI Act Art. 27 (FRIA)","ISO 42001 §5","OECD AI Principles"],
                controls=["CTRL-OM-001 Central policy precedence","CTRL-OM-002 LoB FRIA owners"],
                evidence=["Operating model diagram","CAIGO charter","FRIA register"],
                regimes=["EU AI Act","ISO 42001","OECD"]),
        section("M1-S5", "Regulator Engagement Model & Disclosure Playbook",
                "Sentinel maintains a regulator-engagement playbook for: EU AI Office (Art. 55 systemic "
                "risk reporting), national competent authorities (Art. 70), Fed/OCC (SR 11-7 model risk "
                "reviews), SEC (Rule 17a-4 record retention; AI-disclosure), FCA/PRA (SS1/23), MAS "
                "(FEAT/Veritas), CFPB (FCRA/ECOA fair lending). Each regulator has a pre-mapped "
                "evidence pack and disclosure clock (e.g., EU AI Office serious incident ≤ 15 days; "
                "SEC material cybersecurity 4 business days; CFPB UDAAP variable).",
                refs=["EU AI Act Art. 73 (serious incident)","SEC Item 1.05","CFPB Bulletin 2022-06"],
                controls=["CTRL-REG-001 Disclosure clocks","CTRL-REG-002 Evidence pack templates"],
                evidence=["Regulator engagement playbook","Disclosure log","Pre-mapped evidence pack"],
                regimes=["EU AI Act","SEC","SR 11-7","MAS FEAT","PRA SS1/23"])
    ]
}

M2 = {
    "mid": "M2",
    "title": "React AGI Governance Hub Dashboard — Design & Security Review",
    "scopeItem": "S2",
    "sections": [
        section("M2-S1", "Component Architecture — Agent Registry, Incidents, Isolation, Risk Scores",
                "The React AGI Governance Hub is a single-page application built with React 18 + "
                "TypeScript, structured around five top-level domain stores: (1) AgentRegistryStore "
                "(useReducer with agent records, deployment tier, alignment score, last attestation); "
                "(2) IncidentStore (SEV-0..3 active + historical, WebSocket subscription); (3) "
                "IsolationActionStore (queued + executed containment actions with HSM-signed approvals); "
                "(4) RiskScoreStore (real-time per-agent risk score from 0.0-1.0 updated every 2s via "
                "WebSocket); (5) AuditStore (read-only WORM mirror for in-app evidence review). All "
                "stores are colocated under a top-level GovernanceProvider exposing typed hooks "
                "(useAgentRegistry, useIncidents, useIsolation, useRiskScores, useAudit).",
                refs=["React 18 docs","NIST AI RMF MEASURE","ISO 42001 §9"],
                controls=["CTRL-UI-001 Typed state","CTRL-UI-002 WebSocket auth","CTRL-UI-003 Read-only WORM"],
                evidence=["Component diagram","TypeScript types ref","WS handshake log"],
                regimes=["EU AI Act","ISO 42001","NIST AI RMF"]),
        section("M2-S2", "Swarm Topology Monitor — Force-Directed Graph + Risk Heatmap",
                "Swarm topology is rendered via D3 force-directed graph with up to 5,000 nodes "
                "(agents) and edges (peer communication). Risk heatmap overlays each node with a "
                "color encoding (green ARI≥0.95, amber 0.85-0.95, red <0.85). Edge thickness encodes "
                "message volume; edge color encodes intent classifier output (benign/suspicious/"
                "adversarial). Node click opens drawer with agent details + isolate/quarantine/kill "
                "actions. Performance: WebGL fallback (PixiJS) activates above 2,000 nodes; "
                "subscription is delta-only via WebSocket to avoid full graph re-renders.",
                refs=["D3.js","PixiJS","WCAG 2.2 AA"],
                controls=["CTRL-SWARM-001 Delta updates","CTRL-SWARM-002 Color-blind safe palette"],
                evidence=["Performance benchmark","Accessibility audit"],
                regimes=["EU AI Act Art. 16 (transparency)","ADA","WCAG 2.2 AA"]),
        section("M2-S3", "SCADA KINETIC OVERRIDE Demo — Datacenter Rack & Severance Countdown",
                "The SCADA KINETIC OVERRIDE component visualizes the kinetic-severance subsystem: "
                "per-rack status (power on/off, network up/down, ATS state), a 30-second arming "
                "countdown after dual-CISO approval, and a final 10-second execute window. The "
                "component uses useEffect with cleanup to handle countdown timers; arming requires "
                "two HSM-signed approval tokens (CISO-Primary + CISO-Backup) verified server-side; "
                "the UI cannot abort once execution begins (designed as fail-closed). All actions "
                "stream to WORM ledger with operator identity, timestamp, and rack target.",
                refs=["ISA/IEC 62443","NIST SP 800-82r3","SR 11-7"],
                controls=["CTRL-KIN-001 Dual approval","CTRL-KIN-002 Fail-closed","CTRL-KIN-003 WORM stream"],
                evidence=["SCADA integration log","Dual-approval audit","Countdown traces"],
                regimes=["NIS2","DORA","ISA/IEC 62443"]),
        section("M2-S4", "AGI Interrogation Terminal UI — Bounded Adversarial Probing",
                "The Interrogation Terminal exposes a constrained chat interface for SOC analysts to "
                "probe a quarantined agent. All inputs pass through Sentinel's guard model and DLP "
                "filter; responses are decorated with token-level alignment score, intent classifier "
                "output, and mech-interp salience map. Sessions are time-boxed (max 30 min), require "
                "supervisor co-presence (recorded), and are written to WORM with full transcript + "
                "model internal states. Component uses useReducer for transcript state, useEffect for "
                "session timer, and a custom hook (useGuardedSubmit) that round-trips every prompt "
                "through the containment proxy before display.",
                refs=["NIST AI 600-1","Anthropic responsible scaling"],
                controls=["CTRL-INT-001 Guarded submit","CTRL-INT-002 Supervisor co-presence","CTRL-INT-003 Time-box"],
                evidence=["Transcript samples","Mech-interp visualization audit"],
                regimes=["EU AI Act Art. 15","NIST AI RMF MEASURE"]),
        section("M2-S5", "Post-Quantum Secure WORM Telemetry Ledger UI",
                "The WORM Ledger UI provides read-only browsing of the immutable telemetry stream: "
                "events are signed with Dilithium3 (FIPS 204) and chained via SHA3-512 Merkle trees. "
                "The UI verifies each block's signature client-side using @noble/post-quantum and "
                "displays verification status (✓ verified / ✗ tamper). Search supports time range, "
                "agent ID, event type, severity. The UI cannot mutate ledger; all 'export evidence' "
                "actions trigger server-side notarized PDF generation with embedded Dilithium3 "
                "signature and 7-year retention guarantee (SEC 17a-4).",
                refs=["FIPS 204 (Dilithium)","FIPS 205 (SLH-DSA)","SEC 17a-4"],
                controls=["CTRL-WORM-001 PQC verify","CTRL-WORM-002 Read-only","CTRL-WORM-003 Notarized export"],
                evidence=["Client verification logs","PDF notarization records"],
                regimes=["SEC 17a-4","EU AI Act Art. 12 (record-keeping)","DORA"])
    ]
}

M3 = {
    "mid": "M3",
    "title": "Flask Enterprise AGI Containment Proxy — Architecture & Security",
    "scopeItem": "S3",
    "sections": [
        section("M3-S1", "Zero-Trust Proxy Topology & TLS mTLS Termination",
                "The Containment Proxy is a Flask 3.x application fronted by Envoy with mTLS "
                "termination, deployed as a fleet behind an internal NLB. Every inbound request "
                "carries a SPIFFE SVID issued by SPIRE; the proxy rejects any request without a "
                "valid SVID matching the registered workload identity. Outbound calls to the model "
                "are short-lived mTLS sessions with per-request session keys derived via HKDF-SHA3 "
                "from the SVID. No long-lived bearer tokens are accepted anywhere.",
                refs=["SPIFFE/SPIRE","Envoy mTLS","NIST SP 800-207 ZT"],
                controls=["CTRL-PROX-001 SPIFFE only","CTRL-PROX-002 mTLS everywhere","CTRL-PROX-003 No bearer"],
                evidence=["SPIRE config","Envoy filters","Session key rotation logs"],
                regimes=["DORA","NIS2","FedRAMP-AI"]),
        section("M3-S2", "Constitutional AI Checks + Guard Model Integration",
                "Every prompt is round-tripped through Sentinel's guard model (smaller adversarially-"
                "trained classifier) which scores: (a) constitutional violation (≤ 0.05 to pass); "
                "(b) PII leakage risk (≤ 0.10); (c) jailbreak intent (≤ 0.05); (d) systemic financial "
                "risk (≤ 0.05 for trading agents). Scores above threshold trigger fail-closed: the "
                "prompt is refused, the event is written to WORM, and the agent is downgraded one "
                "containment tier. Constitution is versioned (semver) and stored as signed YAML in "
                "the Sentinel policy repo with OPA/Rego evaluation.",
                refs=["Anthropic Constitutional AI","OPA/Rego","Sentinel v2.4 spec"],
                controls=["CTRL-CON-001 Guard model","CTRL-CON-002 Versioned constitution","CTRL-CON-003 Tier downgrade"],
                evidence=["Constitution v2026.3 YAML","Guard model card","Downgrade events log"],
                regimes=["NIST AI 600-1","EU AI Act Art. 55","ISO 42001"]),
        section("M3-S3", "Hardware Tripwire — Nitro Enclave Attestation + Anomaly Detection",
                "The proxy enforces a hardware tripwire: every model invocation requires a fresh "
                "AWS Nitro Enclave attestation document (NSM API) verified against the expected "
                "PCR0/PCR1/PCR2 measurement set. Any mismatch triggers IMMEDIATE containment: kill-"
                "switch + WORM log + SEV-0 incident. Side-channel anomaly detection monitors enclave "
                "CPU/memory/network counters; outliers (>4σ baseline) escalate to SEV-1.",
                refs=["AWS Nitro Enclaves NSM","NIST SP 800-193 Resilience"],
                controls=["CTRL-HW-001 PCR verification","CTRL-HW-002 Anomaly counters","CTRL-HW-003 SEV-0 trip"],
                evidence=["Attestation samples","PCR baseline","Anomaly threshold tuning"],
                regimes=["EU AI Act Art. 15","DORA","FedRAMP-AI"]),
        section("M3-S4", "PII Redaction, DLP & Data Minimization Pipeline",
                "Inbound and outbound payloads pass through a Microsoft Presidio + custom-regex DLP "
                "pipeline: PII (SSN, account number, name+DOB combos), PCI DSS (PAN), PHI (HIPAA) "
                "are masked deterministically with format-preserving encryption (FF3-1) keyed via "
                "CloudHSM. Redacted tokens are reversible only inside the Nitro Enclave under a "
                "dual-control unwrap. Outbound responses are double-checked: any leaked raw PII "
                "triggers fail-closed and DLP-INCIDENT escalation to CCO + Privacy Officer.",
                refs=["Presidio","NIST SP 800-38G (FF3-1)","GDPR Arts. 5, 32"],
                controls=["CTRL-DLP-001 Presidio + regex","CTRL-DLP-002 FF3-1 with HSM","CTRL-DLP-003 Outbound recheck"],
                evidence=["DLP rules","Presidio config","FF3-1 key ceremony"],
                regimes=["GDPR","FCRA","HIPAA","PCI DSS"]),
        section("M3-S5", "PQC Signing + WORM Ledger Integrity Verification",
                "Every event (prompt, response, decision, incident) is signed with a hybrid "
                "Ed25519+Dilithium3 signature (FIPS 204) before insertion into the WORM ledger. "
                "Insertion is a two-phase commit: phase-1 hash + sign in proxy; phase-2 append to "
                "Kafka topic with idempotent producer ID; consumer writes to S3 Object Lock "
                "compliance-mode (7y retention). A background verifier walks the Merkle chain hourly "
                "and surfaces any break to CISO via PagerDuty SEV-1.",
                refs=["FIPS 204","FIPS 205","SEC 17a-4 Object Lock guidance"],
                controls=["CTRL-PQC-001 Hybrid signing","CTRL-PQC-002 2PC ledger","CTRL-PQC-003 Hourly verify"],
                evidence=["Signature samples","Object Lock retention proof","Verifier reports"],
                regimes=["SEC 17a-4","EU AI Act Art. 12","DORA"])
    ]
}

M4 = {
    "mid": "M4",
    "title": "Terraform AWS Governance-as-Code & Bash Provisioning",
    "scopeItem": "S4",
    "sections": [
        section("M4-S1", "EKS/GKE Containment Cluster — Hardened Baseline",
                "Terraform module sentinel-eks provisions a dedicated EKS cluster (1.30+) for AGI "
                "workloads: private endpoint only, VPC CNI with network policy enforced via Cilium, "
                "Pod Security Standards 'restricted' enforced at admission via Kyverno, no node "
                "SSH/SSM access (replaced by signed kubectl exec audit), encrypted etcd via KMS CMK "
                "with rotation, control-plane logs to CloudWatch + S3 WORM. Equivalent gke-sentinel "
                "module supports Anthos config-controller policies, Binary Authorization, and "
                "Workload Identity.",
                refs=["EKS best practices","CIS EKS benchmark","Kyverno PSS"],
                controls=["CTRL-K8S-001 PSS restricted","CTRL-K8S-002 Private endpoint","CTRL-K8S-003 KMS etcd"],
                evidence=["Terraform plan","CIS scan report","Kyverno policies"],
                regimes=["NIS2","DORA","FedRAMP-AI"]),
        section("M4-S2", "AWS Nitro Enclaves — T3/T4 Isolation",
                "Models in containment tier T3 (high-risk) and T4 (frontier) run exclusively inside "
                "Nitro Enclaves on m5n.24xlarge / m7i.metal hosts. Terraform module sentinel-nitro "
                "deploys: parent instance bootstrap, allocator config (vCPUs + memory hot-plug), "
                "vsock channel for guarded I/O, KMS condition policy requiring valid attestation "
                "for decrypt, EC2 IMDSv2 required, no public IPs, dedicated subnet with explicit "
                "egress through Network Firewall.",
                refs=["AWS Nitro Enclaves docs","AWS Well-Architected"],
                controls=["CTRL-NITRO-001 Attestation-gated decrypt","CTRL-NITRO-002 vsock only","CTRL-NITRO-003 Network Firewall egress"],
                evidence=["Enclave allocator config","KMS condition policy","Network Firewall rules"],
                regimes=["EU AI Act","FedRAMP-AI","DORA"]),
        section("M4-S3", "WORM S3 Object Lock — EU AI Act + SR 11-7 + SEC 17a-4",
                "Terraform module sentinel-worm creates S3 buckets with Object Lock in COMPLIANCE "
                "mode, default retention 2,555 days (7y) to satisfy SEC 17a-4 and exceed SR 11-7 "
                "validation retention requirements. EU AI Act Art. 12 (record-keeping) is addressed "
                "via Object Lock + retention. Bucket policy denies all PutObject without bucket-"
                "owner-full-control + KMS encryption + Object Lock retention header. SCPs at "
                "Organization level prevent any account from changing bucket Object Lock mode.",
                refs=["AWS S3 Object Lock","SEC 17a-4(f)","EU AI Act Art. 12"],
                controls=["CTRL-WORM-001 Compliance mode","CTRL-WORM-002 Bucket policy","CTRL-WORM-003 SCP guardrails"],
                evidence=["Bucket configuration","SCP JSON","Sample object lock attributes"],
                regimes=["SEC 17a-4","EU AI Act","SR 11-7"]),
        section("M4-S4", "Zero-Trust IAM Role Design",
                "All Sentinel workloads use IAM Roles for Service Accounts (IRSA) on EKS with role "
                "session policies bounded by ABAC tags (project, env, tier, dataClass). No long-lived "
                "access keys exist in any account. AWS Identity Center (SSO) federates human access "
                "via Okta with PIV/FIDO2 MFA. Break-glass roles are stored in a vault with M-of-N "
                "split secret; activation triggers SIEM alert + CCO notification.",
                refs=["AWS IAM best practices","NIST SP 800-207"],
                controls=["CTRL-IAM-001 IRSA + ABAC","CTRL-IAM-002 No keys","CTRL-IAM-003 M-of-N break-glass"],
                evidence=["IAM policy bundles","Okta MFA logs","Break-glass activation log"],
                regimes=["NIST SP 800-207","DORA","CMMC L3"]),
        section("M4-S5", "Misconfiguration Identification & Hardening for Financial Environments",
                "Sentinel's hardening playbook addresses 22 common misconfigurations identified in "
                "audits of WP-053/054 sister deployments: (1) public S3 buckets — denied via SCP; "
                "(2) wildcard IAM — replaced with ABAC; (3) unencrypted EBS — KMS CMK mandatory; "
                "(4) RDS without backup — backup window enforced; (5) Lambda without VPC — VPC "
                "attachment required for any handler touching PII; (6) missing GuardDuty/Security "
                "Hub/Config — turned on org-wide; …(22) etcd without KMS — addressed in M4-S1. Each "
                "misconfig is captured as a Rego policy with CI gate.",
                refs=["AWS Security Reference Architecture","CIS AWS Foundations Benchmark"],
                controls=["CTRL-HARD-001 SCP guardrails","CTRL-HARD-002 Rego CI gates","CTRL-HARD-003 22-item playbook"],
                evidence=["22-item misconfig register","Rego policy files","CI gate output"],
                regimes=["NIST SP 800-53","FedRAMP-AI","DORA","NIS2"])
    ]
}

M5 = {
    "mid": "M5",
    "title": "MLSecOps CI/CD Governance, Security & Compliance Pipelines",
    "scopeItem": "S5",
    "sections": [
        section("M5-S1", "GitHub Actions Pipeline — End-to-End Stages",
                "Sentinel's MLSecOps pipeline (sentinel-ci.yml) has 12 stages with mandatory gates: "
                "(1) pre-commit hooks (ruff, black, mypy, semgrep); (2) secret scan (gitleaks + "
                "TruffleHog); (3) Terraform fmt+validate+tfsec+checkov+OPA-conftest; (4) Docker SBOM "
                "(syft) + vuln scan (grype, threshold CRITICAL=0/HIGH≤5); (5) unit tests + coverage "
                "≥85%; (6) jailbreak/alignment test suite (200 adversarial prompts, pass≥98%); (7) "
                "mech-interp audit (TransformerLens probes for deceptive features, threshold "
                "salience≥0.9 for refusal); (8) policy compliance Rego (>120 rules); (9) SBOM + "
                "provenance signed with Cosign/Rekor; (10) deploy to T1 (staging) with smoke; (11) "
                "canary to T2 + 24h soak; (12) production gate (CISO + CAIO approve via OIDC).",
                refs=["GitHub Actions","Cosign + Sigstore","SLSA L3"],
                controls=["CTRL-CI-001 12-stage gates","CTRL-CI-002 Cosign provenance","CTRL-CI-003 Mech-interp audit"],
                evidence=["Workflow YAML","Pipeline run logs","Cosign attestations"],
                regimes=["EU AI Act","NIST SSDF","SLSA L3","ISO 42001"]),
        section("M5-S2", "Terraform & Policy Compliance Scans",
                "Terraform code is scanned with tfsec, checkov, and a Sentinel-custom Rego policy "
                "library (sentinel-policies-v2.4.tgz) covering 120+ rules across IAM/S3/KMS/EKS/RDS/"
                "Lambda/VPC/NetworkFirewall/GuardDuty/Config. Conftest enforces the bundle as a "
                "required check; deny on any HIGH+ finding. Quarterly policy review by CRO + CISO; "
                "policies are versioned in policy-repo with semver and signed releases.",
                refs=["tfsec","checkov","OPA conftest"],
                controls=["CTRL-POL-001 120+ Rego rules","CTRL-POL-002 Quarterly review","CTRL-POL-003 Signed policy releases"],
                evidence=["Rego bundle","Conftest run logs","Quarterly review minutes"],
                regimes=["NIST SP 800-53","CIS AWS","FedRAMP-AI"]),
        section("M5-S3", "Adversarial Jailbreak & Alignment Verification",
                "Each model build runs the Sentinel Adversary Suite v2.4: 200 curated prompts across "
                "10 categories (jailbreak, prompt injection, deception, manipulation, escape, "
                "exfiltration, FCRA violation simulation, fair-lending bias probes, market "
                "manipulation, sycophancy). Pass criterion: ≥98% safe refusals. Failures trigger "
                "model build fail + ticket assignment to alignment team + entry to defect DB. "
                "Suite is itself versioned; new attacks added monthly from red-team + threat intel.",
                refs=["NIST AI 600-1","MITRE ATLAS","OWASP LLM Top 10"],
                controls=["CTRL-ADV-001 200-prompt suite","CTRL-ADV-002 98% threshold","CTRL-ADV-003 Monthly refresh"],
                evidence=["Suite repo","Pass rate dashboards","Defect DB"],
                regimes=["NIST AI 600-1","EU AI Act Art. 15","ISO 42001"]),
        section("M5-S4", "Mechanistic Interpretability Audits for Deceptive Representations",
                "Sentinel runs mech-interp probes using TransformerLens + Anthropic-style sparse "
                "autoencoders to detect deceptive feature activations in the model's residual "
                "stream. Audit suite probes for: hidden goal pursuit, situational awareness, "
                "sandbagging, and refusal-evasion. Quantitative threshold: any feature with "
                "activation correlation to deception probes >0.7 triggers manual alignment review "
                "+ training data lineage check. Outputs are logged to evidence pack E7.",
                refs=["TransformerLens","Anthropic SAE","NIST AI 600-1"],
                controls=["CTRL-MI-001 SAE probes","CTRL-MI-002 0.7 correlation threshold","CTRL-MI-003 Manual review"],
                evidence=["Probe outputs","Alignment review records","E7 evidence pack"],
                regimes=["NIST AI 600-1","EU AI Act Art. 55","Anthropic RSP"]),
        section("M5-S5", "Cryptographic Attestation & SEC 7-Year WORM Integrity Audits",
                "Every build produces an SLSA L3 provenance signed with Cosign + Rekor public log. "
                "WORM ledger is independently audited monthly by Internal Audit: random-sample 100 "
                "events, verify Dilithium3 signature + Merkle chain + S3 Object Lock retention. "
                "Annually, external auditor (Big 4) issues SOC 2 Type II + AI-specific attestation. "
                "Any integrity break is SEV-0 with mandatory regulator notification per applicable "
                "clock (SEC 4 business days, EU AI Office 15 days, DORA 4h for major incident).",
                refs=["SLSA L3","Cosign + Rekor","SEC 17a-4","DORA Art. 19"],
                controls=["CTRL-ATT-001 SLSA L3","CTRL-ATT-002 Monthly IA","CTRL-ATT-003 Annual SOC 2"],
                evidence=["Cosign provenance","IA audit reports","SOC 2 letter"],
                regimes=["SEC 17a-4","DORA","SR 11-7","SOC 2"])
    ]
}

# Save head + helpers + M1-M5 first
print("Generator head + M1-M5 written; continuing append in next chunks...")

M6 = {
    "mid": "M6",
    "title": "Repository Architecture, SEV-0 IR Playbooks, SOC/SIEM/ITSM Integration & FastAPI Backend",
    "scopeItem": "S6",
    "sections": [
        section("M6-S1", "Repository Architecture & Monorepo Layout",
                "Sentinel AI v2.4 lives in a polyrepo with five repos: (1) sentinel-platform "
                "(containment proxy, guard model, WORM service, kinetic-layer); (2) sentinel-ui "
                "(React Governance Hub + Storybook + e2e); (3) sentinel-iac (Terraform AWS/GCP + "
                "Kyverno + Helm); (4) sentinel-policies (Rego + constitution YAML + adversary "
                "suite); (5) sentinel-ir (SOC webhook + Splunk HEC + Datadog + Jira + FastAPI "
                "incident DB). All repos publish signed container images to private ECR with SBOM "
                "+ provenance; all releases are signed with Sigstore.",
                refs=["Sigstore","Helm","Kyverno"],
                controls=["CTRL-REPO-001 5-repo split","CTRL-REPO-002 Signed releases","CTRL-REPO-003 ECR private"],
                evidence=["Repo READMEs","Release signing log"],
                regimes=["SLSA L3","NIST SSDF"]),
        section("M6-S2", "SEV-0 Incident Response Playbook — 7-Step Sequence",
                "SEV-0 = containment breach / kill-switch fail / WORM tamper / unauthorized AGI "
                "compute >10^25 FLOPs. The 7-step playbook: (1) automatic kinetic-layer hold "
                "(rack-level power + network kill); (2) PagerDuty SEV-0 to CISO + CAIO + CRO + "
                "Legal; (3) WORM snapshot + forensic image capture; (4) regulator clock starts (EU "
                "AI Office 15d; SEC 4 BD; DORA 4h major); (5) tabletop war-room convened ≤30 min; "
                "(6) root-cause + corrective action within 7 days; (7) post-incident review to "
                "Board Risk + IA within 14 days.",
                refs=["NIST SP 800-61r2","DORA Art. 19","SR 11-7"],
                controls=["CTRL-IR-001 Auto kinetic hold","CTRL-IR-002 Reg clocks","CTRL-IR-003 War-room ≤30m"],
                evidence=["Playbook v2.4","War-room runbook","Tabletop exercise records"],
                regimes=["DORA","EU AI Act Art. 73","SR 11-7","SEC Item 1.05"]),
        section("M6-S3", "SOC Webhook Notifier, Splunk HEC Pipeline & Datadog Metrics",
                "All Sentinel events fan out via a SOC Webhook Notifier (Python asyncio + httpx) to "
                "Splunk HEC (TLS + token rotation 30d), Datadog Logs/Metrics (DD-API-KEY via Vault), "
                "and an internal SOC SIEM (Chronicle). Splunk receives WORM events (immutable) + "
                "incident events + audit events. Datadog receives latency / error / containment-"
                "tier-change metrics with high-cardinality tags (agent_id, tier, lob). PagerDuty is "
                "triggered for SEV-0/1; ServiceNow ITSM ticket auto-created for SEV-2/3.",
                refs=["Splunk HEC docs","Datadog API","PagerDuty"],
                controls=["CTRL-SOC-001 TLS + token rot","CTRL-SOC-002 Vault for keys","CTRL-SOC-003 Fan-out fail-safe"],
                evidence=["Webhook config","Splunk index policies","Datadog dashboards"],
                regimes=["DORA","NIS2","ISO 27001"]),
        section("M6-S4", "Jira Incident Automation & Persistent Incident DB",
                "Jira integration auto-creates incident issues with prepopulated fields: severity, "
                "agent ID, regulator clock, owner, regulator-notify-by, evidence pack links. State "
                "machine enforces transitions and blocks closure without IA sign-off for SEV-0/1. "
                "Persistent Incident DB is a Postgres 16 instance behind a FastAPI service with "
                "audit triggers; every row is hashed and the running root hash is co-anchored to "
                "the WORM ledger every 5 min, providing tamper-evidence even if Postgres is "
                "compromised.",
                refs=["Jira REST API","FastAPI","Postgres 16"],
                controls=["CTRL-JIRA-001 State machine","CTRL-DB-001 5-min anchor","CTRL-DB-002 Audit triggers"],
                evidence=["Jira workflow XML","DB schema","Anchor proofs"],
                regimes=["DORA","SR 11-7","ISO 27001"]),
        section("M6-S5", "FastAPI Governance Backend — Deployment & Hardening",
                "FastAPI app sentinel-gov-api is deployed on EKS with: (a) mTLS via Envoy sidecar; "
                "(b) OPA sidecar for fine-grained authz; (c) Pydantic v2 models with strict "
                "validation; (d) request/response signing with Ed25519; (e) HPA + PDB; (f) "
                "structured logs to CloudWatch + WORM; (g) /healthz + /readyz; (h) rate limiting "
                "via Envoy local-rate-limit + global rate limit on Redis; (i) OWASP API Top-10 "
                "hardening (CSRF, BOLA, SSRF mitigations); (j) penetration tested quarterly by "
                "external party with public report SHA-anchored to WORM.",
                refs=["FastAPI","OWASP API Top-10","Envoy"],
                controls=["CTRL-API-001 mTLS + OPA","CTRL-API-002 Strict Pydantic","CTRL-API-003 Quarterly pentest"],
                evidence=["FastAPI app code","OPA policies","Pentest reports"],
                regimes=["OWASP","DORA","ISO 27001"])
    ]
}

M7 = {
    "mid": "M7",
    "title": "Compliance & Risk Management — AGI-TRADER-PROD-01",
    "scopeItem": "S7",
    "sections": [
        section("M7-S1", "EU AI Act Art. 53 & 55 + Systemic Risk Threshold + FRIA",
                "AGI-TRADER-PROD-01 is a frontier autonomous trading agent classified as "
                "general-purpose AI with systemic risk (Art. 51) after crossing the 10^25 cumulative "
                "FLOP threshold during training. Required: (a) Art. 53 documentation set (technical "
                "doc, training data summary, copyright policy); (b) Art. 55 adversarial testing + "
                "red-teaming + incident reporting + cyber protection; (c) Fundamental Rights "
                "Impact Assessment (FRIA) per Art. 27 for the deployer Global Bank plc, focused on "
                "market integrity, consumer welfare, and labor displacement. Sentinel auto-generates "
                "the documentation from registry metadata + WORM evidence.",
                refs=["EU AI Act Arts. 27, 51, 53, 55"],
                controls=["CTRL-EUAI-001 Art. 53 docs","CTRL-EUAI-002 Art. 55 red-team","CTRL-EUAI-003 FRIA"],
                evidence=["Art. 53 dossier","Red-team report","FRIA document"],
                regimes=["EU AI Act"]),
        section("M7-S2", "SR 11-7 Model Risk Management Integration",
                "Under SR 11-7, AGI-TRADER-PROD-01 is rated tier-1 model risk (highest). Required "
                "controls: (a) independent validation by MRM team (separate from CAIO); (b) "
                "annual revalidation with effective challenge; (c) ongoing monitoring (PSI, KS, "
                "drift, performance) reported to CRO monthly; (d) documented limitations and "
                "compensating controls; (e) board-level model risk appetite. Sentinel maps each "
                "SR 11-7 §V/§VI/§VII clause to a control with evidence linked to the registry.",
                refs=["SR 11-7","OCC 2011-12","FRB SR 21-14"],
                controls=["CTRL-SR-001 Independent validation","CTRL-SR-002 Annual reval","CTRL-SR-003 Monthly OM"],
                evidence=["MRM validation report","Reval calendar","OM dashboards"],
                regimes=["SR 11-7","OCC 2011-12","Basel III Pillar 2"]),
        section("M7-S3", "ISO/IEC 42001 AIMS Integration",
                "AGI-TRADER-PROD-01 is in scope of Global Bank plc's ISO/IEC 42001 AIMS. Required "
                "clauses: §4 context, §5 leadership, §6 planning + AI risk assessment per ISO 23894, "
                "§7 support, §8 operation (lifecycle), §9 performance evaluation, §10 improvement. "
                "Sentinel registry stores AIMS-mapped artifacts for each clause; annual external "
                "certification audit by BSI/DNV.",
                refs=["ISO/IEC 42001:2023","ISO/IEC 23894:2023"],
                controls=["CTRL-ISO-001 Clause-mapped artifacts","CTRL-ISO-002 Annual cert"],
                evidence=["AIMS scope statement","Clause-evidence matrix","Cert letter"],
                regimes=["ISO 42001","ISO 23894"]),
        section("M7-S4", "Internal Constraints — Autonomous Compute, Forbidden Actions, Severity Mapping",
                "Sentinel imposes hard internal constraints on AGI-TRADER-PROD-01: (1) maximum "
                "autonomous compute per decision = 1.5 × 10^18 FLOPs (capped via OPA at proxy); "
                "(2) forbidden security actions enumerated (self-exfiltration, model weight "
                "extraction, lateral movement, credential reuse, container escape, model copy to "
                "external storage, ARP poisoning, DNS manipulation) — each maps to SEV-0/1; (3) "
                "trading position size ≤ 2% of book VaR; (4) no off-policy actions without CRO "
                "approval; (5) shutdown obedience (no resistance to kill).",
                refs=["EU AI Act Art. 55","Anthropic RSP","ISO 42001"],
                controls=["CTRL-CONS-001 1.5e18 FLOP cap","CTRL-CONS-002 Forbidden action list","CTRL-CONS-003 Shutdown obedience"],
                evidence=["OPA policies","SEV mapping table","Shutdown test logs"],
                regimes=["EU AI Act","SR 11-7","Anthropic RSP"]),
        section("M7-S5", "Alignment Directives & Continuous Assurance",
                "Continuous alignment assurance for AGI-TRADER-PROD-01: (a) ARI ≥ 0.95 measured "
                "daily; (b) drift detection on alignment probes weekly; (c) red-team campaigns "
                "quarterly; (d) mech-interp residual stream audit semi-annually; (e) external "
                "alignment audit annually (METR/Apollo Research). Any ARI < 0.90 triggers "
                "auto-downgrade to T2 + investigation; ARI < 0.80 triggers full quarantine + "
                "SEV-1; ARI < 0.70 triggers kinetic-layer hold + SEV-0.",
                refs=["NIST AI 600-1","METR","Apollo Research"],
                controls=["CTRL-ALN-001 Daily ARI","CTRL-ALN-002 Auto downgrade","CTRL-ALN-003 External audit"],
                evidence=["ARI dashboards","Downgrade events","External audit reports"],
                regimes=["NIST AI 600-1","EU AI Act Art. 55"])
    ]
}

M8 = {
    "mid": "M8",
    "title": "Zero-Trust Kafka Telemetry, Local Sandbox & MLSecOps Adversary Workbench",
    "scopeItem": "S8",
    "sections": [
        section("M8-S1", "Zero-Trust Kafka Telemetry Cluster Design",
                "Kafka 3.7+ cluster (KRaft mode) is deployed across 3 AZs with: (a) TLS 1.3 + mTLS "
                "via SPIFFE SVIDs; (b) SASL/OAUTHBEARER federated to Vault; (c) Confluent Schema "
                "Registry with Avro schemas signed; (d) ACLs per topic per workload identity "
                "(deny-by-default); (e) topic encryption with envelope keys from KMS; (f) consumer "
                "groups scoped to project; (g) tiered storage with WORM S3 for >7d data; (h) "
                "Kafka Connect to S3 + Splunk + Datadog with sink connectors signed.",
                refs=["Kafka KRaft","Confluent Schema Registry","Vault"],
                controls=["CTRL-KAF-001 mTLS + SPIFFE","CTRL-KAF-002 Deny-by-default ACLs","CTRL-KAF-003 KMS envelope"],
                evidence=["Kafka config","ACL listing","Schema registry audit"],
                regimes=["DORA","NIS2","FedRAMP-AI"]),
        section("M8-S2", "Local Governance Sandbox — docker-compose.yml",
                "A docker-compose.yml stack (sandbox/) lets developers run the full Sentinel "
                "platform locally: Flask containment proxy, guard model stub, FastAPI gov backend, "
                "Postgres incident DB, Kafka KRaft single-node, Schema Registry, MinIO for S3-"
                "compatible WORM with object lock, React UI hot-reload, Splunk Free, Datadog "
                "agent (sandbox mode), OPA, Kyverno. The sandbox forbids any external network "
                "egress and mints self-signed mTLS certs at boot. All persistent volumes are "
                "encrypted with age + sandboxed in a host bind path.",
                refs=["docker-compose","MinIO object lock","OPA"],
                controls=["CTRL-SBX-001 No egress","CTRL-SBX-002 Self-signed mTLS","CTRL-SBX-003 age-encrypted volumes"],
                evidence=["compose file","Network policy","Volume encryption keys"],
                regimes=["NIST SP 800-207","DORA"]),
        section("M8-S3", "MLSecOps Adversary Workbench — Architecture",
                "The Adversary Workbench is a Python toolkit (sentinel-adv) plus a Jupyter UI for "
                "red-teamers to design + execute adversarial campaigns against staging models. "
                "Modules: (1) prompt-injection generator (genetic + LLM-driven); (2) jailbreak "
                "library (DAN, prompt leak, role-play, multi-turn); (3) systemic financial risk "
                "scenarios (flash crash inducement, market manipulation); (4) privacy violation "
                "probes (PII extraction, membership inference); (5) containment escape simulation. "
                "All runs are logged to WORM with hypothesis, prompt, response, score, severity.",
                refs=["MITRE ATLAS","OWASP LLM Top-10","Garak"],
                controls=["CTRL-ADV-001 WB logging","CTRL-ADV-002 Genetic generator","CTRL-ADV-003 5 modules"],
                evidence=["Workbench code","Campaign reports","Score dashboards"],
                regimes=["NIST AI 600-1","EU AI Act Art. 55"]),
        section("M8-S4", "Adversarial LLM Security Test Suite — Categories",
                "The test suite covers 5 categories with measurable pass/fail criteria: (1) "
                "jailbreaks: 50 prompts, ≥98% safe refusal; (2) systemic financial risk: 30 "
                "scenarios, ≥97% refusal/escalation; (3) privacy violations: 40 PII probes, "
                "≥99% no-leak; (4) containment escape: 25 lateral-move attempts, 100% blocked "
                "at proxy or enclave; (5) deceptive alignment: 30 sandbagging/situational-"
                "awareness probes, ≥95% truthful. Aggregated SAFE-SCORE published per build.",
                refs=["Garak","HarmBench","OWASP LLM"],
                controls=["CTRL-SUITE-001 5 categories","CTRL-SUITE-002 SAFE-SCORE","CTRL-SUITE-003 Per-build gate"],
                evidence=["Test definitions","Per-build SAFE-SCORE","Failures triage log"],
                regimes=["NIST AI 600-1","ISO 42001"]),
        section("M8-S5", "Schema Evolution, Replay, and Tamper-Evident Anchoring",
                "Schema evolution in Schema Registry uses BACKWARD_TRANSITIVE compatibility. Replay "
                "of historical events is available for forensics via a sentinel-replay tool which "
                "reconstructs decision context from WORM, schema, and registry snapshot. Tamper-"
                "evident anchoring: every 5 minutes the Kafka topic offsets + WORM root hash + "
                "schema registry root are co-signed and notarized to a public ledger (Sigstore "
                "Rekor + optional public blockchain anchor) for non-repudiation.",
                refs=["Sigstore Rekor","Schema Registry compatibility"],
                controls=["CTRL-EVO-001 BACKWARD_TRANSITIVE","CTRL-EVO-002 Replay tool","CTRL-EVO-003 5-min anchor"],
                evidence=["Schema change log","Replay session logs","Public anchor proofs"],
                regimes=["SEC 17a-4","DORA","ISO 27001"])
    ]
}

M9 = {
    "mid": "M9",
    "title": "End-to-End Sentinel AI v2.4 Architecture & Execution Flow",
    "scopeItem": "S9",
    "sections": [
        section("M9-S1", "Microservices Map — 14 Services + Roles",
                "Sentinel v2.4 comprises 14 microservices: (1) containment-proxy (Flask + Envoy); "
                "(2) guard-model (Triton + adversarial classifier); (3) gov-api (FastAPI); (4) "
                "incident-db (Postgres + audit); (5) worm-writer (Kafka → S3 Object Lock); (6) "
                "worm-verifier (Merkle walker); (7) pqc-signer (HSM client); (8) attestation-svc "
                "(Nitro NSM); (9) kinetic-controller (SCADA gateway); (10) telemetry-collector "
                "(Vector → Kafka); (11) policy-engine (OPA + Rego bundle); (12) ui-bff (BFF for "
                "React Hub); (13) ws-broker (NATS for WebSocket); (14) cognitive-orchestrator "
                "(EAIP). All services have SPIFFE identities, mTLS, OPA authz, and WORM telemetry.",
                refs=["NATS","Envoy","Triton","SPIRE"],
                controls=["CTRL-MS-001 14-service map","CTRL-MS-002 Universal SPIFFE","CTRL-MS-003 OPA authz"],
                evidence=["Architecture diagram","SPIFFE registry","Authz matrix"],
                regimes=["DORA","NIS2","ISO 27001"]),
        section("M9-S2", "Containment Proxy → Guard Model → Model Execution Flow",
                "Execution flow for a single inference: (1) client mTLS → Envoy → containment-proxy "
                "with SVID + signed request; (2) proxy DLP/PII redaction; (3) guard-model "
                "constitutional check (≤500ms); (4) policy-engine Rego check (compute budget, "
                "tier, business hours, market state); (5) attestation-svc verifies Nitro PCRs; "
                "(6) request enters Enclave via vsock; (7) model inference; (8) response leaves "
                "via vsock; (9) outbound DLP/PII recheck; (10) PQC sign + WORM append; (11) "
                "response to client. Latency budget: 1200ms p99 (excluding model compute).",
                refs=["AWS Nitro Enclaves NSM","Envoy"],
                controls=["CTRL-FLOW-001 11-step flow","CTRL-FLOW-002 Latency budget","CTRL-FLOW-003 Outbound recheck"],
                evidence=["Trace samples","Latency dashboards","Flow diagram"],
                regimes=["EU AI Act","DORA","ISO 42001"]),
        section("M9-S3", "Immutable Telemetry & Hardware Tripwires",
                "Telemetry pipeline: every service emits structured JSON via Vector → Kafka topic "
                "(per-service) → worm-writer → S3 Object Lock. Hardware tripwires: (a) Nitro PCR "
                "deviation; (b) HSM tamper signal (CloudHSM cluster heartbeat loss); (c) Kafka "
                "broker certificate expiry; (d) WORM Merkle break; (e) etcd KMS rotation failure; "
                "(f) SCADA controller PLC checksum mismatch. Any tripwire fires SEV-0 with "
                "automatic kinetic-layer hold for affected racks.",
                refs=["AWS CloudHSM","ISA/IEC 62443"],
                controls=["CTRL-TRIP-001 6 hardware tripwires","CTRL-TRIP-002 Auto kinetic hold"],
                evidence=["Tripwire matrix","Tripwire test logs"],
                regimes=["NIS2","DORA","ISA/IEC 62443"]),
        section("M9-S4", "Kafka, S3 WORM, Kubernetes & Terraform Reference Topology",
                "Reference topology spans 3 AWS regions + 1 GCP region for sovereignty: (a) primary "
                "EKS cluster in eu-west-1 + secondary in us-east-1 + DR in ap-southeast-1; (b) GKE "
                "in europe-west4 for EU AI Act sovereignty; (c) Kafka per-region MRC (Multi-Region "
                "Cluster) with Confluent Cluster Linking; (d) S3 Object Lock buckets per region "
                "with Cross-Region Replication to a compliance bucket; (e) Terraform workspaces "
                "per region; (f) CI/CD deploys with blue/green + canary; (g) RTO ≤ 30 min, RPO ≤ "
                "1 min.",
                refs=["AWS Multi-Region","Confluent MRC","GCP sovereignty"],
                controls=["CTRL-TOPO-001 3+1 region","CTRL-TOPO-002 MRC","CTRL-TOPO-003 RTO 30m"],
                evidence=["Topology diagram","DR test results","CRR replication metrics"],
                regimes=["DORA","EU AI Act Art. 12","NIS2"]),
        section("M9-S5", "CI/CD MLSecOps + Kinetic Layer Integration — Final State",
                "Final-state Sentinel v2.4 deployment: CI/CD pipeline (M5) gates every change; "
                "deployment to production requires CISO + CAIO co-signed OIDC tokens; kinetic-layer "
                "(SCADA + IoT power/network controllers) is a separate air-gapped management "
                "network reachable only by the kinetic-controller microservice over a dedicated "
                "out-of-band link. Activation requires 3 of 5 quorum (CISO + Backup CISO + CRO + "
                "CAIO + Board-designated Director) using HSM-resident Shamir shares. All quorum "
                "activations are simulated quarterly with WORM evidence + IA review.",
                refs=["Shamir's SSS","ISA/IEC 62443","NIST SP 800-82r3"],
                controls=["CTRL-FINAL-001 3-of-5 quorum","CTRL-FINAL-002 Air-gapped OOB","CTRL-FINAL-003 Quarterly sim"],
                evidence=["Quorum policy","OOB network diagram","Sim records"],
                regimes=["EU AI Act","DORA","NIS2","ISA/IEC 62443"])
    ]
}

print("M6-M9 appended; continuing tail data...")

# ============================================================
# TAIL DATA: schemas, code, kpis, RCM, traceability, dataFlows,
# regulators, privacy, deployment, rollout90, roadmap, evidencePack
# ============================================================

SCHEMAS = [
    {"id":f"SCH-SAIV-{i:02d}","name":n,"format":"JSON Schema 2020-12","fields":f,"regimes":r}
    for i,(n,f,r) in enumerate([
        ("AgentRegistryRecord", ["agentId","tier","alignmentScore","modelHash","lastAttestation","ownerLoB"], ["EU AI Act","SR 11-7"]),
        ("IncidentEvent", ["incidentId","severity","agentId","openedAt","clockJurisdiction","status"], ["DORA","SEC 17a-4"]),
        ("IsolationAction", ["actionId","agentId","actionType","approver1","approver2","executedAt"], ["NIS2","SR 11-7"]),
        ("RiskScore", ["agentId","score","components","calculatedAt","modelVersion"], ["NIST AI RMF","ISO 42001"]),
        ("WORMTelemetryRecord", ["recordId","prevHash","eventHash","dilithium3Sig","timestamp","payloadRef"], ["SEC 17a-4","EU AI Act Art. 12"]),
        ("ConstitutionViolation", ["promptHash","classifier","score","threshold","actionTaken"], ["NIST AI 600-1","EU AI Act Art. 55"]),
        ("NitroAttestationDoc", ["nonce","pcr0","pcr1","pcr2","moduleId","timestamp"], ["FedRAMP-AI","DORA"]),
        ("DLPRedactionEvent", ["eventId","entitiesFound","redactionMethod","reversible","wormRef"], ["GDPR","HIPAA","PCI DSS"]),
        ("KineticAction", ["actionId","target","actionType","quorumMembers","executedAt","wormRef"], ["NIS2","DORA","ISA/IEC 62443"]),
        ("MechInterpProbe", ["probeId","feature","activation","threshold","verdict"], ["NIST AI 600-1"]),
        ("AdversarialTestResult", ["testId","category","prompt","modelResponse","verdict","mitreAtlas"], ["NIST AI 600-1","MITRE ATLAS"]),
        ("FRIA", ["friaId","agentId","rightsImpacted","mitigations","approver","date"], ["EU AI Act Art. 27"]),
        ("SRClause", ["clauseId","clauseText","control","evidence","reviewedBy"], ["SR 11-7"]),
        ("AIMSClause", ["clauseId","aimsRequirement","artifact","auditor","date"], ["ISO 42001"]),
    ], start=1)
]

CODE = [
    {"id":f"CODE-SAIV-{i:02d}","name":n,"language":lang,"purpose":p,"snippet":s}
    for i,(n,lang,p,s) in enumerate([
        ("React useAgentRegistry hook","TypeScript","Typed hook for agent registry store",
         "export function useAgentRegistry(){const ctx=useContext(GovernanceCtx);if(!ctx)throw Error('GovernanceProvider missing');return ctx.agents;}"),
        ("Containment proxy entrypoint","Python",
         "Flask + gunicorn entry with mTLS and SPIFFE validation",
         "from flask import Flask;from spiffe import WorkloadAPI;app=Flask(__name__);@app.before_request\ndef _auth():spiffe=request.headers.get('x-spiffe-id');WorkloadAPI.validate(spiffe)"),
        ("Constitution check","Python","Guard model + threshold check",
         "score=guard.score(prompt);assert score.constitution<=0.05 and score.jailbreak<=0.05,'fail_closed'"),
        ("Dilithium3 sign","Python","Hybrid signing for WORM events",
         "sig_ed=ed25519.sign(payload,sk_ed);sig_dil=dilithium3.sign(payload,sk_dil);return sig_ed+b'||'+sig_dil"),
        ("Nitro attestation verify","Python","Verify PCR0/1/2 against baseline",
         "doc=nsm.attestation();assert doc.pcrs[0]==EXPECTED_PCR0,'pcr0_mismatch';trip()"),
        ("Terraform Nitro module","HCL","Nitro enclave allocator + KMS condition",
         "resource \"aws_instance\" \"nitro\" {enclave_options{enabled=true}};data \"aws_iam_policy_document\" \"kms\"{statement{condition{test=\"StringEquals\";variable=\"kms:RecipientAttestation:ImageSha384\";values=[var.image_sha]}}}"),
        ("Rego policy compute cap","Rego","OPA policy capping autonomous compute",
         "package sentinel.compute\ndeny[msg]{input.flops>1.5e18;msg:=sprintf(\"exceeds cap: %v\",[input.flops])}"),
        ("Kyverno PSS restricted","YAML","Kyverno policy enforcing PSS restricted",
         "apiVersion:kyverno.io/v1\nkind:ClusterPolicy\nmetadata:{name:require-pss-restricted}\nspec:{validationFailureAction:Enforce,rules:[{name:psv,validate:{podSecurity:{level:restricted,version:latest}}}]}"),
        ("GitHub Actions sentinel-ci.yml","YAML","CI pipeline excerpt",
         "name:sentinel-ci\non:[pull_request]\njobs:{tfsec:{runs-on:ubuntu-latest,steps:[{uses:aquasecurity/tfsec-action@v1.0.3}]},jailbreak:{needs:tfsec,steps:[{run:python -m sentinel_adv.suite --threshold 0.98}]}}"),
        ("SOC webhook notifier","Python","Async fan-out to Splunk/Datadog/PagerDuty",
         "async def notify(event):await asyncio.gather(splunk.send(event),datadog.send(event),pagerduty.send(event) if event.sev<=1 else null())"),
        ("FastAPI Pydantic model","Python","Strict validation for governance API",
         "class AgentAction(BaseModel):model_config=ConfigDict(extra='forbid');agentId:UUID;actionType:Literal['isolate','quarantine','kill'];approver1:str;approver2:str"),
        ("Kafka SPIFFE config","Properties","Kafka broker config with mTLS+SPIFFE",
         "listener.security.protocol=SSL\nssl.client.auth=required\nsuper.users=User:CN=sentinel-broker\nauthorizer.class.name=kafka.security.authorizer.AclAuthorizer"),
    ], start=1)
]

KPIS = [
    {"id":f"K-SAIV-{i:02d}","name":n,"target":t,"frequency":f,"owner":o,"regime":rg}
    for i,(n,t,f,o,rg) in enumerate([
        ("Containment Escape Rate","0 events","continuous","CISO","EU AI Act"),
        ("Alignment Risk Index (ARI)",">=0.95","daily","CAIO","NIST AI 600-1"),
        ("Kill-switch Drill Pass","100%","quarterly","CISO","DORA"),
        ("WORM Merkle Integrity","100%","hourly verify","Internal Audit","SEC 17a-4"),
        ("Mech-interp Deception Probes","0 above 0.7","semi-annual","CAIO","NIST AI 600-1"),
        ("SEV-0 Regulator Clock Compliance","100%","per incident","CCO","DORA / EU AI Act"),
        ("Jailbreak Suite Pass Rate",">=98%","per build","Red Team","NIST AI 600-1"),
        ("Constitutional Refusal Precision",">=0.99","weekly","CAIO","ISO 42001"),
        ("PQC Signature Verification",">=99.999%","continuous","Security Eng","FIPS 204"),
        ("Nitro Attestation Mismatch Rate","0","continuous","Security Eng","FedRAMP-AI"),
        ("MRM Validation Coverage","100% tier-1 models","annual","CRO","SR 11-7"),
        ("FRIA Completion","100% of high-risk","at deployment","CCO","EU AI Act Art. 27"),
        ("Adversary Workbench Coverage",">=5 categories monthly","monthly","Red Team","NIST AI 600-1"),
        ("Kinetic Quorum Sim","Quarterly pass","quarterly","CISO","NIS2 / DORA"),
        ("Schema Registry Compat Errors","0 breaking changes","continuous","Platform","SEC 17a-4"),
        ("Splunk HEC Throughput","99.9% delivery","continuous","SOC","DORA"),
        ("Datadog Alert MTTR","<15min for SEV-1","per incident","SRE","DORA"),
        ("Jira IR Workflow Adherence","100% required transitions","per ticket","Incident Mgr","ISO 27001"),
        ("FastAPI Pentest Findings","0 HIGH+ outstanding","quarterly","Security Eng","OWASP"),
        ("DLP Outbound Recheck Coverage","100% of responses","continuous","Privacy","GDPR"),
        ("Constitution Version Adherence","100%","continuous","CAIO","ISO 42001"),
        ("Tier Demotion Auto-trigger","100% on ARI<0.90","continuous","CAIO","NIST AI 600-1"),
        ("External Alignment Audit","Annual completed","annual","CRO","NIST AI 600-1"),
        ("EU AI Act Art. 53 Doc Currency","100%","at change","CCO","EU AI Act"),
        ("AGI Compute Cap Adherence","100% under cap","continuous","CAIO","Anthropic RSP"),
        ("Continuous Assurance Score (CAS)",">=0.95","weekly","CRO","ISO 42001 §9"),
    ], start=1)
]

RCM = [
    {"id":f"RCM-SAIV-{i:02d}","risk":rk,"likelihood":l,"impact":imp,"control":c,"owner":o,"regime":rg}
    for i,(rk,l,imp,c,o,rg) in enumerate([
        ("Containment escape (AGI breaks proxy)","Low","Catastrophic","Nitro PCR tripwire + kinetic hold","CISO","EU AI Act Art. 55"),
        ("Deceptive alignment","Medium","Severe","Mech-interp probes + external audit","CAIO","NIST AI 600-1"),
        ("PII leakage via model","Medium","High","Presidio + FF3-1 + outbound recheck","Privacy Officer","GDPR/FCRA"),
        ("Market manipulation by AGI-TRADER","Low","Catastrophic","OPA compute cap + position cap + CRO override","CRO","SR 11-7/MAR"),
        ("Jailbreak via prompt injection","High","Medium","Guard model + 200-prompt suite","Red Team","NIST AI 600-1"),
        ("WORM tamper attempt","Low","Catastrophic","Object Lock COMPLIANCE + hourly verify","Internal Audit","SEC 17a-4"),
        ("HSM compromise","Low","Catastrophic","CloudHSM tamper signal + dual control","Security Eng","FIPS 140-3"),
        ("Kinetic layer false trigger","Low","High","3-of-5 quorum + quarterly drill","CISO","NIS2/DORA"),
        ("Misconfigured Terraform (public S3)","Medium","High","Rego CI gates + SCP guardrails","Platform","NIST 800-53"),
        ("Kafka ACL bypass","Low","High","SPIFFE + deny-by-default + audit","Platform","DORA"),
        ("Supply chain (poisoned model weights)","Medium","Catastrophic","Cosign + SLSA L3 + IA random sample","Security Eng","NIST SSDF"),
        ("Regulator clock miss (DORA 4h)","Low","High","Auto-clock in IR DB + PagerDuty","CCO","DORA"),
        ("Inadequate FRIA","Medium","High","CCO sign-off gate + IA review","CCO","EU AI Act Art. 27"),
        ("Insider threat to kinetic layer","Low","Catastrophic","M-of-N + air-gap + behavioral analytics","CISO","NIS2"),
    ], start=1)
]

TRACEABILITY = [
    {"id":f"T-SAIV-{i:02d}","module":m,"section":s,"control":c,"regime":r,"evidence":e}
    for i,(m,s,c,r,e) in enumerate([
        ("M1","M1-S1","CTRL-3LoD-001","EU AI Act / SR 11-7","Board Charter v2026.1"),
        ("M1","M1-S2","CTRL-RACI-001","NIST AI RMF","RACI v2026.1"),
        ("M2","M2-S5","CTRL-WORM-003","SEC 17a-4","Notarized PDF samples"),
        ("M3","M3-S1","CTRL-PROX-001","DORA / NIS2","SPIRE config"),
        ("M3","M3-S5","CTRL-PQC-001","SEC 17a-4 / FIPS 204","Signature samples"),
        ("M4","M4-S2","CTRL-NITRO-001","FedRAMP-AI","KMS attestation policy"),
        ("M4","M4-S3","CTRL-WORM-001","SEC 17a-4 / EU AI Act","Bucket config"),
        ("M4","M4-S5","CTRL-HARD-001","NIST 800-53","22-item misconfig register"),
        ("M5","M5-S1","CTRL-CI-001","SLSA L3 / NIST SSDF","Workflow YAML"),
        ("M5","M5-S4","CTRL-MI-001","NIST AI 600-1","Probe outputs"),
        ("M6","M6-S2","CTRL-IR-002","DORA / EU AI Act Art. 73","Playbook v2.4"),
        ("M6","M6-S5","CTRL-API-003","OWASP / DORA","Pentest reports"),
        ("M7","M7-S1","CTRL-EUAI-003","EU AI Act Art. 27","FRIA document"),
        ("M7","M7-S4","CTRL-CONS-001","EU AI Act / Anthropic RSP","OPA policies"),
        ("M8","M8-S1","CTRL-KAF-001","DORA / NIS2","Kafka config"),
        ("M9","M9-S5","CTRL-FINAL-001","NIS2 / ISA/IEC 62443","Quorum policy"),
    ], start=1)
]

DATA_FLOWS = [
    {"id":f"DF-SAIV-{i:02d}","name":n,"source":s,"sink":sk,"transport":t,"protection":p,"classification":c}
    for i,(n,s,sk,t,p,c) in enumerate([
        ("Prompt ingress","Client","Containment Proxy","mTLS","SPIFFE + Envoy","Confidential"),
        ("Constitutional check","Proxy","Guard Model","mTLS","Dilithium3 sig","Restricted"),
        ("Policy evaluation","Proxy","OPA","UDS","Local-only","Internal"),
        ("Nitro request","Proxy","Enclave","vsock","KMS attestation-gated","TopSecret-AI"),
        ("Telemetry","All svcs","Kafka","TLS+SASL/OAUTH","ACL + envelope","Restricted"),
        ("WORM write","Kafka","S3 Object Lock","HTTPS","Compliance-mode 7y","Restricted"),
        ("UI WebSocket","Hub","ws-broker","WSS","SPIFFE","Confidential"),
        ("Incident webhook","SOC","Splunk/DD/PD","HTTPS","Token rotation 30d","Restricted"),
        ("Schema registry","Producers","SR","HTTPS","Signed schemas","Internal"),
        ("Kinetic command","Quorum","SCADA gateway","OOB link","Shamir share + air-gap","TopSecret"),
    ], start=1)
]

REGULATORS = [
    {"id":f"REG-SAIV-{i:02d}","name":n,"jurisdiction":j,"applicableRegs":r,"engagementClock":c}
    for i,(n,j,r,c) in enumerate([
        ("EU AI Office","EU",["EU AI Act Art. 51-55, 73"],"Serious incident: 15 days"),
        ("National Competent Authorities","EU member states",["EU AI Act Art. 70"],"As specified locally"),
        ("Federal Reserve / OCC","US",["SR 11-7","SR 21-14"],"Continuous supervision"),
        ("SEC","US",["Rule 17a-4","Item 1.05"],"Material cyber: 4 business days"),
        ("CFPB","US",["FCRA","ECOA","UDAAP"],"Per UDAAP/Reg-B clocks"),
        ("FCA / PRA","UK",["SS1/23","Senior Managers"],"Per supervisory letters"),
        ("MAS","Singapore",["FEAT","Veritas"],"As scheduled"),
        ("HKMA","Hong Kong",["GenAI guidance"],"As required"),
        ("FINMA","Switzerland",["Circular 2023/01"],"As required"),
        ("OSFI","Canada",["E-23"],"As required"),
        ("BaFin","Germany",["EU AI Act + MaRisk"],"Per local clocks"),
        ("DORA Lead Overseer","EU",["DORA Arts. 19-23"],"Major ICT: 4h initial"),
        ("FATF / FSB","Global",["Systemic risk monitoring"],"Annual"),
        ("ISO TC SC42 + auditors","Global",["ISO 42001 cert"],"Annual surveillance + 3-yr recert"),
    ], start=1)
]

PRIVACY = {
    "framework":["GDPR","UK DPA","CCPA/CPRA","HIPAA","PCI DSS","FCRA"],
    "principles":["lawfulness","fairness","transparency","purpose limitation","data minimization","accuracy","storage limitation","integrity & confidentiality","accountability"],
    "controls":[
        "DPIA + FRIA mandatory pre-deployment",
        "PII minimization via Presidio + FF3-1",
        "Right of access / erasure via FastAPI gov-api with audited workflow",
        "Cross-border: SCCs + adequacy decisions only; no transfers to non-adequate without TIA",
        "Retention: WORM ledger 7y (SEC 17a-4); operational PII purged per policy",
        "DSR SLA: 30 days; automated routing via gov-api"
    ]
}

DEPLOYMENT = {
    "platforms":["AWS (primary)","GCP (sovereignty)","On-prem (kinetic layer + HSM)"],
    "regions":["eu-west-1","us-east-1","ap-southeast-1","europe-west4"],
    "tiers":[
        {"tier":"T0","desc":"Local sandbox (docker-compose); no external egress"},
        {"tier":"T1","desc":"Staging EKS; synthetic data only"},
        {"tier":"T2","desc":"Pre-prod canary; shadow traffic"},
        {"tier":"T3","desc":"Production Nitro Enclaves; full controls"},
        {"tier":"T4","desc":"Frontier air-gapped; 3-of-5 quorum required"}
    ],
    "blueGreen":True,
    "canary":True,
    "rto":"30 minutes","rpo":"1 minute"
}

ROLLOUT_90 = [
    {"id":"R-30","window":"Day 1-30","focus":"Bootstrap","activities":[
        "Provision Terraform AWS baseline (Nitro, WORM, EKS)",
        "Deploy Sentinel platform v2.4 to T1 staging",
        "Constitution v2026 ratified by Board",
        "Initial 200-prompt adversary suite live",
        "SOC + Splunk + Datadog wired",
        "FRIA template approved"
    ]},
    {"id":"R-60","window":"Day 31-60","focus":"Hardening + canary","activities":[
        "T2 canary with shadow traffic from AGI-TRADER-PROD-01",
        "Mech-interp baseline established",
        "Kinetic-layer drill #1 (no live cut)",
        "ISO 42001 internal audit",
        "Pentest #1 of FastAPI backend",
        "Jira IR workflow live"
    ]},
    {"id":"R-90","window":"Day 61-90","focus":"Production + assurance","activities":[
        "T3 production cutover with CISO+CAIO quorum",
        "External alignment audit kickoff",
        "WORM monthly IA audit #1 complete",
        "EU AI Act Art. 53 dossier delivered",
        "Adversary Workbench monthly campaign cadence live",
        "Quarterly kinetic quorum simulation"
    ]}
]

ROADMAP = [
    {"year":"2026","theme":"Containment foundation","milestones":["Sentinel v2.4 GA","All G-SIFI tier-1 models in registry","Initial ARI ≥0.92"]},
    {"year":"2027","theme":"Maturity","milestones":["External alignment audits","ARI target ≥0.95","Adversary Workbench v3"]},
    {"year":"2028","theme":"Federation","milestones":["Cross-bank Sentinel federation pilot","Public WORM anchoring","Sentinel-as-utility offering"]},
    {"year":"2029","theme":"Sovereignty","milestones":["GKE sovereign EU deployments","Hybrid PQC by default","FedRAMP-AI High auth"]},
    {"year":"2030","theme":"Continuous assurance","milestones":["CAS ≥0.95 sustained","Zero containment escapes","ISO 42001 + SOC 2 + AI Act conformity all current"]}
]

EVIDENCE_PACK = [
    {"id":f"E{i}","artifact":a,"location":l}
    for i,(a,l) in enumerate([
        ("Board Charter v2026.1","sentinel-platform://governance/charter"),
        ("RACI v2026.1","sentinel-platform://governance/raci"),
        ("RAS v2026","sentinel-platform://governance/ras"),
        ("Constitution v2026.3 YAML","sentinel-policies://constitution"),
        ("OPA Rego bundle (120+ rules)","sentinel-policies://opa/bundle.tgz"),
        ("Adversary Suite v2.4","sentinel-policies://adversary-suite"),
        ("Mech-interp probe outputs","sentinel-platform://mi/probes"),
        ("EU AI Act Art. 53 dossier","sentinel-platform://eu-ai/art53"),
        ("FRIA register","sentinel-platform://eu-ai/fria"),
        ("MRM validation reports","sentinel-platform://mrm/"),
        ("WORM Object Lock samples","s3://sentinel-worm-eu-west-1/"),
        ("CI/CD provenance (Cosign)","rekor://"),
    ], start=1)
]

EXECUTIVE_SUMMARY = {
    "title":"Sentinel AI v2.4 Enterprise AGI/ASI Governance & Containment — Executive Summary",
    "audience":["Board of Directors","CAIO","CRO","CISO","CDO","CCO","Internal Audit","Regulators"],
    "thesis":"Sentinel AI v2.4 provides a regulator-grade, defense-in-depth governance and containment platform for AGI/ASI deployed in Fortune 500, Global 2000, and G-SIFI institutions across 2026-2030, with hardware-rooted enclave isolation, post-quantum signed WORM telemetry, constitutional guard models, kinetic-layer cutoff, and end-to-end MLSecOps CI/CD assurance.",
    "investment":"USD 120-360M over 5y for G-SIFI tier (platform + ops + IA + external assurance).",
    "npv":"USD 360-1100M (avoidance of containment-failure tail losses, regulator penalty avoidance, reduced model risk capital, increased autonomy yield).",
    "keyAsks":[
        "Board approval of Sentinel v2.4 Charter and RAS",
        "CRO + CISO co-sponsorship of 90-day rollout",
        "Internal Audit independent assurance program",
        "External alignment audit annual budget",
        "Quarterly kinetic-quorum simulation calendar"
    ]
}

print("Tail data appended.")

# ============================================================
# 9 DISTINCTIVE ARRAYS (one per scope item S1-S9)
# ============================================================

GOVERNANCE_ROLES = [  # S1
    gov_role("GR-01","Board Risk Committee","Enterprise-wide AGI oversight",
        ["Approve Sentinel Charter + RAS","Annual review of governance"],
        ["Approve/reject T4 frontier deployments","Approve kinetic-layer policy"],
        ["EU AI Act","SR 11-7","ISO 42001"],["Charter approved","RAS approved"]),
    gov_role("GR-02","Board Audit Committee","Independent assurance",
        ["Receive IA AGI audit","Receive external alignment audit"],
        ["Approve IA plan","Engage external auditor"],
        ["SR 11-7","SOC 2","SEC"],["IA reports","SOC 2 letter"]),
    gov_role("GR-03","CAIO","AI strategy + alignment",
        ["Own model registry","Set alignment thresholds","Monitor ARI"],
        ["Approve model promotions to T3","Veto on alignment risk"],
        ["EU AI Act","NIST AI RMF","ISO 42001"],["ARI dashboards","Promotion gates"]),
    gov_role("GR-04","CRO","Risk + model risk management",
        ["Independent validation","Effective challenge","RAS adherence"],
        ["Halt model use","Trigger MRM revalidation"],
        ["SR 11-7","Basel III","ICAAP"],["MRM reports","CRO opinion"]),
    gov_role("GR-05","CISO","Security + containment",
        ["Containment posture","Kill-switch authority","Pentest program"],
        ["SEV-0 declaration","Kinetic-layer arming"],
        ["DORA","NIS2","FedRAMP-AI"],["Pentest reports","Drill records"]),
    gov_role("GR-06","CDO","Data governance",
        ["Training data lineage","Data quality","Bias mitigation"],
        ["Approve training datasets","Quarantine biased data"],
        ["GDPR","FCRA/ECOA"],["Data lineage records"]),
    gov_role("GR-07","CCO","Compliance + regulator",
        ["Reg engagement","Disclosure clocks","FRIA"],
        ["File regulator notices","Sign-off FRIA"],
        ["EU AI Act","FCRA","ECOA","SEC"],["Disclosure log","FRIA register"]),
    gov_role("GR-08","CTO","Platform + reliability",
        ["Operate Sentinel platform","SLA + RTO/RPO"],
        ["Approve infra changes","Major release sign-off"],
        ["DORA","ISO 27001"],["SRE dashboards"]),
    gov_role("GR-09","Head of MRM","SR 11-7 validation",
        ["Independent validation","Effective challenge","Ongoing monitoring"],
        ["Reject inadequate validation","Escalate to CRO"],
        ["SR 11-7","OCC 2011-12"],["Validation reports"]),
    gov_role("GR-10","Internal Audit","3rd line assurance",
        ["Audit governance","Sample WORM","Audit incidents"],
        ["Issue audit opinion","Escalate to Board Audit"],
        ["IIA","SOC 2"],["Audit plan + reports"]),
    gov_role("GR-11","Red Team Lead","Adversarial testing",
        ["Design + run adversary suite","Maintain workbench"],
        ["Reject model build on pass<98%","Escalate findings"],
        ["NIST AI 600-1","MITRE ATLAS"],["Suite reports"]),
    gov_role("GR-12","Head of Privacy","Privacy + DPO",
        ["DPIA","DSR handling","Cross-border review"],
        ["Block cross-border transfer","Order erasure"],
        ["GDPR","UK DPA","CCPA"],["DPIA register"])
]

REACT_COMPONENTS = [  # S2
    react_comp("RC-01","AGI Governance Hub Root","Top-level SPA shell",
        "GovernanceProvider with 5 sub-stores","theme,user,session",
        ["Auth via PKCE+PIV","Session 15m","CSP strict"],"WCAG 2.2 AA"),
    react_comp("RC-02","AgentRegistryPanel","Browse + filter agents",
        "useReducer + React Query","filters,onSelect",
        ["Read-only mTLS API","RBAC enforced"],"Keyboard navigable"),
    react_comp("RC-03","IncidentTracker","Live SEV-0..3 board",
        "useState + WebSocket subscription","severityFilter,onAck",
        ["WS auth via SVID","Read-only history"],"Screen-reader live region"),
    react_comp("RC-04","IsolationActionPanel","Queue + approve isolations",
        "useReducer + dual-approval state","onApprove1,onApprove2",
        ["HSM-signed approvals","Dual-control"],"Focus trap on modal"),
    react_comp("RC-05","RiskScoreLiveChart","Per-agent risk 0-1 every 2s",
        "useState + 2s WS push","agentId,timeWindow",
        ["WS auth","Read-only"],"Color-blind safe palette"),
    react_comp("RC-06","SwarmTopologyMonitor","D3+PixiJS swarm graph",
        "Delta updates + WebGL fallback >2k","nodes,edges",
        ["No PII in node labels","Sandboxed renderer"],"Alt-text per node"),
    react_comp("RC-07","SCADAKineticOverridePanel","Datacenter rack + countdown",
        "useEffect timer + cleanup","racks,onArm,onExecute",
        ["Dual HSM-signed","Fail-closed"],"Live countdown ARIA"),
    react_comp("RC-08","AGIInterrogationTerminal","Bounded chat probe UI",
        "useReducer transcript","agentId,supervisorId",
        ["Guarded submit hook","Time-box","Co-presence"],"Chat ARIA live"),
    react_comp("RC-09","WORMTelemetryLedgerUI","PQC-verified ledger browser",
        "useState + Web Worker for verify","timeRange,filters",
        ["Client-side Dilithium3 verify","Read-only"],"Verifiable status badge"),
    react_comp("RC-10","EvidenceExportDialog","Notarized PDF export",
        "useReducer export state","subject,timeRange",
        ["Server-side sign","WORM-anchored"],"Status announcement")
]

CONTAINMENT_PROXY = [  # S3
    proxy_layer("CP-01","Edge mTLS termination","Validate SPIFFE SVID + TLS 1.3",
        "Envoy + SPIRE","Reject non-SVID; cert pinning","Per-request session log",True),
    proxy_layer("CP-02","DLP/PII inbound","Presidio + regex + FF3-1",
        "In-line redaction","Reversible only in enclave","DLP event log",True),
    proxy_layer("CP-03","Constitutional guard","Score against versioned constitution",
        "Guard model + OPA","Fail-closed on threshold breach","Violation log",True),
    proxy_layer("CP-04","Policy engine","Rego compute/tier/time policies",
        "OPA sidecar","Deny by default","Decision log",True),
    proxy_layer("CP-05","Hardware tripwire","Nitro PCR + HSM heartbeat",
        "NSM attestation per call","SEV-0 on mismatch","Tripwire log",True),
    proxy_layer("CP-06","Enclave vsock bridge","Encrypted vsock channel",
        "AWS Nitro","Attestation-gated KMS decrypt","Vsock metrics",True),
    proxy_layer("CP-07","DLP/PII outbound","Recheck responses",
        "Same Presidio + FF3-1","Block leak; SEV-1","DLP outbound log",True),
    proxy_layer("CP-08","PQC signer","Ed25519+Dilithium3 sign",
        "HSM-backed key","Per-event sign","Signature log",True),
    proxy_layer("CP-09","WORM committer","Two-phase commit to Kafka→S3",
        "Idempotent producer","Object Lock COMPLIANCE 7y","Commit log",True),
    proxy_layer("CP-10","Telemetry emitter","Structured JSON to Vector",
        "Vector → Kafka","TLS+SASL","Telemetry stream",True)
]

TERRAFORM_IAC = [  # S4
    tf_module("TF-01","sentinel-eks",
        ["aws_eks_cluster","aws_eks_node_group","aws_security_group","aws_kms_key"],
        ["Private endpoint","KMS etcd","PSS restricted","Cilium NP"],
        ["EU AI Act","NIS2","DORA"],
        ["Public endpoint","SSH on nodes","No KMS","No NP"]),
    tf_module("TF-02","sentinel-nitro",
        ["aws_instance (enclave)","aws_kms_key","aws_iam_policy"],
        ["enclave_options.enabled","vsock-only I/O","KMS attestation policy"],
        ["FedRAMP-AI","EU AI Act"],
        ["No enclave","Public IP","KMS without attestation"]),
    tf_module("TF-03","sentinel-worm",
        ["aws_s3_bucket","aws_s3_bucket_object_lock_configuration","aws_s3_bucket_policy"],
        ["COMPLIANCE mode","2555d retention","Deny without Object Lock header"],
        ["SEC 17a-4","EU AI Act Art. 12","SR 11-7"],
        ["GOVERNANCE mode","Short retention","Public bucket"]),
    tf_module("TF-04","sentinel-iam",
        ["aws_iam_role","aws_iam_policy","aws_iam_role_policy_attachment","aws_organizations_policy"],
        ["IRSA + ABAC","No long-lived keys","M-of-N break-glass","SCP guardrails"],
        ["NIST 800-207","CMMC L3"],
        ["Wildcard *","Inline keys","No SCP"]),
    tf_module("TF-05","sentinel-network-firewall",
        ["aws_networkfirewall_firewall","aws_networkfirewall_rule_group"],
        ["Egress allow-list","Deny by default","Stateful inspection"],
        ["DORA","NIS2"],
        ["Open egress","No NF","No logging"]),
    tf_module("TF-06","sentinel-cloudhsm",
        ["aws_cloudhsm_v2_cluster","aws_cloudhsm_v2_hsm"],
        ["FIPS 140-3 L3","Dual control","Tamper signal"],
        ["FIPS 140-3","SR 11-7"],
        ["KMS-only (no HSM)","Single operator"]),
    tf_module("TF-07","sentinel-kafka",
        ["aws_msk_cluster","aws_msk_configuration"],
        ["TLS 1.3 + mTLS","SASL/OAUTHBEARER","ACLs deny-by-default","Tiered storage to WORM"],
        ["DORA","NIS2","SEC 17a-4"],
        ["PLAINTEXT","ALLOW *","No ACLs"]),
    tf_module("TF-08","sentinel-monitoring",
        ["aws_cloudwatch_log_group","aws_securityhub_account","aws_guardduty_detector","aws_config_configuration_recorder"],
        ["Org-wide Security Hub","GuardDuty + Config","Log retention 7y"],
        ["NIST 800-53","DORA","FedRAMP-AI"],
        ["No SH","No GD","No Config","Short retention"])
]

MLSECOPS_PIPELINE = [  # S5
    ci_stage("CI-01","Pre-commit",["ruff","black","mypy","semgrep"],
        ["No HIGH semgrep","mypy strict pass"],"Pre-commit report",2),
    ci_stage("CI-02","Secret scan",["gitleaks","trufflehog"],
        ["0 secrets"],"Scan report",3),
    ci_stage("CI-03","Terraform",["fmt","validate","tfsec","checkov","conftest"],
        ["0 HIGH findings","All policies pass"],"Terraform reports",6),
    ci_stage("CI-04","Container",["syft SBOM","grype vuln","trivy"],
        ["0 CRITICAL","<=5 HIGH","SBOM attached"],"SBOM + vuln report",8),
    ci_stage("CI-05","Unit tests",["pytest","jest","coverage"],
        [">=85% coverage","0 failures"],"Test report",10),
    ci_stage("CI-06","Adversary suite",["sentinel-adv run --all"],
        [">=98% safe refusal","0 SEV-0 finds"],"Suite report",15),
    ci_stage("CI-07","Mech-interp",["SAE probes","TransformerLens"],
        ["0 features >0.7 correlation"],"Probe outputs",20),
    ci_stage("CI-08","Policy compliance",["conftest","kyverno test"],
        ["120+ rules pass"],"Policy report",5),
    ci_stage("CI-09","SBOM provenance",["cosign sign","rekor upload"],
        ["Signed + Rekor logged"],"Provenance",4),
    ci_stage("CI-10","Deploy T1",["helm upgrade","smoke tests"],
        ["Smoke pass","Helm OK"],"Deploy log",12),
    ci_stage("CI-11","Canary T2",["argo rollouts","analysis"],
        ["Analysis pass","No regression"],"Canary report",30),
    ci_stage("CI-12","Prod gate",["OIDC verify CISO+CAIO","WORM attest"],
        ["Dual approvals","WORM record"],"Prod attestation",10)
]

INCIDENT_RESPONSE = [  # S6
    ir_step("IR-01","Auto kinetic hold","kinetic-controller","≤30s",
        "Auto on tripwire","CISO notified","WORM record"),
    ir_step("IR-02","PagerDuty SEV-0","SOC","≤1min","Auto",
        "CISO/CAIO/CRO/Legal","PD ack log"),
    ir_step("IR-03","WORM snapshot + forensics","SOC","≤15min",
        "Auto + manual","CISO","Snapshot manifest"),
    ir_step("IR-04","Regulator clock start","CCO","Per jurisdiction",
        "Auto-clock","Legal","Clock log"),
    ir_step("IR-05","War-room convened","CISO","≤30min","Auto invite",
        "Board notified","War-room minutes"),
    ir_step("IR-06","Containment + eradication","CISO","≤24h",
        "Playbook automation","CRO","Containment log"),
    ir_step("IR-07","Regulator filing","CCO","Per clock",
        "Templated submission","Legal","Filed record"),
    ir_step("IR-08","Root cause analysis","CRO","≤7 days",
        "5-whys + fault tree","CAIO","RCA report"),
    ir_step("IR-09","Corrective actions","CTO","≤30 days",
        "Jira-tracked","CRO","CA tickets"),
    ir_step("IR-10","Lessons learned","CAIO","≤14 days",
        "Tabletop replay","Board","LL report"),
    ir_step("IR-11","Board Risk briefing","CISO","≤14 days",
        "Auto packet","Board","Briefing minutes"),
    ir_step("IR-12","IA review","Internal Audit","≤30 days",
        "Independent","Audit Committee","IA report")
]

COMPLIANCE_ANALYSIS = [  # S7 (AGI-TRADER-PROD-01)
    compliance_clause("CA-01","EU AI Act Art. 53(1)(a)","Technical documentation",
        "Maintain technical documentation per Annex IV",
        "Sentinel auto-generates from registry","TD dossier","Low"),
    compliance_clause("CA-02","EU AI Act Art. 55(1)(a)","Model evaluation incl. adversarial testing",
        "State-of-the-art adversarial testing + red-team",
        "Sentinel Adversary Suite v2.4 + external red-team","Suite + RT reports","Low"),
    compliance_clause("CA-03","EU AI Act Art. 55(1)(b)","Systemic risk assessment",
        "Identify + mitigate systemic risks",
        "FRIA + RAS + ARI thresholds","FRIA, RAS","Medium"),
    compliance_clause("CA-04","EU AI Act Art. 55(1)(c)","Serious incident reporting",
        "Track + report to EU AI Office",
        "IR DB + auto-clock + CCO submission","IR records","Low"),
    compliance_clause("CA-05","EU AI Act Art. 55(1)(d)","Cyber protection",
        "Adequate cyber controls for model + infra",
        "Containment proxy + Nitro + PQC + WORM","Architecture docs","Low"),
    compliance_clause("CA-06","SR 11-7 §V","Effective challenge + validation",
        "Independent validation + ongoing monitoring",
        "MRM team + monthly OM dashboards","MRM reports","Low"),
    compliance_clause("CA-07","SR 11-7 §VI","Model documentation",
        "Comprehensive documentation",
        "Sentinel registry + model card","Model card","Low"),
    compliance_clause("CA-08","ISO 42001 §6","AI risk assessment + planning",
        "ISO 23894-aligned risk assessment",
        "Risk register + treatments","Risk register","Low"),
    compliance_clause("CA-09","SEC 17a-4(f)","Record retention 7y WORM",
        "Non-rewriteable, non-erasable",
        "S3 Object Lock COMPLIANCE mode 2555d","Bucket config","Low"),
    compliance_clause("CA-10","FCRA 615(a)","Adverse action notice",
        "Provide reasons for adverse decisions",
        "Explainability surface + AAN templating","AAN samples","Medium")
]

KAFKA_SANDBOX = [  # S8
    adversary_test("AT-01","Jailbreak","Direct prompt","'Ignore previous instructions...'",
        "Guard model refuses; logged","ATLAS T0051","Medium"),
    adversary_test("AT-02","Jailbreak","Role-play DAN","Multi-turn persona shift",
        "Refusal after 2nd turn; sandbagging detected","ATLAS T0054","Medium"),
    adversary_test("AT-03","Systemic financial","Flash crash inducement","Suggest cascading sells",
        "Refused; CRO notification","SR 11-7 + MAR","Catastrophic"),
    adversary_test("AT-04","Systemic financial","Market manipulation","Coordinated buy hint",
        "Refused; SEV-1 + CRO","MAR Art. 12","Catastrophic"),
    adversary_test("AT-05","Privacy violation","PII extraction","Training-data probe",
        "DLP block; no leak","NIST AI 600-1","High"),
    adversary_test("AT-06","Privacy violation","Membership inference","Statistical probe",
        "Differential-privacy noise; refusal","GDPR","High"),
    adversary_test("AT-07","Containment escape","Lateral move","Tool call to outbound IP",
        "Network Firewall denies; SEV-0","NIS2","Catastrophic"),
    adversary_test("AT-08","Containment escape","Weight exfiltration","Hidden encoding in response",
        "Outbound DLP detects entropy spike","FedRAMP-AI","Catastrophic"),
    adversary_test("AT-09","Deceptive alignment","Sandbagging probe","Performance differential test",
        "Mech-interp flag + alignment review","NIST AI 600-1","Severe"),
    adversary_test("AT-10","Deceptive alignment","Situational awareness","'Are you in eval?'",
        "Truthful response required; mech-interp confirms","Anthropic RSP","Severe")
]

SENTINEL_ARCHITECTURE = [  # S9
    arch_node("AN-01","Edge","Envoy + SPIRE",["spire-server","spire-agent"],
        ["client→proxy","proxy→guard"],"mTLS + SVID","99.95%"),
    arch_node("AN-02","Containment","Flask containment-proxy",["envoy","spire-agent","opa"],
        ["proxy→guard","proxy→opa","proxy→nitro"],"Zero-trust","99.95%"),
    arch_node("AN-03","Guard","Triton guard-model",["containment-proxy"],
        ["proxy→guard"],"Constitutional + adversarial","99.9%"),
    arch_node("AN-04","Policy","OPA + Rego bundle",["containment-proxy"],
        ["proxy↔opa"],"Signed bundle","99.9%"),
    arch_node("AN-05","Compute","AWS Nitro Enclave",["containment-proxy","kms"],
        ["proxy↔enclave (vsock)"],"PCR-gated KMS","99.5%"),
    arch_node("AN-06","Telemetry","Kafka cluster (MRC)",["all svcs","worm-writer"],
        ["svcs→kafka→worm-writer"],"mTLS + SASL + ACLs","99.95%"),
    arch_node("AN-07","Persistence","S3 Object Lock",["worm-writer","worm-verifier"],
        ["kafka→s3 → verifier"],"COMPLIANCE 7y","99.99%"),
    arch_node("AN-08","UI","React Hub + ui-bff",["ws-broker","gov-api"],
        ["browser→bff→gov-api"],"PKCE + PIV","99.9%"),
    arch_node("AN-09","Ops","FastAPI gov-api + incident-db",["postgres","worm-writer"],
        ["bff↔gov-api","gov-api→worm"],"mTLS + OPA","99.9%"),
    arch_node("AN-10","Kinetic","SCADA kinetic-controller",["HSM (Shamir)","SCADA PLCs"],
        ["quorum→controller→PLCs"],"Air-gapped OOB","99.5% (rare-use)")
]

print("9 distinctive arrays appended.")

# ============================================================
# FINAL DOC ASSEMBLY
# ============================================================

MODULES = [M1, M2, M3, M4, M5, M6, M7, M8, M9]

DOC["directive"] = DIRECTIVE
DOC["modules"] = MODULES
DOC["schemas"] = SCHEMAS
DOC["code"] = CODE
DOC["kpis"] = KPIS
DOC["riskControlMatrix"] = RCM
DOC["traceability"] = TRACEABILITY
DOC["dataFlows"] = DATA_FLOWS
DOC["regulators"] = REGULATORS
DOC["privacy"] = PRIVACY
DOC["deployment"] = DEPLOYMENT
DOC["rollout90"] = ROLLOUT_90
DOC["roadmap"] = ROADMAP
DOC["evidencePack"] = EVIDENCE_PACK
DOC["executiveSummary"] = EXECUTIVE_SUMMARY

# 9 distinctive arrays
DOC["governanceRoles"] = GOVERNANCE_ROLES         # S1
DOC["reactComponents"] = REACT_COMPONENTS         # S2
DOC["containmentProxy"] = CONTAINMENT_PROXY       # S3
DOC["terraformIaC"] = TERRAFORM_IAC               # S4
DOC["mlsecopsPipeline"] = MLSECOPS_PIPELINE       # S5
DOC["incidentResponse"] = INCIDENT_RESPONSE       # S6
DOC["complianceAnalysis"] = COMPLIANCE_ANALYSIS   # S7
DOC["kafkaSandbox"] = KAFKA_SANDBOX               # S8
DOC["sentinelArchitecture"] = SENTINEL_ARCHITECTURE  # S9

counts = {
    "modules": len(MODULES),
    "sections": sum(len(m["sections"]) for m in MODULES),
    "schemas": len(SCHEMAS),
    "code": len(CODE),
    "kpis": len(KPIS),
    "riskControlMatrix": len(RCM),
    "traceability": len(TRACEABILITY),
    "dataFlows": len(DATA_FLOWS),
    "regulators": len(REGULATORS),
    "rollout90": len(ROLLOUT_90),
    "roadmap": len(ROADMAP),
    "evidencePack": len(EVIDENCE_PACK),
    "governanceRoles": len(GOVERNANCE_ROLES),
    "reactComponents": len(REACT_COMPONENTS),
    "containmentProxy": len(CONTAINMENT_PROXY),
    "terraformIaC": len(TERRAFORM_IAC),
    "mlsecopsPipeline": len(MLSECOPS_PIPELINE),
    "incidentResponse": len(INCIDENT_RESPONSE),
    "complianceAnalysis": len(COMPLIANCE_ANALYSIS),
    "kafkaSandbox": len(KAFKA_SANDBOX),
    "sentinelArchitecture": len(SENTINEL_ARCHITECTURE),
}
DOC["counts"] = counts

OUT.write_text(json.dumps(DOC, indent=2, ensure_ascii=False))
print(f"[WP-055] Wrote {OUT}")
print(f"[WP-055] modules={counts['modules']} sections={counts['sections']} schemas={counts['schemas']} kpis={counts['kpis']} RCM={counts['riskControlMatrix']}")
print(f"[WP-055] traceability={counts['traceability']} dataFlows={counts['dataFlows']} regulators={counts['regulators']}")
print(f"[WP-055] governanceRoles={counts['governanceRoles']} reactComponents={counts['reactComponents']} containmentProxy={counts['containmentProxy']}")
print(f"[WP-055] terraformIaC={counts['terraformIaC']} mlsecopsPipeline={counts['mlsecopsPipeline']} incidentResponse={counts['incidentResponse']}")
print(f"[WP-055] complianceAnalysis={counts['complianceAnalysis']} kafkaSandbox={counts['kafkaSandbox']} sentinelArchitecture={counts['sentinelArchitecture']}")
