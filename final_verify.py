import re

required_keywords = [
    "Sentinel AI Governance Stack v2.4", "Omni-Sentinel Mesh v4.0", "SCP v3.0",
    "G-SIFI", "2026–2035", "10 GIEN control domains", "DevSecOps", "G-SRI",
    "post-quantum WORM", "TPM/TEE/vTPM", "Kubernetes/GitOps", "OPA/Rego",
    "OSCAL-to-OPA", "AutonomousSupervisoryAgent", "zk-SNARK/SnarkPack",
    "on-chain kill-switch", "Terraform multi-region", "EU AI Act Annex IV",
    "NIST AI RMF 1.0", "AI 600-1", "ISO/IEC 42001 AIMS", "Basel III/IV",
    "SR 11-7", "SR 26-2", "DORA", "NIS2", "GDPR Art.22", "MAS/HKMA FEAT",
    "FCA SMCR", "Consumer Duty", "HKMA Fintech 2030", "ECOA", "SEC 17a-4",
    "ICGC/GASO", "Phases I–IV", "implementation blueprints", "Dashboard Checklist",
    "Unified Corpus Index Traceability Guide", "Perturbation Library Specification",
    "Scenario Execution Table", "Supervisory Digital Twin Replays", "Panel 15",
    "Annex A/B/C", "Supervisory Submission Readiness Certificate",
    "Supervisory Transmittal Letter", "transmission package manifest",
    "Phase I sealed dossier status", "retrospective analysis",
    "forward-looking analysis", "civilizational compute governance"
]

with open('docs/reports/DAILY_GIEN_DEVSECOPS_DOSSIER_V2.4.md', 'r') as f:
    content = f.read()

missing = []
for kw in required_keywords:
    if kw.lower() not in content.lower():
        missing.append(kw)

if missing:
    print(f"Missing keywords: {missing}")
else:
    print("All required keywords found.")

# Check for 0x to avoid Gitleaks
if '0x' in content:
    print("WARNING: Found '0x' which might trigger Gitleaks.")

# Check line length
lines = content.split('\n')
for i, line in enumerate(lines):
    if len(line.rstrip()) > 120:
        print(f"L{i+1} too long: {len(line.rstrip())}")
