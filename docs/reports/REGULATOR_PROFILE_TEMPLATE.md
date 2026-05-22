# Regulator Profile: [Authority Name] (e.g., ECB AI Office)

## 1. Jurisdiction & Mandate
- **Jurisdiction:** EU / US / APAC
- **Primary Regulation:** [e.g., EU AI Act]
- **Enforcement Capability:** Fine / License Revocation / Hardware Interdict

## 2. Governance Interface Requirements
- **zk-Verifier Shard:** [URL/Address]
- **OSCAL Catalog Format:** v1.1.0
- **Telemetry Frequency:** Real-time (Heartbeat < 1s)

## 3. Safety Thresholds (Red-Line Invariants)
| Metric | Threshold | Action on Breach |
| :--- | :--- | :--- |
| **G-SRI Index** | > 0.75 | 48hr Warning |
| **G-SRI Index** | > 0.90 | Immediate Containment |
| **Inference Drift** | > 15% | Tier-1 Restriction |

## 4. Audit API Endpoint
`https://governance-api.[institution].com/v1/oscal/verify`
