# OPA/Rego Policy Join-Points & Enforcement Logic

This document specifies the integration points (Join-Points) where the Open Policy Agent (OPA) interacts with the Supervisory Control Plane (SCP) and institutional sidecars.

## 1. Join-Point A: Inference Admission (Sidecar)
Before an AI model processes a prompt, the sidecar calls OPA to verify the action.
- **Input:** `{ "model_id": "ASI-v4", "action": "tool_use", "data_tier": "PII", "jurisdiction": "EU" }`
- **Rego Logic:** Checks if the model is in **GSM PROD state** and if the tool-use is sanctioned for the data tier.
- **Response:** `allow: true | false`.

## 2. Join-Point B: Model Promotion (SCP Core)
When a developer requests a state transition in the GSM.
- **Input:** `{ "from": "STAGING", "to": "PROD", "evidence_root": "0x5f3e...", "quorum": ["ASO", "Auditor"] }`
- **Rego Logic:** Verifies that a valid ZK compliance proof exists and that the G-SRI is below the intervention threshold.
- **Response:** `promotion_valid: true`.

## 3. Join-Point C: Regional Gossip (GIEN Agent)
Filtering incoming risk telemetry from the federated mesh.
- **Input:** `{ "peer_id": "G-SIFI-02", "posture_root": "0xABCD...", "signature_valid": true }`
- **Rego Logic:** Ensures the peer institution is part of the approved treaty mesh before syncing roots.
- **Response:** `sync_authorized: true`.

## 4. Policy Bundle Distribution
Policies are versioned and distributed as signed **WebAssembly (Wasm)** modules to the sidecars to ensure sub-millisecond enforcement latency.
