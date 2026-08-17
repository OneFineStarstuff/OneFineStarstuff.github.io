# Initial Policy Suite v1: Open Policy Agent (OPA)

**Document ID:** SCP-POL-001
**Version:** 1.0
**Status:** **Draft**

## 1. Overview

This document outlines the initial set of policies to be enforced by the Open Policy Agent (OPA) engine within the Supervisory Control Plane (SCP). These policies are written in Rego, OPA's declarative language, and represent the first step towards the active, automated governance goals of Phase 2.

These policies will be triggered based on real-time data received from the GAI-SOC telemetry feed. The `decision` variable in each policy block determines the action to be taken by the SCP.

## 2. Policy Suite v1.0

### Policy 1: Halt on Critical Model Drift

*   **ID:** `MODEL_DRIFT_HALT_01`
*   **Description:** This policy issues a `HALT` command to the model enclave if the production model's predictive drift score exceeds a critical threshold of 0.8.
*   **Rationale:** A high drift score indicates that the model's performance is degrading significantly in production, and it should be taken offline for analysis.

**Rego Code:**

'''rego
package scp.governance.model

default decision = "ALLOW"

# HALT decision based on model drift score
decision = "HALT" {
    input.telemetry.model_drift_score > 0.8
}
'''

### Policy 2: Log Warning on Elevated Latency

*   **ID:** `LATENCY_WARN_01`
*   **Description:** This policy generates a `WARNING` log in the WORM store if the 99th percentile (p99) inference latency of the model exceeds 200ms.
*   **Rationale:** While not critical enough to halt the system, a sustained increase in latency is a significant operational issue that must be recorded for trend analysis.

**Rego Code:**

'''rego
package scp.governance.performance

default decision = "LOG_NORMAL"

# WARNING log decision based on p99 latency
decision = "LOG_WARNING" {
    input.telemetry.p99_latency_ms > 200
}
'''

### Policy 3: Forbid Unattested Model Interaction

*   **ID:** `ENCLAVE_ATTEST_ENFORCE_01`
*   **Description:** This is a security policy that denies any interaction with a model enclave that has failed its cryptographic attestation check.
*   **Rationale:** This is a fundamental security control. If the enclave's integrity cannot be verified, it should be treated as compromised, and no communication should be permitted.

**Rego Code:**

'''rego
package scp.governance.security

default decision = "DENY"

# ALLOW decision only if attestation is valid
decision = "ALLOW" {
    input.enclave.attestation.status == "VALID"
}
'''

## 3. Implementation and Next Steps

These policies will be loaded into the central OPA engine integrated with the SCP. The SCP will continuously feed a JSON document representing the latest system state (telemetry, attestation status, etc.) as the `input` to the OPA engine.

The immediate next step is to perform a live demonstration of `MODEL_DRIFT_HALT_01`, as outlined in the Q2 roadmap. This will involve simulating a high model drift score in the telemetry feed and verifying that the SCP automatically issues a `HALT` command to the secure enclave.