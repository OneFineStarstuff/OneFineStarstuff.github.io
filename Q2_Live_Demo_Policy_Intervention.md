# Q2 Live Demo Plan: Policy-Driven Intervention

**Objective:** To demonstrate a live, policy-driven intervention by the Supervisory Control Plane (SCP), fulfilling the final key deliverable of the Q2 roadmap.

**Meeting:** To be performed during the `Monthly Checkpoint Call` for the third month of Q2.

**Policy Under Test:** `MODEL_DRIFT_HALT_01` (Halt on Critical Model Drift)

## 1. Demonstration Narrative

"We have now deployed a live AI model in a secure, confidential computing enclave, and we have defined a set of governance rules using a policy-as-code engine. We will now demonstrate the SCP's ability to automatically enforce these rules.

We will simulate a scenario where our production model's quality degrades rapidly, a condition known as model drift. The SCP, without any human intervention, will detect this condition, apply a predefined policy, and automatically take corrective action by halting the model within its secure enclave."

## 2. Demonstration Steps

| Step | Action                                                                                             | System Component(s) Involved                                  | Expected Outcome                                                                                                                              |
| :--- | :------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Show Normal State:** Display the Governance Cockpit UI, showing the model operating in a `Normal` state with a low drift score (< 0.1). | Governance Cockpit (UI)                                         | The UI shows a green status, and the model is processing inference requests normally.                                                        |
| 2    | **Simulate Model Drift:** Manually inject a simulated telemetry message into the GAI-SOC feed with `"model_drift_score": 0.85`. | GAI-SOC Telemetry Feed                                          | The injected message is sent to the SCP for processing.                                                                                       |
| 3    | **Observe Policy Evaluation:** The SCP receives the high-drift telemetry and passes it as `input` to the Open Policy Agent (OPA) engine. | SCP Core Logic, OPA Engine                                      | OPA evaluates the `MODEL_DRIFT_HALT_01` policy. The policy returns a `HALT` decision because `0.85 > 0.8`.                                     |
| 4    | **Witness Automated Intervention:** The SCP, acting on the `HALT` decision, issues a `HALT` command to the model via the secure `vsock`. | SCP Core Logic, Secure Enclave                                  | The Governance Cockpit UI immediately transitions to a red `HALT` state. The log shows a new entry: `"Event: HALT command issued to enclave."`. |
| 5    | **Verify Halting:** Attempt to send an inference request to the model and show that it fails or returns a "model halted" status.     | Model Enclave, Governance Cockpit                             | The UI shows that inference requests are now failing, confirming the model is offline. The WORM log shows the `HALT` event as an immutable record. |

## 3. Success Criteria

*   The entire sequence from telemetry injection to model halt must take less than 2 seconds.
*   The Governance Cockpit UI must accurately reflect the real-time state change.
*   A permanent, cryptographically signed record of the `HALT` event must be written to the PQC-WORM log and be verifiable by the Regulator Verifier Node.
