# Q4 Live Demo Plan: Human-in-the-Loop (HITL) Workflow

**Objective:** To demonstrate the fully implemented Human-in-the-Loop (HITL) workflow, showcasing how the SCP can enforce a human approval step for a critical action in a cryptographically secure and auditable manner.

**Meeting:** To be performed during the `Monthly Checkpoint Call` for the first month of Q4.

**Policy Under Test:** The custom OPA policy that returns `AWAIT_APPROVAL` for model rollbacks.

## 1. Demonstration Narrative

"We will now demonstrate the final piece of our core governance framework: the Human-in-the-Loop workflow. While automation is powerful, some actions are too critical to be left solely to a machine. We will show how the SCP can identify a high-stakes operation, pause its execution, and require a formal, cryptographically signed approval from a designated human operator before proceeding. This merges automated speed with human accountability."

## 2. Demonstration Steps

| Step | Action                                                                                                             | System Component(s) Involved                                  | Expected Outcome                                                                                                                                                                                                                                                                             |
| :--- | :----------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | **Show Normal State:** Display the Governance Cockpit. The system is in a `Normal` state.                                      | Governance Cockpit (UI)                                         | All systems are green.                                                                                                                                                                                                                                                                       |
| 2    | **Propose a Critical Action:** An operator uses a CLI command to request a rollback of the primary model to a previous version (`v1.9`). | Operator CLI, SCP Core Logic                                  | The request is sent to the SCP.                                                                                                                                                                                                                                                              |
| 3    | **Observe `AWAIT_APPROVAL` State:** The OPA engine evaluates the request and, based on the policy, returns `AWAIT_APPROVAL`.     | SCP Core Logic, OPA Engine                                      | The Governance Cockpit UI immediately transitions to a blue `PendingApproval` state. A new entry appears in the "Pending Actions" queue, showing the proposed rollback and a unique **Proposal Hash**. The model is **not** rolled back.                                                       |
| 4    | **Act as the Approver:** Switch to the "Approver View" in the Cockpit. Review the pending action.                | Governance Cockpit (UI)                                         | The approver can clearly see the action, its parameters, and who proposed it.                                                                                                                                                                                                                |
| 5    | **Generate Signed Approval:** The approver clicks "Approve". This action uses a connected YubiKey (simulated) to sign the Proposal Hash. | Approver's Browser, YubiKey (Simulated), Governance Cockpit     | A valid cryptographic signature is generated and sent back to the SCP.                                                                                                                                                                                                                     |
| 6    | **Witness Automated Execution:** The SCP verifies the signature against the authorized approver's public key and the Proposal Hash. | SCP Core Logic                                                  | Upon successful verification, the UI state changes to `Executing`. The SCP now issues the `ROLLBACK_MODEL` command. After a moment, the state returns to `Normal`, with the active model version now listed as `v1.9`.                                                                       |
| 7    | **Verify Audit Trail:** Navigate to the WORM log viewer.                                                           | WORM Log Viewer                                                 | A new, detailed log entry is visible. It contains the initial request, the Proposal Hash, the approver's signature, and the final execution confirmation, all bundled in one immutable, verifiable record. This proves the end-to-end chain of custody for the decision. | 

## 3. Success Criteria

*   The SCP must correctly pause the execution of the critical action and enter the `PendingApproval` state.
*   The action must not proceed without a valid cryptographic signature from an authorized approver.
*   Upon receiving a valid signature, the SCP must promptly execute the action.
*   The entire workflow, including the signature, must be captured in the immutable audit log.