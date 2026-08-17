# Sentinel Implementation Checklists & Technical Design Guide

**Document ID:** `SENTINEL-TECH-GUIDE-v1.0`
**Date:** 27 June 2026
**Audience:** AI Architects, DevSecOps Engineers, and Compliance Engineering Teams
**Classification:** Internal // Technical Implementation Guidance

---

## **Part 1: Execution Checklists**

These checklists provide the tactical, step-by-step actions required to deploy and operate a Sentinel-compliant node within the Omni-Sentinel Mesh. They should be automated and integrated into CI/CD pipelines wherever possible.

### **Checklist 1: New AI System Onboarding**

- [ ] **1.1 Register in Inventory:** Add the new AI model/system to the central service catalog.
- [ ] **1.2 Define OSCAL Profile:** Create or select an OSCAL component definition for the system, inheriting all relevant baseline controls.
- [ ] **1.3 Generate Initial Rego Policies:** Use the `oscal-to-opa` toolchain to generate the baseline set of OPA policies from the system's OSCAL profile.
- [ ] **1.4 Provision Secure Infrastructure via Terraform:** Deploy the required Kubernetes namespace and cloud resources using the approved, centrally-managed Terraform modules.
- [ ] **1.5 Configure vTPM & SPIFFE ID:** Ensure the Kubernetes nodes have vTPM devices enabled and issue a unique SPIFFE identity for the new service.
- [ ] **1.6 Deploy Application via GitOps:** Commit the Kubernetes manifests to the GitOps repository and allow ArgoCD to sync the application.
- [ ] **1.7 Attach SDT Logger Sidecar:** The deployment manifest MUST include the `sdt-logger` sidecar container, configured to point to the institutional SDT endpoint.
- [ ] **1.8 Run Initial Attestation:** Trigger a remote attestation of the host node's TPM/TEE and the pod's vTPM to establish the initial trusted baseline in the WORM log.
- [ ] **1.9 Health Check:** Verify the service is emitting containment heartbeats and that the SDT is receiving governance events.

### **Checklist 2: Daily Operational Verification (Automated)**

- [ ] **2.1 Run `daily-verify.sh` Script:** Execute the master script that performs the checks detailed in the *Daily DevSecOps Operational Verification Report*.
- [ ] **2.2 Check G-SRI Drift:** Assert that the institutional G-SRI has not deviated by more than 5% from its 7-day moving average.
- [ ] **2.3 Verify WORM Log Integrity:** Re-calculate the Merkle root of the last 24 hours of WORM logs and verify the PQC signature.
- [ ] **2.4 Attest All Nodes:** Trigger a mesh-wide hardware and virtual attestation sweep.
- [ ] **2.5 Check Policy Drift:** Run a `diff` between the `main` branch of the OPA policy Git repository and the policies loaded in all running OPA instances.
- [ ] **2.6 Check Terraform Drift:** Run `terraform plan` for all production workspaces and assert that no drift is detected.
- [ ] **2.7 Verify zkML Proof Pipeline:** Check the latency and success rate of the zkML proof generation and verification queue. Alert on any backlog greater than 5 minutes.

---

## **Part 2: Constitutional AI Governance Technical Design Guide**

This guide provides the architectural principles and design patterns for building AI systems that are constitutionally compliant by design.

### **Principle 1: Governance is an Enforced State, Not a Checked Property**

Your goal is not to build an AI and then ask a tool if it's compliant. Your goal is to build the AI within a framework that makes non-compliance impossible.

*   **Design Pattern: The OPA Enforcement Point:** Never place a policy check in a separate, asynchronous process. Use an OPA sidecar or an API gateway with an OPA plugin as a blocking, synchronous enforcement point. An API call to an AI model should succeed *only if* it passes the OPA policy check for that specific call. The `allow` rule in your Rego policy is the gatekeeper of execution.

### **Principle 2: Trust is Explicit and Cryptographically Proven**

Do not trust network location, IP addresses, or even service names. Trust is a cryptographic assertion that must be continuously re-established.

*   **Design Pattern: Hardware-Anchored Trust:** An AI model is only trusted if it can prove it is running on a specific piece of hardware (or virtual hardware) whose integrity has been verified. The **TPM/TEE/vTPM attestation** is the root of this trust. A service should refuse to interact with another service that cannot provide a recent, valid attestation receipt from the central attestation service.

### **Principle 3: The Log is the System of Record**

The only thing that truly happened is what was written to the immutable **post-quantum WORM log**. Dashboards and metrics are derivatives of the log.

*   **Design Pattern: Fire-and-Forget Logging Sidecar:** Your AI service's only logging responsibility is to write a structured event to its local `stdout`. A dedicated, hardened **`sdt-logger` sidecar** is responsible for capturing this event, enriching it with the pod's SPIFFE ID and vTPM attestation receipt, and securely forwarding it to the institutional SDT. The application code should have no direct knowledge of the WORM log.

### **Principle 4: Privacy is Not a Feature, It is a Mathematical Guarantee**

When dealing with sensitive data, do not rely on policies alone to prevent its leakage. Use cryptography to make leakage impossible.

*   **Design Pattern: Zero-Knowledge Model Execution:** For models that must process highly sensitive data (e.g., customer PII for a credit decision model), design the model from day one to be compatible with a **zkML** framework. The model itself is executed inside a prover, which generates a **zk-SNARK** proving that the model was executed correctly on some private data to produce a specific public output, without revealing the private data itself. The verifier (the calling service) can then trust the result without ever seeing the sensitive inputs.

### **Principle 5: Compliance is Code**

Regulatory documents are philosophical guides. The actual implementation of compliance lives in your OSCAL and Rego files.

*   **Design Pattern: The OSCAL-to-OPA Pipeline:** Your compliance team's primary deliverable for a new regulation should be an **OSCAL profile**. Your engineering team's responsibility is to build and maintain the `oscal-to-opa` toolchain that translates this human-readable profile into machine-enforceable **Rego policies**. The link between a high-level rule (e.g., from the EU AI Act) and a specific line of Rego code should be explicit, version-controlled, and auditable.

By building according to these principles and checklists, you ensure that your AI systems are not just performant and profitable, but also secure, resilient, and constitutionally governable by design.
