# **Registry Manifest (RM) Standard**
## **Part 6: RM-CPR Governance Ecosystem Guide**
### **RM-CPR-ECO-1.0 — Version 1.0**

---

### **1. Scope**

This document provides a non-normative guide to the full suite of specifications and artifacts that constitute the **RM-CPR-1.0 governance ecosystem**. It defines the purpose, governance status, and relationships between the core constitutional specification and its operational extensions.

### **2. Governance Roles and Responsibilities**

- **Custodian (RMGC):** The Registry Manifest Governance Committee is the custodian of all `*Specification` artifacts. It is responsible for approving new editions.
- **Implementer:** An organization that builds a software system conforming to the RM-CPR-1.0 specification.
- **Auditor:** An entity that uses the `CTS`, `TVC`, and `Schema` artifacts to verify the conformance and integrity of an implementation.

### **3. Ecosystem Artifacts**

#### **3.1 The Constitutional Core (Frozen)**

- **`RM-CPR-1.0` (Specification):** The foundational, normative specification defining the registry's identity, state, operations, and integrity model. **Status: Frozen.**

#### **3.2 Conformance and Verification Artifacts**

These artifacts operationalize the frozen constitution for automated verification. They are governed by the RMGC and must remain in strict alignment with RM-CPR-1.0.

- **`RM-CPR-CTS-1.0` (Specification):** The Conformance Test Suite. Defines positive and negative tests to verify that an implementation correctly adheres to the normative requirements.
- **`RM-CPR-Schema-1.0` (Machine-Readable Schema):** A set of machine-readable files (e.g., JSON Schema, OpenAPI definitions) that formally describe the object models and API endpoints. It is a direct translation of the normative requirements in RM-CPR-1.0.
- **`RM-CPR-TVC-1.0` (Test Vector Specification):** Defines a set of "constitutional adversary" test vectors—malformed or malicious inputs designed to prove the robustness of an implementation's constitutional boundaries.

#### **3.3 Operational and Interoperability Artifacts**

These artifacts define how conformant registries operate and exchange data.

- **`RM-CPR-EXCH-1.0` (Specification):** The Registry Exchange and Interoperability Profile. Defines the normative format for exporting and importing registry data to ensure lossless exchange of governance history.
- **`RM-CPR-RVI-1.0` (Reference Validator/Implementation):** A non-normative, open-source software project that provides a working implementation of a conformant registry. It serves as a baseline for other implementers and as a tool for validating the coherence of the specifications.

#### **3.4 Certification Artifacts**

- **`RM-CPR-CERT-1.0` (Certification Profile):** Defines the process and requirements for an implementer to be awarded an official **RM-CPR-1.0 Conformance Certificate**. This includes passing all tests in the CTS and demonstrating resilience against the TVC.

### **4. Relationships and Governance Flow**

```mermaid
graph TD
    A[RM-CPR-1.0<br/><b>(Frozen Constitution)</b>] --> B{RM-CPR-Schema-1.0<br/>(Defines)};
    A --> C{RM-CPR-CTS-1.0<br/>(Verifies)};
    A --> D{RM-CPR-TVC-1.0<br/>(Stress-Tests)};
    A --> E{RM-CPR-EXCH-1.0<br/>(Extends)};

    subgraph Verification
        C --> F[Conformance Claim];
        D --> F;
    end

    subgraph Implementation
        B --> G[Registry Software];
        E --> G;
    end

    G -- runs --> C;
    G -- resists --> D;

    F & G --> H(RM-CPR-CERT-1.0<br/><b>(Official Certificate)</b>);
```
