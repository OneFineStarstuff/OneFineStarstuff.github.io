# **Registry Manifest (RM) Standard**
## **Part 4: Change Proposal Register**
### **RM-CPR-1.0 — Version 1.0**

---
**Notice**

This document is a **Draft for Review** and is subject to change without notice. The constitutional architecture defined in Part I is considered stable. The drafting of sections in Part III will proceed according to the plan in Part II.

---

## **Part I: Foundation (Constitutional Freeze)**

### **1. Scope**

This document provides the normative specification for the **Registry Manifest Change Proposal Register (RM-CPR-1.0)**. It defines the identity, object model, state management, and operational requirements for the register, which serves as the single source of truth for all proposed changes to the Registry Manifest standards ecosystem.

### **2. Normative References**

- RM-GCC-1.0: Governance Committee Charter
- RM-ICT-1.0: Issue Classification Taxonomy
- RM-CPT-1.0: Change Proposal Template

### **3. Terms and Definitions**

- **Change Proposal (CP):** A machine-readable governance object, compliant with RM-CPT-1.0, that describes a proposed change to the RM standard.
- **Register:** The RM-CPR-1.0 instance.
- **Record:** A Change Proposal that has been assigned a stable identity within the Register.

---

## **Part II: Normative Drafting Plan**

### **4. Constitutional Integrity**

The architecture of **Part I: Foundation** is frozen. All subsequent sections must maintain logical and normative alignment with the specifications referenced therein.

### **5. Drafting Sequence and Clause Structure**

Drafting will proceed sequentially from Section 6. Each clause and sub-clause will be drafted using the following normative structure:

- **`.1 Normative`**: The binding requirements, using conformance keywords (MUST, SHOULD, MAY) as defined in RFC 2119.
- **`.2 Rationale`**: The design principles and justification for the normative requirements.
- **`.3 Notes`**: Non-normative examples, clarifications, or implementation guidance.
- **`.4 Cross-References`**: Links to related requirements within this or other RM specifications.

---

## **Part III: Registry Specification**

### **6. Registry Identity**

#### **6.1 Registry Identifier**

**6.1.1 Normative**
The registry SHALL have a single, globally unique identifier. The identifier for this registry edition is `gito:register:RM-CPR-1.0`.

**6.1.2 Rationale**
A stable, machine-readable identifier is required to ensure that governance objects and external systems can unambiguously reference the correct register. The `gito:` scheme provides a semantic namespace for governance objects.

**6.1.3 Notes**
Example of referencing this register from a Change Proposal Template (RM-CPT-1.0):
```yaml
governance:
  register_id: "gito:register:RM-CPR-1.0"
```

**6.1.4 Cross-References**
- RM-CPT-1.0 (Change Proposal Template)

#### **6.2 Registry Edition**

**6.2.1 Normative**
The Registry Edition SHALL identify a specific, published version of this specification (RM-CPR-1.0). The initial edition is `1.0`.

**6.2.2 Rationale**
The Edition tracks the evolution of the register's own specification (its schema, rules, and operations), as distinct from the data it contains. This ensures that tooling and clients can align with the correct version of the register's capabilities.

**6.2.3 Cross-References**
- Section 7: Registry Semantic Versioning

#### **6.3 Registry Status**

**6.3.1 Normative**
The Registry Status SHALL be represented by a value from a controlled vocabulary. The vocabulary SHALL include `Active`, `Superseded`, and `Deprecated`. The status of RM-CPR-1.0 is `Active`.

**6.3.2 Rationale**
The status provides a clear signal about the operational state of a given Registry Edition, enabling automated systems to determine if a register is current.

#### **6.4 Registry Custodian**

**6.4.1 Normative**
The Registry SHALL have a designated custodian responsible for its maintenance and operational integrity. The custodian for RM-CPR-1.0 is the **Registry Manifest Governance Committee (RMGC)**.

**6.4.2 Rationale**
Designating a custodian clarifies accountability for the governance and operational stability of the register.

**6.4.4 Cross-References**
- RM-GCC-1.0: Governance Committee Charter

#### **6.5 Baseline Identifier**

**6.5.1 Normative**
The Registry SHALL declare a Baseline Identifier that points to the foundational set of governance rules and schemas it enforces. The Baseline Identifier for RM-CPR-1.0 is a composite identifier referencing the tuple `(RM-GCC-1.0, RM-ICT-1.0, RM-CPT-1.0)`.

**6.5.2 Rationale**
The Baseline Identifier makes the register's governing constitution explicit and machine-readable, enabling automated validation and integrity checks.

### **7. Registry Semantic Versioning (Drafting Guidelines)**

*This section provides ISO/IEC-style drafting guidelines for the development of the full normative text. The core principle is the formal separation of concerns between three distinct versioning lifecycles.*

#### **7.1 Clause Objective**
To define a semantic versioning model that allows the Registry's specification, its runtime instance, and its individual records to evolve independently while maintaining traceability and constitutional alignment.

#### **7.2 Orthogonal Versioning Concepts**
The drafter MUST define and specify the following three concepts as orthogonal, each with its own identifier, lifecycle, and governance model.

**7.2.1 `Registry Edition`**
- **Definition:** A specific, published version of the **RM-CPR specification itself**. It signifies changes to the register's fundamental schema, rules, or capabilities.
- **Example:** `1.0`, `1.1`, `2.0`
- **Governance:** New editions are authorized by the RMGC and trigger the deprecation or supersession of the previous edition. Changes between editions MAY be breaking.
- **Drafting Focus:** Specify the format of the edition identifier and the normative process for creating and publishing a new edition.

**7.2.2 `Registry Instance Version`**
- **Definition:** An identifier for the state of the **entire dataset** within the register at a specific point in time. It is a snapshot of the collection of all records.
- **Example:** A Git commit hash (`a1b2c3d`), a timestamp (`2024-05-21T10:00:00Z`), or a serial number.
- **Governance:** Instance Versions are created automatically whenever a record within the register changes its state (e.g., a CP is `APPROVED`). This creates a complete, auditable history of the register's data.
- **Drafting Focus:** Specify that the Register MUST generate a new, unique Instance Version upon any state change to any of its constituent records. Define the required format for this identifier.

**7.2.3 `Registry Record Revision`**
- **Definition:** A version number for an **individual record (Change Proposal)** within the register. It tracks the modification history of that specific record.
- **Example:** `CP-2024-042-rev1`, `CP-2024-042-rev2`
- **Governance:** A new revision is created whenever a field within a CP record is modified (e.g., a description is clarified, a state is changed from `DRAFT` to `TRIAGE`).
- **Drafting Focus:** Specify that every record MUST have a revision number that is incremented on every modification. The combination of a record's stable ID and its revision number must uniquely identify the state of that record.

#### **7.3 Relationship Model**
The drafter MUST specify the relationship: A `Registry Instance Version` is a snapshot of a set of `Registry Record Revisions`, and the entire system operates according to the rules of a specific `Registry Edition`.

### **8. Registry Record Identity**

**8.1 Record Identifier**

**8.1.1 Normative**
Upon creation, a record SHALL be assigned a single, globally unique, and persistent identifier. This identifier MUST NOT be changed, reassigned, or deleted. The format of the Record Identifier SHALL be `gito:cp:YYYY-NNN`, where `YYYY` is the year of submission and `NNN` is a monotonically increasing integer.

**8.1.2 Rationale**
A stable, human-readable, and unique identifier is the cornerstone of traceability. It ensures that a change proposal can be referenced unambiguously throughout its lifecycle and across all related documentation and implementations, independent of its revision or state. This orthogonality is a key constitutional principle (EC-01).

**8.1.3 Notes**
The first proposal submitted in 2024 would have the identifier `gito:cp:2024-001`.

**8.1.4 Cross-References**
- Section 6: Registry Identity
- Section 7: Registry Semantic Versioning

**8.2 Record Revision**

**8.2.1 Normative**
Every record SHALL have a revision number, which MUST be a positive integer. The revision number of a newly created record SHALL be `1`. The revision number MUST be incremented by exactly one upon any successful `UPDATE` operation on the record.

**8.2.2 Rationale**
The revision number provides a simple, ordered mechanism for tracking the history of a specific record. Combined with the immutable Record Identifier, it allows any past state of a record to be retrieved and audited.

**8.2.3 Cross-References**
- Section 7.2.3: Registry Record Revision
- Section 11.3: UPDATE Operation

### **9. Record Object Model**

**9.1 Normative Specification**

**9.1.1 Normative**
The object model for a record within this register SHALL be a valid instance of the **Registry Manifest Change Proposal Template (RM-CPT-1.0)**. All fields, data types, and validation rules defined in RM-CPT-1.0 are incorporated into this specification by reference.

**9.1.2 Rationale**
This clause establishes a normative and unbreakable link between the register's content and its governing template. It ensures that all records are structurally and semantically consistent, which is fundamental for machine-readability and automated governance.

**9.1.3 Cross-References**
- RM-CPT-1.0: Change Proposal Template

### **10. Registry State Management**

**10.1 State Model Layer: `governance.state`**

**10.1.1 Normative**
The state of a record SHALL be determined exclusively by the `governance.state` field of its object model. The value of this field MUST be one of the states defined in the controlled vocabulary of the **Registry Manifest Issue Classification Taxonomy (RM-ICT-1.0)**.

**10.1.2 Rationale**
This layer defines the "what" of the state model. By binding the state to a single, authoritative external taxonomy, it ensures that the lifecycle semantics are consistent across the entire RM standards ecosystem.

**10.1.3 Cross-References**
- RM-ICT-1.0: Issue Classification Taxonomy

**10.2 Governance Layer: State Transition Authorization**

**10.2.1 Normative**
State transitions SHALL be governed by the rules and authorities defined in the **Registry Manifest Governance Committee Charter (RM-GCC-1.0)**. A state transition is valid only if it is authorized by the role or body specified in the charter.

**10.2.2 Rationale**
This layer defines the "who" of the state model. It establishes the principle that state changes are not merely data updates but are formal governance acts, authorized by a designated entity (e.g., the Proposer, Technical Secretary, or RMGC).

**10.2.3 Cross-References**
- RM-GCC-1.0: Governance Committee Charter

**10.3 Operational Layer: State Transition Semantics**

**10.3.1 Normative**
A change to the `governance.state` field SHALL only be effected via a successful `UPDATE` operation. The `UPDATE` operation is the sole mechanism for triggering a state transition. The allowed transitions between states (e.g., from `DRAFT` to `TRIAGE`) SHALL be defined and enforced by the register's business logic.

**10.3.2 Rationale**
This layer defines the "how" of the state model. It ensures that all state changes are explicit, transactional, and subject to the validation rules of a formal operation, preventing ad-hoc or invalid modifications.

**10.3.3 Cross-References**
- Section 11: Registry Operations

**10.4 Historical Layer: State Transition Invariants**

**10.4.1 Normative**
Every successful `UPDATE` operation that results in a change to the `governance.state` field SHALL produce a new, immutable **Record Revision**. This operation SHALL also result in the creation of a new, immutable **Registry Instance Version**, capturing the snapshot of the entire register after the state change.

**10.4.2 Rationale**
This layer enforces the creation of a complete and auditable history. It guarantees that every governance decision (a state change) is recorded as both a new version of the specific record and a new version of the register as a whole, providing an unbroken chain of provenance.

**10.4.3 Cross-References**
- Section 7: Registry Semantic Versioning
- Section 12: Integrity and Audit Requirements

### **11. Registry Operations**

**11.1 CREATE Operation**

**11.1.1 Normative**
The register SHALL support a `CREATE` operation. This operation SHALL accept an object compliant with RM-CPT-1.0. Upon successful validation, the operation MUST:
1. Assign a new, unique `Record Identifier`.
2. Set the `governance.state` to `DRAFT`.
3. Set the `Record Revision` number to `1`.
4. Generate a new `Registry Instance Version`.

**11.1.2 Rationale**
The `CREATE` operation is the sole entry point for new proposals into the governance ecosystem. Its strict invariants ensure that every new record is initialized in a consistent and valid state.

**11.2 READ Operation**

**11.2.1 Normative**
The register SHALL support a `READ` operation that can retrieve any revision of any record by specifying its `Record Identifier` and `Record Revision` number. If no revision is specified, the latest revision SHALL be returned.

**11.2.2 Rationale**
This operation provides transparent access to the current and historical state of all governance artifacts within the register.

**11.3 UPDATE Operation**

**11.3.1 Normative**
The register SHALL support an `UPDATE` operation. This operation SHALL accept a `Record Identifier` and a modified record object. The operation MUST fail if:
1. The proposed `governance.state` transition is not a valid transition from the current state.
2. The `UPDATE` is not authorized according to the rules in the Governance Layer (10.2).
Upon successful validation, the operation MUST:
1. Increment the `Record Revision` number by one.
2. Update the record's data to the new state.
3. Generate a new `Registry Instance Version`.

**11.3.2 Rationale**
The `UPDATE` operation is the engine of the governance lifecycle. Its strict preconditions and post-conditions ensure that every change is a valid, authorized, and fully-auditable state transition, preserving the integrity of the register.

### **12. Registry Integrity**

**12.1 Legitimacy and Continuity**

**12.1.1 Normative**
Every operation (`CREATE`, `UPDATE`) SHALL be transactionally atomic. A failed operation MUST NOT alter the state of the registry. The registry's state SHALL be recoverable to any valid, previously recorded `Registry Instance Version`.

**12.1.2 Rationale**
These principles ensure that the registry can survive operational failures without corruption. Legitimacy requires that every state was the result of a valid, authorized transaction. Continuity (via recoverability) ensures that the complete, verifiable history is never lost.

**12.2 Ordering and Non-Repudiation**

**12.2.1 Normative**
`Registry Instance Versions` SHALL form a strictly ordered, append-only sequence. It MUST be computationally infeasible to alter the historical sequence of instance versions without detection. Each operation recorded in the history MUST be attributable to the authenticated principal that initiated it.

**12.2.2 Rationale**
A guaranteed order is essential for audit and establishing precedence. Non-repudiation ensures accountability by creating a verifiable link between an operation and its originator.

**12.2.3 Notes**
An implementation using a Git repository naturally satisfies these requirements. Each commit is an Instance Version, the commit history provides the ordered sequence, and GPG signing of commits provides non-repudiation.

**12.3 Interoperability Integrity**

**12.3.1 Normative**
A registry conforming to this specification MUST provide a machine-readable export of its full history, including all `Record Revisions` and the sequence of `Registry Instance Versions`. The serialization format for this export is defined in Section 15.

**12.3.2 Rationale**
This provides the foundation for `Federation` and `Interoperability` (Section 13, future work). It allows independent third parties to replicate, verify, and build services upon the registry's complete governance history, ensuring the integrity of the ecosystem beyond a single canonical implementation.

### **13. Registry Interoperability (Placeholder)**

*(This section is reserved for future editions of the standard to define protocols for registry federation, replication, and cross-register event notification.)*

### **14. Conformance**

**14.1 Conformance Classes**

**14.1.1 Normative**
An implementation SHALL be evaluated against one of the following conformance classes:
- **Core Conformance:** The implementation satisfies all normative requirements in Sections 6-12.
- **Interoperability Conformance:** The implementation meets all requirements for Core Conformance AND all normative requirements in Section 13 (when defined).

**14.2 Conformance Requirements**

**14.2.1 Normative**
A claim of conformance to this specification SHALL declare the `Registry Edition` (`1.0`) and the `Conformance Class` being claimed. To be conformant, an implementation MUST satisfy all of the following requirements for its claimed class, as verified by the assertions in RM-CPR-CTS-1.0:

1.  **Constitutional Conformance:** The implementation operates under the authority of the artifacts specified in the `Baseline Identifier` (6.5).
2.  **Identity Conformance:** The implementation correctly manages all identity and versioning schemes for the Registry, Records, and Instances (6, 7, 8).
3.  **State Conformance:** The implementation correctly enforces the four-layer state management architecture (10).
4.  **Operational Conformance:** The implementation correctly implements the `CREATE`, `READ`, and `UPDATE` operations with their specified invariants (11).
5.  **Integrity Conformance:** The implementation guarantees the integrity principles of legitimacy, continuity, and ordering (12).

**14.3 Conformance Preservation Principle**

**14.3.1 Normative**
Future editions of this standard SHALL be designed to preserve backward-compatible conformance where possible. If a future edition introduces a breaking change, it MUST specify a clear transition path for existing conformant implementations.

**14.3.2 Rationale**
This principle provides long-term stability and investment protection for implementers. It ensures that the governance framework evolves in a predictable and manageable way.

---

## **Part IV: Constitutional Freeze Declaration**

### **15. Declaration of Freeze**

As of the publication date of this document, **Sections 1–14 are declared constitutionally frozen**. The normative requirements contained within these sections form the immutable core of RM-CPR-1.0. Subsequent artifacts, including extensions or new editions of this standard, MUST NOT contradict the principles and requirements of this frozen core, in accordance with the Conformance Preservation Principle (14.3).

### **16. Next Governance-Safe Artifact**

The next artifact to be developed under the RM-CPR-1.0 governance framework is the **RM-CPR-CTS-1.0 (Conformance Test Suite)**. This artifact is considered "governance-safe" because its role is to verify, not define, the normative core. It operationalizes the frozen constitution into machine-verifiable assertions.

### **17. Informative Sections**

Sections of this specification published after this declaration and not explicitly included in the frozen core (such as implementation guides or usage examples) are considered informative.
