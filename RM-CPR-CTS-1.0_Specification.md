# **Registry Manifest (RM) Standard**
## **Part 5: Conformance Test Suite for the Change Proposal Register**
### **RM-CPR-CTS-1.0 — Version 1.0**

---

### **1. Scope**

This document defines the normative Conformance Test Suite (CTS) for implementations of the **RM-CPR-1.0** specification. It provides a set of machine-verifiable assertions that operationalize the requirements of the frozen constitutional core (Sections 1-14) of RM-CPR-1.0. An implementation MUST pass all applicable tests in this suite to claim conformance.

### **2. Normative References**

- **RM-CPR-1.0:** Change Proposal Register, Version 1.0 (specifically the frozen constitutional core, Sections 1-14).

### **3. Test Class Taxonomy**

Tests are organized into classes that directly correspond to the conformance requirements outlined in RM-CPR-1.0, Section 14.2.

- `GITO-C.CONSTITUTION`: Tests for Constitutional Conformance.
- `GITO-C.ID`: Tests for Identity Conformance.
- `GITO-C.STATE`: Tests for State Conformance.
- `GITO-C.OPS`: Tests for Operational Conformance.
- `GITO-C.INTEGRITY`: Tests for Integrity Conformance.

### **4. Assertion and Predicate Model**

**4.1 Assertion Structure**

Each assertion is a discrete, testable requirement derived from the RM-CPR-1.0 specification. Assertions are structured as follows:

- **`assertionId`**: A unique identifier linking directly to a test case (e.g., `GITO-C.ID-001`).
- **`description`**: A human-readable description of the test objective.
- **`predicate`**: A machine-verifiable statement that MUST evaluate to `true` for the test to pass.
- **`normativeReference`**: The specific section(s) in RM-CPR-1.0 that this assertion verifies.
- **`testType`**: `positive` (the required behavior occurs) or `negative` (an invalid action is correctly rejected).

**4.2 Example Assertion**

- **`assertionId`**: `GITO-C.OPS-001`
- **`description`**: "The CREATE operation must assign a valid, sequentially correct Record Identifier."
- **`predicate`**: `is_valid_gito_cp_id(new_record.id) && sequence_number(new_record.id) == sequence_number(previous_record.id) + 1`
- **`normativeReference`**: RM-CPR-1.0, Section 11.1.1
- **`testType`**: `positive`

### **5. Test Suite Assertions**

#### **5.1 GITO-C.CONSTITUTION: Constitutional Conformance**

| assertionId | description | normativeReference | testType |
|---|---|---|---|
| GITO-C.CONSTITUTION-001 | Registry correctly declares its Baseline Identifier. | 6.5.1 | positive |

#### **5.2 GITO-C.ID: Identity Conformance**

| assertionId | description | normativeReference | testType |
|---|---|---|---|
| GITO-C.ID-001 | Registry declares a valid `gito:register:RM-CPR-1.0` identifier. | 6.1.1 | positive |
| GITO-C.ID-002 | A new record is assigned a persistent, unique, and correctly formatted ID. | 8.1.1 | positive |
| GITO-C.ID-003 | Attempting to modify a Record Identifier on an existing record fails. | 8.1.1 | negative |
| GITO-C.ID-004 | A new record is assigned a Record Revision of `1`. | 8.2.1 | positive |

#### **5.3 GITO-C.STATE: State Conformance**

| assertionId | description | normativeReference | testType |
|---|---|---|---|
| GITO-C.STATE-001 | The `governance.state` field only accepts values from RM-ICT-1.0. | 10.1.1 | positive |
| GITO-C.STATE-002 | An attempt to set `governance.state` to an invalid value fails. | 10.1.1 | negative |
| GITO-C.STATE-003 | A state transition not authorized by RM-GCC-1.0 rules fails. | 10.2.1 | negative |
| GITO-C.STATE-004 | A state transition from `DRAFT` to `APPROVED` (an invalid hop) fails. | 10.3.1 | negative |

#### **5.4 GITO-C.OPS: Operational Conformance**

| assertionId | description | normativeReference | testType |
|---|---|---|---|
| GITO-C.OPS-001 | A successful CREATE operation initializes state to `DRAFT` and revision to `1`. | 11.1.1 | positive |
| GITO-C.OPS-002 | A successful CREATE operation generates a new Registry Instance Version. | 11.1.1 | positive |
| GITO-C.OPS-003 | A successful UPDATE operation increments the Record Revision number by one. | 11.3.1 | positive |
| GITO-C.OPS-004 | A successful UPDATE operation generates a new Registry Instance Version. | 11.3.1, 10.4.1 | positive |
| GITO-C.OPS-005 | An UPDATE operation with an invalid state transition fails and does not alter the record. | 11.3.1 | negative |

#### **5.5 GITO-C.INTEGRITY: Integrity Conformance**

| assertionId | description | normativeReference | testType |
|---|---|---|---|
| GITO-C.INTEGRITY-001 | A failed operation does not change the last known valid Registry Instance Version. | 12.1.1 | negative |
| GITO-C.INTEGRITY-002 | Each Registry Instance Version is unique and strictly sequential. | 12.2.1 | positive |
| GITO-C.INTEGRITY-003 | The registry can be restored to a previous valid Registry Instance Version. | 12.1.1 | positive |
