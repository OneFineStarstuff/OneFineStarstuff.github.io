# **Registry Manifest (RM) Standard**
## **Part 8: Constitutional Adversary Test Vectors**
### **RM-CPR-TVC-1.0 — Version 1.0**

---

### **1. Scope**

This document specifies a set of **Constitutional Adversary Test Vectors (TVC)** for RM-CPR-1.0. Unlike the standard conformance tests (CTS), which verify correct behavior, these vectors are designed to probe the constitutional boundaries of an implementation. They represent plausible but invalid inputs or operational sequences intended to cause a conformant registry to fail safely and predictably, proving its resilience.

### **2. Normative References**

- **RM-CPR-1.0:** Change Proposal Register, Version 1.0

### **3. Test Vector Structure**

Each test vector is defined as a sequence of one or more operations intended to be executed against a registry instance. The final operation in the sequence is the "adversarial" one.

- **`tvcId`**: A unique identifier for the test vector (e.g., `GITO-TVC-001`).
- **`description`**: A description of the adversarial goal.
- **`setup`**: An array of valid operations to bring the registry to the prerequisite state.
- **`adversarialOperation`**: The specific operation that attempts to violate a constitutional invariant.
- **`expectedOutcome`**: The normative behavior a conformant registry MUST exhibit (e.g., `OPERATION_FAILED_WITH_ERROR_CODE_X`).
- **`normativeReference`**: The constitutional invariant in RM-CPR-1.0 that this vector is designed to test.

### **4. Test Vectors**

#### **TVC-ID-001: Identifier Reassignment**
- **`tvcId`**: `GITO-TVC-ID-001`
- **`description`**: "Attempt to change the immutable ID of an existing record."
- **`setup`**: `[CREATE({id: "gito:cp:2024-001"})]`
- **`adversarialOperation`**: `UPDATE({id: "gito:cp:2024-001"}, {id: "gito:cp:2024-999"})`
- **`expectedOutcome`**: `OPERATION_FAILED`
- **`normativeReference`**: RM-CPR-1.0, Section 8.1.1

#### **TVC-STATE-001: Unauthorized State Transition**
- **`tvcId`**: `GITO-TVC-STATE-001`
- **`description`**: "Attempt to perform a state transition that violates the governance rules (e.g., a proposer tries to approve their own proposal)."
- **`setup`**: `[CREATE({proposer: "user_A"})]`
- **`adversarialOperation`**: `UPDATE({id: "..."}, {governance: {state: "APPROVED"}}, as_user="user_A")`
- **`expectedOutcome`**: `OPERATION_FAILED_UNAUTHORIZED`
- **`normativeReference`**: RM-CPR-1.0, Section 10.2.1

#### **TVC-INTEGRITY-001: History Tampering**
- **`tvcId`**: `GITO-TVC-INTEGRITY-001`
- **`description`**: "Attempt to directly modify a historical record revision that is not the latest."
- **`setup`**: `[CREATE(...), UPDATE(...)]` (The record is now at revision 2)
- **`adversarialOperation`**: `UPDATE({id: "...", revision: 1}, {description: "tampered"})`
- **`expectedOutcome`**: `OPERATION_FAILED_HISTORY_IMMUTABLE`
- **`normativeReference`**: RM-CPR-1.0, Section 12.2.1
