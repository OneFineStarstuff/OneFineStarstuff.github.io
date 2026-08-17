# **Registry Manifest (RM) Standard**
## **Part 7: Registry Exchange Profile**
### **RM-CPR-EXCH-1.0 — Version 1.0**

---

### **1. Scope**

This document defines the normative specification for the **RM-CPR Exchange Profile**. It provides a standardized, machine-readable format for the complete, lossless export and import of an RM-CPR-1.0 conformant registry's entire state and history.

### **2. Normative References**

- **RM-CPR-1.0:** Change Proposal Register, Version 1.0

### **3. Exchange Object Model**

**3.1 Root Object**

**3.1.1 Normative**
The exchange format SHALL be a single JSON object, designated the `RegistryExchangeObject`. This object SHALL contain two top-level fields: `metadata` and `history`.

**3.2 Metadata Object**

**3.2.1 Normative**
The `metadata` object SHALL contain information about the registry instance from which the export was generated. It MUST contain the following fields:
- `registryIdentifier`: The identifier of the source registry (from RM-CPR-1.0, Sec 6.1).
- `registryEdition`: The edition of the source registry (from RM-CPR-1.0, Sec 6.2).
- `exportTimestamp`: The ISO 8601 timestamp of when the export was created.
- `lastInstanceVersion`: The `Registry Instance Version` of the final state captured in this export.

**3.3 History Array**

**3.3.1 Normative**
The `history` field SHALL be a JSON array. Each element in the array MUST be a `HistoryEntry` object. The array MUST be ordered chronologically from the first `Registry Instance Version` to the last.

**3.4 HistoryEntry Object**

**3.4.1 Normative**
Each `HistoryEntry` object represents a single, atomic state transition in the registry. It MUST contain the following fields:
- `instanceVersion`: The `Registry Instance Version` created by this state transition.
- `timestamp`: The timestamp of the transition.
- `operation`: The operation that triggered the transition (`CREATE` or `UPDATE`).
- `recordId`: The `Record Identifier` of the record that was created or updated.
- `recordState`: A complete JSON object representing the full state of the record **after** the operation, including its new `Record Revision` number.

### **4. Example Exchange Object**

```json
{
  "metadata": {
    "registryIdentifier": "gito:register:RM-CPR-1.0",
    "registryEdition": "1.0",
    "exportTimestamp": "2024-05-22T14:00:00Z",
    "lastInstanceVersion": "a1b2c3d5"
  },
  "history": [
    {
      "instanceVersion": "e6f7g8h9",
      "timestamp": "2024-05-21T10:00:00Z",
      "operation": "CREATE",
      "recordId": "gito:cp:2024-001",
      "recordState": {
        "id": "gito:cp:2024-001",
        "revision": 1,
        "governance": { "state": "DRAFT" },
        "description": "Initial proposal."
      }
    },
    {
      "instanceVersion": "a1b2c3d5",
      "timestamp": "2024-05-22T13:59:00Z",
      "operation": "UPDATE",
      "recordId": "gito:cp:2024-001",
      "recordState": {
        "id": "gito:cp:2024-001",
        "revision": 2,
        "governance": { "state": "TRIAGE" },
        "description": "Initial proposal with updates."
      }
    }
  ]
}
```

### **5. Conformance**

An implementation claiming **Interoperability Conformance** (as defined in RM-CPR-1.0, Sec 14.1) MUST be able to generate and parse a `RegistryExchangeObject` that fully adheres to this specification.
