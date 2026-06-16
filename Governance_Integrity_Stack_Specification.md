# Governance Integrity Stack Specification v1.0

**Status:** Draft for Review
**Audience:** Supervisory Technology (SupTech) Architects, Standards Bodies, Regulated Institutions, Assurance & Certification Bodies
**Purpose:** This document specifies the core operational, conformance, and trust layers of the governance-integrity architecture. It provides the reference designs for querying the Governance Knowledge Graph (GKG), executing standardized workflows, and ensuring trust and conformance across the ecosystem.

---

## Part 1: Governance Knowledge Graph Query Language (GKQL v1.0)

### 1.1. Overview

GKQL is not a new query language. It is a hybrid API specification that combines the simplicity of REST/GraphQL for predefined queries with the power of SPARQL for complex graph traversals. This allows for broad accessibility while enabling deep forensic analysis.

### 1.2. API Specification (Extending GIRAM-API)

The GIRAM-API is extended with the following endpoints, which constitute the GKQL.

```yaml
openapi: 3.1.0
# ... (info, security, etc. from GIRAM-API v1.0) ...

paths:
  # ... (existing /controls, /metrics paths) ...

  /query/sparql:
    post:
      summary: Execute a raw SPARQL query against the GKG
      description: For complex, exploratory analysis and forensic investigations.
      requestBody:
        required: true
        content:
          application/sparql-query:
            schema:
              type: string
              example: "SELECT ?control ?threat WHERE { ?control gito:mitigates ?threat . }"
      responses:
        '200':
          description: SPARQL query results in JSON format.
          content:
            application/sparql-results+json: { }

  /query/lineage:
    get:
      summary: Get the lineage for a specific governance artifact
      description: A predefined query to trace dependencies upwards (e.g., from a metric to the control that influences it).
      parameters:
        - name: entityId
          in: query
          required: true
          schema: { type: string, example: "gidd:metric:01" }
      responses:
        '200':
          description: A graph visualization of the entity's lineage.
          content:
            application/json:
              schema: { $ref: '#/components/schemas/GraphObject' }

  /query/impact:
    get:
      summary: Get the downstream impact of a specific governance artifact
      description: A predefined query to trace dependencies downwards (e.g., from a control to the regulations it satisfies).
      parameters:
        - name: entityId
          in: query
          required: true
          schema: { type: string, example: "gicc:control:01" }
      responses:
        '200':
          description: A graph visualization of the entity's impact.
          content:
            application/json:
              schema: { $ref: '#/components/schemas/GraphObject' }

components:
  schemas:
    GraphObject: # Defines a simple nodes-and-edges graph structure for responses
      type: object
      properties:
        nodes: { type: array, items: { /* node object */ } }
        edges: { type: array, items: { /* edge object */ } }
# ... (other components)
```

---

## Part 2: Governance Integrity Workflow Library (GIWL v1.0)

### 2.1. Overview

The GIWL is a standardized catalog of machine-executable workflow templates. It ensures that complex assurance and supervisory processes are repeatable, auditable, and consistent across institutions. These workflows are designed to run on a **Governance Integrity Workflow Service (GIWS)**, which is a core component of the **Governance Integrity Enterprise Middleware (GIEM)**.

### 2.2. Template Formats

*   **BPMN 2.0 (Business Process Model and Notation):** For orchestrating the sequence of tasks, human interactions, and API calls.
*   **DMN 1.3 (Decision Model and Notation):** For encapsulating and executing the business rules that guide the workflows.

### 2.3. Catalog of Key Workflow Templates

| Template ID | Name | Description | Trigger | Key Steps |
| :--- | :--- | :--- | :--- | :--- |
| **GIWL-CERT-01** | GICF Conformance Certification | Annual workflow to certify a vendor tool or an institution's stack against the GICF. | Manual (Annual) | Run GIRTH test suite -> Collect Evidence -> Invoke human auditor via tasklist -> Issue/Deny digital certificate. |
| **GIWL-REM-01** | GSA Hash Mismatch Remediation | Automated workflow to manage a critical Governance-State Attestation failure. | GOM Alert: `gsa.hash.mismatch` | Create incident ticket -> Freeze affected system -> Notify AI Risk Officer -> Execute diagnostic tests -> Rollback to last known good state. |
| **GIWL-OBS-01** | New Metric Onboarding | Workflow for adding a new metric to the GIDD and connecting it to the GOM. | Manual | Update GIDD-DS -> Deploy new telemetry collector -> Validate stream in GOM -> Update GKG with new node. |
| **GIWL-SUP-01** | Supervisory Data Call | Workflow for an institution to respond to a GIRS-based data call from a supervisor. | API Call from Regulator | Query GKG via GKQL -> Assemble GIRS report -> Human review & sign-off -> Submit signed GIRS via GIRAM-API. |

---

## Part 3: Governance Integrity Conformance Framework (GICF v1.0)

### 3.1. Overview

The GICF defines *how to be compliant* with the governance-integrity architecture. It ensures that a tool from Vendor A can interoperate with a platform from Vendor B and be trusted by a supervisor.

### 3.2. Conformance Classes

An implementation must claim conformance to one or more of the following classes:

*   **Class GKG-P (GKG Provider):** A system that exposes a GKG via the GKQL API (e.g., a graph database).
*   **Class GOM-E (GOM Emitter):** A system that emits governance telemetry according to GOM specifications (e.g., an SCP).
*   **Class GIWS-E (GIWS Engine):** A system that can execute GIWL workflow templates.
*   **Class GIRS-C (GIRS Consumer):** A system that can ingest and parse GIRS reports (e.g., a supervisory platform).

### 3.3. Certification Criteria (Example for Class GKG-P)

*   **Interoperability Profile:** Must expose all GKQL endpoints as defined in GIRAM-API v1.0.
*   **Implementation Requirement:** Must use mTLS for authentication as defined in GITAF v1.0.
*   **Certification Requirement:** Must pass at least 98% of the tests in the **GIRTH** GKG-P test suite.

---

## Part 4: Governance Integrity Reference Implementation (GIRI v1.0)

### 4.1. Overview

The GIRI is an architectural blueprint for a fully-functional, open-source prototype that operationalizes the entire stack. Its purpose is to prove the specifications are viable and to provide a starting point for vendors and institutions.

### 4.2. High-Level Architecture

*   **GOM Ingestor:** A microservice that listens for telemetry streams (e.g., via Kafka) and persists them.
*   **GKG Database:** A graph database (e.g., Neo4j) that implements the GIMM-Meta and is populated by GOM events.
*   **GKQL API Gateway:** An API gateway that exposes the GKQL endpoints and translates them into queries for the GKG database.
*   **GIWS Workflow Engine:** A BPMN/DMN engine (e.g., Camunda) loaded with the GIWL templates.
*   **GIRS Reporting Service:** A service that can be triggered by the GIWS to query the GKG and generate GIRS reports.
*   **GIRTH (Governance Integrity Reference Test Harness):** A suite of automated tests (e.g., using Postman/Newman) that continuously runs against the GIRI components to validate GICF conformance.

### 4.3. Use Case Example: End-to-End Assurance

1.  The `GIRTH` runs a test that simulates a policy violation in a governed AI model.
2.  The model's host emits a `gito:telemetry` event to the `GOM Ingestor`.
3.  The event updates the state of a `gidd:metric` node in the `GKG Database`.
4.  The metric change triggers a rule in the `GIWS Engine`, initiating the `GIWL-REM-01` remediation workflow.
5.  A supervisor queries the `GKQL API Gateway` to view the incident report, which was generated by the workflow.

---

## Part 5: Governance Integrity Trust Architecture Framework (GITAF v1.0)

### 5.1. Overview

The GITAF defines the cryptographic trust layer that underpins the entire ecosystem. It answers the question: "Why should I trust this data?" It extends beyond simple transport security (mTLS) to data-at-rest and data-in-use.

### 5.2. Core Components

1.  **Identity & Actors:** Every entity (human users, institutions, software services like an SCP, AI models themselves) must have a unique, cryptographically verifiable identity, typically based on the X.509 standard.

2.  **Trust Anchors:** A small number of root Certificate Authorities (CAs) operated by the primary supervisory bodies. These CAs form the ultimate root of trust for the ecosystem.

3.  **Attestation Chains:** Trust is established through chains of digital signatures that lead back to a Trust Anchor.
    *   **Example:** An AI model produces a prediction. The prediction is signed by the model's key. The model's certificate was signed by the institution's intermediate CA. The institution's certificate was signed by the supervisory Trust Anchor. A verifier can traverse this chain to confirm the prediction came from a legitimate model at a regulated institution.

4.  **Evidence Signing:** All evidence artifacts (GSA hashes, logs, GIRS reports) **MUST** be digitally signed before being submitted to the GKG or a supervisor. The signature provides non-repudiation and integrity.

5.  **Federation & Revocation:** The framework specifies protocols for cross-jurisdictional trust (federation) and for revoking trust when an entity is compromised (e.g., via Certificate Revocation Lists or OCSP).

**Integration:** The `security` section of the GIRAM-API, which specifies mTLS, is a direct implementation of the GITAF's identity and transport security requirements. The requirement for signed GIRS reports is an implementation of the evidence signing requirement. Gitaf provides the "why," and the other specs provide the "how."