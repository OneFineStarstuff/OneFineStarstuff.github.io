# Edition 1 SAF Campaign: Architectural and Operational Framework

**Document ID:** SAF-OP-ED1-2026  
**Status:** Normative / Frozen Baseline  
**Authority:** Sentinel AI Governance Suite (Edition 1)  
**Classification:** Public / Regulatory Specification  

---

## 1. Governance Stack & Architectural Hierarchy

### 1.1 Architectural Closure and Specialization
The Edition 1 SAF Campaign is governed by a hierarchical dependency model designed to ensure that domain-specific extensions do not corrupt the stable semantic kernel.
*   **Layer 0: Semantic Kernel (§3A/B):** The frozen normative core providing common assessment semantics (Identity, Lineage, Successor, Adoption).
*   **Layer 1: DS-SAF-001 (Safety Specialization):** A normative proposal that extends Layer 0 by defining safety-specific invariants and criteria.
*   **Layer 2: VP-ED1 (Validation Protocol):** The invariant execution logic governing how evidence is collected, analyzed, and evaluated.

### 1.2 The Design Completion Principle
Validation may only commence once Layer 0 and Layer 1 are in a `FROZEN` or `PROPOSED` state. The **Design Completion Principle** mandates that the architecture is structurally complete prior to the first execution event (E1), preventing "on-the-fly" specification changes that would invalidate evidence reproducibility.

### 1.3 Immutability Levels and Acyclic Dependency
*   **Level 1 (Governance Artifacts):** Immutable upon publication (e.g., §3A, Edition 1 Baseline).
*   **Level 2 (Execution Records):** Append-only; once an identifier (e.g., EV-SAF-002) is committed to the campaign ledger, its content is immutable.
*   **Acyclic Dependency Rule:** Records must only reference identifiers that preceded them in the provenance chain. Forward-referencing is strictly prohibited to maintain causal integrity.

---

## 2. Operational Methodology: Evidence-First Validation

### 2.1 The Normative Provenance Chain
The framework enforces a rigorous, directional flow of information to prevent analytical bias and ensure that evaluations are grounded in empirical fact:
1.  **DS (Domain Specialization):** Defines *what* is being tested.
2.  **EV (Evidence):** Captures *raw observations* without interpretation.
3.  **AN (Analysis):** Applies *analytical methodology* to the EV- record.
4.  **Validation Basis:** A logical binding of EV and AN into a substrate for evaluation.
5.  **INV (Invariant Evaluation):** Records a *time-local finding* (Satisfied, Unsatisfied, Inconclusive).
6.  **VC (Validation Conclusion):** Aggregates INV results for a specific cycle.
7.  **VR (Validation Report):** The final governance summary of the exercise.

### 2.2 The Mapping Justification Rule
Informative justifications (Mapping Justifications) may accompany records but are explicitly flagged as non-evidential. They explain *why* a specific piece of evidence maps to a specific invariant without substituting for the evidence itself.

### 2.3 Monotonic Provenance Model
The **Validation Basis** is a monotonic set. New evidence (EV-SAF-002) expands the substrate available for evaluation but does not delete or overwrite the substrate established by EV-SAF-001. This ensures a "perfect memory" of the campaign's progress.

---

## 3. Execution Plan: VA-001 & EV-SAF-002 Cycle

### 3.1 EV-SAF-002 Cycle Checklist
The second execution cycle (Cycle 02) is the first to carry substantive domain data. Reviewers must verify:
- [ ] **Direct Observability:** Evidence contains no internal conclusions.
- [ ] **Independent Reproducibility:** A third party could recreate the EV record using the same inputs.
- [ ] **Context Invariance:** The environment (CTX-) of the execution is fully recorded.
- [ ] **Basis Expansion:** AN-SAF-002 materially adds to the Validation Basis.

### 3.2 Evaluation Locality (INV-SAF-n)
Evaluations (INV-SAF-001, INV-SAF-002) are **time-local**. An `INCONCLUSIVE` result in INV-SAF-001 does not imply a failure of the safety domain; it merely records that the evidence available at $T_1$ was insufficient. Truth is emergent through the accumulation of cycles.

---

## 4. Semantic Kernel & Governance Invariants

### 4.1 The Three Normative Invariants
1.  **Record Immutability:** Once a hash is generated for a record, it is never altered.
2.  **Monotonic Provenance:** The evidence graph only grows; it never prunes.
3.  **Evaluation Locality:** Conclusions are valid only for the specific evidence cited.

### 4.2 S1/P1/I1 Diagnostic Framework
Gaps identified during the campaign must be classified to guide Edition 2 evolution:
*   **S1 (Semantic Gaps):** The kernel (§3A/B) lacks the vocabulary to describe an observation.
*   **P1 (Process Gaps):** The protocol (VP-ED1) was followed but failed to produce actionable evidence.
*   **I1 (Infrastructure Gaps):** Tooling or automation (EXECOBJ) prevented successful execution.

---

## 5. Campaign Event Log & Findings

### 5.1 Event Logging (E1–E6)
The Campaign Event Log is the authoritative ledger of the campaign's lifecycle. Each entry must record:
- **Event ID:** (e.g., E4)
- **Timestamp:** ISO 8601
- **Record Impacted:** (e.g., INV-SAF-002 created)
- **Governance State:** (e.g., VALIDATION_COMMENCED)

### 5.2 Synthesis of Findings
The final stage of the SAF campaign involves aggregating all `INCONCLUSIVE` or `UNSATISFIED` INV- records to determine if the result stems from a domain failure or an architectural limitation of Edition 1. This synthesis forms the "Evidence-Based Roadmap" for future governance editions.