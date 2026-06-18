# Visual Design Guide: SCP Regulator Cockpit & Briefing Materials

This guide defines the aesthetic and informational standards for all regulator-facing interfaces and artifacts within the Supervisory Control Plane (SCP) sandbox.

## 1. Core Aesthetic: "The High-Assurance Cockpit"
The design should reflect precision, mathematical rigor, and real-time operational readiness.

- **Primary Palette:** Deep Charcoal (#1A1A1B), Slate Blue (#2D3748), and Regulatory Gold (#ECC94B) for highlights.
- **Status Colors:**
  - **Success (Compliant):** Emerald Green (#38A169).
  - **Caution (G-SRI Drift):** Amber Orange (#D69E2E).
  - **Critical (Quarantine):** Crimson Red (#E53E3E).
- **Typography:** Inter or Roboto Mono for data-heavy views (Verifier Node CLI); San Francisco or Segoe UI for executive summaries.

## 2. Dashboard Information Hierarchy
- **Layer 1 (The Pulse):** Top-level G-SRI score and Attestation Heartbeat (Must be visible at all times).
- **Layer 2 (The Flow):** D3.js topological map of active agent interactions and GSM states.
- **Layer 3 (The Proof):** Verification log showing proof hashes and Merkle root anchoring timestamps.

## 3. Briefing Deck Design (Slides)
- **Contrast:** High contrast between text and background to ensure legibility during remote screen shares.
- **Visual Evidence:** Every slide claiming "Safety" or "Compliance" must include a small "Formal Logic Anchor" icon linked to the relevant TLA+ spec or ZK circuit.
- **Diagrams:** Use Mermaid.js or stylized SVG for architecture maps; avoid low-resolution bitmaps.

## 4. Documentation Standards (PDF/OSCAL)
- **Branding:** Consistent use of the institution's AI Safety seal and PQC-WORM signature watermark.
- **Metadata:** All exported reports must include a "Verification Metadata Block" on the first page, listing the ML-DSA-65 public key and Merkle root.

## 5. Verifier Node CLI Aesthetic
- **Color Coding:** Consistent with the Status Colors (Green/Amber/Red).
- **Progress Indicators:** Use ASCII progress bars for multi-step ZK proof verifications to provide immediate feedback to the technical auditor.
