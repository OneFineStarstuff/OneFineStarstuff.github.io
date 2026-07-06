# Team Rehearsal Checklist & Post-Demo Debrief Framework

This document provides a structured framework for internal team rehearsals and the subsequent debriefing process following a regulator demonstration.

## 1. Team Rehearsal Checklist
- **[ ] Timing Cues:** Does each section (Vision, Architecture, Verification, Drill) fit within its allocated slot?
- **[ ] Handoffs:** Are transitions between the ASO, Technical Lead, and Verification Lead seamless?
- **[ ] Live Segments:** Have the Verifier Node CLI and TLA+ Toolbox been tested on the demo-day hardware?
- **[ ] Fallback Drills:** Can the team switch to pre-recorded "Gold Path" videos in under 30 seconds?
- **[ ] Q&A Role-play:** Has the team practiced the "Anticipated Questions" from the Briefing Deck?

## 2. Rehearsal Scorecard
| Category | Metric | Target | Result |
| :--- | :--- | :---: | :---: |
| **Technical** | Verifier CLI command execution time. | < 10s | |
| **Pace** | Architecture walkthrough duration. | 20 min | |
| **Assurance** | Clear link between TLA+ and live drift. | Yes/No | |
| **Clarity** | ZK-Privacy concept explanation. | High | |

## 3. Post-Demo Debrief Framework (Internal)
**Date:** [Date]
**Lead:** Chief AI Safety Officer (ASO)

### What Went Well?
- (e.g., Regulator was impressed by the MTTC of 450ms).
- (e.g., The Verifier Node CLI demonstration was the high point of the session).

### Technical & Procedural Hiccups
- (e.g., Slight delay in ZK proof generation due to enclave resource contention).
- (e.g., One regulator question on SIP v3.0 gossip topology was too deep for the current handout).

### Regulator Sentiment & Feedback Capture
- **Key Concern:** "How do we verify the fairness circuit itself?"
- **Key Interest:** "Can we use this for non-AI ICT systems as well?"

### Sandbox Issue Tracker Usage
- [ ] Create Issue #428: "Expand SIP v3.0 topology diagram in Takeaway Packet."
- [ ] Create Issue #429: "Optimize Groth16 prover memory footprint."

## 4. 24-Hour Reflection Document
A summary of the debrief sent to the Board Risk Committee to confirm institutional readiness for live promotion.
