# Supervisory FAQ: Security, Privacy, and Non-Repudiation

## 1. Security & Containment
**Q: What prevents the AI model from disabling its own sidecar?**
**A:** The sidecar and the model run in separate memory spaces within the TEE (AMD SEV-SNP). The SCP Core uses TLA+ verified invariants to ensure that any attempt to bypass the sidecar results in immediate hardware-level compute throttling.

**Q: Is the "Kill-Switch" actually a human or an automated process?**
**A:** It is both. The SCP Core can execute an **Autonomous Containment** action based on threshold breaches (e.g., G-SRI > 85). However, moving from "QUARANTINE" back to "PROD" requires a multi-sig human supervisory quorum.

## 2. Privacy & Data Sovereignty
**Q: Why can't I see the raw telemetry for every decision?**
**A:** G-SIFIs process highly sensitive consumer and market data. ZK-Compliance allows you to perform your supervisory duty with 100% mathematical certainty without the liability of handling PII or proprietary IP.

**Q: Can the institution "cherry-pick" which proofs it shares?**
**A:** No. The Merkle log anchoring ensures that for every model action, there is a corresponding entry in the append-only WORM log. If an entry is missing, the Verifier Node will flag a "Gap in Sequence."

## 3. Non-Repudiation
**Q: How do I know the institution didn't rewrite its history after an incident?**
**A:** The PQC-WORM fabric uses S3 Object Lock in COMPLIANCE mode. Once a block is written and the Merkle root is gossiped via SIP v3.0, it cannot be deleted or modified by anyone—including the institution's admins.

**Q: What happens if the institution's PQC keys are compromised?**
**A:** The **PQC Key Management Policy** defines a rapid revocation protocol. A Revocation Token is broadcast to the GIEN mesh, and all Verifier Nodes will immediately stop trusting signatures from that key until a verified re-key event occurs.
