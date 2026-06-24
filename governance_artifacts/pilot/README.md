# 2028 G-SIFI Pilot — Acceptance Gates

`run_pilot_acceptance_gates.py` operationalizes §14 of
`governance_blueprint/DECADAL_STRATEGIC_TECHNICAL_PLAN_2026_2035.md` as a runnable checklist.

```bash
python3 governance_artifacts/pilot/run_pilot_acceptance_gates.py
python3 governance_artifacts/pilot/run_pilot_acceptance_gates.py --json   # machine-readable
```

Each of the six monthly pilot gates is one of:

- **AUTOMATED (Tier A):** actually executed against in-repo artifacts (Terraform validate, OPA
  gates, PQC WORM tamper test, containment TLC, zk relayer, full assurance suite). The script
  reports a real PASS/FAIL.
- **MANUAL (Tier B):** depends on real hardware / vendor accounts / a supervisor. The script does
  **not** fake these — it prints the precise acceptance criterion and the evidence the pilot team
  must capture, and marks them `PENDING-EVIDENCE`.

**Exit code** is non-zero only if an *automated* gate fails. Manual gates never fail the run
(faking them would violate the program's integrity discipline). The pilot go-decision requires all
automated gates green **and** all manual evidence items collected and signed off.

| Month | Automated gate | Manual / Tier-B gate |
|-------|----------------|----------------------|
| 1 | P1-IAC (terraform validate) | P1-ATTEST (PCR_MATCH=TRUE on real HW) |
| 2 | P2-OPA (policy gates green) | P2-MOE (drift index ≤ 0.1 on live model) |
| 3 | P3-WORM (tamper detected) | P3-GSRI (prod Kafka/S3 Object Lock) |
| 4 | P4-CONTAIN (containment TLC) | P4-MTTC (Red-Dawn MTTC ≤ 60s) |
| 5 | P5-ZK (relayer verifier compiles) | P5-DOSSIER (Annex IV ≥ 98% auto) |
| 6 | P6-REPRO (assurance 12/12) | P6-SUPERVISOR (supervisor sign-off) |
