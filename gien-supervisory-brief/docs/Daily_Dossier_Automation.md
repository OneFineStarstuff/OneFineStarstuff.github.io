# Daily Dossier Automation — Design and CI Contract

## Pipeline

1. **Collect** — telemetry store, OSCAL service, WORM ledger reader, attestation API and CI API are polled at 08:55Z; the snapshot is frozen at 09:00:00Z exactly.
2. **Compute** — indices are recomputed from raw counters, not copied, using the same deterministic functions the UI uses. The window hash is `sha256(canonical_json(snapshot))`.
3. **Bundle** — the snapshot plus index results become a Merkle tree; the root is signed with ML-DSA-65 and anchored to Rekor and the WORM ledger.
4. **Draft** — a fixed template renders every required section. An LLM may only rephrase from the snapshot facts; any number not present in the snapshot fails validation.
5. **Review** — a named supervisor approves or rejects. Rejection is recorded; nothing is published unsigned.
6. **Publish** — signed dossier to the repository, the supervisory portal and the college distribution list, with the evidence root in the header.
7. **Seal** — at 23:59Z the cycle closes and the archive seal is written.

## Freshness contract

The portal renders a dossier only if it is under 26 hours old, its signature verifies, and its embedded index values hash to the recorded snapshot. On breach it shows a DEGRADED banner and the last valid dossier rather than a stale one presented as current.

## CI gate

```yaml
name: dossier-freshness
on: [pull_request, workflow_dispatch]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Latest dossier age and signature
        run: ./tools/verify-dossier.sh --max-age-hours 26 --require-signature
      - name: Index values match snapshot root
        run: ./tools/verify-dossier.sh --check-index-hash
```

The same script backs the supervisor verification harness, so what CI enforces and what a regulator checks cannot diverge.

## Failure handling

| Failure | Behaviour |
|---|---|
| Collector late | Publish with an explicit DEGRADED section naming the missing source; do not interpolate values |
| Signature failure | Block publication; alert the signing service owner |
| Snapshot changed between draft and sign | Discard the draft and regenerate from the signed snapshot |
| Review timeout | Escalate to the deputy supervisor; publication remains blocked |
| Ledger anchor unreachable | Queue with a timestamped retry; publication marks the anchor PENDING |

## Determinism rules

Seeded PRNG only; no `Date.now()` inside computed series; window boundaries fixed at 09:00:00Z; ordering stable by index id; floats rounded once at render. These four rules are what let a regulator replay a dossier months later and get the same numbers.
