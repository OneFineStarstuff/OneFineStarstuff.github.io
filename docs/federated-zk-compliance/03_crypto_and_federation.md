# 03 — zk Proof Pipeline and Verifier Federation

## Purpose
Define the cryptographic compliance lifecycle from evidence generation through supervisory verification, including federation governance.

## Proof Pipeline
1. Canonicalize and sign evidence events.
2. Build commitments for reporting windows.
3. Execute zk circuits for mapped controls.
4. Aggregate proofs recursively for submission efficiency.
5. Verify against jurisdiction policy profiles.
6. Publish evidence envelope and verifier receipts.

## Security Requirements
- Completeness and soundness.
- Non-malleability of supervisory submissions.
- Domain separation across institutions and jurisdictions.
- Key-rotation continuity and forward security.

## Verifier Federation Model
- Roles: national supervisor, regional supervisor, multilateral observer.
- Governance: threshold validation `(n,t)` and quorum publication.
- Challenge-response: time-bounded dispute procedures with evidence replay.
- Membership discipline: accession, suspension, reinstatement.

## Required Artifacts
1. Assumption register.
2. Proof-system profile matrix.
3. Federation policy configuration.
4. Challenge-response SOP.
