# Security Review — OmegaActual / Omni-Sentinel Smart Contracts

**Target:** `governance_blueprint/OmegaActualTreatyEngine.sol`
**Reviewer role:** Enterprise AI safety & governance architect (G-SIFI)
**Compiler:** solc 0.8.26 (both original and hardened compile with 0 errors/warnings)
**Hardened rewrite:** `contracts/OmegaActualTreatyEngineHardened.sol`
**Method:** manual review + compilation; behavioural assertions in `test_contract_logic.py`

> Scope note: this is a design/blueprint review, not a production audit. A
> production deployment additionally requires a third-party audit, full EVM
> integration tests (Foundry/Hardhat), reentrancy analysis of any external calls,
> and on-chain verification of the TEE/TPM attestation proof.

## Findings

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| SEC-01 | **Critical** | `approveTreaty` has no access control and no existence check | Fixed |
| SEC-02 | **Critical** | `recordHeartbeat` is unauthenticated — anyone can defeat the dead-man's switch | Fixed |
| SEC-03 | High | Containment latch has no controlled re-arm path; mixed responsibilities | Fixed |
| SEC-04 | Medium | Treaty can be re-proposed over an active one (state clobber) | Fixed |
| SEC-05 | Medium | Missing events on admin/state-changing operations (auditability) | Fixed |
| SEC-06 | Low | Magic constants / timestamp semantics undocumented | Fixed |

### SEC-01 — Unauthenticated, existence-blind treaty ratification (Critical)

```solidity
function approveTreaty(bytes32 treatyId) external {
    require(!approvals[treatyId][msg.sender], "Already approved");
    treaties[treatyId].currentApprovals++;
    ...
    if (treaties[treatyId].currentApprovals >= treaties[treatyId].quorumRequired) {
        treaties[treatyId].active = true;   // quorumRequired defaults to 0!
```

Two compounding problems:
1. **No approver allow-list.** Any externally-owned account can call `approveTreaty`.
2. **No existence check.** For an `treatyId` that was never proposed, `quorumRequired`
   is the default `0`, so `currentApprovals (1) >= 0` is immediately true and the
   attacker **ratifies an arbitrary treaty in a single transaction**, emitting
   `TreatyRatified` and flipping `active = true`.

**Impact:** complete bypass of multi-sig treaty governance — the core control this
contract exists to enforce. Maps to a failure of SR 11-7 model-change control and
EU AI Act Art. 14 human oversight.

**Fix (hardened):** `isApprover` allow-list (CASO-managed), `t.exists` check,
`active` check, and `proposeTreaty` rejects `quorum == 0`.

### SEC-02 — Unauthenticated heartbeat defeats containment (Critical)

```solidity
function recordHeartbeat() external {
    lastHeartbeat = block.timestamp;   // any caller
```

The dead-man's switch trips only if `block.timestamp - lastHeartbeat > THRESHOLD`.
Because **any address** can refresh `lastHeartbeat`, an adversary (or a compromised
model attempting to evade containment) can keep the switch from ever firing.

**Impact:** the containment kill-switch — the highest-severity safety control — is
trivially neutralised. Directly contradicts the TLA+ `KillSwitchIntegrity` invariant.

**Fix (hardened):** `isMonitor` allow-list, reject heartbeats once `containmentTripped`
(latched), and a documented hook to verify the TEE/TPM attestation proof on-chain.

### SEC-03 — No controlled re-arm; latch semantics unclear (High)

The original `checkLiveness` sets `containmentEnforced = true` but the heartbeat path
keeps updating `lastHeartbeat`, so the relationship between "enforced" and "live" is
ambiguous and there is no safe way to return to service after a trip.

**Fix:** containment is a single latched boolean `containmentTripped`; `rearm()` is
CASO-gated and requires a **fresh** heartbeat (`now - lastHeartbeat <= THRESHOLD`),
mirroring the TLA+ model's latched-TRIPPED posture with an explicit out-of-band rearm.

### SEC-04 / SEC-05 / SEC-06

- **SEC-04:** `proposeTreaty` now reverts `TreatyAlreadyActive` to prevent clobbering.
- **SEC-05:** events added for `MonitorSet`, `ApproverSet`, `TreatyProposed`,
  `TreatyApproved`, `ContainmentRearmed` — supervisory log completeness (EU AI Act
  Art. 12, DORA ICT logging).
- **SEC-06:** custom errors (gas-efficient, explicit), `immutable` CASO, documented
  constants.

## Compliance mapping

| Finding | Regime touchpoint |
|---------|-------------------|
| SEC-01 | SR 11-7 (model-change control), EU AI Act Art. 14 (human oversight) |
| SEC-02 | EU AI Act Art. 15 (robustness), DORA (operational resilience) |
| SEC-03 | DORA (recovery), NIST AI RMF (Manage) |
| SEC-05 | EU AI Act Art. 12 (logging), GDPR Art. 30 (records) |

## Verification

```bash
cd governance_blueprint/contracts
npm install                      # solc@0.8.26
node compile.js                  # both contracts compile, 0 errors
python3 test_contract_logic.py   # asserts the SEC-01/02 exploits on a Python model
                                 # of the original, and their absence in the hardened model
```
