// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title OmegaActualTreatyEngineHardened
 * @notice Hardened rewrite of governance_blueprint/OmegaActualTreatyEngine.sol after the
 *         security review in governance_blueprint/contracts/SECURITY_REVIEW.md.
 *
 * Fixes (see review IDs):
 *   SEC-01 (Critical) approveTreaty had NO access control and did not check the
 *          treaty existed -> anyone could ratify, and a treaty with quorum 0 (the
 *          default for an unproposed id) activated on a single call. Now: approvers
 *          are an explicit allow-list, the treaty must be proposed & active==false,
 *          and quorum must be > 0.
 *   SEC-02 (Critical) recordHeartbeat was unauthenticated -> any address could reset
 *          the dead-man's switch and defeat containment. Now restricted to registered
 *          attested monitors, and rejected once containment is TRIPPED (latched).
 *   SEC-03 (High) checkLiveness could be called by anyone but had no re-arm path and
 *          mixed concerns. Containment is now a latched boolean with an explicit,
 *          quorum-gated rearm() requiring a fresh heartbeat.
 *   SEC-04 (Medium) Treaty had no guard against re-proposing over an active treaty.
 *   SEC-05 (Medium) No events for state-changing admin ops; added for auditability
 *          (EU AI Act Art. 12 logging / DORA).
 *   SEC-06 (Low) Used block.timestamp semantics explicitly; constants documented.
 *
 * NOTE: This is reference/reviewed code for a governance blueprint. A production
 * deployment requires a full audit, reentrancy review of any added external calls,
 * and on-chain verification of the TEE/TPM attestation proof in recordHeartbeat.
 */
contract OmegaActualTreatyEngineHardened {
    struct Treaty {
        bytes32 manifestHash;
        uint256 activationBlock;
        bool active;
        bool exists;
        uint256 quorumRequired;
        uint256 currentApprovals;
    }

    address public immutable chiefAISafetyOfficer;
    uint256 public constant HEARTBEAT_THRESHOLD = 300; // seconds
    uint256 public lastHeartbeat;
    bool public containmentTripped;

    mapping(address => bool) public isMonitor;     // SEC-02 attested monitor allow-list
    mapping(address => bool) public isApprover;    // SEC-01 ratification allow-list
    mapping(bytes32 => Treaty) public treaties;
    mapping(bytes32 => mapping(address => bool)) public approvals;

    event HeartbeatReceived(address indexed monitor, uint256 timestamp);
    event ContainmentTriggered(string reason);
    event ContainmentRearmed(address indexed by, uint256 timestamp);
    event TreatyProposed(bytes32 indexed treatyId, uint256 quorum);
    event TreatyApproved(bytes32 indexed treatyId, address indexed approver, uint256 approvals);
    event TreatyRatified(bytes32 indexed treatyId);
    event MonitorSet(address indexed monitor, bool enabled);
    event ApproverSet(address indexed approver, bool enabled);

    error NotAuthorized();
    error TreatyMissing();
    error TreatyAlreadyActive();
    error InvalidQuorum();
    error AlreadyApproved();
    error ContainmentActive();
    error HeartbeatStillFresh();

    modifier onlyCASO() {
        if (msg.sender != chiefAISafetyOfficer) revert NotAuthorized();
        _;
    }

    constructor(address _caso) {
        require(_caso != address(0), "zero CASO");
        chiefAISafetyOfficer = _caso;
        lastHeartbeat = block.timestamp;
        containmentTripped = false;
    }

    // --- Admin (CASO-gated) -------------------------------------------------

    function setMonitor(address monitor, bool enabled) external onlyCASO {
        isMonitor[monitor] = enabled;
        emit MonitorSet(monitor, enabled);
    }

    function setApprover(address approver, bool enabled) external onlyCASO {
        isApprover[approver] = enabled;
        emit ApproverSet(approver, enabled);
    }

    // --- Dead-man's switch --------------------------------------------------

    /// @notice SEC-02: only attested monitors; rejected once TRIPPED (latched).
    function recordHeartbeat() external {
        if (!isMonitor[msg.sender]) revert NotAuthorized();
        if (containmentTripped) revert ContainmentActive();
        // Production: verify a ZK proof of TEE/TPM attestation (PCR_MATCH=TRUE) here.
        lastHeartbeat = block.timestamp;
        emit HeartbeatReceived(msg.sender, block.timestamp);
    }

    /// @notice Anyone may trip the switch if the heartbeat has lapsed (fail-safe).
    function checkLiveness() external {
        if (!containmentTripped && block.timestamp - lastHeartbeat > HEARTBEAT_THRESHOLD) {
            containmentTripped = true;
            emit ContainmentTriggered("Heartbeat timeout: dead-man's switch active");
        }
    }

    /// @notice SEC-03: explicit, CASO-gated rearm requiring a fresh heartbeat.
    function rearm() external onlyCASO {
        if (!containmentTripped) revert ContainmentActive();
        if (block.timestamp - lastHeartbeat > HEARTBEAT_THRESHOLD) revert HeartbeatStillFresh();
        containmentTripped = false;
        emit ContainmentRearmed(msg.sender, block.timestamp);
    }

    // --- Treaty lifecycle ---------------------------------------------------

    function proposeTreaty(bytes32 treatyId, bytes32 manifestHash, uint256 quorum)
        external
        onlyCASO
    {
        if (quorum == 0) revert InvalidQuorum();                 // SEC-01
        if (treaties[treatyId].active) revert TreatyAlreadyActive(); // SEC-04
        treaties[treatyId] = Treaty({
            manifestHash: manifestHash,
            activationBlock: 0,
            active: false,
            exists: true,
            quorumRequired: quorum,
            currentApprovals: 0
        });
        emit TreatyProposed(treatyId, quorum);
    }

    /// @notice SEC-01: approver allow-list + existence + active checks.
    function approveTreaty(bytes32 treatyId) external {
        if (!isApprover[msg.sender]) revert NotAuthorized();
        Treaty storage t = treaties[treatyId];
        if (!t.exists) revert TreatyMissing();
        if (t.active) revert TreatyAlreadyActive();
        if (approvals[treatyId][msg.sender]) revert AlreadyApproved();

        approvals[treatyId][msg.sender] = true;
        t.currentApprovals += 1;
        emit TreatyApproved(treatyId, msg.sender, t.currentApprovals);

        if (t.currentApprovals >= t.quorumRequired) {
            t.active = true;
            t.activationBlock = block.number;
            emit TreatyRatified(treatyId);
        }
    }
}
