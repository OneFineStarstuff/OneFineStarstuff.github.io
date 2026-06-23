#!/usr/bin/env python3
"""
Behavioural verification of the OmegaActual contract security review.
=====================================================================
Full EVM execution (Foundry/Hardhat) is not available in this environment, so we
model the *logic* of both contracts in Python and assert:

  - the ORIGINAL contract is exploitable (SEC-01 single-tx ratification of an
    unproposed treaty; SEC-02 unauthenticated heartbeat), and
  - the HARDENED contract rejects those same exploits.

This is a logic-equivalence harness, not a substitute for on-chain testing; it
keeps the security review's claims falsifiable and CI-checkable. The Solidity
itself is separately compiled by compile.js (solc 0.8.26).
"""
from __future__ import annotations


class OriginalEngine:
    HEARTBEAT_THRESHOLD = 300

    def __init__(self, caso):
        self.caso = caso
        self.last_heartbeat = 0
        self.now = 0
        self.containment_enforced = False
        self.treaties = {}      # id -> dict
        self.approvals = {}     # (id, addr) -> bool

    def record_heartbeat(self, sender):           # SEC-02: no auth
        self.last_heartbeat = self.now

    def approve_treaty(self, treaty_id, sender):  # SEC-01: no auth, no existence check
        assert not self.approvals.get((treaty_id, sender)), "Already approved"
        t = self.treaties.setdefault(
            treaty_id, {"quorum": 0, "approvals": 0, "active": False})
        t["approvals"] += 1
        self.approvals[(treaty_id, sender)] = True
        if t["approvals"] >= t["quorum"]:
            t["active"] = True
        return t["active"]


class HardenedEngine:
    HEARTBEAT_THRESHOLD = 300

    def __init__(self, caso):
        self.caso = caso
        self.last_heartbeat = 0
        self.now = 0
        self.containment_tripped = False
        self.is_monitor = set()
        self.is_approver = set()
        self.treaties = {}
        self.approvals = {}

    def _only_caso(self, sender):
        if sender != self.caso:
            raise PermissionError("NotAuthorized")

    def set_monitor(self, sender, m, enabled=True):
        self._only_caso(sender)
        (self.is_monitor.add if enabled else self.is_monitor.discard)(m)

    def set_approver(self, sender, a, enabled=True):
        self._only_caso(sender)
        (self.is_approver.add if enabled else self.is_approver.discard)(a)

    def record_heartbeat(self, sender):
        if sender not in self.is_monitor:
            raise PermissionError("NotAuthorized")
        if self.containment_tripped:
            raise RuntimeError("ContainmentActive")
        self.last_heartbeat = self.now

    def propose_treaty(self, sender, treaty_id, quorum):
        self._only_caso(sender)
        if quorum == 0:
            raise ValueError("InvalidQuorum")
        if self.treaties.get(treaty_id, {}).get("active"):
            raise RuntimeError("TreatyAlreadyActive")
        self.treaties[treaty_id] = {"quorum": quorum, "approvals": 0,
                                    "active": False, "exists": True}

    def approve_treaty(self, treaty_id, sender):
        if sender not in self.is_approver:
            raise PermissionError("NotAuthorized")
        t = self.treaties.get(treaty_id)
        if not t or not t.get("exists"):
            raise LookupError("TreatyMissing")
        if t["active"]:
            raise RuntimeError("TreatyAlreadyActive")
        if self.approvals.get((treaty_id, sender)):
            raise RuntimeError("AlreadyApproved")
        self.approvals[(treaty_id, sender)] = True
        t["approvals"] += 1
        if t["approvals"] >= t["quorum"]:
            t["active"] = True
        return t["active"]


def test_sec01_original_exploitable():
    """Attacker ratifies an UNPROPOSED treaty in a single tx (quorum defaults to 0)."""
    e = OriginalEngine(caso="0xCASO")
    activated = e.approve_treaty(treaty_id="0xEVIL", sender="0xATTACKER")
    assert activated is True, "expected original to be exploitable (SEC-01)"


def test_sec01_hardened_blocks_unproposed():
    e = HardenedEngine(caso="0xCASO")
    e.set_approver("0xCASO", "0xATTACKER")  # even a registered approver...
    try:
        e.approve_treaty(treaty_id="0xEVIL", sender="0xATTACKER")
        raise AssertionError("hardened must reject unproposed treaty")
    except LookupError:
        pass  # TreatyMissing


def test_sec01_hardened_blocks_non_approver():
    e = HardenedEngine(caso="0xCASO")
    e.propose_treaty("0xCASO", "0xGOOD", quorum=2)
    try:
        e.approve_treaty("0xGOOD", sender="0xRANDOM")
        raise AssertionError("hardened must reject non-approver")
    except PermissionError:
        pass


def test_sec01_hardened_happy_path():
    e = HardenedEngine(caso="0xCASO")
    e.propose_treaty("0xCASO", "0xGOOD", quorum=2)
    e.set_approver("0xCASO", "0xA")
    e.set_approver("0xCASO", "0xB")
    assert e.approve_treaty("0xGOOD", "0xA") is False  # 1/2
    assert e.approve_treaty("0xGOOD", "0xB") is True   # 2/2 -> ratified


def test_sec02_original_heartbeat_unauthenticated():
    e = OriginalEngine(caso="0xCASO")
    e.now = 1000
    e.record_heartbeat(sender="0xATTACKER")  # accepted -> defeats dead-man switch
    assert e.last_heartbeat == 1000


def test_sec02_hardened_heartbeat_requires_monitor():
    e = HardenedEngine(caso="0xCASO")
    e.now = 1000
    try:
        e.record_heartbeat(sender="0xATTACKER")
        raise AssertionError("hardened must reject non-monitor heartbeat")
    except PermissionError:
        pass


def test_sec02_hardened_heartbeat_rejected_when_tripped():
    e = HardenedEngine(caso="0xCASO")
    e.set_monitor("0xCASO", "0xMON")
    e.containment_tripped = True
    try:
        e.record_heartbeat(sender="0xMON")
        raise AssertionError("must reject heartbeat while tripped (latched)")
    except RuntimeError:
        pass


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  PASS {fn.__name__}")
    print(f"contract logic: {len(fns)}/{len(fns)} PASS")


if __name__ == "__main__":
    _run()
