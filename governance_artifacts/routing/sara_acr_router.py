#!/usr/bin/env python3
"""
SARA / ACR MoE routing stabilization — runnable reference + governance invariants.
==================================================================================
Backs OSCAL control rte-01 (routing stability for Mixture-of-Experts models).

Definitions (this stack's normative definitions; not external standards):

  SARA — Stabilized Adaptive Routing Algorithm.
    Augments the gating softmax with (a) a load-aware bias that penalises experts
    already carrying high cumulative load and (b) a temperature term, so the
    router cannot collapse onto a small subset of experts ("expert collapse").

  ACR — Adaptive Capacity Regulation.
    Each expert has a capacity = capacity_factor * (tokens / num_experts).
    Tokens routed beyond an expert's remaining capacity overflow to the next
    preferred expert; persistent overflow is a governance signal.

Governance invariants enforced (rte-01 exit criteria):
  I1  routing entropy (normalised, 0..1) >= ENTROPY_MIN
  I2  max-to-mean expert load ratio       <= LOAD_RATIO_MAX
  I3  dropped-token fraction              <= DROP_MAX

This module is deterministic (seeded) and dependency-free (pure stdlib) so it
runs anywhere CI runs. `assert_stability()` raises AssertionError on violation,
which the harness/CI converts to a failing build.
"""
from __future__ import annotations
import math
import random
from dataclasses import dataclass, field

# --- Governance thresholds (would live in data.reference / board ratification) ---
ENTROPY_MIN = 0.80
LOAD_RATIO_MAX = 1.60
DROP_MAX = 0.02


@dataclass
class RoutingStats:
    expert_load: list[int]
    dropped: int
    total: int

    @property
    def normalised_entropy(self) -> float:
        n = len(self.expert_load)
        routed = sum(self.expert_load)
        if routed == 0 or n <= 1:
            return 0.0
        h = 0.0
        for c in self.expert_load:
            if c > 0:
                p = c / routed
                h -= p * math.log(p)
        return h / math.log(n)  # normalise by log(n) -> [0,1]

    @property
    def load_ratio(self) -> float:
        routed = sum(self.expert_load)
        n = len(self.expert_load)
        if routed == 0:
            return 0.0
        mean = routed / n
        return max(self.expert_load) / mean

    @property
    def drop_fraction(self) -> float:
        return self.dropped / self.total if self.total else 0.0


@dataclass
class MoERouter:
    num_experts: int = 8
    capacity_factor: float = 1.25
    sara_enabled: bool = True
    acr_enabled: bool = True
    load_bias_strength: float = 1.5  # SARA load-aware penalty
    temperature: float = 1.0
    seed: int = 1234
    _rng: random.Random = field(default=None, repr=False)

    def __post_init__(self):
        self._rng = random.Random(self.seed)

    def _logits(self, skew: float) -> list[float]:
        # Token gating logits; `skew` biases tokens toward a few "popular" experts,
        # the condition under which naive top-1 routing collapses.
        base = [self._rng.gauss(0, 1) for _ in range(self.num_experts)]
        base[0] += skew
        base[1] += skew * 0.7
        return base

    def route(self, tokens: int = 4096, skew: float = 3.0) -> RoutingStats:
        n = self.num_experts
        capacity = math.inf
        if self.acr_enabled:
            capacity = self.capacity_factor * (tokens / n)
        load = [0] * n
        dropped = 0

        for _ in range(tokens):
            logits = self._logits(skew)
            if self.sara_enabled:
                # load-aware bias: subtract a penalty proportional to current load share
                routed_so_far = sum(load) or 1
                for e in range(n):
                    share = load[e] / routed_so_far
                    logits[e] -= self.load_bias_strength * share
                logits = [x / self.temperature for x in logits]

            order = sorted(range(n), key=lambda e: logits[e], reverse=True)
            placed = False
            for e in order:
                if load[e] < capacity:
                    load[e] += 1
                    placed = True
                    break
            if not placed:
                dropped += 1  # all preferred experts at capacity -> token dropped

        return RoutingStats(expert_load=load, dropped=dropped, total=tokens)


def assert_stability(stats: RoutingStats, label: str = "") -> None:
    assert stats.normalised_entropy >= ENTROPY_MIN, (
        f"{label} entropy {stats.normalised_entropy:.3f} < {ENTROPY_MIN}")
    assert stats.load_ratio <= LOAD_RATIO_MAX, (
        f"{label} load_ratio {stats.load_ratio:.3f} > {LOAD_RATIO_MAX}")
    assert stats.drop_fraction <= DROP_MAX, (
        f"{label} drop_fraction {stats.drop_fraction:.3f} > {DROP_MAX}")


def _fmt(stats: RoutingStats) -> str:
    return (f"entropy={stats.normalised_entropy:.3f} "
            f"load_ratio={stats.load_ratio:.3f} "
            f"drop={stats.drop_fraction:.4f} loads={stats.expert_load}")


def main() -> int:
    print("SARA/ACR MoE routing stabilization (rte-01)")
    print(f"  thresholds: entropy>={ENTROPY_MIN} load_ratio<={LOAD_RATIO_MAX} drop<={DROP_MAX}")

    baseline = MoERouter(sara_enabled=False, acr_enabled=False).route()
    stabilized = MoERouter(sara_enabled=True, acr_enabled=True).route()

    print(f"  BASELINE   (no SARA/ACR): {_fmt(baseline)}")
    print(f"  STABILIZED (SARA+ACR)   : {_fmt(stabilized)}")

    # The governance claim: baseline VIOLATES at least one invariant (collapse),
    # while the stabilized router SATISFIES all of them.
    baseline_violates = (
        baseline.normalised_entropy < ENTROPY_MIN
        or baseline.load_ratio > LOAD_RATIO_MAX
        or baseline.drop_fraction > DROP_MAX
    )
    assert baseline_violates, "expected baseline router to demonstrate instability"
    assert_stability(stabilized, "stabilized")

    print("  RESULT: baseline unstable (as expected); SARA+ACR satisfies all rte-01 invariants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
