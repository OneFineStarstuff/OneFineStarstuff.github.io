"""Tests for SARA/ACR MoE routing stabilization (rte-01 governance invariants)."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from sara_acr_router import (  # noqa: E402
    MoERouter, assert_stability, ENTROPY_MIN, LOAD_RATIO_MAX, DROP_MAX,
)


def test_baseline_router_collapses():
    """Without SARA/ACR, skewed gating collapses onto few experts."""
    stats = MoERouter(sara_enabled=False, acr_enabled=False).route()
    assert stats.normalised_entropy < ENTROPY_MIN
    assert stats.load_ratio > LOAD_RATIO_MAX


def test_stabilized_router_satisfies_invariants():
    stats = MoERouter(sara_enabled=True, acr_enabled=True).route()
    assert stats.normalised_entropy >= ENTROPY_MIN
    assert stats.load_ratio <= LOAD_RATIO_MAX
    assert stats.drop_fraction <= DROP_MAX
    assert_stability(stats, "stabilized")  # must not raise


def test_stability_holds_across_seeds():
    for seed in range(5):
        stats = MoERouter(sara_enabled=True, acr_enabled=True, seed=seed).route()
        assert_stability(stats, f"seed={seed}")


def test_acr_capacity_bounds_max_load():
    """ACR caps any expert at capacity_factor * tokens/num_experts."""
    r = MoERouter(sara_enabled=True, acr_enabled=True, num_experts=8, capacity_factor=1.25)
    tokens = 4096
    stats = r.route(tokens=tokens)
    cap = 1.25 * (tokens / 8)
    assert max(stats.expert_load) <= cap + 1  # +1 rounding slack
