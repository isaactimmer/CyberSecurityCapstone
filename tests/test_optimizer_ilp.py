"""
Tests for the ILP optimal comparison (epic #5, ticket #35 — STRETCH).

PuLP is an optional dependency, so the whole module is skipped when it is not
installed — the required Sprint-2 path never touches it.
"""
import pandas as pd
import pytest

pytest.importorskip("pulp")

import capacity
import optimizer
import optimizer_ilp


def _frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"cve_id": "CVE-A", "composite_score": 90.0, "cvss_score": 4.0, "pool": "solo", "effort": 2.0},
            {"cve_id": "CVE-B", "composite_score": 80.0, "cvss_score": 5.0, "pool": "solo", "effort": 2.0},
            {"cve_id": "CVE-C", "composite_score": 60.0, "cvss_score": 9.8, "pool": "solo", "effort": 1.0},
            {"cve_id": "CVE-D", "composite_score": 55.0, "cvss_score": 9.5, "pool": "solo", "effort": 1.0},
        ]
    )


def _one_pool(cap: float) -> dict[str, capacity.CapacityPool]:
    return {"solo": capacity.CapacityPool("solo", cap, "units")}


class TestIlpOptimize:
    def test_respects_capacity(self):
        pools = _one_pool(cap=3.0)
        plan = optimizer_ilp.ilp_optimize(_frame(), pools=pools)
        assert plan.consumed["solo"] <= 3.0 + 1e-9

    def test_ilp_is_at_least_as_good_as_greedy(self):
        # The whole point: the optimum can never be beaten by the heuristic.
        pools = _one_pool(cap=3.0)
        greedy = optimizer.greedy_optimize(_frame(), pools=pools)
        optimal = optimizer_ilp.ilp_optimize(_frame(), pools=pools)
        assert optimal.total_risk_reduction >= greedy.total_risk_reduction - 1e-9

    def test_gap_is_non_negative_and_reported(self):
        pools = _one_pool(cap=3.0)
        greedy = optimizer.greedy_optimize(_frame(), pools=pools)
        optimal = optimizer_ilp.ilp_optimize(_frame(), pools=pools)
        assert optimizer_ilp.greedy_gap(greedy, optimal) >= -1e-9

    def test_finds_the_known_optimum_on_a_small_case(self):
        # capacity 2: best is C+D (60+55=115), beating A or B alone (90) and the
        # ratio-greedy pick. Verifies the ILP truly optimises.
        pools = _one_pool(cap=2.0)
        optimal = optimizer_ilp.ilp_optimize(_frame(), pools=pools)
        assert optimal.total_risk_reduction == pytest.approx(115.0)
