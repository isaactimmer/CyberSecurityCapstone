"""
Tests for the capacity-aware optimizer (epic #5, tickets #32/#33/#34).

- greedy_optimize (#32): fill each pool by risk-reduction/effort ratio until
  full, never exceeding any pool's capacity.
- severity_baseline (#33): the "before" picture — fill the same pools by CVSS
  severity only, with no EPSS/KEV/importance signal.
- improvement_metric (#34): the headline number — % extra risk reduction the
  optimizer buys over the baseline, computed from both plans' actual totals.
"""
import pandas as pd
import pytest

import capacity
import optimizer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def _scored_frame() -> pd.DataFrame:
    """A scored, pool-and-effort-assigned frame ready for the optimizer."""
    frame = pd.DataFrame(
        [
            {"cve_id": "CVE-A", "composite_score": 90.0, "cvss_score": 4.0},
            {"cve_id": "CVE-B", "composite_score": 80.0, "cvss_score": 5.0},
            {"cve_id": "CVE-C", "composite_score": 70.0, "cvss_score": 9.8},
            {"cve_id": "CVE-D", "composite_score": 60.0, "cvss_score": 9.5},
            {"cve_id": "CVE-E", "composite_score": 50.0, "cvss_score": 3.0},
            {"cve_id": "CVE-F", "composite_score": 40.0, "cvss_score": 2.0},
        ]
    )
    return capacity.assign_remediation_effort(frame)


def _one_pool(name: str = "solo", cap: float = 3.0) -> dict[str, capacity.CapacityPool]:
    return {name: capacity.CapacityPool(name=name, capacity=cap, unit="units")}


def _single_pool_frame() -> pd.DataFrame:
    # Everything drawn from one pool, uniform effort 1 => capacity == item count.
    return pd.DataFrame(
        [
            {"cve_id": "CVE-A", "composite_score": 90.0, "cvss_score": 4.0, "pool": "solo", "effort": 1.0},
            {"cve_id": "CVE-B", "composite_score": 80.0, "cvss_score": 5.0, "pool": "solo", "effort": 1.0},
            {"cve_id": "CVE-C", "composite_score": 10.0, "cvss_score": 9.8, "pool": "solo", "effort": 1.0},
            {"cve_id": "CVE-D", "composite_score": 5.0, "cvss_score": 9.5, "pool": "solo", "effort": 1.0},
        ]
    )


# ---------------------------------------------------------------------------
# #32 — greedy optimizer
# ---------------------------------------------------------------------------
class TestGreedyOptimize:
    def test_never_exceeds_any_pool_capacity(self):
        plan = optimizer.greedy_optimize(_scored_frame())
        for name, used in plan.consumed.items():
            assert used <= plan.pools[name].capacity + 1e-9

    def test_orders_selected_items_by_ratio_desc(self):
        plan = optimizer.greedy_optimize(_single_pool_frame(), pools=_one_pool(cap=4.0))
        ratios = (plan.items["composite_score"] / plan.items["effort"]).tolist()
        assert ratios == sorted(ratios, reverse=True)

    def test_picks_highest_score_first_in_a_uniform_pool(self):
        # capacity 2, uniform effort 1 => the two highest composite scores win,
        # regardless of their CVSS severity.
        plan = optimizer.greedy_optimize(_single_pool_frame(), pools=_one_pool(cap=2.0))
        assert plan.items["cve_id"].tolist() == ["CVE-A", "CVE-B"]

    def test_total_risk_reduction_sums_selected_scores(self):
        plan = optimizer.greedy_optimize(_single_pool_frame(), pools=_one_pool(cap=2.0))
        assert plan.total_risk_reduction == pytest.approx(170.0)

    def test_runs_on_the_full_scored_dataset(self):
        plan = optimizer.greedy_optimize(_scored_frame())
        assert len(plan.items) > 0
        assert set(plan.consumed) == set(capacity.default_pools())

    def test_zero_capacity_pool_selects_nothing_from_it(self):
        pools = {"solo": capacity.CapacityPool("solo", 0.0, "units")}
        plan = optimizer.greedy_optimize(_single_pool_frame(), pools=pools)
        assert len(plan.items) == 0
        assert plan.total_risk_reduction == 0.0

    def test_missing_required_column_raises(self):
        frame = _single_pool_frame().drop(columns=["effort"])
        with pytest.raises(KeyError):
            optimizer.greedy_optimize(frame, pools=_one_pool())

    def test_does_not_mutate_input(self):
        frame = _scored_frame()
        before = frame.copy()
        optimizer.greedy_optimize(frame)
        pd.testing.assert_frame_equal(frame, before)


# ---------------------------------------------------------------------------
# #33 — naive severity-first baseline
# ---------------------------------------------------------------------------
class TestSeverityBaseline:
    def test_orders_by_cvss_severity_only(self):
        plan = optimizer.severity_baseline(_single_pool_frame(), pools=_one_pool(cap=2.0))
        # highest CVSS first: CVE-C (9.8), CVE-D (9.5) — even though their
        # composite risk is low.
        assert plan.items["cve_id"].tolist() == ["CVE-C", "CVE-D"]

    def test_ignores_epss_kev_importance_and_composite_for_ordering(self):
        # Give composite the opposite order to cvss; the baseline must follow
        # cvss, proving it does not peek at the composite/EPSS/KEV signal.
        plan = optimizer.severity_baseline(_single_pool_frame(), pools=_one_pool(cap=4.0))
        assert plan.items["cvss_score"].tolist() == sorted(
            plan.items["cvss_score"].tolist(), reverse=True
        )

    def test_consumes_the_same_pools_as_the_optimizer(self):
        greedy = optimizer.greedy_optimize(_scored_frame())
        baseline = optimizer.severity_baseline(_scored_frame())
        assert set(baseline.consumed) == set(greedy.consumed)
        for name, used in baseline.consumed.items():
            assert used <= baseline.pools[name].capacity + 1e-9

    def test_total_risk_reduction_still_measured_by_composite(self):
        # The baseline picks by severity but the risk it actually removes is
        # measured with the same composite metric, so the two plans compare
        # apples-to-apples.
        plan = optimizer.severity_baseline(_single_pool_frame(), pools=_one_pool(cap=2.0))
        assert plan.total_risk_reduction == pytest.approx(15.0)  # 10 + 5


# ---------------------------------------------------------------------------
# #34 — headline improvement metric
# ---------------------------------------------------------------------------
class TestImprovementMetric:
    def test_computed_from_actual_plan_totals(self):
        greedy = optimizer.greedy_optimize(_single_pool_frame(), pools=_one_pool(cap=2.0))
        baseline = optimizer.severity_baseline(_single_pool_frame(), pools=_one_pool(cap=2.0))
        # optimizer 170, baseline 15 => (170-15)/15 * 100
        expected = (greedy.total_risk_reduction - baseline.total_risk_reduction) / (
            baseline.total_risk_reduction
        ) * 100
        assert optimizer.improvement_metric(greedy, baseline) == pytest.approx(expected)

    def test_optimizer_never_lower_than_baseline_on_the_dataset(self):
        greedy = optimizer.greedy_optimize(_scored_frame())
        baseline = optimizer.severity_baseline(_scored_frame())
        assert greedy.total_risk_reduction >= baseline.total_risk_reduction
        assert optimizer.improvement_metric(greedy, baseline) >= 0.0

    @pytest.mark.parametrize("cap", [1.0, 2.0, 3.0, 4.0])
    def test_invariant_holds_across_capacities(self, cap):
        pools = _one_pool(cap=cap)
        greedy = optimizer.greedy_optimize(_single_pool_frame(), pools=pools)
        baseline = optimizer.severity_baseline(_single_pool_frame(), pools=pools)
        assert greedy.total_risk_reduction >= baseline.total_risk_reduction

    def test_zero_baseline_returns_zero_when_optimizer_also_zero(self):
        pools = {"solo": capacity.CapacityPool("solo", 0.0, "units")}
        greedy = optimizer.greedy_optimize(_single_pool_frame(), pools=pools)
        baseline = optimizer.severity_baseline(_single_pool_frame(), pools=pools)
        assert optimizer.improvement_metric(greedy, baseline) == 0.0
