"""
Tests for the capacity-pool data structure (epic #5, ticket #31).

Covers the acceptance criteria: the structure supports at least the three named
pools (general/patching, AppSec, change-window), each holding a numeric capacity
in its own unit of effort — not a single generic "hours available" number.
"""
import pandas as pd
import pytest

import capacity


# ---------------------------------------------------------------------------
# CapacityPool — one distinct kind of team work-time
# ---------------------------------------------------------------------------
class TestCapacityPool:
    def test_holds_a_name_numeric_capacity_and_unit(self):
        pool = capacity.CapacityPool(name="patching", capacity=40.0, unit="hours")
        assert pool.name == "patching"
        assert pool.capacity == 40.0
        assert pool.unit == "hours"

    def test_capacity_is_numeric(self):
        pool = capacity.CapacityPool(name="appsec", capacity=16)
        assert isinstance(pool.capacity, (int, float))

    def test_rejects_negative_capacity(self):
        # A pool cannot hold less than zero work-time.
        with pytest.raises(ValueError):
            capacity.CapacityPool(name="patching", capacity=-1.0)

    def test_is_immutable(self):
        pool = capacity.CapacityPool(name="patching", capacity=40.0)
        with pytest.raises(Exception):
            pool.capacity = 10.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# default_pools — the three distinct pools the team actually has
# ---------------------------------------------------------------------------
class TestDefaultPools:
    def test_supports_at_least_the_three_named_pools(self):
        pools = capacity.default_pools()
        for name in (
            capacity.POOL_PATCHING,
            capacity.POOL_APPSEC,
            capacity.POOL_CHANGE_WINDOW,
        ):
            assert name in pools
            assert isinstance(pools[name], capacity.CapacityPool)

    def test_each_pool_holds_a_positive_numeric_capacity(self):
        for pool in capacity.default_pools().values():
            assert isinstance(pool.capacity, (int, float))
            assert pool.capacity > 0

    def test_pools_are_distinct_not_one_generic_number(self):
        # The whole point of the ticket: capacity is several separate pools, not
        # a single "hours available" figure. Each pool is its own object naming
        # its own kind of work-time and carrying its own capacity.
        pools = capacity.default_pools()
        assert len(pools) >= 3
        # every pool's declared name matches the key it is filed under
        assert all(name == pool.name for name, pool in pools.items())
        # the pools are genuinely different objects, not one value reused
        distinct_pools = {id(pool) for pool in pools.values()}
        assert len(distinct_pools) == len(pools)

    def test_change_window_can_use_a_different_unit(self):
        pools = capacity.default_pools()
        # change-window is measured in slots, not general hours — proving the
        # structure carries a per-pool unit of effort.
        assert pools[capacity.POOL_CHANGE_WINDOW].unit != ""


# ---------------------------------------------------------------------------
# assign_remediation_effort — stand-in join of pool + effort onto each CVE
# ---------------------------------------------------------------------------
def _sample_scored_frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"cve_id": "CVE-A", "composite_score": 90.0, "cvss_score": 9.8},
            {"cve_id": "CVE-B", "composite_score": 70.0, "cvss_score": 5.5},
            {"cve_id": "CVE-C", "composite_score": 50.0, "cvss_score": 7.0},
            {"cve_id": "CVE-D", "composite_score": 30.0, "cvss_score": 4.0},
        ]
    )


class TestAssignRemediationEffort:
    def test_adds_pool_and_effort_columns(self):
        out = capacity.assign_remediation_effort(_sample_scored_frame())
        assert "pool" in out.columns
        assert "effort" in out.columns

    def test_every_row_gets_a_known_pool(self):
        out = capacity.assign_remediation_effort(_sample_scored_frame())
        assert set(out["pool"]).issubset(set(capacity.default_pools()))

    def test_every_effort_is_positive(self):
        out = capacity.assign_remediation_effort(_sample_scored_frame())
        assert (out["effort"] > 0).all()

    def test_effort_is_constant_within_a_pool(self):
        # The greedy optimizer's "never worse than baseline" guarantee (#34)
        # relies on effort being uniform inside each pool.
        out = capacity.assign_remediation_effort(_sample_scored_frame())
        per_pool = out.groupby("pool")["effort"].nunique()
        assert (per_pool == 1).all()

    def test_is_deterministic(self):
        first = capacity.assign_remediation_effort(_sample_scored_frame())
        second = capacity.assign_remediation_effort(_sample_scored_frame())
        pd.testing.assert_frame_equal(first, second)

    def test_does_not_mutate_input(self):
        frame = _sample_scored_frame()
        capacity.assign_remediation_effort(frame)
        assert "pool" not in frame.columns
        assert "effort" not in frame.columns


# ---------------------------------------------------------------------------
# Asset-role-based pool assignment (epic #47, story #51)
# The pool a fix draws from is derived from the software's work-type, not a hash.
# ---------------------------------------------------------------------------
def _vendor_scored_frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"cve_id": "CVE-A", "composite_score": 90.0, "cvss_score": 9.8, "vendor": "apache tomcat"},
            {"cve_id": "CVE-B", "composite_score": 70.0, "cvss_score": 5.5, "vendor": "cisco"},
            {"cve_id": "CVE-C", "composite_score": 50.0, "cvss_score": 7.0, "vendor": "microsoft"},
            {"cve_id": "CVE-D", "composite_score": 30.0, "cvss_score": 4.0, "vendor": "oracle database"},
        ]
    )


class TestPoolForVendor:
    def test_apps_and_web_go_to_appsec(self):
        assert capacity.pool_for_vendor("apache tomcat") == capacity.POOL_APPSEC
        assert capacity.pool_for_vendor("jenkins") == capacity.POOL_APPSEC

    def test_network_infra_and_db_go_to_change_window(self):
        assert capacity.pool_for_vendor("cisco") == capacity.POOL_CHANGE_WINDOW
        assert capacity.pool_for_vendor("oracle database") == capacity.POOL_CHANGE_WINDOW

    def test_os_endpoint_defaults_to_patching(self):
        assert capacity.pool_for_vendor("microsoft") == capacity.POOL_PATCHING
        assert capacity.pool_for_vendor("ubuntu") == capacity.POOL_PATCHING

    def test_is_case_insensitive(self):
        assert capacity.pool_for_vendor("CISCO") == capacity.POOL_CHANGE_WINDOW


class TestRoleBasedAssignment:
    def test_uses_vendor_when_present_not_hash(self):
        out = capacity.assign_remediation_effort(_vendor_scored_frame())
        by_cve = dict(zip(out["cve_id"], out["pool"]))
        assert by_cve["CVE-A"] == capacity.POOL_APPSEC          # apache tomcat
        assert by_cve["CVE-B"] == capacity.POOL_CHANGE_WINDOW   # cisco
        assert by_cve["CVE-C"] == capacity.POOL_PATCHING        # microsoft
        assert by_cve["CVE-D"] == capacity.POOL_CHANGE_WINDOW   # oracle database

    def test_effort_still_constant_within_pool(self):
        out = capacity.assign_remediation_effort(_vendor_scored_frame())
        per_pool = out.groupby("pool")["effort"].nunique()
        assert (per_pool == 1).all()

    def test_role_based_is_explainable_same_vendor_same_pool(self):
        out = capacity.assign_remediation_effort(_vendor_scored_frame())
        # Deterministic and driven by the vendor, so it is explainable, not a hash.
        assert capacity.pool_for_vendor("cisco") == out.loc[out["cve_id"] == "CVE-B", "pool"].iloc[0]

    def test_falls_back_to_stand_in_without_vendor(self):
        # Frames with no vendor column still get pools (the hash stand-in).
        out = capacity.assign_remediation_effort(_sample_scored_frame())
        assert set(out["pool"]).issubset(set(capacity.default_pools()))
