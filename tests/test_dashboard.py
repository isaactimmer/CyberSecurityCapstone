"""
Tests for the dashboard logic layer (epic #6, stories #38/#39/#40/#53).

`dashboard.py` is the Streamlit-free seam between the widgets in `app.py` and the
real engine (`pipeline`/`scoring`/`capacity`). Keeping the orchestration and
view-shaping here — not in the app — is what makes the dashboard's behaviour
unit-testable without a browser: slider values map to real backend parameters,
the plan re-derives, and the live/KEV flows are pure functions over a frame.
"""
import pandas as pd
import pytest

import capacity
import dashboard
import pipeline
import scoring


def _env_frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"cve_id": "CVE-KEV", "cvss_score": 5.5, "epss_score": 0.9, "kev_flag": True,
             "importance_tier": "critical", "vendor": "apache tomcat"},
            {"cve_id": "CVE-BIG", "cvss_score": 9.8, "epss_score": 0.01, "kev_flag": False,
             "importance_tier": "low", "vendor": "microsoft"},
            {"cve_id": "CVE-MID", "cvss_score": 7.0, "epss_score": 0.3, "kev_flag": False,
             "importance_tier": "high", "vendor": "cisco"},
        ]
    )


# --- #38 scoring-weight sliders --------------------------------------------

def test_normalize_weights_rescales_to_a_valid_sum():
    # Raw slider values need not sum to 1.0; the helper rescales them so
    # ScoringWeights' sum==1.0 invariant holds (it would otherwise raise).
    w = dashboard.normalize_weights(cvss=2, epss=2, kev=2, importance=2)
    assert isinstance(w, scoring.ScoringWeights)
    assert w.cvss == pytest.approx(0.25)
    assert w.epss == pytest.approx(0.25)


def test_normalize_weights_preserves_relative_emphasis():
    # Doubling EPSS's raw value should give it the largest share.
    w = dashboard.normalize_weights(cvss=1, epss=4, kev=1, importance=1)
    assert w.epss == pytest.approx(0.5714, abs=1e-3)
    assert w.epss > w.cvss == w.kev == w.importance


def test_normalize_weights_falls_back_when_all_zero():
    # All sliders at zero can't be normalized; fall back to the defaults rather
    # than divide by zero or raise in the UI.
    w = dashboard.normalize_weights(cvss=0, epss=0, kev=0, importance=0)
    assert w == scoring.DEFAULT_WEIGHTS


# --- #38 capacity sliders ---------------------------------------------------

def test_build_pools_maps_sliders_to_real_pool_capacities():
    pools = dashboard.build_pools(patching=50, appsec=10, change_window=4)
    assert pools[capacity.POOL_PATCHING].capacity == 50
    assert pools[capacity.POOL_APPSEC].capacity == 10
    assert pools[capacity.POOL_CHANGE_WINDOW].capacity == 4
    assert pools[capacity.POOL_CHANGE_WINDOW].unit == "slots"


def test_bigger_capacity_lets_the_plan_remove_more_risk():
    # The Tech Auditor's #38 check: moving a capacity parameter must change the
    # plan output, not just a UI value.
    env = _env_frame()
    small = dashboard.plan(env, pools=dashboard.build_pools(1, 1, 1))
    big = dashboard.plan(env, pools=dashboard.build_pools(100, 100, 100))
    assert big.optimized.total_risk_reduction > small.optimized.total_risk_reduction


def test_weight_change_reorders_scores():
    # #38: changing a weight changes the composite scores the plan is built on.
    env = _env_frame()
    epss_heavy = dashboard.plan(env, weights=dashboard.normalize_weights(0, 10, 0, 0))
    cvss_heavy = dashboard.plan(env, weights=dashboard.normalize_weights(10, 0, 0, 0))
    epss_top = epss_heavy.scored.iloc[0]["cve_id"]
    cvss_top = cvss_heavy.scored.iloc[0]["cve_id"]
    assert cvss_top == "CVE-BIG"   # 9.8 CVSS dominates
    assert epss_top == "CVE-KEV"   # 0.9 EPSS dominates
    assert epss_top != cvss_top


# --- #39 view shaping -------------------------------------------------------

def test_findings_view_exposes_the_breakdown_columns():
    result = dashboard.plan(_env_frame())
    view = dashboard.findings_view(result.scored)
    for col in ("cve_id", "cvss_score", "epss_score", "kev_flag", "composite_score"):
        assert col in view.columns


def test_headline_reports_optimizer_vs_baseline():
    result = dashboard.plan(_env_frame())
    head = dashboard.headline(result)
    assert head["optimized_risk"] >= head["baseline_risk"]
    assert head["improvement_pct"] == pytest.approx(result.improvement)
    assert head["optimized_fixes"] == len(result.optimized.items)


# --- #40 KEV-alert trigger --------------------------------------------------

def test_inject_kev_flags_the_named_cve_and_lifts_its_score():
    env = _env_frame()
    before = dashboard.plan(env)
    after_env = dashboard.inject_kev(env, "CVE-BIG")
    after = dashboard.plan(after_env)
    assert bool(after_env.loc[after_env["cve_id"] == "CVE-BIG", "kev_flag"].iloc[0]) is True
    # A newly-KEV'd CVE scores strictly higher than it did before.
    before_score = before.scored.set_index("cve_id").loc["CVE-BIG", "composite_score"]
    after_score = after.scored.set_index("cve_id").loc["CVE-BIG", "composite_score"]
    assert after_score > before_score


def test_inject_kev_does_not_mutate_the_input_frame():
    env = _env_frame()
    dashboard.inject_kev(env, "CVE-BIG")
    assert bool(env.loc[env["cve_id"] == "CVE-BIG", "kev_flag"].iloc[0]) is False


def test_kev_candidates_excludes_already_known_exploited():
    # Injecting a CVE that's already KEV would be a no-op, so it's not offered.
    env = _env_frame()  # CVE-KEV is already kev_flag=True
    candidates = dashboard.kev_candidates(env)
    assert "CVE-KEV" not in candidates
    # Highest CVSS among the remaining leads.
    assert candidates[0] == "CVE-BIG"


def test_default_environment_delegates_to_the_pipeline(monkeypatch):
    # The view must not call pipeline's I/O directly; this wrapper is the seam.
    sentinel = pd.DataFrame([{"cve_id": "CVE-X"}])
    monkeypatch.setattr(pipeline, "scan_environment", lambda **k: sentinel)
    assert dashboard.default_environment() is sentinel


# --- #53 live "show me <vendor>" input -------------------------------------

def _fake_feed(vendor: str, **_) -> pd.DataFrame:
    return pd.DataFrame(
        [{"cve_id": "CVE-L1", "cvss_score": 8.0, "epss_score": 0.4, "kev_flag": False}]
    )


def test_live_environment_scores_a_vendor_with_no_asset_context():
    scan = dashboard.live_environment(
        "acme waf", tier="high", fetch=_fake_feed, cache_probe=lambda *a, **k: True
    )
    assert scan is not None
    # A queried vendor has no asset graph, so the helper supplies a tier + vendor
    # so the real pipeline can still score it.
    assert set(scan.env["importance_tier"]) == {"high"}
    assert set(scan.env["vendor"]) == {"acme waf"}
    assert scan.source == "cached"


def test_live_environment_reports_live_when_not_cached():
    scan = dashboard.live_environment(
        "brand new vendor", fetch=_fake_feed, cache_probe=lambda *a, **k: False
    )
    assert scan.source == "live"


def test_live_environment_returns_none_on_empty_pull():
    scan = dashboard.live_environment(
        "nothing", fetch=lambda *a, **k: pd.DataFrame(), cache_probe=lambda *a, **k: False
    )
    assert scan is None


def test_live_scan_result_feeds_build_plan():
    scan = dashboard.live_environment("acme", fetch=_fake_feed, cache_probe=lambda *a, **k: True)
    result = dashboard.plan(scan.env)
    assert len(result.scored) == 1
    assert "composite_score" in result.scored.columns
