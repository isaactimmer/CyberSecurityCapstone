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


# --- landing inputs: how many / which years / focus asset ------------------

def _scored_with_assets() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"cve_id": "CVE-2021-1", "cvss_score": 9.0, "epss_score": 0.5, "kev_flag": True,
             "importance_tier": "critical", "vendor": "oracle database", "asset_id": "crown",
             "composite_score": 80.0, "pool": "change_window", "effort": 1.0},
            {"cve_id": "CVE-2023-2", "cvss_score": 7.0, "epss_score": 0.2, "kev_flag": False,
             "importance_tier": "critical", "vendor": "apache tomcat", "asset_id": "mid",
             "composite_score": 55.0, "pool": "appsec", "effort": 2.0},
            {"cve_id": "CVE-2024-3", "cvss_score": 5.0, "epss_score": 0.1, "kev_flag": False,
             "importance_tier": "high", "vendor": "ubuntu", "asset_id": "edge",
             "composite_score": 20.0, "pool": "patching", "effort": 1.0},
        ]
    )


def test_cve_year_parses_the_disclosure_year():
    assert dashboard.cve_year("CVE-2024-12345") == 2024
    assert dashboard.cve_year("cve-1999-0001") == 1999
    assert dashboard.cve_year("not-a-cve") is None


def test_year_bounds_spans_the_present_years():
    assert dashboard.year_bounds(_scored_with_assets()) == (2021, 2024)


def test_filter_findings_caps_the_row_count():
    view = dashboard.filter_findings(_scored_with_assets(), max_results=2)
    assert len(view) == 2  # "how many to list?"


def test_filter_findings_keeps_only_the_year_range():
    view = dashboard.filter_findings(_scored_with_assets(), year_range=(2023, 2024))
    assert set(view["cve_id"]) == {"CVE-2023-2", "CVE-2024-3"}


def test_filter_findings_focuses_one_asset():
    view = dashboard.filter_findings(_scored_with_assets(), asset_id="crown")
    assert list(view["cve_id"]) == ["CVE-2021-1"]


def test_filter_findings_all_none_returns_every_row():
    view = dashboard.filter_findings(_scored_with_assets())
    assert len(view) == 3


# --- asset map -------------------------------------------------------------

def _asset_table() -> pd.DataFrame:
    # Two hops from a single crown jewel: crown -> mid -> edge.
    return pd.DataFrame(
        [
            {"asset_id": "crown", "name": "Customer DB", "criticality": "Critical",
             "crown_jewel": True, "connections": "mid", "vendor": "oracle database",
             "hop_distance": 0, "importance_tier": "critical"},
            {"asset_id": "mid", "name": "App Server", "criticality": "High",
             "crown_jewel": False, "connections": "crown|edge", "vendor": "apache tomcat",
             "hop_distance": 1, "importance_tier": "critical"},
            {"asset_id": "edge", "name": "Dev Box", "criticality": "Low",
             "crown_jewel": False, "connections": "mid", "vendor": "ubuntu",
             "hop_distance": 2, "importance_tier": "high"},
        ]
    )


def test_load_asset_table_reads_the_sample_environment():
    table = dashboard.load_asset_table()  # defaults to assets.csv
    assert "hop_distance" in table.columns
    assert "importance_tier" in table.columns
    assert (table["crown_jewel"].sum()) == 1  # exactly one crown jewel


def test_load_asset_table_rejects_a_broken_file(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("asset_id,name\nonly,two-columns\n", encoding="utf-8")
    with pytest.raises(ValueError):
        dashboard.load_asset_table(str(bad))


def test_asset_map_data_columns_by_hop_distance():
    amap = dashboard.asset_map_data(_asset_table())
    assert amap.max_hop == 2
    assert amap.crown_jewels == ["crown"]
    cols = {n["asset_id"]: n["col"] for n in amap.nodes}
    assert cols == {"crown": 0, "mid": 1, "edge": 2}
    # Edges are undirected and de-duped (crown-mid and mid-edge, not doubled).
    assert len(amap.edges) == 2


def test_asset_map_svg_marks_selection_and_plan_membership():
    amap = dashboard.asset_map_data(_asset_table())
    svg = dashboard.asset_map_svg(amap, selected="mid", in_plan_assets={"edge"})
    assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
    assert "Customer DB" in svg          # a node label rendered
    assert "#1D9E75" in svg              # the in-plan green dot for "edge"


# --- plan decision-support -------------------------------------------------

def test_annotate_plan_joins_asset_name_and_hops():
    items = _scored_with_assets()
    annotated = dashboard.annotate_plan(items, _asset_table())
    row = annotated.set_index("cve_id").loc["CVE-2021-1"]
    assert row["asset_name"] == "Customer DB"
    assert int(row["hop_distance"]) == 0


def test_annotate_plan_tolerates_no_asset_context():
    items = pd.DataFrame([{"cve_id": "CVE-L1", "composite_score": 10.0}])
    annotated = dashboard.annotate_plan(items, None)
    assert annotated["asset_name"].isna().all()
    assert annotated["hop_distance"].isna().all()


def test_plan_item_detail_explains_a_kev_finding():
    items = dashboard.annotate_plan(_scored_with_assets(), _asset_table())
    detail = dashboard.plan_item_detail(items.iloc[0])  # CVE-2021-1, KEV, crown
    assert detail["kev_flag"] is True
    assert detail["hop_distance"] == 0
    assert detail["tier_weight"] == pytest.approx(1.0)  # critical
    assert "actively exploited" in detail["reason_sentence"]
    assert detail["reason_sentence"].endswith(".")


def test_plan_item_detail_resolves_tier_color_in_the_seam():
    # The view must not re-derive "unknown tier ⇒ low" inline; the seam paints it.
    items = dashboard.annotate_plan(_scored_with_assets(), _asset_table())
    detail = dashboard.plan_item_detail(items.iloc[0])  # critical
    assert detail["tier_color"] == dashboard.TIER_COLORS["critical"]


def test_plan_item_detail_handles_a_row_with_no_asset():
    row = pd.Series({"cve_id": "CVE-L1", "cvss_score": 8.0, "epss_score": 0.1,
                     "kev_flag": False, "importance_tier": "high", "composite_score": 40.0})
    detail = dashboard.plan_item_detail(row)
    assert detail["hop_distance"] is None
    assert "high-importance" in detail["reason_sentence"]


def test_asset_coverage_counts_critical_assets_with_a_fix():
    result = dashboard.plan(_scored_with_assets(),
                            pools=dashboard.build_pools(100, 100, 100))
    coverage = dashboard.asset_coverage(_asset_table(), result.optimized)
    # crown + mid are critical; both have a scheduled CVE, so 2 of 2.
    assert coverage["total"] == 2
    assert coverage["covered"] == 2


def test_in_plan_assets_lists_scheduled_asset_ids():
    result = dashboard.plan(_scored_with_assets(),
                            pools=dashboard.build_pools(100, 100, 100))
    assert dashboard.in_plan_assets(result.optimized) == {"crown", "mid", "edge"}


# --- asset click-through detail (summary board -> one system) --------------

def test_asset_detail_summarizes_one_system_and_its_fixes():
    result = dashboard.plan(_scored_with_assets(),
                            pools=dashboard.build_pools(100, 100, 100))
    detail = dashboard.asset_detail("crown", _asset_table(), result)
    assert detail["name"] == "Customer DB"
    assert detail["importance_tier"] == "critical"
    assert detail["hop_distance"] == 0
    assert detail["crown_jewel"] is True
    assert detail["tier_color"] == dashboard.TIER_COLORS["critical"]
    assert "mid" in detail["connections"]
    # crown carries CVE-2021-1, which fits the generous capacity, so it's scheduled.
    assert "CVE-2021-1" in detail["scheduled_cves"]
    assert detail["scheduled_count"] == 1
    assert detail["finding_count"] == 1


def test_asset_detail_handles_an_unknown_asset():
    result = dashboard.plan(_scored_with_assets(),
                            pools=dashboard.build_pools(100, 100, 100))
    detail = dashboard.asset_detail("ghost", _asset_table(), result)
    assert detail["name"] is None
    assert detail["scheduled_cves"] == []
    assert detail["connections"] == []


# --- tabbed console seams (Dashboard / Attack surface / Risk engine / Plan) --

def _generous_result() -> pipeline.PlanResult:
    # Capacity large enough to schedule every fix, so the derived shapers have
    # a full, deterministic plan to read.
    return dashboard.plan(_scored_with_assets(),
                          pools=dashboard.build_pools(100, 100, 100))


def test_tier_color_defaults_unknown_and_missing_to_low():
    assert dashboard.tier_color("critical") == dashboard.TIER_COLORS["critical"]
    assert dashboard.tier_color("HIGH") == dashboard.TIER_COLORS["high"]
    assert dashboard.tier_color(None) == dashboard.TIER_COLORS["low"]
    assert dashboard.tier_color("nonsense") == dashboard.TIER_COLORS["low"]


def test_tier_spread_counts_scheduled_fixes_by_tier():
    spread = dashboard.tier_spread(_generous_result())
    # crown + mid are critical, edge is high; all three scheduled.
    assert spread["critical"] == 2
    assert spread["high"] == 1
    assert spread["medium"] == 0 and spread["low"] == 0


def test_top_picks_limits_and_annotates_with_asset_name():
    picks = dashboard.top_picks(_generous_result(), _asset_table(), limit=2)
    assert len(picks) == 2
    assert "asset_name" in picks.columns
    # Risk-first order: the highest composite score leads.
    assert picks.iloc[0]["cve_id"] == "CVE-2021-1"


def test_pool_utilization_reports_used_capacity_and_unit():
    util = dashboard.pool_utilization(_generous_result())
    # One change-window fix (effort 1), one appsec (effort 2), one patching (1).
    assert util["change_window"]["used"] == 1
    assert util["appsec"]["used"] == 2
    assert util["patching"]["capacity"] == 100
    assert util["change_window"]["unit"] == "slots"


def test_plan_delta_reports_adds_and_drops():
    from optimizer import RemediationPlan
    base = RemediationPlan(items=pd.DataFrame({"cve_id": ["A", "B"]}),
                           total_risk_reduction=0.0, consumed={}, pools={})
    opt = RemediationPlan(items=pd.DataFrame({"cve_id": ["B", "C"]}),
                          total_risk_reduction=0.0, consumed={}, pools={})
    delta = dashboard.plan_delta(base, opt)
    assert delta["added"] == {"C"}
    assert delta["dropped"] == {"A"}


def test_asset_map_layout_positions_nodes_and_pairs_edges():
    layout = dashboard.asset_map_layout(_asset_table())
    assert set(layout.nodes["asset_id"]) == {"crown", "mid", "edge"}
    x_by_id = dict(zip(layout.nodes["asset_id"], layout.nodes["x"]))
    assert x_by_id["crown"] == 0 and x_by_id["edge"] == 2  # x = hop distance
    assert "tier_color" in layout.nodes.columns
    # crown-mid and mid-edge, de-duped and endpoint-resolved.
    assert len(layout.edges) == 2
    assert {"x", "y", "x2", "y2"} <= set(layout.edges.columns)


def test_asset_map_layout_flags_planned_nodes():
    layout = dashboard.asset_map_layout(_asset_table(), _generous_result())
    in_plan = dict(zip(layout.nodes["asset_id"], layout.nodes["in_plan"]))
    assert bool(in_plan["crown"]) is True  # crown carries a scheduled fix


def test_rank_table_numbers_rows_in_order():
    ranked = dashboard.rank_table(_scored_with_assets())
    assert list(ranked["rank"]) == [1, 2, 3]
    assert list(ranked["cve_id"]) == ["CVE-2021-1", "CVE-2023-2", "CVE-2024-3"]


def test_rank_table_filters_are_independent():
    scored = _scored_with_assets()
    assert set(dashboard.rank_table(scored, kev_only=True)["cve_id"]) == {"CVE-2021-1"}
    assert set(dashboard.rank_table(scored, tier="critical")["cve_id"]) == {
        "CVE-2021-1", "CVE-2023-2"}
    assert list(dashboard.rank_table(scored, search="2024")["cve_id"]) == ["CVE-2024-3"]
