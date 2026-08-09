"""
Tests for the end-to-end pipeline wiring (epic #47, story #52).

Ties the real seams together — asset graph -> CVE->asset join -> scoring ->
capacity -> optimizer — with no manual tier or pool injection. `build_plan` is
pure (fixture DataFrame in, plans out); `scan_environment` is the only I/O.
"""
import pandas as pd

import pipeline


def _env_frame() -> pd.DataFrame:
    # Mimics build_environment_vulnerabilities output: the 4 scoring inputs plus
    # the vendor that drives pool assignment.
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


def test_build_plan_runs_all_seams_end_to_end():
    result = pipeline.build_plan(_env_frame())
    assert "composite_score" in result.scored.columns
    assert {"pool", "effort"}.issubset(result.scored.columns)
    # The optimizer never removes less risk than the naive baseline (#34).
    assert result.optimized.total_risk_reduction >= result.baseline.total_risk_reduction
    assert result.improvement >= 0.0


def test_build_plan_needs_no_manual_tier_or_pool():
    # The env frame carries importance_tier + vendor only; pools/scores are
    # derived inside the pipeline, not injected by the caller.
    env = _env_frame()
    assert "pool" not in env.columns and "composite_score" not in env.columns
    result = pipeline.build_plan(env)
    assert len(result.scored) == len(env)  # nothing dropped


def test_scan_environment_uses_injected_fetch(monkeypatch):
    feeds = {
        "apache tomcat": pd.DataFrame([{"cve_id": "CVE-1", "cvss_score": 9.0, "epss_score": 0.5, "kev_flag": True}]),
        "cisco": pd.DataFrame([{"cve_id": "CVE-2", "cvss_score": 6.0, "epss_score": 0.2, "kev_flag": False}]),
    }
    asset_table = pd.DataFrame(
        [
            {"asset_id": "a1", "importance_tier": "critical", "vendor": "apache tomcat"},
            {"asset_id": "a2", "importance_tier": "high", "vendor": "cisco"},
        ]
    )
    env = pipeline.scan_environment(
        asset_table=asset_table, fetch=lambda vendor, **k: feeds[vendor].copy()
    )
    assert sorted(env["cve_id"]) == ["CVE-1", "CVE-2"]
    # Full run from the same stub produces a valid plan.
    result = pipeline.build_plan(env)
    assert result.optimized.total_risk_reduction >= result.baseline.total_risk_reduction
