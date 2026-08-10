"""
Tests for the CVE->asset join (epic #47, story #50).

Each asset declares the vendor/product it runs; NVD keyword search returns that
software's CVEs; a CVE's importance_tier is the tier of the asset(s) running it.
When several assets share a vendor, the highest tier wins. CVEs with no matching
asset get an explicit null tier ("not in environment"), never dropped.
"""
import pandas as pd
import pytest

import cve_asset_map as cam
import scoring


def _asset_table() -> pd.DataFrame:
    # Same vendor 'microsoft' on both a critical and a low asset -> highest wins.
    return pd.DataFrame(
        [
            {"asset_id": "db-01", "importance_tier": "critical", "vendor": "microsoft"},
            {"asset_id": "ws-09", "importance_tier": "low", "vendor": "microsoft"},
            {"asset_id": "web-01", "importance_tier": "medium", "vendor": "apache"},
        ]
    )


# ---------------------------------------------------------------------------
# tier ranking + vendor->tier resolution
# ---------------------------------------------------------------------------
def test_highest_tier_prefers_critical():
    assert cam.highest_tier(["low", "critical", "medium"]) == "critical"
    assert cam.highest_tier(["low", "medium"]) == "medium"


def test_vendor_tiers_takes_highest_asset_per_vendor():
    vt = cam.vendor_tiers(_asset_table())
    assert vt["microsoft"] == "critical"   # critical db-01 beats low ws-09
    assert vt["apache"] == "medium"


# ---------------------------------------------------------------------------
# attach_importance_tier — single-vendor annotation
# ---------------------------------------------------------------------------
def test_attach_tier_for_matched_vendor():
    vulns = pd.DataFrame(
        [
            {"cve_id": "CVE-1", "cvss_score": 9.0, "epss_score": 0.5, "kev_flag": True},
            {"cve_id": "CVE-2", "cvss_score": 4.0, "epss_score": 0.1, "kev_flag": False},
        ]
    )
    out = cam.attach_importance_tier(vulns, "microsoft", _asset_table())
    assert len(out) == 2                       # nothing dropped
    assert (out["importance_tier"] == "critical").all()
    assert (out["vendor"] == "microsoft").all()
    assert (out["asset_id"] == "db-01").all()  # representative = highest-tier asset


def test_unmatched_vendor_gets_null_tier_not_dropped():
    vulns = pd.DataFrame([{"cve_id": "CVE-9", "cvss_score": 7.0, "epss_score": 0.2, "kev_flag": False}])
    out = cam.attach_importance_tier(vulns, "nonesuch", _asset_table())
    assert len(out) == 1
    assert pd.isna(out.iloc[0]["importance_tier"])


# ---------------------------------------------------------------------------
# build_environment_vulnerabilities — union across all asset vendors
# ---------------------------------------------------------------------------
def test_build_environment_unions_vendors_and_dedups_highest_tier():
    # A fake fetcher: 'microsoft' and 'apache' each return one shared CVE plus
    # one unique CVE, so we can prove union + dedup-by-highest-tier.
    feeds = {
        "microsoft": pd.DataFrame(
            [
                {"cve_id": "CVE-SHARED", "cvss_score": 8.0, "epss_score": 0.4, "kev_flag": False},
                {"cve_id": "CVE-MS", "cvss_score": 6.0, "epss_score": 0.2, "kev_flag": False},
            ]
        ),
        "apache": pd.DataFrame(
            [
                {"cve_id": "CVE-SHARED", "cvss_score": 8.0, "epss_score": 0.4, "kev_flag": False},
                {"cve_id": "CVE-AP", "cvss_score": 5.0, "epss_score": 0.1, "kev_flag": False},
            ]
        ),
    }
    out = cam.build_environment_vulnerabilities(
        _asset_table(), fetch=lambda vendor, **k: feeds[vendor].copy()
    )
    # Three distinct CVEs (CVE-SHARED deduped)
    assert sorted(out["cve_id"]) == ["CVE-AP", "CVE-MS", "CVE-SHARED"]
    # CVE-SHARED matched both microsoft(critical) and apache(medium) -> critical
    shared = out.loc[out["cve_id"] == "CVE-SHARED"].iloc[0]
    assert shared["importance_tier"] == "critical"


def test_build_environment_skips_a_failing_vendor():
    def _fetch(vendor, **k):
        if vendor == "apache":
            raise RuntimeError("rate limited")
        return pd.DataFrame([{"cve_id": "CVE-MS", "cvss_score": 6.0, "epss_score": 0.2, "kev_flag": False}])

    out = cam.build_environment_vulnerabilities(_asset_table(), fetch=_fetch)
    # apache failed and was skipped; microsoft still came through.
    assert list(out["cve_id"]) == ["CVE-MS"]


def test_environment_output_feeds_scoring():
    feeds = {
        "microsoft": pd.DataFrame([{"cve_id": "CVE-1", "cvss_score": 9.0, "epss_score": 0.9, "kev_flag": True}]),
        "apache": pd.DataFrame([{"cve_id": "CVE-2", "cvss_score": 5.0, "epss_score": 0.1, "kev_flag": False}]),
    }
    env = cam.build_environment_vulnerabilities(
        _asset_table(), fetch=lambda vendor, **k: feeds[vendor].copy()
    )
    scored = scoring.score_dataframe(env)  # must not raise; needs the 4 inputs
    assert "composite_score" in scored.columns
    # KEV+critical CVE-1 should outrank the quiet medium CVE-2.
    assert scored.iloc[0]["cve_id"] == "CVE-1"
