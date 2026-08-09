"""
Tests for the Data Source adapter (epic #47, story #48).

The ingestion module must be importable and testable *without* an NVD API key
(the key only raises NVD's rate limit), and `fetch_merged` must serve a cached
pull from disk so the tool and the demo run offline and deterministically.
"""
import importlib

import pandas as pd
import pytest

import combine_feeds_with_custom_inputs as cf


# ---------------------------------------------------------------------------
# Importability — the module must not require a key just to be imported.
# ---------------------------------------------------------------------------
def test_module_imports_without_api_key(monkeypatch):
    # Regression: the module used to raise RuntimeError at import time when
    # NVD_API_KEY was absent, which made it impossible to import in tests.
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    importlib.reload(cf)
    assert hasattr(cf, "fetch_merged")


# ---------------------------------------------------------------------------
# fetch_merged — orchestration + disk cache
# ---------------------------------------------------------------------------
def _fake_feeds(monkeypatch):
    """Stub the three network clients with tiny deterministic frames."""
    nvd = pd.DataFrame(
        [
            {"cve_id": "CVE-2021-1", "cvss_score": 9.8, "cvss_severity": "CRITICAL", "published": "2021"},
            {"cve_id": "CVE-2021-2", "cvss_score": 5.0, "cvss_severity": "MEDIUM", "published": "2021"},
        ]
    )
    epss = pd.DataFrame(
        # Only one of the two CVEs has an EPSS score, to prove the other is kept
        # with a null rather than dropped.
        [{"cve_id": "CVE-2021-1", "epss_score": 0.9, "epss_percentile": 0.99}]
    )
    kev = pd.DataFrame(
        [{"cve_id": "CVE-2021-1", "kev_flag": True, "kev_date_added": "2021-12-10", "kev_ransomware_use": "Known"}]
    )
    monkeypatch.setattr(cf, "fetch_nvd_cves", lambda *a, **k: nvd.copy())
    monkeypatch.setattr(cf, "fetch_epss_scores", lambda *a, **k: epss.copy())
    monkeypatch.setattr(cf, "fetch_kev_flags", lambda *a, **k: kev.copy())


def test_fetch_merged_missing_feeds_are_null_not_dropped(monkeypatch, tmp_path):
    _fake_feeds(monkeypatch)
    df = cf.fetch_merged("microsoft", max_results=2, cache_dir=tmp_path)

    assert len(df) == 2  # neither CVE dropped
    row2 = df.loc[df["cve_id"] == "CVE-2021-2"].iloc[0]
    assert pd.isna(row2["epss_score"])       # missing EPSS -> null, not dropped
    assert bool(row2["kev_flag"]) is False   # not in KEV -> explicit False
    row1 = df.loc[df["cve_id"] == "CVE-2021-1"].iloc[0]
    assert bool(row1["kev_flag"]) is True


def test_fetch_merged_writes_then_replays_from_cache(monkeypatch, tmp_path):
    _fake_feeds(monkeypatch)
    first = cf.fetch_merged("apache", max_results=2, cache_dir=tmp_path)
    assert len(first) == 2

    # Now make every network client explode; a second call for the same
    # (vendor, max_results) must be served from the cache with no network.
    def _boom(*a, **k):
        raise AssertionError("network client called despite a warm cache")

    monkeypatch.setattr(cf, "fetch_nvd_cves", _boom)
    monkeypatch.setattr(cf, "fetch_epss_scores", _boom)
    monkeypatch.setattr(cf, "fetch_kev_flags", _boom)

    second = cf.fetch_merged("apache", max_results=2, cache_dir=tmp_path)
    pd.testing.assert_frame_equal(
        first.reset_index(drop=True), second.reset_index(drop=True)
    )


def test_cache_is_keyed_by_vendor_and_max(monkeypatch, tmp_path):
    _fake_feeds(monkeypatch)
    cf.fetch_merged("cisco", max_results=2, cache_dir=tmp_path)
    cf.fetch_merged("cisco", max_results=5, cache_dir=tmp_path)
    cf.fetch_merged("openssl", max_results=2, cache_dir=tmp_path)

    files = sorted(p.name for p in tmp_path.glob("*.csv"))
    assert len(files) == 3  # three distinct (vendor, max) keys -> three files


def test_refresh_bypasses_cache(monkeypatch, tmp_path):
    _fake_feeds(monkeypatch)
    cf.fetch_merged("redhat", max_results=2, cache_dir=tmp_path)

    calls = {"n": 0}

    def _counting_nvd(*a, **k):
        calls["n"] += 1
        return pd.DataFrame(
            [{"cve_id": "CVE-2021-1", "cvss_score": 9.8, "cvss_severity": "CRITICAL", "published": "2021"}]
        )

    monkeypatch.setattr(cf, "fetch_nvd_cves", _counting_nvd)
    cf.fetch_merged("redhat", max_results=2, cache_dir=tmp_path, refresh=True)
    assert calls["n"] == 1  # refresh forced a live pull even with a warm cache
