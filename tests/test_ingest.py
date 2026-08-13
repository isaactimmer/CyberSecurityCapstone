"""
Tests for the Data Source adapter (epic #47, story #48; corpus swap #56/#60).

The module must be importable and testable *without* an NVD API key (the key
only raises NVD's rate limit). As of epic #56, `fetch_merged` reads the local NVD
corpus (`corpus_store`) rather than the NVD API + disk cache, so a scan is
complete and offline; these tests drive it against an in-memory corpus.
"""
import importlib

import pandas as pd

import combine_feeds_with_custom_inputs as cf
from corpus_store import CVE_COLUMNS, CorpusStore


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
# combine_feeds — merge step (still used by the legacy CLI fallback)
# ---------------------------------------------------------------------------
def test_combine_feeds_missing_feeds_are_null_not_dropped():
    nvd = pd.DataFrame(
        [
            {"cve_id": "CVE-2021-1", "cvss_score": 9.8, "cvss_severity": "CRITICAL", "published": "2021"},
            {"cve_id": "CVE-2021-2", "cvss_score": 5.0, "cvss_severity": "MEDIUM", "published": "2021"},
        ]
    )
    # Only one of the two CVEs has an EPSS score, to prove the other is kept with
    # a null rather than dropped.
    epss = pd.DataFrame([{"cve_id": "CVE-2021-1", "epss_score": 0.9, "epss_percentile": 0.99}])
    kev = pd.DataFrame(
        [{"cve_id": "CVE-2021-1", "kev_flag": True, "kev_date_added": "2021-12-10", "kev_ransomware_use": "Known"}]
    )
    df = cf.combine_feeds(nvd, epss, kev)

    assert len(df) == 2  # neither CVE dropped
    row2 = df.loc[df["cve_id"] == "CVE-2021-2"].iloc[0]
    assert pd.isna(row2["epss_score"])       # missing EPSS -> null, not dropped
    assert bool(row2["kev_flag"]) is False   # not in KEV -> explicit False
    row1 = df.loc[df["cve_id"] == "CVE-2021-1"].iloc[0]
    assert bool(row1["kev_flag"]) is True


# ---------------------------------------------------------------------------
# fetch_merged / cache_exists — now a filter over the local corpus (#60)
# ---------------------------------------------------------------------------
def _seed_corpus(store: CorpusStore):
    """Load a tiny two-vendor corpus: one KEV+EPSS mysql CVE, one plain one, and
    an unrelated redis CVE that a mysql scan must not return."""
    store.upsert_cves(
        [
            {"cve_id": "CVE-2021-1", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
             "published": "2021", "epss_score": 0.9, "epss_percentile": 0.99, "kev_flag": True},
            {"cve_id": "CVE-2021-2", "cvss_score": 5.0, "cvss_severity": "MEDIUM", "published": "2021"},
            {"cve_id": "CVE-2021-9", "cvss_score": 7.0, "cvss_severity": "HIGH", "published": "2021"},
        ]
    )
    store.upsert_cpe(
        [
            ("CVE-2021-1", "oracle", "mysql"),
            ("CVE-2021-2", "oracle", "mysql"),
            ("CVE-2021-9", "redis", "redis"),
        ]
    )


def test_fetch_merged_returns_corpus_matches_in_contract_schema():
    store = CorpusStore(db_path=":memory:")
    _seed_corpus(store)
    df = cf.fetch_merged("mysql", store=store)

    # Exactly the two mysql CVEs, none of the redis one, in the frozen column set.
    assert list(df.columns) == list(CVE_COLUMNS)
    assert set(df["cve_id"]) == {"CVE-2021-1", "CVE-2021-2"}
    # Worst-first: the KEV+high-EPSS CVE leads.
    assert df.iloc[0]["cve_id"] == "CVE-2021-1"
    # Missing feeds surface as null / explicit False, not dropped rows.
    row2 = df.loc[df["cve_id"] == "CVE-2021-2"].iloc[0]
    assert pd.isna(row2["epss_score"])
    assert bool(row2["kev_flag"]) is False
    assert bool(df.iloc[0]["kev_flag"]) is True


def test_fetch_merged_limit_keeps_worst_n():
    store = CorpusStore(db_path=":memory:")
    _seed_corpus(store)
    df = cf.fetch_merged("mysql", max_results=1, store=store)
    assert len(df) == 1
    assert df.iloc[0]["cve_id"] == "CVE-2021-1"  # the KEV critical, not an arbitrary slice


def test_fetch_merged_empty_match_returns_empty_contract_frame():
    store = CorpusStore(db_path=":memory:")
    _seed_corpus(store)
    df = cf.fetch_merged("no-such-vendor", store=store)
    assert df.empty
    assert list(df.columns) == list(CVE_COLUMNS)  # empty but still the contract schema


def test_cache_exists_reflects_corpus_loaded():
    store = CorpusStore(db_path=":memory:")
    assert cf.cache_exists("mysql", store=store) is False  # nothing ingested yet
    _seed_corpus(store)
    assert cf.cache_exists("mysql", store=store) is True
