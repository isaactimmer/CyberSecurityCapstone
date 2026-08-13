"""
Phase 0 (#57): the full-corpus SQLite store.

All tests run against an in-memory DB — no disk, no network. They pin the two
contracts later phases depend on: the write API (`upsert_*`, `set_meta`) is
idempotent, and `query_vendor` returns exactly the column set `fetch_merged`
has always returned, worst-CVE first.
"""
from __future__ import annotations

import pytest

from corpus_store import CVE_COLUMNS, CorpusStore


@pytest.fixture
def store():
    s = CorpusStore(db_path=":memory:")
    yield s
    s.close()


def _cve(cve_id, **over):
    """A minimal CVE row; override any field for the case under test."""
    base = {
        "cve_id": cve_id,
        "cvss_score": 5.0,
        "cvss_severity": "MEDIUM",
        "published": "2023-01-01T00:00:00",
        "description": "a vulnerability",
        "epss_score": 0.1,
        "epss_percentile": 0.5,
        "kev_flag": False,
    }
    base.update(over)
    return base


# -- load state ------------------------------------------------------------

def test_empty_store_is_not_loaded(store):
    assert store.is_loaded() is False
    assert store.count() == 0


def test_upsert_marks_loaded_and_counts(store):
    written = store.upsert_cves([_cve("CVE-2023-0001"), _cve("CVE-2023-0002")])
    assert written == 2
    assert store.is_loaded() is True
    assert store.count() == 2


def test_upsert_is_idempotent_on_cve_id(store):
    store.upsert_cves([_cve("CVE-2023-0001", cvss_score=1.0)])
    store.upsert_cves([_cve("CVE-2023-0001", cvss_score=9.8)])  # same id, re-ingest
    assert store.count() == 1
    (row,) = store.query_vendor("vulnerability")  # description fallback hit
    assert row["cvss_score"] == 9.8  # replaced, not duplicated


# -- matching --------------------------------------------------------------

def test_query_matches_cpe_vendor(store):
    store.upsert_cves([_cve("CVE-2023-1000", description="unrelated text")])
    store.upsert_cpe([("CVE-2023-1000", "oracle", "mysql")])
    hits = store.query_vendor("oracle")
    assert [r["cve_id"] for r in hits] == ["CVE-2023-1000"]


def test_query_matches_cpe_product(store):
    store.upsert_cves([_cve("CVE-2023-1001", description="unrelated text")])
    store.upsert_cpe([("CVE-2023-1001", "oracle", "mysql")])
    assert [r["cve_id"] for r in store.query_vendor("mysql")] == ["CVE-2023-1001"]


def test_query_is_separator_insensitive(store):
    # CPE stores `http_server`; a user types "http server".
    store.upsert_cves([_cve("CVE-2023-1002", description="unrelated")])
    store.upsert_cpe([("CVE-2023-1002", "apache", "http_server")])
    assert [r["cve_id"] for r in store.query_vendor("http server")] == ["CVE-2023-1002"]


def test_query_description_fallback_for_cpe_less_cve(store):
    # A Rejected/Awaiting-Analysis CVE with no CPE config still surfaces by text.
    store.upsert_cves([_cve("CVE-2023-1003", description="A flaw in ACME Widget")])
    assert [r["cve_id"] for r in store.query_vendor("widget")] == ["CVE-2023-1003"]


def test_query_no_match_returns_empty(store):
    store.upsert_cves([_cve("CVE-2023-1004", description="nothing relevant")])
    assert store.query_vendor("nonexistent-vendor") == []


def test_description_fallback_matches_whole_word_not_substring(store):
    # The FTS fallback is word-granular: "widget" matches the token "widget" but
    # not the token "widgetized" — the intended precision trade vs. the old LIKE.
    store.upsert_cves([_cve("CVE-2023-1005", description="A flaw in the widget")])
    store.upsert_cves([_cve("CVE-2023-1006", description="A flaw when widgetized")])
    assert [r["cve_id"] for r in store.query_vendor("widget")] == ["CVE-2023-1005"]


def test_reingest_with_changed_description_reindexes_fallback(store):
    # Guards the FTS sync on INSERT OR REPLACE: the delete trigger must fire (it
    # only does with recursive_triggers ON) so the stale text stops matching and
    # the new text starts. A CPE-less CVE, so the description arm is the only hit.
    store.upsert_cves([_cve("CVE-2023-1007", description="alpha widget")])
    assert [r["cve_id"] for r in store.query_vendor("widget")] == ["CVE-2023-1007"]

    store.upsert_cves([_cve("CVE-2023-1007", description="beta gadget")])  # re-ingest
    assert store.query_vendor("widget") == []                # stale text gone
    assert [r["cve_id"] for r in store.query_vendor("gadget")] == ["CVE-2023-1007"]


# -- contract: shape & ordering -------------------------------------------

def test_query_returns_exact_column_set(store):
    store.upsert_cves([_cve("CVE-2023-2000")])
    (row,) = store.query_vendor("vulnerability")
    assert set(row.keys()) == set(CVE_COLUMNS)


def test_kev_flag_roundtrips_as_bool(store):
    store.upsert_cves([_cve("CVE-2023-2001", kev_flag=True)])
    (row,) = store.query_vendor("vulnerability")
    assert row["kev_flag"] is True


def test_query_orders_worst_first(store):
    # KEV outranks EPSS outranks CVSS. Give each contender the trait that should
    # sink or float it, then assert the resulting order.
    store.upsert_cves([
        _cve("CVE-LOW", cvss_score=2.0, epss_score=0.01, kev_flag=False),
        _cve("CVE-HIGH-CVSS", cvss_score=9.9, epss_score=0.01, kev_flag=False),
        _cve("CVE-HIGH-EPSS", cvss_score=2.0, epss_score=0.90, kev_flag=False),
        _cve("CVE-KEV", cvss_score=2.0, epss_score=0.01, kev_flag=True),
    ])
    order = [r["cve_id"] for r in store.query_vendor("vulnerability")]
    assert order == ["CVE-KEV", "CVE-HIGH-EPSS", "CVE-HIGH-CVSS", "CVE-LOW"]


def test_limit_keeps_worst_first(store):
    store.upsert_cves([
        _cve("CVE-KEV", kev_flag=True),
        _cve("CVE-PLAIN", kev_flag=False),
    ])
    top = store.query_vendor("vulnerability", limit=1)
    assert [r["cve_id"] for r in top] == ["CVE-KEV"]


# -- cpe & meta idempotency -----------------------------------------------

def test_upsert_cpe_ignores_duplicate_triples(store):
    store.upsert_cves([_cve("CVE-2023-3000", description="x")])
    store.upsert_cpe([("CVE-2023-3000", "vendorx", "prod")])
    store.upsert_cpe([("CVE-2023-3000", "vendorx", "prod")])  # dup — ignored
    assert [r["cve_id"] for r in store.query_vendor("vendorx")] == ["CVE-2023-3000"]


def test_meta_roundtrip(store):
    assert store.last_refresh("nvd") is None
    store.set_meta("nvd", "2026-08-13T00:00:00Z")
    assert store.last_refresh("nvd") == "2026-08-13T00:00:00Z"
    store.set_meta("nvd", "2026-08-14T00:00:00Z")  # upsert, not insert
    assert store.last_refresh("nvd") == "2026-08-14T00:00:00Z"
