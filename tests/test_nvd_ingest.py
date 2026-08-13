"""
Phases 1 & 2 (#58, #59): the ingest parsers and the EPSS/KEV overlay loaders.

Everything here is network-free — the parse functions are pure, and the loaders
are driven against an in-memory `CorpusStore` seeded by hand. The end-to-end
merge (NVD base → EPSS → KEV, in order) is asserted against that store so the
ingest ordering contract is pinned.
"""
from __future__ import annotations

import gzip
import json
import lzma

import pytest

import nvd_ingest as ni
from corpus_store import CorpusStore


@pytest.fixture
def store():
    s = CorpusStore(db_path=":memory:")
    yield s
    s.close()


# A minimal but realistic NVD 2.0 CVE object (the shape fkie-cad ships).
_CVE_OBJ = {
    "id": "CVE-2024-0001",
    "published": "2024-09-23T18:15:04.070",
    "descriptions": [
        {"lang": "es", "value": "Una vulnerabilidad"},
        {"lang": "en", "value": "A flaw in Purity//FA"},
    ],
    "metrics": {
        "cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
        ]
    },
    "configurations": [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {"criteria": "cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*"},
                        {"criteria": "cpe:2.3:a:purestorage:purity\\/\\/fa:6.3.0:*:*:*:*:*:*:*"},
                    ]
                }
            ]
        }
    ],
}


# -- parse_cve -------------------------------------------------------------

def test_parse_cve_extracts_base_fields():
    row, _ = ni.parse_cve(_CVE_OBJ)
    assert row == {
        "cve_id": "CVE-2024-0001",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "published": "2024-09-23T18:15:04.070",
        "description": "A flaw in Purity//FA",  # English chosen over Spanish
    }


def test_parse_cve_dedups_cpe_triples():
    _, triples = ni.parse_cve(_CVE_OBJ)
    # Both cpeMatch entries share vendor/product — one triple, not two.
    assert triples == [("CVE-2024-0001", "purestorage", "purity\\/\\/fa")]


def test_parse_cve_cvss_fallback_v2_severity_is_outer():
    obj = {
        "id": "CVE-1999-0001",
        "metrics": {
            "cvssMetricV2": [
                {"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}
            ]
        },
    }
    row, _ = ni.parse_cve(obj)
    assert (row["cvss_score"], row["cvss_severity"]) == (5.0, "MEDIUM")


def test_parse_cve_handles_missing_metrics_and_config():
    row, triples = ni.parse_cve({"id": "CVE-2000-0001"})
    assert row["cvss_score"] is None and row["cvss_severity"] is None
    assert row["description"] is None
    assert triples == []


@pytest.mark.parametrize(
    "criteria,expected",
    [
        ("cpe:2.3:a:oracle:mysql:8.0:*:*:*:*:*:*:*", ("oracle", "mysql")),
        ("cpe:2.3:o:bsdi:bsd_os:3.1:*:*:*:*:*:*:*", ("bsdi", "bsd_os")),
        ("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*", None),   # wildcard vendor/product
        ("cpe:2.3:a:vendoronly", None),            # malformed / too short
    ],
)
def test_parse_cpe_criteria(criteria, expected):
    assert ni.parse_cpe_criteria(criteria) == expected


# -- EPSS parse + overlay --------------------------------------------------

def _epss_gz() -> bytes:
    body = (
        "#model_version:v2026.06.15,score_date:2026-08-13T12:03:51Z\n"
        "cve,epss,percentile\n"
        "CVE-2024-0001,0.42,0.97\n"
        "CVE-9999-0000,0.01,0.10\n"  # not in the corpus — must be skipped
    )
    return gzip.compress(body.encode("utf-8"))


def test_parse_epss_csv_reads_rows_and_score_date():
    rows, score_date = ni.parse_epss_csv(_epss_gz())
    assert score_date == "2026-08-13T12:03:51Z"
    assert rows[0] == {
        "cve_id": "CVE-2024-0001",
        "epss_score": 0.42,
        "epss_percentile": 0.97,
    }


def test_epss_overlay_updates_only_present_cves(store):
    row, triples = ni.parse_cve(_CVE_OBJ)
    store.upsert_cves([row])
    store.upsert_cpe(triples)
    rows, _ = ni.parse_epss_csv(_epss_gz())
    store.update_epss(rows)
    (hit,) = store.query_vendor("purestorage")
    assert hit["epss_score"] == 0.42 and hit["epss_percentile"] == 0.97
    # The non-corpus CVE-9999-0000 was a no-op, not an insert.
    assert store.count() == 1


# -- KEV parse + overlay ---------------------------------------------------

_KEV_PAYLOAD = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-0001",
            "dateAdded": "2024-10-01",
            "knownRansomwareCampaignUse": "Known",
            "vulnerabilityName": "Purity//FA flaw",
            "shortDescription": "Something bad",
            "requiredAction": "Patch it",
        }
    ]
}


def test_parse_kev_json_maps_fields():
    (row,) = ni.parse_kev_json(_KEV_PAYLOAD)
    assert row["cve_id"] == "CVE-2024-0001"
    assert row["kev_ransomware_use"] == "Known"
    assert row["kev_required_action"] == "Patch it"


def test_kev_overlay_sets_flag_and_fields(store):
    row, triples = ni.parse_cve(_CVE_OBJ)
    store.upsert_cves([row])
    store.upsert_cpe(triples)
    store.update_kev(ni.parse_kev_json(_KEV_PAYLOAD))
    (hit,) = store.query_vendor("purestorage")
    assert hit["kev_flag"] is True
    assert hit["kev_required_action"] == "Patch it"


# -- ordering contract: the three feeds compose ---------------------------

def test_nvd_then_epss_then_kev_compose_on_one_row(store):
    row, triples = ni.parse_cve(_CVE_OBJ)
    store.upsert_cves([row])
    store.upsert_cpe(triples)
    store.update_epss(ni.parse_epss_csv(_epss_gz())[0])
    store.update_kev(ni.parse_kev_json(_KEV_PAYLOAD))

    (hit,) = store.query_vendor("purestorage")
    # NVD base survived both overlays; EPSS and KEV are both attached.
    assert hit["cvss_score"] == 9.8
    assert hit["epss_score"] == 0.42
    assert hit["kev_flag"] is True


# -- Phase 4: refresh / update maintenance modes (#61) ---------------------

def _write_feed_file(path, cve_objs):
    """Write a `CVE-*.json.xz` feed file in fkie-cad's shape."""
    with lzma.open(path, "wt", encoding="utf-8") as fh:
        json.dump({"cve_items": cve_objs}, fh)


def test_upsert_feed_file_loads_a_feed(store, tmp_path):
    path = tmp_path / "CVE-2024.json.xz"
    _write_feed_file(path, [_CVE_OBJ])
    n = ni._upsert_feed_file(store, path)
    assert n == 1
    (hit,) = store.query_vendor("purestorage")
    assert hit["cvss_score"] == 9.8


def test_ingest_modified_upserts_the_delta(store, tmp_path, monkeypatch):
    # A CVE already in the corpus with a stale score, then re-issued in the delta.
    stale = {**_CVE_OBJ, "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 1.0, "baseSeverity": "LOW"}}]}}
    store.upsert_cves([ni.parse_cve(stale)[0]])
    store.upsert_cpe(ni.parse_cve(stale)[1])

    feed = tmp_path / "CVE-Modified.json.xz"
    _write_feed_file(feed, [_CVE_OBJ])  # the fresh 9.8 record
    # Stub the network download to hand back our local feed file.
    monkeypatch.setattr(ni, "_download", lambda url, dest, **k: feed)

    n = ni.ingest_modified(store, feeds_dir=tmp_path)
    assert n == 1
    (hit,) = store.query_vendor("purestorage")
    assert hit["cvss_score"] == 9.8            # the delta overwrote the stale row
    assert store.last_refresh("nvd_modified")  # bookkeeping stamped


def test_parse_args_refresh_and_update_are_mutually_exclusive():
    assert ni._parse_args(["--refresh"]).refresh is True
    assert ni._parse_args(["--update"]).update is True
    with pytest.raises(SystemExit):
        ni._parse_args(["--refresh", "--update"])


def test_main_update_takes_the_fast_path(monkeypatch):
    calls = []
    monkeypatch.setattr(ni, "CorpusStore", lambda *a, **k: _NoopStore())
    monkeypatch.setattr(ni, "run_update", lambda store: calls.append("update"))
    monkeypatch.setattr(ni, "run_ingest", lambda *a, **k: calls.append("ingest"))
    ni.main(["--update"])
    assert calls == ["update"]


def test_main_refresh_forces_fresh_download(monkeypatch):
    seen = {}
    monkeypatch.setattr(ni, "CorpusStore", lambda *a, **k: _NoopStore())
    monkeypatch.setattr(ni, "run_ingest", lambda store, **k: seen.update(k))
    ni.main(["--refresh"])
    assert seen["reuse"] is False  # --refresh re-downloads every feed


class _NoopStore:
    def close(self):
        pass
