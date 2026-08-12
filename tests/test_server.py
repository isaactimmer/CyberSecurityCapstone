"""
Smoke tests for the FastAPI console endpoints (`server.py`).

These check the transport wiring — status codes and response shape — against a
fixture environment injected in place of the real scan, so they stay offline and
fast. The engine maths behind the payload are covered in test_console_payload.py.
"""
import pandas as pd
import pytest
from fastapi.testclient import TestClient

import overrides
import server


@pytest.fixture
def client(monkeypatch):
    env = pd.DataFrame(
        [
            {"cve_id": "CVE-2020-1111", "cvss_score": 9.8, "epss_score": 0.7,
             "kev_flag": True, "importance_tier": "critical", "vendor": "microsoft",
             "asset_id": "a1"},
            {"cve_id": "CVE-2021-2222", "cvss_score": 7.2, "epss_score": 0.2,
             "kev_flag": False, "importance_tier": "high", "vendor": "cisco",
             "asset_id": "a2"},
            {"cve_id": "CVE-2019-3333", "cvss_score": 5.0, "epss_score": 0.05,
             "kev_flag": False, "importance_tier": "low", "vendor": "oracle",
             "asset_id": "a1"},
        ]
    )
    # Inject a ready state so no scan (network/cache I/O) runs during tests.
    server._state = server.ConsoleState(
        env=env, asset_table=None, override_log=overrides.OverrideLog()
    )
    yield TestClient(server.app)
    server._state = None


def test_plan_endpoint_returns_the_board_payload(client):
    resp = client.post("/api/plan", json={})
    assert resp.status_code == 200
    body = resp.json()
    assert {"kpis", "rank_table", "plans", "tier_spread", "pool_utilization"} <= set(body)
    assert body["kpis"]["kev_count"] == 1


def test_plan_endpoint_honours_custom_capacity(client):
    zero = client.post("/api/plan", json={
        "capacity": {"patching": 0, "appsec": 0, "change_window": 0}}).json()
    # No capacity ⇒ nothing scheduled ⇒ no risk removed.
    assert zero["kpis"]["optimized_fixes"] == 0


def test_override_endpoint_records_and_reranks(client):
    resp = client.post("/api/override", json={
        "cve_id": "CVE-2019-3333", "score": 100, "user": "lead",
        "reason": "compensating control absent"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["rank_table"][0]["cve_id"] == "CVE-2019-3333"
    assert body["rank_table"][0]["is_overridden"] is True


def test_override_endpoint_rejects_a_blank_reason(client):
    resp = client.post("/api/override", json={
        "cve_id": "CVE-2019-3333", "score": 80, "user": "lead", "reason": "  "})
    assert resp.status_code == 422


def test_override_clear_reverts_to_computed(client):
    client.post("/api/override", json={
        "cve_id": "CVE-2019-3333", "score": 100, "user": "lead", "reason": "x"})
    body = client.post("/api/override/clear", json={
        "cve_id": "CVE-2019-3333", "score": 0, "user": "lead", "reason": "done"}).json()
    reverted = [r for r in body["rank_table"] if r["cve_id"] == "CVE-2019-3333"][0]
    assert reverted["is_overridden"] is False


def test_finding_endpoint_gives_a_score_breakdown(client):
    body = client.post("/api/finding/CVE-2020-1111", json={}).json()
    assert set(body["breakdown"]) == {"cvss", "epss", "kev", "importance"}
    assert body["cve_id"] == "CVE-2020-1111"


def test_finding_endpoint_404s_on_unknown_cve(client):
    assert client.post("/api/finding/CVE-0000-0000", json={}).status_code == 404
