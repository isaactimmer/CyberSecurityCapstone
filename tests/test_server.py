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


def test_plan_endpoint_caps_findings_to_max(client):
    body = client.post("/api/plan", json={"max_findings": 1}).json()
    assert len(body["rank_table"]) == 1


def test_plan_endpoint_scopes_to_year_range(client):
    # Fixture spans 2019–2021; keep only 2020–2021.
    body = client.post("/api/plan", json={"year_range": [2020, 2021]}).json()
    ids = {r["cve_id"] for r in body["rank_table"]}
    assert ids == {"CVE-2020-1111", "CVE-2021-2222"}


def test_plan_endpoint_display_mode_caps_table_but_optimizer_sees_all(client):
    # scope_mode "display": the count trims only the table; the optimizer still
    # weighs every finding, so more fixes are scheduled than the single listed row.
    big = {"patching": 500, "appsec": 500, "change_window": 500}
    plan_mode = client.post("/api/plan", json={
        "max_findings": 1, "capacity": big}).json()
    disp_mode = client.post("/api/plan", json={
        "max_findings": 1, "scope_mode": "display", "capacity": big}).json()
    assert len(plan_mode["rank_table"]) == 1
    assert len(disp_mode["rank_table"]) == 1
    # Plan mode plans over the top-1 only; display mode plans over all three.
    assert plan_mode["kpis"]["optimized_fixes"] == 1
    assert disp_mode["kpis"]["optimized_fixes"] > 1


def test_plan_endpoint_display_mode_still_honours_year_range(client):
    # In display mode the year range remains a real scope (narrows the universe);
    # only the count is demoted to a display cap.
    body = client.post("/api/plan", json={
        "max_findings": 5, "scope_mode": "display", "year_range": [2020, 2021],
        "capacity": {"patching": 500, "appsec": 500, "change_window": 500}}).json()
    ids = {r["cve_id"] for r in body["rank_table"]}
    assert ids == {"CVE-2020-1111", "CVE-2021-2222"}   # 2019 excluded from universe


def test_override_endpoint_records_and_reranks(client):
    resp = client.post("/api/override", json={
        "cve_id": "CVE-2019-3333", "score": 100, "user": "lead",
        "reason": "compensating control absent"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["rank_table"][0]["cve_id"] == "CVE-2019-3333"
    assert body["rank_table"][0]["is_overridden"] is True


def test_override_endpoint_keeps_the_display_cap(client):
    # Recording an override in display mode must return the same top-N table the
    # board shows — not silently un-trim it (the override overlaid on rank 1).
    body = client.post("/api/override", json={
        "cve_id": "CVE-2019-3333", "score": 100, "user": "lead", "reason": "x",
        "max_findings": 1, "scope_mode": "display"}).json()
    assert len(body["rank_table"]) == 1
    assert body["rank_table"][0]["cve_id"] == "CVE-2019-3333"   # floated to the top


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


# --- CSV upload -------------------------------------------------------------

VALID_ASSET_CSV = (
    b"asset_id,name,criticality,crown_jewel,connections,vendor\n"
    b"a1,Crown DB,high,true,a2,oracle\n"
    b"a2,Web,medium,false,a1,microsoft\n"
)


def test_upload_swaps_state_and_returns_environment(client, monkeypatch):
    # Stub the scan so validation runs for real but no network/cache I/O happens.
    scanned = pd.DataFrame(
        [{"cve_id": "CVE-2024-9999", "cvss_score": 8.0, "epss_score": 0.4,
          "kev_flag": False, "importance_tier": "high", "vendor": "oracle",
          "asset_id": "a1"}]
    )
    monkeypatch.setattr(server.pipeline, "scan_environment",
                        lambda **kw: scanned)

    resp = client.post("/api/upload",
                       files={"file": ("mine.csv", VALID_ASSET_CSV, "text/csv")})
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "Uploaded: mine.csv"
    assert body["finding_count"] == 1
    assert len(body["asset_map"]["nodes"]) == 2      # both uploaded assets mapped
    assert server._state.asset_table is not None      # state was swapped


def test_upload_rejects_a_csv_missing_required_columns(client, monkeypatch):
    # Should never reach the scan — validation fails first.
    monkeypatch.setattr(server.pipeline, "scan_environment",
                        lambda **kw: pytest.fail("scan ran on an invalid upload"))
    # Builds a valid graph but omits the required `vendor` column.
    bad = (b"asset_id,name,criticality,crown_jewel,connections\n"
           b"a1,Crown DB,high,true,a2\n"
           b"a2,Web,medium,false,a1\n")
    resp = client.post("/api/upload",
                       files={"file": ("bad.csv", bad, "text/csv")})
    assert resp.status_code == 422
    assert "vendor" in resp.json()["detail"].lower()


def test_reset_restores_the_sample_environment(client, monkeypatch):
    sample = server.ConsoleState(env=pd.DataFrame(), asset_table=None,
                                 override_log=overrides.OverrideLog())
    monkeypatch.setattr(server, "load_state", lambda: sample)
    body = client.post("/api/reset").json()
    assert body["source"] == "Sample environment"
    assert server._state is sample
