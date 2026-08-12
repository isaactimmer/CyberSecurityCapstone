"""
Tests for the web-console API seams in `dashboard.py` (FastAPI console reshape).

These are the pure shapers the JSON API (`server.py`) calls: they assemble the
existing engine seams into JSON-ready structures so the endpoints stay thin and
the front end never re-implements scoring. Tested here without FastAPI so the
contract is pinned independently of the transport.
"""
import pandas as pd
import pytest

import dashboard
import overrides
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


# --- score_breakdown: the finding modal's weighted-contribution split --------

def test_score_breakdown_splits_composite_into_four_weighted_parts():
    # Worked example against the documented formula (scoring.py):
    #   cvss 8.0, epss 0.5, kev True, tier high, default weights
    #   (.25,.30,.20,.25), tier_weight[high]=.75
    #   cvss part = .25*(8/10)*100      = 20.00
    #   epss part = .30*0.5*100         = 15.00
    #   kev  part = .20*1*100           = 20.00
    #   imp  part = .25*.75*100         = 18.75  -> composite 73.75
    row = pd.Series({"cvss_score": 8.0, "epss_score": 0.5, "kev_flag": True,
                     "importance_tier": "high"})
    parts = dashboard.score_breakdown(row, scoring.DEFAULT_WEIGHTS)
    assert parts["cvss"] == pytest.approx(20.0)
    assert parts["epss"] == pytest.approx(15.0)
    assert parts["kev"] == pytest.approx(20.0)
    assert parts["importance"] == pytest.approx(18.75)


def test_score_breakdown_parts_sum_to_the_composite_score():
    # The four parts must reconstruct compute_score exactly — the modal bar can't
    # imply a different total than the table's score.
    row = pd.Series({"cvss_score": 6.4, "epss_score": 0.22, "kev_flag": False,
                     "importance_tier": "medium"})
    parts = dashboard.score_breakdown(row, scoring.DEFAULT_WEIGHTS)
    composite = scoring.compute_score(6.4, 0.22, False, "medium", scoring.DEFAULT_WEIGHTS)
    assert sum(parts.values()) == pytest.approx(composite)


# --- presets: risk-appetite weight sets, shared by API and UI ----------------

def test_presets_expose_the_four_named_appetites_as_valid_weight_sets():
    got = dashboard.presets()
    assert set(got) == {"Default", "Exploit-first", "Severity-first", "Asset-first"}
    # Every preset must be a usable ScoringWeights (components sum to 1.0), or the
    # console would raise when a preset is pressed.
    for name, weights in got.items():
        keys = {"cvss", "epss", "kev", "importance"}
        assert set(weights) == keys
        assert sum(weights.values()) == pytest.approx(1.0)


def test_default_preset_matches_the_shipped_default_weights():
    default = dashboard.presets()["Default"]
    assert default["cvss"] == pytest.approx(scoring.DEFAULT_WEIGHTS.cvss)
    assert default["epss"] == pytest.approx(scoring.DEFAULT_WEIGHTS.epss)
    assert default["kev"] == pytest.approx(scoring.DEFAULT_WEIGHTS.kev)
    assert default["importance"] == pytest.approx(scoring.DEFAULT_WEIGHTS.importance)


# --- plan_payload: the whole /api/plan recompute response --------------------

def _big_pools():
    # Generous pools so the tiny fixture fully packs — keeps the assembly test
    # about shape, not the packer's edge cases (those are tested in optimizer).
    return dashboard.build_pools(patching=100, appsec=100, change_window=100)


def test_plan_payload_reports_engine_kpis_and_a_ranked_table():
    payload = dashboard.plan_payload(
        _env_frame(), weights=scoring.DEFAULT_WEIGHTS, pools=_big_pools()
    )
    # One KEV finding in the fixture.
    assert payload["kpis"]["kev_count"] == 1
    # rank_table is every finding, numbered 1..n, highest final_score first.
    rows = payload["rank_table"]
    assert [r["rank"] for r in rows] == [1, 2, 3]
    scores = [r["final_score"] for r in rows]
    assert scores == sorted(scores, reverse=True)
    assert all(r["is_overridden"] is False for r in rows)
    # Both plan lists come back, plus the map's in-plan asset set.
    assert set(payload["plans"]) == {"baseline", "optimized"}
    assert isinstance(payload["in_plan_assets"], list)


def test_plan_payload_applies_overrides_and_reranks():
    # A hand override to 100 on the lowest-composite finding must float it to the
    # top of the table with the overridden flag set — the security-lead authority.
    log = overrides.OverrideLog()
    log.record("CVE-BIG", computed_score=1.0, override_score=100.0,
               user="lead", reason="active incident")
    payload = dashboard.plan_payload(
        _env_frame(), weights=scoring.DEFAULT_WEIGHTS, pools=_big_pools(),
        override_log=log,
    )
    top = payload["rank_table"][0]
    assert top["cve_id"] == "CVE-BIG"
    assert top["final_score"] == pytest.approx(100.0)
    assert top["is_overridden"] is True
    # The override shows up in the audit trail with who/why and the from->to move.
    assert payload["audit"][0]["cve_id"] == "CVE-BIG"
    assert payload["audit"][0]["to"] == pytest.approx(100.0)
    assert payload["audit"][0]["user"] == "lead"
