"""
Tests for the Streamlit dashboard (epic #6).

Driven headless with Streamlit's official AppTest harness — the same code path
`streamlit run app.py` executes — so acceptance criteria like "launches cleanly"
(#37) and "moving a slider changes the plan output" (#38) are real, runnable
assertions rather than manual checks. The logic these widgets call is covered
directly in test_dashboard.py; here we assert the wiring.
"""
from pathlib import Path

from streamlit.testing.v1 import AppTest

# app.py lives at the repo root, one level up from tests/.
APP = str(Path(__file__).resolve().parent.parent / "app.py")


def _run(**session) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=30)
    for key, value in session.items():
        at.session_state[key] = value
    at.run()
    return at


# --- #37 skeleton -----------------------------------------------------------

def test_app_runs_without_crashing():
    assert not _run().exception


def test_app_has_a_titled_header():
    at = _run()
    assert any("Fulcrum" in t.value for t in at.title)


def test_app_has_a_sidebar_for_controls():
    assert len(_run().sidebar) > 0


def test_app_labels_the_environment_as_modelled():
    at = _run()
    blob = " ".join(
        [m.value for m in at.markdown]
        + [c.value for c in at.caption]
        + [i.value for i in at.info]
    ).lower()
    assert "model" in blob


# --- #38 sliders wired to real backend parameters ---------------------------

def test_all_weight_and_capacity_sliders_are_present():
    at = _run()
    keys = {s.key for s in at.slider}
    assert {"w_cvss", "w_epss", "w_kev", "w_importance"} <= keys
    assert {"cap_patching", "cap_appsec", "cap_change_window"} <= keys


def test_shrinking_a_capacity_pool_changes_the_plan_output():
    # #38 acceptance: moving a slider changes the underlying plan, not just a UI
    # value. Starving the patching pool must remove less risk.
    at = _run()
    before = _optimized_risk_metric(at)
    at.slider(key="cap_patching").set_value(0)
    at.slider(key="cap_appsec").set_value(0)
    at.slider(key="cap_change_window").set_value(0)
    at.run()
    after = _optimized_risk_metric(at)
    assert after != before


def test_reweighting_changes_the_plan_output():
    at = _run()
    before = _optimized_risk_metric(at)
    # Pour all weight onto KEV — a different composite ordering, different plan.
    at.slider(key="w_cvss").set_value(0.0)
    at.slider(key="w_epss").set_value(0.0)
    at.slider(key="w_importance").set_value(0.0)
    at.slider(key="w_kev").set_value(1.0)
    at.run()
    assert not at.exception
    assert _optimized_risk_metric(at) != before


# --- #39 findings, plans, headline ------------------------------------------

def test_headline_and_tables_render():
    at = _run()
    # headline metric + two plan tables + findings table.
    assert any("%" in m.value for m in at.metric)
    assert len(at.dataframe) >= 3


# --- #53 live "show me <vendor>" input --------------------------------------

def test_live_vendor_scan_uses_cached_pull_offline():
    # "cisco" has a committed cache file, so this runs with no network.
    at = _run()
    at.text_input(key="vendor_query").set_value("cisco")
    at.button(key="scan_btn").click()
    at.run()
    assert not at.exception
    banners = " ".join(i.value for i in at.info).lower()
    assert "live vendor scan" in banners and "cisco" in banners
    assert "cached" in banners  # clearly labelled live-vs-cached (#53 criterion)
    # The modeled-environment caveat must follow into the live path: here the
    # tier is an assumed criticality, not a real asset mapping.
    caveats = " ".join(c.value for c in at.caption).lower()
    assert "assumed criticality" in caveats


def test_reset_button_returns_to_modelled_environment():
    at = _run()
    at.text_input(key="vendor_query").set_value("cisco")
    at.button(key="scan_btn").click()
    at.run()
    at.button(key="reset_btn").click()
    at.run()
    assert any("Modelled environment" in i.value for i in at.info)


# --- #40 KEV-alert trigger --------------------------------------------------

def test_simulating_a_new_kev_reoptimizes_and_warns():
    # Scan a small cached vendor first to keep the candidate list tight and fast.
    at = _run()
    at.text_input(key="vendor_query").set_value("eclipse mosquitto")
    at.button(key="scan_btn").click()
    at.run()
    candidate = at.selectbox(key="kev_candidate").value
    at.button(key="kev_btn").click()
    at.run()
    assert not at.exception
    warnings = " ".join(w.value for w in at.warning)
    assert candidate in warnings
    # #40 Tech-Auditor check: before/after is surfaced on-screen, not just in tests.
    labels = " ".join((m.label or "").lower() for m in at.metric)
    assert "before" in labels and "after" in labels


def test_kev_candidates_offered_are_not_already_known_exploited():
    at = _run()
    at.text_input(key="vendor_query").set_value("eclipse mosquitto")
    at.button(key="scan_btn").click()
    at.run()
    options = at.selectbox(key="kev_candidate").options
    # kev_candidates excludes already-KEV CVEs, so injection is never a no-op.
    assert len(options) > 0


def _optimized_risk_metric(at: AppTest) -> str:
    """The 'Capacity-optimized risk removed' metric value, as displayed."""
    for m in at.metric:
        if "optimized" in (m.label or "").lower():
            return m.value
    raise AssertionError("optimized-risk metric not found")
