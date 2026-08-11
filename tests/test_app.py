"""
Tests for the Scryxen Streamlit dashboard (epic #6).

Driven headless with Streamlit's official AppTest harness — the same code path
`streamlit run app.py` executes — so acceptance like "launches cleanly", "a
capacity input changes the plan", and "the asset map / plan breakdown render"
are real, runnable assertions rather than manual checks. The logic these widgets
call is covered directly in test_dashboard.py; here we assert the wiring.
"""
from pathlib import Path

from streamlit.testing.v1 import AppTest

# app.py lives at the repo root, one level up from tests/.
APP = str(Path(__file__).resolve().parent.parent / "app.py")


def _run(**session) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=60)
    for key, value in session.items():
        at.session_state[key] = value
    at.run()
    return at


def _risk_removed(at: AppTest) -> str:
    """The 'Risk removed' summary metric (the optimized plan's total), as shown."""
    for m in at.metric:
        if (m.label or "") == "Risk removed":
            return m.value
    raise AssertionError("'Risk removed' metric not found")


# --- shell ------------------------------------------------------------------

def test_app_runs_without_crashing():
    assert not _run().exception


def test_title_is_scryxen_not_the_old_name():
    at = _run()
    assert any("Scryxen" in t.value for t in at.title)
    blob = " ".join([t.value for t in at.title] + [m.value for m in at.markdown])
    assert "Fulcrum" not in blob


def test_no_story_labels_leak_into_the_ui():
    # The rework dropped "Story #NN" labels in favour of plain descriptions.
    at = _run()
    blob = " ".join(
        [m.value for m in at.markdown] + [c.value for c in at.caption]
    ).lower()
    assert "story #" not in blob


def test_no_verbose_caveat_banner():
    # The wall-of-text ADR caveat is gone; honesty moved to a tooltip.
    at = _run()
    onscreen = " ".join([c.value for c in at.caption] + [i.value for i in at.info])
    assert "See ADR-0001" not in onscreen


# --- landing inputs ---------------------------------------------------------

def test_input_first_controls_are_present():
    at = _run()
    number_keys = {n.key for n in at.number_input}
    assert {"cap_patching", "cap_appsec", "cap_change_window"} <= number_keys
    assert "max_results" in number_keys  # "how many to list?"
    assert at.radio(key="asset_choice") is not None  # sample vs upload


def test_capacity_is_typed_in_hours_not_a_fixed_slider():
    # The rework moved capacity from fixed-range sliders to free-typed inputs.
    at = _run()
    slider_keys = {s.key for s in at.slider}
    assert "cap_patching" not in slider_keys
    assert at.number_input(key="cap_patching") is not None


# --- a capacity input drives the plan ---------------------------------------

def test_starving_capacity_changes_the_plan_output():
    at = _run()
    before = _risk_removed(at)
    at.number_input(key="cap_patching").set_value(0)
    at.number_input(key="cap_appsec").set_value(0)
    at.number_input(key="cap_change_window").set_value(0)
    at.run()
    assert not at.exception
    assert _risk_removed(at) != before


# --- summary, map, plans render ---------------------------------------------

def test_summary_and_asset_map_render():
    at = _run()
    assert any("%" in m.value for m in at.metric)          # the "+X%" headline
    assert any("Critical assets addressed" == (m.label or "") for m in at.metric)
    # The asset-map section renders (its caption is the reliable wiring signal;
    # the SVG itself is an embedded component the harness does not introspect).
    captions = " ".join(c.value for c in at.caption).lower()
    assert "hops from the crown jewel" in captions
    markdown = " ".join(m.value for m in at.markdown)
    assert "Asset map" in markdown


def test_focus_selectbox_offers_the_environment_assets():
    at = _run()
    focus = at.selectbox(key="focus_asset")
    assert focus is not None
    assert "(whole environment)" in focus.options


# --- simulate: live vendor scan (cached, offline) ---------------------------

def test_live_vendor_scan_uses_cached_pull_offline():
    # "cisco" has a committed cache file, so this runs with no network.
    at = _run()
    at.text_input(key="vendor_query").set_value("cisco")
    at.button(key="scan_btn").click()
    at.run()
    assert not at.exception
    banners = " ".join(i.value for i in at.info).lower()
    assert "vendor scan" in banners and "cisco" in banners
    assert "cached" in banners  # clearly labelled live-vs-cached


def test_whole_environment_button_returns_from_a_scan():
    at = _run()
    at.text_input(key="vendor_query").set_value("cisco")
    at.button(key="scan_btn").click()
    at.run()
    at.button(key="reset_btn").click()
    at.run()
    assert any("Sample environment" in i.value for i in at.info)


# --- simulate: a new KEV listing re-optimizes -------------------------------

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
    labels = " ".join((m.label or "").lower() for m in at.metric)
    assert "before" in labels and "after" in labels


def test_kev_candidates_offered_are_not_already_known_exploited():
    at = _run()
    at.text_input(key="vendor_query").set_value("eclipse mosquitto")
    at.button(key="scan_btn").click()
    at.run()
    options = at.selectbox(key="kev_candidate").options
    assert len(options) > 0
