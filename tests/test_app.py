"""
Tests for the Streamlit dashboard skeleton (epic #6, story #37).

The dashboard is a thin view over `pipeline.py`; these tests drive it headless
with Streamlit's official AppTest harness (no browser, no server), which is the
same code path `streamlit run app.py` executes. That makes the acceptance
criterion — "launches cleanly with placeholder content, no crash" — a real,
runnable assertion rather than a manual check.
"""
from pathlib import Path

from streamlit.testing.v1 import AppTest

# app.py lives at the repo root, one level up from tests/.
APP = str(Path(__file__).resolve().parent.parent / "app.py")


def _run() -> AppTest:
    at = AppTest.from_file(APP)
    at.run()
    return at


def test_app_runs_without_crashing():
    at = _run()
    assert not at.exception


def test_app_has_a_titled_header():
    at = _run()
    titles = [t.value for t in at.title]
    assert any("Fulcrum" in t for t in titles)


def test_app_has_a_sidebar_for_controls():
    # Later stories (#38 sliders, #53 live vendor input) hang off the sidebar;
    # the skeleton must already stand it up.
    at = _run()
    assert len(at.sidebar) > 0


def test_app_labels_the_environment_as_modelled():
    # ADR-0001 / handoff: any output must keep labelling the asset environment
    # as modelled while the feed data is real. The shell carries that caveat.
    at = _run()
    blob = " ".join(
        [m.value for m in at.markdown]
        + [c.value for c in at.caption]
        + [i.value for i in at.info]
    ).lower()
    assert "model" in blob  # "modelled" / "modeled"
