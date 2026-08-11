"""
Fulcrum dashboard — Streamlit view over the planning engine (epic #6).

A thin view: every number comes from `dashboard.py` (which wraps
`pipeline`/`scoring`/`capacity`/`optimizer`). This module owns only widgets and
layout — no business logic (the epic #6 rule).

Stories wired here:
    #37  the shell (page, sidebar, sections)
    #38  scoring-weight + capacity sliders -> re-derive the plan live
    #39  findings table + severity-first vs capacity-optimized + headline metric
    #40  "a new KEV landed" trigger -> re-optimize and show the shift
    #53  live "show me <vendor>" input -> fetch_merged -> build_plan (cached offline)

Run:
    streamlit run app.py
"""
from __future__ import annotations

import pandas as pd
import streamlit as st

import capacity
import dashboard
import pipeline
import scoring

PAGE_TITLE = "Fulcrum"
HEADLINE = "Fulcrum — Capacity-Aware Remediation Planner"
TIERS = ("critical", "high", "medium", "low")

# ADR-0001: the feed data (NVD/EPSS/KEV) is real; the asset environment is a
# modelled mid-sized company. Any output must keep saying so.
ENVIRONMENT_CAVEAT = (
    "Feed data (NVD · EPSS · CISA KEV) is **real and live**. "
    "The asset environment is a **modelled** mid-sized company (`assets.csv`) — "
    "in production this is customer-supplied. See ADR-0001."
)
# During a live vendor scan there is no asset graph, so the tier is presenter-set.
LIVE_CAVEAT = (
    "Live vendor scan: the CVE feed is real, but the **assumed criticality** is a "
    "value you picked — not a real asset mapping. Still a modelled tier."
)


@st.cache_data(show_spinner="Scanning the modelled environment…")
def load_default_environment() -> pd.DataFrame:
    """Cache the default scan for the session (the I/O itself lives in dashboard)."""
    return dashboard.default_environment()


def sidebar_controls() -> tuple[scoring.ScoringWeights, dict[str, capacity.CapacityPool]]:
    """Render every control and return the weights + pools the plan builds from."""
    with st.sidebar:
        st.header("Controls")

        st.subheader("Live scan — show me a vendor")
        st.caption("Story #53 · fetches live, falls back to the offline cache.")
        st.text_input("Vendor / product", key="vendor_query", placeholder="e.g. fortinet")
        st.select_slider("Assumed criticality", options=TIERS, value="high", key="live_tier")
        cols = st.columns(2)
        cols[0].button("Scan vendor", key="scan_btn", use_container_width=True,
                       on_click=_run_live_scan)
        cols[1].button("Back to environment", key="reset_btn", use_container_width=True,
                       on_click=_clear_live_scan)

        st.divider()
        st.subheader("Scoring weights")
        st.caption("Story #38 · rebalanced to sum to 1.0; relative emphasis kept.")
        cvss = st.slider("CVSS (severity)", 0.0, 1.0, 0.25, 0.05, key="w_cvss")
        epss = st.slider("EPSS (exploit prob.)", 0.0, 1.0, 0.30, 0.05, key="w_epss")
        kev = st.slider("KEV (known exploited)", 0.0, 1.0, 0.20, 0.05, key="w_kev")
        importance = st.slider("Asset importance", 0.0, 1.0, 0.25, 0.05, key="w_importance")

        st.subheader("Team capacity")
        st.caption("Story #38 · the hard ceilings the optimizer packs fixes into.")
        patching = st.slider("Patching (hours)", 0, 200, 40, key="cap_patching")
        appsec = st.slider("AppSec (hours)", 0, 100, 16, key="cap_appsec")
        change_window = st.slider("Change window (slots)", 0, 40, 8, key="cap_change_window")

    weights = dashboard.normalize_weights(cvss, epss, kev, importance)
    pools = dashboard.build_pools(patching, appsec, change_window)
    return weights, pools


def _run_live_scan() -> None:
    """Scan button: pull the typed vendor and store it as the active environment."""
    vendor = st.session_state.get("vendor_query", "").strip()
    if not vendor:
        return
    scan = dashboard.live_environment(vendor, tier=st.session_state.get("live_tier", "high"))
    st.session_state["live_scan"] = scan
    st.session_state["live_scan_vendor"] = vendor
    st.session_state.pop("kev_injected", None)  # a new scan clears the KEV sim


def _clear_live_scan() -> None:
    st.session_state.pop("live_scan", None)
    st.session_state.pop("live_scan_vendor", None)
    st.session_state.pop("kev_injected", None)


def active_environment() -> tuple[pd.DataFrame, str, bool]:
    """The environment the plan runs on: a live vendor scan if one is active, else
    the modelled company. Returns the frame, a source label, and whether it's live."""
    scan = st.session_state.get("live_scan")
    if scan is not None:
        return scan.env, f"Live vendor scan · **{scan.vendor}** · {scan.source}", True
    return load_default_environment(), "Modelled environment · `assets.csv`", False


def render_kev_controls(env: pd.DataFrame) -> str | None:
    """#40: let the presenter simulate CISA adding a CVE to KEV. Returns the CVE to
    inject (from session), or None. The plan shift itself is rendered by the caller."""
    st.subheader("KEV alert — simulate a new listing")
    st.caption("Story #40 · flip a CVE to known-exploited and watch the plan re-pack.")

    candidates = dashboard.kev_candidates(env)
    cols = st.columns([3, 1, 1])
    cols[0].selectbox("CVE just added to CISA KEV", candidates, key="kev_candidate")
    cols[1].button("Add to KEV", key="kev_btn", on_click=_inject_kev, use_container_width=True)
    cols[2].button("Clear KEV sim", key="kev_clear_btn", on_click=_clear_kev,
                   use_container_width=True)
    return st.session_state.get("kev_injected")


def render_kev_delta(
    cve_id: str, before: pipeline.PlanResult, after: pipeline.PlanResult
) -> None:
    """#40 Tech-Auditor check: show the plan visibly change — before vs. after the
    new KEV listing, side by side, so the re-optimization is on-screen not just in
    the numbers below."""
    st.warning(f"Simulating a new KEV listing for **{cve_id}** — plan re-optimized.")
    cols = st.columns(3)
    cols[0].metric("Risk removed — before", f"{before.optimized.total_risk_reduction:,.0f}")
    cols[1].metric("Risk removed — after", f"{after.optimized.total_risk_reduction:,.0f}",
                   f"{after.optimized.total_risk_reduction - before.optimized.total_risk_reduction:+,.0f}")
    in_plan = cve_id in set(after.optimized.items.get("cve_id", []))
    cols[2].metric("Newly-KEV CVE now scheduled?", "yes" if in_plan else "no")


def _inject_kev() -> None:
    st.session_state["kev_injected"] = st.session_state.get("kev_candidate")


def _clear_kev() -> None:
    st.session_state.pop("kev_injected", None)


def render_headline(result: pipeline.PlanResult) -> None:
    """#39: the one number the demo turns on — extra risk the optimizer buys."""
    st.subheader("Headline")
    head = dashboard.headline(result)
    cols = st.columns(3)
    cols[0].metric("Optimizer buys", f"+{head['improvement_pct']:.1f}%",
                   help="Extra risk reduction over the severity-first baseline.")
    cols[1].metric("Capacity-optimized risk removed", f"{head['optimized_risk']:,.0f}",
                   f"{head['optimized_fixes']} fixes")
    cols[2].metric("Severity-first risk removed", f"{head['baseline_risk']:,.0f}",
                   f"{head['baseline_fixes']} fixes")


def render_plans(result: pipeline.PlanResult) -> None:
    """#39: severity-first vs. capacity-optimized, side by side."""
    st.subheader("Plans")
    baseline_col, optimized_col = st.columns(2)
    with baseline_col:
        st.markdown("**Severity-first plan** (baseline)")
        st.dataframe(dashboard.findings_view(result.baseline.items),
                     use_container_width=True, hide_index=True)
    with optimized_col:
        st.markdown("**Capacity-optimized plan**")
        st.dataframe(dashboard.findings_view(result.optimized.items),
                     use_container_width=True, hide_index=True)


def render_findings(result: pipeline.PlanResult) -> None:
    """#39: every scored CVE with its composite-score breakdown, highest first."""
    st.subheader(f"Findings — {len(result.scored):,} scored vulnerabilities")
    st.dataframe(dashboard.findings_view(result.scored, limit=200),
                 use_container_width=True, hide_index=True)


def main() -> None:
    st.set_page_config(page_title=PAGE_TITLE, layout="wide")
    st.title(HEADLINE)
    st.caption(ENVIRONMENT_CAVEAT)

    weights, pools = sidebar_controls()
    env, source, is_live = active_environment()
    st.info(source)
    if is_live:
        st.caption(LIVE_CAVEAT)

    injected = render_kev_controls(env)
    result = dashboard.plan(env, weights=weights, pools=pools)
    if injected:
        after = dashboard.plan(
            dashboard.inject_kev(env, injected), weights=weights, pools=pools
        )
        render_kev_delta(injected, result, after)
        result = after  # the tables below reflect the post-KEV plan

    render_headline(result)
    render_plans(result)
    render_findings(result)


# Streamlit runs the script with __name__ == "__main__" (both `streamlit run`
# and the AppTest harness), so the standard guard drives the render.
if __name__ == "__main__":
    main()
