"""
Scryxen dashboard — Streamlit view over the planning engine (epic #6).

A thin view: every number comes from `dashboard.py` (which wraps
`pipeline`/`scoring`/`capacity`/`optimizer`). This module owns only widgets and
layout — no business logic (the epic #6 rule).

Flow (the reshape): the app opens on an **intake page** — inputs only, nothing
computed — and holds there until "Build my plan" is pressed. That flips it to the
**summary board**: the headline metrics, the asset map, and the side-by-side
plans, with the same inputs moved to the sidebar so they stay live (a slider
re-plans in place). Any finding or system is a click away from its **detail**.

Run:
    streamlit run app.py
"""
from __future__ import annotations

import io

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

import capacity
import dashboard
import pipeline

PAGE_TITLE = "Scryxen"
TAGLINE = "Capacity-aware remediation planning — fix what protects the most, first."
TIERS = ("critical", "high", "medium", "low")

# ADR-0001, kept honest but not as a wall of text: the feeds are real, the asset
# environment is modelled. Surfaced as a single tooltip, not an on-screen banner.
HONESTY_NOTE = (
    "Vulnerability feeds (NVD · EPSS · CISA KEV) are real and live. The sample "
    "asset environment is a modelled mid-sized company — in production this is "
    "your own uploaded asset inventory. See ADR-0001."
)


# --- cached I/O (the scans; the logic itself lives in dashboard) ------------

@st.cache_data(show_spinner="Scanning the sample environment…")
def _scan_sample() -> pd.DataFrame:
    return dashboard.default_environment()


@st.cache_data(show_spinner="Scanning your uploaded environment…")
def _scan_uploaded(csv_bytes: bytes) -> pd.DataFrame:
    table = dashboard.load_asset_table(io.BytesIO(csv_bytes))
    return pipeline.scan_environment(asset_table=table)


@st.cache_data(show_spinner=False)
def _sample_asset_table() -> pd.DataFrame:
    return dashboard.load_asset_table()


# --- inputs (rendered on the intake page, then in the sidebar once built) ---

def environment_inputs() -> tuple[pd.DataFrame, pd.DataFrame | None, str]:
    """
    "Your assets": upload a CSV (the primary, demo path) or fall back to the
    sample environment. Returns the scored environment plus its asset table
    (None if the upload failed / had no graph).
    """
    st.markdown("**1 · Your assets**")
    choice = st.radio(
        "Assets",
        ("Upload your assets", "Use the sample environment"),
        horizontal=True, key="asset_choice", label_visibility="collapsed",
        help="Upload a CSV with the same columns as the sample to map your own systems.",
    )

    if choice == "Upload your assets":
        upload = st.file_uploader(
            "Insert your assets (CSV)", type="csv", key="asset_upload",
            help="Columns: " + ", ".join(dashboard.REQUIRED_ASSET_COLUMNS),
        )
        if upload is not None:
            data = upload.getvalue()
            try:
                table = dashboard.load_asset_table(io.BytesIO(data))
            except ValueError as exc:
                st.error(f"{exc}  Falling back to the sample environment.")
            else:
                return _scan_uploaded(data), table, f"Your assets · {upload.name}"
        else:
            st.caption("No file yet — using the sample environment until you upload one.")

    return _scan_sample(), _sample_asset_table(), "Sample environment"


def listing_inputs(env: pd.DataFrame) -> tuple[int | None, tuple[int, int] | None]:
    """
    "How many vulnerabilities to list?" (defaulting to *all*) and an optional
    disclosure-year range.
    """
    st.markdown("**2 · How much to show**")
    show_all = st.toggle("List every vulnerability", value=True, key="list_all",
                         help="On = show them all. Off = cap the findings table to a number.")
    max_results = None
    if not show_all:
        max_results = int(st.number_input(
            "How many vulnerabilities to list?", min_value=1, value=100, step=25,
            key="max_results",
        ))

    year_range = None
    bounds = dashboard.year_bounds(env)
    if bounds and bounds[0] < bounds[1]:
        year_range = st.slider(
            "Disclosure years", bounds[0], bounds[1], bounds, key="year_range",
            help="Narrow to CVEs disclosed in a year range. Full span = all years.",
        )
        if year_range == bounds:
            year_range = None  # full span means "no filter"
    return max_results, year_range


def capacity_inputs() -> dict[str, capacity.CapacityPool]:
    """"Team capacity", in the team's own work-time. Free-typed, so the ceiling is
    the user's to set (no artificial slider max)."""
    st.markdown("**3 · Team capacity**")
    defaults = capacity.DEFAULT_POOL_CAPACITY
    patching = st.number_input(
        "Patching (hours)", min_value=0, value=int(defaults[capacity.POOL_PATCHING][0]),
        step=10, key="cap_patching", help="Routine OS & package updates.",
    )
    appsec = st.number_input(
        "AppSec (hours)", min_value=0, value=int(defaults[capacity.POOL_APPSEC][0]),
        step=5, key="cap_appsec", help="Code fixes and dependency bumps.",
    )
    change_window = st.number_input(
        "Change-window slots", min_value=0,
        value=int(defaults[capacity.POOL_CHANGE_WINDOW][0]),
        step=1, key="cap_change_window", help="Scheduled reboots / prod-impacting work.",
    )
    return dashboard.build_pools(patching, appsec, change_window)


def scoring_inputs() -> dashboard.scoring.ScoringWeights:
    """How much each signal counts. Tucked in an expander — sensible by default."""
    with st.expander("Scoring emphasis — how much each signal counts", expanded=False):
        st.caption("Weights are rebalanced to sum to 1; only their relative size matters.")
        cvss = st.slider("Severity (CVSS)", 0.0, 1.0, 0.25, 0.05, key="w_cvss")
        epss = st.slider("Exploit prob. (EPSS)", 0.0, 1.0, 0.30, 0.05, key="w_epss")
        kev = st.slider("Known exploited (KEV)", 0.0, 1.0, 0.20, 0.05, key="w_kev")
        importance = st.slider("Asset importance", 0.0, 1.0, 0.25, 0.05, key="w_importance")
    return dashboard.normalize_weights(cvss, epss, kev, importance)


def collect_inputs(env: pd.DataFrame):
    """Render every input control (in whatever container is active) and return the
    resolved values. Called in the body on the intake page, then in the sidebar
    once a plan is built — the stable widget keys carry the values across."""
    env2, asset_table, source = environment_inputs()
    max_results, year_range = listing_inputs(env2)
    pools = capacity_inputs()
    weights = scoring_inputs()
    return env2, asset_table, source, max_results, year_range, pools, weights


# --- simulate: live vendor scan + a new KEV listing (results-page sidebar) ---

def simulate_controls(env: pd.DataFrame) -> str | None:
    """The demo levers. Assumes it is already inside the sidebar container."""
    st.subheader("Scan a specific vendor")
    st.caption("Pull one vendor's live CVEs instead of the whole environment.")
    st.text_input("Vendor / product", key="vendor_query", placeholder="e.g. fortinet")
    st.select_slider("Assumed criticality", options=TIERS, value="high", key="live_tier")
    cols = st.columns(2)
    cols[0].button("Scan vendor", key="scan_btn", use_container_width=True,
                   on_click=_run_live_scan)
    cols[1].button("Whole environment", key="reset_btn", use_container_width=True,
                   on_click=_clear_live_scan)

    st.divider()
    st.subheader("New KEV listing")
    st.caption("Flip a CVE to known-exploited and watch the plan re-pack.")
    candidates = dashboard.kev_candidates(env)
    st.selectbox("CVE just added to CISA KEV", candidates, key="kev_candidate")
    cols = st.columns(2)
    cols[0].button("Add to KEV", key="kev_btn", on_click=_inject_kev,
                   use_container_width=True)
    cols[1].button("Clear", key="kev_clear_btn", on_click=_clear_kev,
                   use_container_width=True)
    return st.session_state.get("kev_injected")


def _run_live_scan() -> None:
    vendor = st.session_state.get("vendor_query", "").strip()
    if not vendor:
        return
    scan = dashboard.live_environment(vendor, tier=st.session_state.get("live_tier", "high"))
    if scan is None:
        st.session_state["live_scan_error"] = vendor
        return
    st.session_state.pop("live_scan_error", None)
    st.session_state["live_scan"] = scan
    st.session_state.pop("kev_injected", None)


def _clear_live_scan() -> None:
    for key in ("live_scan", "live_scan_error", "kev_injected"):
        st.session_state.pop(key, None)


def _inject_kev() -> None:
    st.session_state["kev_injected"] = st.session_state.get("kev_candidate")


def _clear_kev() -> None:
    st.session_state.pop("kev_injected", None)


# --- build / edit gate ------------------------------------------------------

def _build() -> None:
    st.session_state["plan_built"] = True


def _unbuild() -> None:
    st.session_state["plan_built"] = False


# --- click-through detail (modals) ------------------------------------------

@st.dialog("Why this finding ranks here")
def _finding_dialog(detail: dict) -> None:
    _render_detail(detail)


@st.dialog("System detail")
def _asset_dialog(detail: dict) -> None:
    st.markdown(f"### {detail['name'] or detail['asset_id']}")
    tier = detail["importance_tier"]
    if tier:
        colour = dashboard.TIER_COLORS.get(tier, dashboard.TIER_COLORS["low"])
        st.markdown(
            f"<span style='color:{colour};font-weight:600'>{tier} importance</span>"
            + ("  ·  crown jewel" if detail["crown_jewel"] else ""),
            unsafe_allow_html=True,
        )
    if detail["hop_distance"] is not None:
        st.caption(f"{detail['hop_distance']} hop(s) from the crown jewel · "
                   f"criticality: {detail['criticality'] or '—'} · "
                   f"vendor: {detail['vendor'] or '—'}")
    if detail["connections"]:
        st.write("**Connected to:** " + ", ".join(detail["connections"]))
    st.metric("Fixes scheduled here", detail["scheduled_count"],
              help=f"{detail['finding_count']} finding(s) affect this system.")
    if detail["scheduled_cves"]:
        st.write("**Scheduled CVEs:** " + ", ".join(detail["scheduled_cves"]))
    else:
        st.info("No fix is scheduled for this system under the current capacity.")


# --- render: the summary board ---------------------------------------------

def render_summary(result: pipeline.PlanResult, coverage: dict) -> None:
    st.markdown("### Summary")
    head = dashboard.headline(result)
    cols = st.columns(4)
    cols[0].metric("Optimizer buys", f"+{head['improvement_pct']:.1f}%",
                   help="Extra risk removed vs. fixing by severity alone.")
    cols[1].metric("Risk removed", f"{head['optimized_risk']:,.0f}",
                   f"{head['optimized_fixes']} fixes")
    cols[2].metric("Severity-first would remove", f"{head['baseline_risk']:,.0f}",
                   f"{head['baseline_fixes']} fixes")
    if coverage["total"]:
        cols[3].metric("Critical assets addressed",
                       f"{coverage['covered']} of {coverage['total']}",
                       help="Critical-importance systems with at least one scheduled fix.")


def render_asset_map(asset_table: pd.DataFrame, result: pipeline.PlanResult,
                     focus: str | None) -> None:
    st.markdown("### Asset map")
    st.caption("Importance by hops from the crown jewel · 0–1 critical · 2–3 high · "
               "4–5 medium · 6+ low. Green dot = a fix is scheduled for that system.")
    amap = dashboard.asset_map_data(asset_table)
    svg = dashboard.asset_map_svg(
        amap, selected=focus, in_plan_assets=dashboard.in_plan_assets(result.optimized)
    )
    components.html(
        f'<div style="overflow-x:auto">{svg}</div>',
        height=dashboard.asset_map_height(amap) + 12,
    )


def render_plans(result: pipeline.PlanResult, asset_table: pd.DataFrame | None) -> None:
    st.markdown("### Remediation plans")
    st.caption("Click a finding to see why it ranks where it does.")
    baseline_col, optimized_col = st.columns(2)
    with baseline_col:
        st.markdown("**Severity-first** — CVSS order only")
        _render_plan_list(result.baseline, asset_table, key="base")
    with optimized_col:
        st.markdown("**Capacity-optimized** — most risk removed per hour")
        _render_plan_list(result.optimized, asset_table, key="opt")


def _render_plan_list(plan: pipeline.RemediationPlan, asset_table: pd.DataFrame | None,
                      *, key: str, limit: int = 12) -> None:
    if plan.items.empty:
        st.info("No fixes fit the current capacity.")
        return
    annotated = dashboard.annotate_plan(plan.items.head(limit), asset_table)
    for i, (_, row) in enumerate(annotated.iterrows()):
        detail = dashboard.plan_item_detail(row)
        title = f"{detail['composite_score']:.0f} · {detail['cve_id']}"
        if detail["asset_name"]:
            title += f" — {detail['asset_name']}"
        if st.button(title, key=f"{key}_{i}", use_container_width=True):
            _finding_dialog(detail)


def _render_detail(detail: dict) -> None:
    def line(label: str, value: str) -> None:
        left, right = st.columns([2, 1])
        left.markdown(f"<span style='color:gray'>{label}</span>", unsafe_allow_html=True)
        right.markdown(f"**{value}**")

    st.markdown(f"#### {detail['cve_id']}"
                + (f" — {detail['asset_name']}" if detail["asset_name"] else ""))
    line("CVSS severity", f"{detail['cvss_score']:.1f} of 10"
         if detail["cvss_score"] is not None else "—")
    line("Exploitation likelihood (EPSS)", f"{round(detail['epss_score'] * 100)}%")
    line("Active exploitation (CISA KEV)", "yes — on KEV" if detail["kev_flag"] else "not listed")
    if detail["hop_distance"] is not None:
        line("Hops from crown jewel",
             f"{detail['hop_distance']} → {detail['importance_tier']} importance")
    elif detail["importance_tier"]:
        line("Asset importance", detail["importance_tier"])
    if detail["pool"]:
        line("Work pool", str(detail["pool"]).replace("_", " "))
    if detail["effort"] is not None:
        line("Effort estimate", f"{detail['effort']:g}")
    line("Composite risk score", f"{detail['composite_score']:.0f} of 100")
    st.caption(detail["reason_sentence"])


def render_findings(result: pipeline.PlanResult, max_results: int | None,
                    year_range: tuple[int, int] | None, focus: str | None) -> None:
    view = dashboard.filter_findings(
        result.scored, max_results=max_results, year_range=year_range, asset_id=focus
    )
    with st.expander(f"All scored findings — showing {len(view):,} of "
                     f"{len(result.scored):,}", expanded=False):
        st.dataframe(dashboard.findings_view(view), use_container_width=True, hide_index=True)


def render_kev_delta(cve_id: str, before: pipeline.PlanResult,
                     after: pipeline.PlanResult) -> None:
    st.warning(f"Simulating a new KEV listing for **{cve_id}** — plan re-optimized.")
    cols = st.columns(3)
    cols[0].metric("Risk removed — before", f"{before.optimized.total_risk_reduction:,.0f}")
    delta = after.optimized.total_risk_reduction - before.optimized.total_risk_reduction
    cols[1].metric("Risk removed — after",
                   f"{after.optimized.total_risk_reduction:,.0f}", f"{delta:+,.0f}")
    scheduled = cve_id in set(after.optimized.items.get("cve_id", []))
    cols[2].metric("Newly-KEV CVE now scheduled?", "yes" if scheduled else "no")


# --- pages ------------------------------------------------------------------

def intake_page() -> None:
    """The load-in page: inputs only, nothing computed, until "Build my plan"."""
    st.markdown("### Set up your scan")
    st.caption("Tell Scryxen what to look at. Everything has a sensible default — "
               "you can just press Build.")
    # env is scanned (cached) so the year-range control knows its bounds; no plan
    # is computed or shown yet.
    env = _scan_sample()
    collect_inputs(env)
    st.divider()
    st.button("Build my plan  ▶", type="primary", on_click=_build,
              use_container_width=True, key="build_btn")


def results_page() -> None:
    """The summary board: inputs move to the sidebar (still live), results fill
    the body — summary strip, asset map, side-by-side plans, findings."""
    with st.sidebar:
        st.header("Inputs")
        env, asset_table, source, max_results, year_range, pools, weights = (
            collect_inputs(_scan_sample())
        )
        st.button("◀  Edit inputs", on_click=_unbuild, key="edit_btn",
                  use_container_width=True)
        st.divider()
        st.header("Simulate")
        # A live vendor scan replaces the environment (it has no asset graph, so
        # the map is hidden for it).
        injected = simulate_controls(env)

    scan = st.session_state.get("live_scan")
    if st.session_state.get("live_scan_error"):
        st.sidebar.error(f"No CVEs found for '{st.session_state['live_scan_error']}'.")
    if scan is not None:
        env, asset_table, source = scan.env, None, f"Vendor scan · {scan.vendor} · {scan.source}"

    st.info(source)

    result = dashboard.plan(env, weights=weights, pools=pools)
    if injected:
        after = dashboard.plan(dashboard.inject_kev(env, injected),
                               weights=weights, pools=pools)
        render_kev_delta(injected, result, after)
        result = after

    focus = None
    if asset_table is not None:
        options = ["(whole environment)"] + sorted(asset_table["asset_id"].tolist())
        picked = st.selectbox("Focus a system", options, key="focus_asset",
                              help="Highlight it on the map and filter the findings to it.")
        focus = None if picked == options[0] else picked
        if focus and st.button(f"View “{focus}” detail", key="asset_detail_btn"):
            _asset_dialog(dashboard.asset_detail(focus, asset_table, result))

    coverage = (dashboard.asset_coverage(asset_table, result.optimized)
                if asset_table is not None else {"covered": 0, "total": 0})
    render_summary(result, coverage)

    if asset_table is not None:
        render_asset_map(asset_table, result, focus)

    render_plans(result, asset_table)
    render_findings(result, max_results, year_range, focus)


# --- main -------------------------------------------------------------------

def main() -> None:
    st.set_page_config(page_title=PAGE_TITLE, layout="wide")
    st.title(PAGE_TITLE)
    st.caption(TAGLINE, help=HONESTY_NOTE)

    if st.session_state.get("plan_built"):
        results_page()
    else:
        intake_page()


# Streamlit runs the script with __name__ == "__main__" (both `streamlit run`
# and the AppTest harness), so the standard guard drives the render.
if __name__ == "__main__":
    main()
