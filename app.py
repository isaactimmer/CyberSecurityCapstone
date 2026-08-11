"""
Fulcrum dashboard — Streamlit view over the planning engine (epic #6, story #37).

This is the *shell*: page layout, sidebar, and the section stubs the rest of the
dashboard epic fills in. It is deliberately a thin view — every real number comes
from `pipeline.py` (which wraps scoring / capacity / optimizer). No business
logic lives here.

Run:
    streamlit run app.py

The later stories slot into the stubs below:
    #38  capacity + weighting sliders (sidebar)
    #39  findings table + severity-first vs capacity-optimized + headline metric
    #40  KEV-alert re-optimize trigger
    #53  live "show me <vendor>" input (sidebar) -> fetch_merged -> build_plan
"""
from __future__ import annotations

import streamlit as st

PAGE_TITLE = "Fulcrum"
HEADLINE = "Fulcrum — Capacity-Aware Remediation Planner"

# ADR-0001: the feed data (NVD/EPSS/KEV) is real; the asset environment is a
# modelled mid-sized company. Any output must keep saying so.
ENVIRONMENT_CAVEAT = (
    "Feed data (NVD · EPSS · CISA KEV) is **real and live**. "
    "The asset environment is a **modelled** mid-sized company (`assets.csv`) — "
    "in production this is customer-supplied. See ADR-0001."
)


def render_sidebar() -> None:
    """Controls live here. Story #38 (sliders) and #53 (live vendor) fill this in."""
    with st.sidebar:
        st.header("Controls")

        st.subheader("Live scan")
        st.caption("Story #53 — type a vendor/product and re-plan in front of the audience.")

        st.subheader("Scoring weights")
        st.caption("Story #38 — sliders wired to `scoring.ScoringWeights`.")

        st.subheader("Team capacity")
        st.caption("Story #38 — sliders wired to `capacity.CapacityPool` sizes.")


def render_headline_metric() -> None:
    """The one number the demo turns on: extra risk the optimizer buys. Story #39."""
    st.subheader("Headline")
    st.info("Story #39 — optimizer-vs-baseline improvement metric renders here.")


def render_plans() -> None:
    """Severity-first vs. capacity-optimized, side by side. Story #39."""
    st.subheader("Plans")
    col_baseline, col_optimized = st.columns(2)
    with col_baseline:
        st.markdown("**Severity-first plan** (baseline)")
        st.info("Story #39 — naive plan table renders here.")
    with col_optimized:
        st.markdown("**Capacity-optimized plan**")
        st.info("Story #39 — optimized plan table renders here.")


def render_findings() -> None:
    """Every scored CVE with its composite-score breakdown. Story #39."""
    st.subheader("Findings")
    st.info("Story #39 — scored findings table renders here.")


def main() -> None:
    st.set_page_config(page_title=PAGE_TITLE, layout="wide")
    st.title(HEADLINE)
    st.caption(ENVIRONMENT_CAVEAT)

    render_sidebar()
    render_headline_metric()
    render_plans()
    render_findings()


# Streamlit runs the script with __name__ == "__main__" (both `streamlit run`
# and the AppTest harness), so the standard guard drives the render.
if __name__ == "__main__":
    main()
