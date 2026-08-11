"""
Dashboard logic layer (epic #6) — the Streamlit-free seam under `app.py`.

The Streamlit view (`app.py`) owns only widgets and layout. Everything that
turns a widget value into a real backend parameter, or a plan into something
renderable, lives here so it can be unit-tested without a browser:

    #38  normalize_weights / build_pools   sliders  -> ScoringWeights / pools
    #39  plan / findings_view / headline    engine   -> tables + headline metric
    #40  inject_kev                          "a new KEV landed" -> re-scored env
    #53  live_environment                    a typed vendor -> a scorable env

None of these reimplement scoring, capacity, or the optimizer — they call
`pipeline.build_plan`, which wraps them. Keeping this layer pure is what lets the
app stay a thin view (the epic #6 rule: no business logic in the view).
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

import capacity
import pipeline
import scoring
from combine_feeds_with_custom_inputs import cache_exists, fetch_merged

DEFAULT_MAX_RESULTS = 200

# Columns surfaced in the findings / plan tables, in reading order: identity,
# then the four raw scoring inputs, then the derived pool/effort and composite.
FINDING_COLUMNS = (
    "cve_id", "vendor", "importance_tier",
    "cvss_score", "epss_score", "kev_flag",
    "pool", "effort", "composite_score",
)


# --- #38 slider -> real backend parameter ----------------------------------

def normalize_weights(
    cvss: float, epss: float, kev: float, importance: float
) -> scoring.ScoringWeights:
    """
    Turn four raw slider values into a valid `ScoringWeights`.

    Sliders move independently, so their values won't sum to 1.0 — but
    `ScoringWeights` requires that (it keeps the composite on a 0-100 scale).
    We rescale to preserve each slider's *relative* emphasis, folding any
    floating-point drift onto one component so the sum is exactly 1.0. All-zero
    sliders can't be rescaled, so fall back to the shipped defaults.
    """
    raw = {"cvss": float(cvss), "epss": float(epss), "kev": float(kev),
           "importance": float(importance)}
    total = sum(raw.values())
    if total <= 0:
        return scoring.DEFAULT_WEIGHTS

    norm = {name: value / total for name, value in raw.items()}
    norm["importance"] += 1.0 - sum(norm.values())  # absorb rounding drift
    return scoring.ScoringWeights(**norm)


def build_pools(
    patching: float, appsec: float, change_window: float
) -> dict[str, capacity.CapacityPool]:
    """Build the three capacity pools from their slider sizes (unit per pool)."""
    return {
        capacity.POOL_PATCHING:
            capacity.CapacityPool(capacity.POOL_PATCHING, float(patching), "hours"),
        capacity.POOL_APPSEC:
            capacity.CapacityPool(capacity.POOL_APPSEC, float(appsec), "hours"),
        capacity.POOL_CHANGE_WINDOW:
            capacity.CapacityPool(capacity.POOL_CHANGE_WINDOW, float(change_window), "slots"),
    }


# --- #39 build + shape for display -----------------------------------------

def default_environment() -> pd.DataFrame:
    """
    The modelled company's CVEs, from the warm on-disk cache — the app's default
    view. Wraps the pipeline's one I/O step so the Streamlit view never reaches
    into `pipeline` itself (the epic #6 view/logic split).
    """
    return pipeline.scan_environment(use_cache=True)


def plan(
    env: pd.DataFrame,
    *,
    weights: scoring.ScoringWeights = scoring.DEFAULT_WEIGHTS,
    pools: dict[str, capacity.CapacityPool] | None = None,
) -> pipeline.PlanResult:
    """Re-derive the plan for the current controls — a thin pass to the pipeline."""
    return pipeline.build_plan(env, weights=weights, pools=pools)


def findings_view(scored: pd.DataFrame, *, limit: int | None = None) -> pd.DataFrame:
    """Project a scored/plan frame down to the display columns that exist."""
    cols = [c for c in FINDING_COLUMNS if c in scored.columns]
    view = scored[cols]
    return view.head(limit) if limit is not None else view


def headline(result: pipeline.PlanResult) -> dict[str, float]:
    """The demo's headline numbers: optimizer vs. baseline, plus the lift %."""
    return {
        "improvement_pct": result.improvement,
        "optimized_risk": result.optimized.total_risk_reduction,
        "baseline_risk": result.baseline.total_risk_reduction,
        "optimized_fixes": len(result.optimized.items),
        "baseline_fixes": len(result.baseline.items),
    }


# --- #40 "a new KEV landed" -------------------------------------------------

def kev_candidates(env: pd.DataFrame, *, limit: int = 25) -> list[str]:
    """
    CVEs a presenter could plausibly flag as newly KEV: the highest-CVSS ones
    that are *not* already known-exploited (injecting an already-KEV CVE would be
    a no-op, so it is never offered). Highest severity first.
    """
    not_kev = env[~env["kev_flag"].astype(bool)]
    return (
        not_kev.sort_values("cvss_score", ascending=False)["cve_id"]
        .head(limit)
        .tolist()
    )


def inject_kev(env: pd.DataFrame, cve_ids: str | list[str]) -> pd.DataFrame:
    """
    Simulate CISA adding CVE(s) to the KEV catalog: flip `kev_flag` True for the
    named CVEs. Returns a new frame (the input is not mutated) so the app can
    re-optimize and show the plan shift a fresh KEV listing forces.
    """
    ids = {cve_ids} if isinstance(cve_ids, str) else set(cve_ids)
    out = env.copy()
    out["kev_flag"] = out["kev_flag"].where(~out["cve_id"].isin(ids), other=True)
    return out


# --- #53 live "show me <vendor>" -------------------------------------------

@dataclass
class LiveScan:
    """One live/cached vendor pull, ready for `plan`."""

    env: pd.DataFrame
    source: str   # "live" (freshly fetched) or "cached" (replayed from disk)
    vendor: str
    tier: str


def live_environment(
    vendor: str,
    *,
    tier: str = "high",
    max_results: int = DEFAULT_MAX_RESULTS,
    use_cache: bool = True,
    fetch=fetch_merged,
    cache_probe=cache_exists,
) -> LiveScan | None:
    """
    Fetch a vendor/product's CVEs and dress them up as a scorable environment.

    A typed vendor has no asset graph, so the pipeline's two asset-derived inputs
    are supplied here: an `importance_tier` (the presenter's assumed criticality)
    and a `vendor` column (so capacity's vendor->pool rule applies). `fetch` and
    `cache_probe` are injectable for tests. Returns None when the pull is empty
    (unknown vendor / no CVEs) so the app can say so instead of planning nothing.
    """
    cached = cache_probe(vendor, max_results)
    df = fetch(vendor, max_results=max_results, use_cache=use_cache)
    if df is None or df.empty:
        return None

    env = df.copy()
    env["vendor"] = vendor
    env["importance_tier"] = tier
    return LiveScan(
        env=env, source="cached" if cached else "live", vendor=vendor, tier=tier
    )
