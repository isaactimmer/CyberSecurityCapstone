"""
Dashboard logic layer (epic #6) — the Streamlit-free seam under `app.py`.

The Streamlit view (`app.py`) owns only widgets and layout. Everything that
turns a widget value into a real backend parameter, or a plan into something
renderable, lives here so it can be unit-tested without a browser:

    normalize_weights / build_pools   controls -> ScoringWeights / pools
    plan / findings_view / headline    engine   -> tables + headline metric
    filter_findings                    list-size / year / focus-asset inputs
    load_asset_table                   sample or uploaded CSV -> asset graph
    asset_map_data / asset_map_svg     asset graph -> a rendered system map
    plan_item_detail                   a plan row -> its score breakdown
    asset_coverage                     plan -> "critical assets addressed"
    inject_kev                         "a new KEV landed" -> re-scored env
    live_environment                   a typed vendor -> a scorable env

None of these reimplement scoring, capacity, or the optimizer — they call
`pipeline.build_plan`, which wraps them. Keeping this layer pure is what lets the
app stay a thin view (the epic #6 rule: no business logic in the view).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import pandas as pd

import asset_graph
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

# The columns an uploaded asset CSV must supply (same schema as assets.csv).
REQUIRED_ASSET_COLUMNS = (
    "asset_id", "name", "criticality", "crown_jewel", "connections", "vendor",
)

# Importance-tier accent colours, shared by the map and the plan breakdown so a
# tier reads the same everywhere. Keyed by the hop-distance tier labels.
TIER_COLORS: dict[str, str] = {
    "critical": "#E24B4A",
    "high": "#EF9F27",
    "medium": "#378ADD",
    "low": "#888780",
}


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


# --- inputs: how many to list / which years / which asset -------------------

_CVE_YEAR_RE = re.compile(r"CVE-(\d{4})-", re.IGNORECASE)


def cve_year(cve_id: object) -> int | None:
    """Pull the disclosure year out of a CVE id (`CVE-2024-1234` -> 2024)."""
    match = _CVE_YEAR_RE.match(str(cve_id).strip())
    return int(match.group(1)) if match else None


def year_bounds(scored: pd.DataFrame) -> tuple[int, int] | None:
    """(earliest, latest) CVE year present, for the year-range control. None if
    no row carries a parseable year (so the view can hide the control)."""
    if "cve_id" not in scored.columns:
        return None
    years = [y for y in (cve_year(c) for c in scored["cve_id"]) if y is not None]
    return (min(years), max(years)) if years else None


def filter_findings(
    scored: pd.DataFrame,
    *,
    max_results: int | None = None,
    year_range: tuple[int, int] | None = None,
    asset_id: str | None = None,
) -> pd.DataFrame:
    """
    Narrow a scored/plan frame by the landing-page inputs, in priority order:
    focus a single asset, keep only CVEs in a disclosure-year range, then cap the
    row count ("how many to list?"). Every argument is optional — all-None returns
    the frame unchanged (bar the copy). Row order (risk-first) is preserved.
    """
    view = scored
    if asset_id is not None and "asset_id" in view.columns:
        view = view[view["asset_id"] == asset_id]
    if year_range is not None and "cve_id" in view.columns:
        low, high = year_range
        years = view["cve_id"].map(cve_year)
        view = view[years.between(low, high) & years.notna()]
    if max_results is not None:
        view = view.head(max_results)
    return view.reset_index(drop=True)


# --- asset map: the company system, importance by hops from crown jewel -----

@dataclass
class AssetMap:
    """A laid-out asset graph ready to render: nodes positioned in hop-distance
    columns, the edges between them, and which nodes are crown jewels."""

    nodes: list[dict]        # asset_id, name, tier, hop, crown, col, slot, col_size
    edges: list[tuple[str, str]]
    crown_jewels: list[str]
    max_hop: int


def load_asset_table(source: object = None) -> pd.DataFrame:
    """
    Build the hop-distance asset table from the sample CSV (source=None) or an
    uploaded file-like / path. Wraps `asset_graph.build_asset_table` so the view
    never touches the graph code. Raises ValueError with a plain-English message
    when the CSV is missing columns or fails the graph's integrity checks (unknown
    connection, not exactly one crown jewel) — the view catches it and falls back.
    """
    csv = asset_graph.DEFAULT_ASSET_CSV if source is None else source
    try:
        table = asset_graph.build_asset_table(csv)
    except (ValueError, KeyError) as exc:
        raise ValueError(f"Could not read that asset file: {exc}") from exc

    missing = [c for c in REQUIRED_ASSET_COLUMNS if c not in table.columns]
    if missing:
        raise ValueError(
            "Asset file is missing required column(s): "
            f"{', '.join(missing)}. Expected: {', '.join(REQUIRED_ASSET_COLUMNS)}."
        )
    return table


def asset_map_data(asset_table: pd.DataFrame) -> AssetMap:
    """
    Lay the asset graph out for drawing: each asset sits in the column of its
    hop-distance from the crown jewel (0 = crown jewel, left-most), stacked within
    the column. Edges come from the `connections` cell. Pure — no rendering.
    """
    rows = asset_table.to_dict("records")
    by_hop: dict[int, list[dict]] = {}
    for row in rows:
        by_hop.setdefault(int(row["hop_distance"]), []).append(row)

    max_hop = max(by_hop) if by_hop else 0
    nodes: list[dict] = []
    for hop, group in sorted(by_hop.items()):
        for slot, row in enumerate(group):
            nodes.append({
                "asset_id": str(row["asset_id"]),
                "name": str(row["name"]),
                "tier": str(row["importance_tier"]),
                "hop": hop,
                "crown": bool(row["crown_jewel"]),
                "col": hop,
                "slot": slot,
                "col_size": len(group),
            })

    ids = {n["asset_id"] for n in nodes}
    edges: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        src = str(row["asset_id"])
        conns = asset_graph._parse_connections(row.get("connections"))
        for dst in conns:
            if dst not in ids:
                continue
            key = tuple(sorted((src, dst)))
            if key not in seen:
                seen.add(key)
                edges.append((src, dst))

    crown_jewels = [n["asset_id"] for n in nodes if n["crown"]]
    return AssetMap(nodes=nodes, edges=edges, crown_jewels=crown_jewels, max_hop=max_hop)


# Layout constants shared by the SVG builder and the pixel-height helper so the
# view can size its render frame without re-deriving the geometry.
_MAP_COL_W, _MAP_ROW_H, _MAP_PAD_X, _MAP_PAD_Y, _MAP_NODE_H = 150, 46, 70, 34, 30


def asset_map_height(amap: AssetMap) -> int:
    """Pixel height the SVG needs — so the view can size its embed frame."""
    max_slots = max((n["col_size"] for n in amap.nodes), default=1)
    return _MAP_PAD_Y * 2 + max(0, max_slots - 1) * _MAP_ROW_H + _MAP_NODE_H


def _node_xy(node: dict, *, col_w: int, row_h: int, pad_x: int, pad_y: int) -> tuple[int, int]:
    """Pixel centre of a node from its column (hop) and slot within the column."""
    x = pad_x + node["col"] * col_w
    y = pad_y + node["slot"] * row_h
    return x, y


def asset_map_svg(
    amap: AssetMap,
    *,
    selected: str | None = None,
    in_plan_assets: object = (),
) -> str:
    """
    Render an `AssetMap` to a standalone SVG string (the view just prints it).

    Colour = importance tier; a filled left dot marks a crown jewel, a green right
    dot marks an asset the optimized plan schedules a fix for, and the selected
    ("focused") asset gets a thick outline. Kept here (not the view) so the layout
    is unit-testable.
    """
    in_plan = set(in_plan_assets or ())
    col_w, row_h, pad_x, pad_y = _MAP_COL_W, _MAP_ROW_H, _MAP_PAD_X, _MAP_PAD_Y
    node_w, node_h = 116, _MAP_NODE_H

    max_slots = max((n["col_size"] for n in amap.nodes), default=1)
    width = pad_x * 2 + amap.max_hop * col_w
    height = pad_y * 2 + max(0, max_slots - 1) * row_h + node_h

    pos = {
        n["asset_id"]: _node_xy(n, col_w=col_w, row_h=row_h, pad_x=pad_x, pad_y=pad_y)
        for n in amap.nodes
    }

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" '
        f'style="height:auto;font-family:system-ui,sans-serif" '
        f'xmlns="http://www.w3.org/2000/svg">'
    ]
    for src, dst in amap.edges:
        if src in pos and dst in pos:
            x1, y1 = pos[src]
            x2, y2 = pos[dst]
            parts.append(
                f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
                f'stroke="#c9c9c9" stroke-width="1"/>'
            )

    for node in amap.nodes:
        x, y = pos[node["asset_id"]]
        colour = TIER_COLORS.get(node["tier"], TIER_COLORS["low"])
        is_sel = node["asset_id"] == selected
        stroke_w = 3 if is_sel else (2 if node["asset_id"] in in_plan else 1)
        left = x - node_w // 2
        parts.append(
            f'<g><rect x="{left}" y="{y - node_h // 2}" width="{node_w}" '
            f'height="{node_h}" rx="6" fill="#ffffff" stroke="{colour}" '
            f'stroke-width="{stroke_w}"/>'
        )
        if node["crown"]:
            parts.append(
                f'<circle cx="{left + 9}" cy="{y - node_h // 2 + 9}" r="4" fill="{colour}"/>'
            )
        if node["asset_id"] in in_plan:
            parts.append(
                f'<circle cx="{left + node_w - 9}" cy="{y - node_h // 2 + 9}" r="4" '
                f'fill="#1D9E75"/>'
            )
        label = node["name"] if len(node["name"]) <= 18 else node["name"][:17] + "…"
        parts.append(
            f'<text x="{x}" y="{y + 4}" text-anchor="middle" font-size="11" '
            f'fill="#1a1a1a">{_svg_escape(label)}</text></g>'
        )

    parts.append(
        f'<text x="{pad_x}" y="{height - 6}" text-anchor="middle" font-size="10" '
        f'fill="#888">crown jewel</text>'
    )
    if amap.max_hop:
        parts.append(
            f'<text x="{pad_x + amap.max_hop * col_w}" y="{height - 6}" '
            f'text-anchor="middle" font-size="10" fill="#888">'
            f'{amap.max_hop} hops away</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def _svg_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


# --- plans as decision-support: the score breakdown behind a finding --------

def annotate_plan(items: pd.DataFrame, asset_table: pd.DataFrame | None = None) -> pd.DataFrame:
    """
    Join the asset's display name and hop-distance onto each plan row so a finding
    can explain *where* it sits. Pure. When there is no asset context (a live
    vendor scan has no graph), the two columns come back null rather than absent.
    """
    out = items.copy()
    name_by_id: dict[str, str] = {}
    hop_by_id: dict[str, int] = {}
    if asset_table is not None and "asset_id" in asset_table.columns:
        name_by_id = dict(zip(asset_table["asset_id"], asset_table["name"]))
        hop_by_id = dict(zip(asset_table["asset_id"], asset_table["hop_distance"]))

    if "asset_id" in out.columns:
        out["asset_name"] = out["asset_id"].map(name_by_id)
        out["hop_distance"] = out["asset_id"].map(hop_by_id)
    else:
        out["asset_name"] = pd.NA
        out["hop_distance"] = pd.NA
    return out


def plan_item_detail(
    row: pd.Series,
    *,
    tier_weights: dict[str, float] | None = None,
) -> dict:
    """
    Turn one plan row into the extended, plain-English breakdown the UI expands
    into: the raw signals, where the asset sits, the pool/effort, the composite
    score, and a "ranked here because …" sentence. Keeps the explanation logic out
    of the view so it can be tested. Tolerates rows with no asset/hop context.
    """
    tier_weights = tier_weights or scoring.DEFAULT_TIER_WEIGHTS
    tier = row.get("importance_tier")
    tier_key = str(tier).strip().lower() if pd.notna(tier) else None
    hop = row.get("hop_distance")
    has_hop = hop is not None and pd.notna(hop)
    kev = bool(row.get("kev_flag"))
    epss = float(row.get("epss_score") or 0.0)

    reasons: list[str] = []
    if kev:
        reasons.append("it is already being actively exploited (on CISA KEV)")
    if epss >= 0.4:
        reasons.append(f"exploitation is likely at {round(epss * 100)}%")
    if has_hop:
        hops = int(hop)
        reasons.append(
            f"the affected system sits {hops} hop{'s' if hops != 1 else ''} "
            f"from the crown jewel ({tier_key or 'unrated'} importance)"
        )
    elif tier_key:
        reasons.append(f"it affects a {tier_key}-importance asset")
    if not reasons:
        reasons.append("it removes the most risk per hour of team effort")

    return {
        "cve_id": row.get("cve_id"),
        "asset_name": row.get("asset_name") if pd.notna(row.get("asset_name")) else None,
        "cvss_score": row.get("cvss_score"),
        "epss_score": epss,
        "kev_flag": kev,
        "importance_tier": tier_key,
        "tier_weight": tier_weights.get(tier_key) if tier_key else None,
        "hop_distance": int(hop) if has_hop else None,
        "pool": row.get("pool"),
        "effort": row.get("effort"),
        "composite_score": row.get("composite_score"),
        "reasons": reasons,
        "reason_sentence": "Ranked here because " + ", ".join(reasons) + ".",
    }


def asset_coverage(asset_table: pd.DataFrame, plan: pipeline.RemediationPlan) -> dict:
    """
    "Critical assets addressed": of the environment's critical-importance assets,
    how many have at least one fix in this plan. A crisp coverage number for the
    summary strip. Returns zeros when there is no asset context (live scan).
    """
    if "importance_tier" not in asset_table.columns or "asset_id" not in asset_table.columns:
        return {"covered": 0, "total": 0}
    critical = set(
        asset_table.loc[asset_table["importance_tier"] == "critical", "asset_id"]
    )
    planned = (
        set(plan.items["asset_id"].dropna()) if "asset_id" in plan.items.columns else set()
    )
    return {"covered": len(critical & planned), "total": len(critical)}


def in_plan_assets(plan: pipeline.RemediationPlan) -> set[str]:
    """The asset ids the plan schedules a fix for — used to mark the map."""
    if "asset_id" not in plan.items.columns:
        return set()
    return set(str(a) for a in plan.items["asset_id"].dropna())


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
