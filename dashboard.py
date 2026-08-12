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
from collections.abc import Callable
from dataclasses import dataclass

import networkx as nx
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

# Tier order, most important first — shared by the tier-spread bars and any
# control that lists tiers.
TIER_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")

# Risk-appetite presets for the Risk-engine tab: named (cvss, epss, kev,
# importance) weight sets a user can apply in one click to re-rank the whole
# console. "Default" mirrors scoring.DEFAULT_WEIGHTS; the others lean the
# emphasis toward one signal. Single source shared by the API and the view.
WEIGHT_PRESETS: dict[str, tuple[float, float, float, float]] = {
    "Default": (0.25, 0.30, 0.20, 0.25),
    "Exploit-first": (0.15, 0.50, 0.20, 0.15),
    "Severity-first": (0.55, 0.20, 0.10, 0.15),
    "Asset-first": (0.20, 0.20, 0.15, 0.45),
}


def presets() -> dict[str, dict[str, float]]:
    """The risk-appetite presets as JSON-ready `{cvss,epss,kev,importance}` dicts
    (each summing to 1.0). One source for the API's preset buttons and any test."""
    keys = ("cvss", "epss", "kev", "importance")
    return {name: dict(zip(keys, values)) for name, values in WEIGHT_PRESETS.items()}


def tier_color(tier: object) -> str:
    """
    Resolve an importance-tier label to its accent colour.

    The single home of the "unknown / missing tier ⇒ low" domain rule: the view
    used to hand-roll this fallback inline (epic #6 said business logic belongs in
    the seam, not the widget), so the map, the plan breakdown, and the system
    drill-in all resolve their colour here.
    """
    key = str(tier).strip().lower() if tier is not None and pd.notna(tier) else ""
    return TIER_COLORS.get(key, TIER_COLORS["low"])


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
    scope: Callable[[pd.DataFrame], pd.DataFrame] | None = None,
) -> pipeline.PlanResult:
    """Re-derive the plan for the current controls — a thin pass to the pipeline.
    `scope` (a scored-frame -> scored-frame callable) narrows to the landing-page
    list-size / year-range inputs; None plans over the whole environment."""
    return pipeline.build_plan(env, weights=weights, pools=pools, scope=scope)


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
        conns = asset_graph.parse_connections(row.get("connections"))
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


def score_breakdown(
    row: pd.Series, weights: scoring.ScoringWeights = scoring.DEFAULT_WEIGHTS
) -> dict[str, float]:
    """
    The four weighted contributions (cvss / epss / kev / importance) behind a
    finding's composite score, each already scaled to the 0-100 composite so they
    sum to `scoring.compute_score`. Drives the finding modal's breakdown bar —
    the one bit of the composite formula the other seams don't expose. Tolerant of
    missing signals (they contribute 0) and unknown tiers (weight 0) so a live
    vendor scan doesn't raise.
    """
    cvss = float(row.get("cvss_score")) if pd.notna(row.get("cvss_score")) else 0.0
    epss = float(row.get("epss_score")) if pd.notna(row.get("epss_score")) else 0.0
    kev = bool(row.get("kev_flag"))
    tier = row.get("importance_tier")
    tier_key = str(tier).strip().lower() if pd.notna(tier) else None
    tier_w = weights.tier_weights.get(tier_key, 0.0) if tier_key else 0.0
    return {
        "cvss": round(100.0 * weights.cvss * (max(0.0, min(cvss, 10.0)) / 10.0), 2),
        "epss": round(100.0 * weights.epss * max(0.0, min(epss, 1.0)), 2),
        "kev": round(100.0 * weights.kev * (1.0 if kev else 0.0), 2),
        "importance": round(100.0 * weights.importance * tier_w, 2),
    }


# CVE-id shape used to gate the external links: only build authoritative URLs
# for a well-formed id so a live/vendor scan with an odd id doesn't emit a
# broken NVD link. Matches "CVE-YYYY-NNNN+" (case-insensitive).
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def finding_references(cve_id: object, *, kev_flag: bool = False) -> list[dict]:
    """
    Deterministic, offline-safe out-links for a finding's detail modal (rec #1):
    the authoritative pages for the CVE itself, its EPSS score, and — only when the
    CVE is known-exploited — its CISA KEV catalog entry. Every URL is built from
    the id alone (no lookup), so this stays pure and needs no network. Returns []
    for a malformed/absent id rather than emitting a link that 404s.

    Each entry is ``{"label", "url", "source"}`` — `source` is the short provider
    name the view badges the link with (NVD / FIRST / CISA / MITRE).
    """
    cid = str(cve_id).strip() if cve_id is not None and pd.notna(cve_id) else ""
    if not _CVE_ID_RE.match(cid):
        return []
    cid = cid.upper()
    refs = [
        {"label": "CVE detail (NVD)", "source": "NVD",
         "url": f"https://nvd.nist.gov/vuln/detail/{cid}"},
        {"label": "CVE record (MITRE)", "source": "MITRE",
         "url": f"https://www.cve.org/CVERecord?id={cid}"},
        {"label": "Exploit-prediction score (EPSS)", "source": "FIRST",
         "url": f"https://api.first.org/data/v1/epss?cve={cid}"},
    ]
    if kev_flag:
        refs.append({
            "label": "Known-exploited entry (CISA KEV)", "source": "CISA",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                   f"?search_api_fulltext={cid}",
        })
    return refs


def finding_recommendation(row: pd.Series) -> dict:
    """
    A remediation recommendation for the finding's detail modal (rec #1), honest
    about where it comes from:

    * KEV CVEs carry CISA's own **required action** — an authoritative instruction
      (`source="CISA KEV"`, `authoritative=True`). When a due date is present it is
      surfaced as urgency.
    * For everything else there is no official fix text in the feeds, so we return
      *derived* guidance built only from signals we actually have (severity, EPSS,
      exploitation) plus a "consult the vendor's advisory" pointer
      (`source="derived"`, `authoritative=False`). We never invent specific patch
      steps for a CVE we have no advisory text for.

    Shape: ``{"text", "source", "authoritative", "urgency"|None}``.
    """
    kev = bool(row.get("kev_flag"))
    action = row.get("kev_required_action")
    if kev and action is not None and pd.notna(action) and str(action).strip():
        due = row.get("kev_date_added")
        urgency = None
        if due is not None and pd.notna(due) and str(due).strip():
            urgency = f"CISA listed this as known-exploited on {str(due).strip()}."
        return {
            "text": str(action).strip(),
            "source": "CISA KEV",
            "authoritative": True,
            "urgency": urgency,
        }

    cvss = float(row.get("cvss_score") or 0.0)
    epss = float(row.get("epss_score") or 0.0)
    if kev:
        lead = "Actively exploited in the wild"
    elif cvss >= 9.0 or epss >= 0.5:
        lead = "High-risk finding"
    elif cvss >= 7.0:
        lead = "Notable-severity finding"
    else:
        lead = "Lower-severity finding"
    text = (
        f"{lead}. No official CISA action applies, so consult the vendor's "
        "security advisory (linked below) and apply the patch or upgrade it "
        "prescribes; if none is available yet, apply the vendor's interim "
        "mitigation or compensating controls."
    )
    return {"text": text, "source": "derived", "authoritative": False, "urgency": None}


def plan_item_detail(
    row: pd.Series,
    *,
    tier_weights: dict[str, float] | None = None,
) -> dict:
    """
    Turn one plan row into the extended, plain-English breakdown the UI expands
    into: the raw signals, where the asset sits, the pool/effort, the composite
    score, a "ranked here because …" sentence, the plain-English CVE description,
    a remediation recommendation, and authoritative out-links. Keeps the
    explanation logic out of the view so it can be tested. Tolerates rows with no
    asset/hop context (and no enrichment columns — description/links come back
    null/empty).
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
        "tier_color": tier_color(tier_key),
        "tier_weight": tier_weights.get(tier_key) if tier_key else None,
        "hop_distance": int(hop) if has_hop else None,
        "pool": row.get("pool"),
        "effort": row.get("effort"),
        "composite_score": row.get("composite_score"),
        "reasons": reasons,
        "reason_sentence": "Ranked here because " + ", ".join(reasons) + ".",
        "description": (str(row.get("description")).strip()
                        if pd.notna(row.get("description"))
                        and str(row.get("description")).strip() else None),
        "recommendation": finding_recommendation(row),
        "references": finding_references(row.get("cve_id"), kev_flag=kev),
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


def asset_detail(
    asset_id: str, asset_table: pd.DataFrame | None, result: pipeline.PlanResult
) -> dict:
    """
    One system's drill-in, for the summary board's click-through: who it is
    (name, tier, hops, criticality, neighbours) and what the optimized plan does
    about it (the CVEs scheduled on it, and how many findings it carries).

    Pure and view-free so the "click an asset" panel can be unit-tested. Tolerates
    an unknown id or a missing asset context (live vendor scan) by returning nulls
    and empty lists rather than raising.
    """
    row = None
    if asset_table is not None and "asset_id" in asset_table.columns:
        match = asset_table[asset_table["asset_id"] == asset_id]
        if not match.empty:
            row = match.iloc[0]

    scheduled = result.optimized.items
    if "asset_id" in scheduled.columns:
        scheduled = scheduled[scheduled["asset_id"] == asset_id]
    else:
        scheduled = scheduled.iloc[0:0]
    findings = result.scored
    findings = (findings[findings["asset_id"] == asset_id]
                if "asset_id" in findings.columns else findings.iloc[0:0])

    connections: list[str] = []
    if row is not None and "connections" in row.index:
        connections = list(asset_graph.parse_connections(row["connections"]))

    return {
        "asset_id": asset_id,
        "name": str(row["name"]) if row is not None else None,
        "importance_tier": str(row["importance_tier"]) if row is not None else None,
        "tier_color": tier_color(
            row["importance_tier"] if row is not None else None
        ),
        "hop_distance": (int(row["hop_distance"])
                         if row is not None and pd.notna(row["hop_distance"]) else None),
        "criticality": (str(row["criticality"])
                        if row is not None and "criticality" in row.index else None),
        "vendor": (str(row["vendor"])
                   if row is not None and "vendor" in row.index else None),
        "crown_jewel": bool(row["crown_jewel"]) if row is not None else False,
        "connections": connections,
        "scheduled_cves": (scheduled["cve_id"].tolist()
                           if "cve_id" in scheduled.columns else []),
        "scheduled": scheduled,
        "scheduled_count": int(len(scheduled)),
        "finding_count": int(len(findings)),
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


# --- tabbed console seams (epic #6 reshape) --------------------------------
#
# The console splits the old single page into four tabs (Dashboard · Attack
# surface · Risk engine · Plan). These are the extra pure shapers the tabs need
# on top of the ones above — each still view-free so the layout stays testable.

def tier_spread(result: pipeline.PlanResult) -> dict[str, int]:
    """
    Count the optimized plan's scheduled fixes per importance tier ("Where the
    fixes land", most-important first). Tiers with no fix report 0; rows carrying
    an unknown/absent tier are ignored rather than bucketed.
    """
    counts = {t: 0 for t in TIER_ORDER}
    items = result.optimized.items
    if "importance_tier" in items.columns:
        for value in items["importance_tier"]:
            key = str(value).strip().lower() if pd.notna(value) else ""
            if key in counts:
                counts[key] += 1
    return counts


def top_picks(
    result: pipeline.PlanResult,
    asset_table: pd.DataFrame | None = None,
    *,
    limit: int = 8,
) -> pd.DataFrame:
    """
    The optimizer's first `limit` scheduled fixes, annotated with asset name and
    hop-distance — the Dashboard tab's "Top optimizer picks" list. Thin wrapper
    over `annotate_plan` so the view keeps no shaping logic.
    """
    return annotate_plan(result.optimized.items.head(limit), asset_table)


def pool_utilization(result: pipeline.PlanResult) -> dict[str, dict]:
    """
    Per-pool `{used, capacity, unit}` for the Plan tab's utilisation bars, read
    straight off the optimized plan's consumed effort and the pools it was built
    against — no re-derivation of the packing.
    """
    plan = result.optimized
    out: dict[str, dict] = {}
    for name, pool in plan.pools.items():
        out[name] = {
            "used": float(plan.consumed.get(name, 0.0)),
            "capacity": float(pool.capacity),
            "unit": pool.unit,
        }
    return out


def plan_delta(
    baseline: pipeline.RemediationPlan, optimized: pipeline.RemediationPlan
) -> dict[str, set]:
    """
    Which CVEs the optimized plan schedules that the severity baseline does not
    (`added`), and which the baseline schedules that the optimizer drops
    (`dropped`) — drives the Plan tab's new-pick / dropped-row highlighting.
    """
    def ids(plan: pipeline.RemediationPlan) -> set:
        return set(plan.items["cve_id"]) if "cve_id" in plan.items.columns else set()

    base, opt = ids(baseline), ids(optimized)
    return {"added": opt - base, "dropped": base - opt}


@dataclass
class AssetMapLayout:
    """The asset graph laid out as two frames Altair can draw directly: one row
    per node (positioned, coloured, flagged) and one per edge (endpoints)."""

    nodes: pd.DataFrame   # asset_id, name, tier, tier_color, x, y, hop, crown, in_plan
    edges: pd.DataFrame   # source, target, x, y, x2, y2


# Fixed RNG seed for the force-directed layout so the map is stable across reloads
# (a jittering scatter reads as "something changed" — it hasn't).
ASSET_MAP_SEED = 42


def _force_directed_positions(amap: AssetMap) -> dict[str, tuple[float, float]]:
    """Force-directed (spring) node positions in a unit box, with the crown jewel
    pinned to the centre (0.5, 0.5) as the visual anchor.

    A spring layout gives the organic scatter that reads far better than rigid
    hop columns, but the crown jewel — the thing the whole map is *about* — drifts
    wherever the physics settles. So we run the layout with the crown fixed at the
    origin, then scale each side of each axis independently so the crown lands dead
    centre and the furthest node on every side reaches the box edge. That keeps the
    crown centred even when the graph's mass is lopsided (which it usually is), and
    means the front end's own min/max normalisation can't push it back off-centre.
    """
    graph = nx.Graph()
    graph.add_nodes_from(n["asset_id"] for n in amap.nodes)
    graph.add_edges_from(amap.edges)
    if graph.number_of_nodes() == 0:
        return {}

    crown = amap.crown_jewels[0] if amap.crown_jewels else None
    if crown is not None:
        raw = nx.spring_layout(
            graph, pos={crown: (0.0, 0.0)}, fixed=[crown],
            seed=ASSET_MAP_SEED, iterations=200,
        )
    else:  # no crown jewel (shouldn't happen — build_graph enforces one) — free layout
        raw = nx.spring_layout(graph, seed=ASSET_MAP_SEED, iterations=200)
        crown = min(raw, key=lambda n: raw[n][0] ** 2 + raw[n][1] ** 2)

    cx, cy = raw[crown]
    xs = [p[0] - cx for p in raw.values()]
    ys = [p[1] - cy for p in raw.values()]
    right = max((x for x in xs if x > 0), default=0.0)
    left = max((-x for x in xs if x < 0), default=0.0)
    up = max((y for y in ys if y > 0), default=0.0)
    down = max((-y for y in ys if y < 0), default=0.0)
    # If a side is empty, borrow the opposite side's span so we never divide by
    # zero and the crown still sits at the centre.
    right = right or left or 1.0
    left = left or right
    up = up or down or 1.0
    down = down or up

    def to_unit(value: float, pos_span: float, neg_span: float) -> float:
        return 0.5 + 0.5 * value / pos_span if value >= 0 \
            else 0.5 - 0.5 * (-value) / neg_span

    return {
        n: (to_unit(raw[n][0] - cx, right, left),
            to_unit(raw[n][1] - cy, up, down))
        for n in graph.nodes
    }


def asset_map_layout(
    asset_table: pd.DataFrame, result: pipeline.PlanResult | None = None
) -> AssetMapLayout:
    """
    Lay the asset graph out for the clickable graph on the Attack-surface tab:
    a force-directed (spring) scatter with the crown jewel pinned to the centre
    (see `_force_directed_positions`), then resolve per-node colour and
    plan-membership. When a `result` is given, nodes the optimized plan schedules
    a fix for are flagged `in_plan`. Hop distance still rides along on each node
    (for the click-detail panel and tier colour) — it just no longer drives the x.
    """
    amap = asset_map_data(asset_table)
    in_plan = in_plan_assets(result.optimized) if result is not None else set()
    positions = _force_directed_positions(amap)

    node_rows = []
    for node in amap.nodes:
        x, y = positions[node["asset_id"]]
        node_rows.append({
            "asset_id": node["asset_id"],
            "name": node["name"],
            "tier": node["tier"],
            "tier_color": tier_color(node["tier"]),
            "x": float(x),
            "y": float(y),
            "hop": node["hop"],
            "crown": bool(node["crown"]),
            "in_plan": node["asset_id"] in in_plan,
        })
    nodes = pd.DataFrame(
        node_rows,
        columns=["asset_id", "name", "tier", "tier_color", "x", "y",
                 "hop", "crown", "in_plan"],
    )

    pos = {r["asset_id"]: (r["x"], r["y"]) for r in node_rows}
    edge_rows = []
    for src, dst in amap.edges:
        if src in pos and dst in pos:
            x, y = pos[src]
            x2, y2 = pos[dst]
            edge_rows.append({"source": src, "target": dst,
                              "x": x, "y": y, "x2": x2, "y2": y2})
    edges = pd.DataFrame(edge_rows, columns=["source", "target", "x", "y", "x2", "y2"])
    return AssetMapLayout(nodes=nodes, edges=edges)


def rank_table(
    scored: pd.DataFrame,
    *,
    search: str | None = None,
    tier: str | None = None,
    kev_only: bool = False,
) -> pd.DataFrame:
    """
    Filter the scored findings for the Risk-engine table and number them in their
    current (risk-first) order. Filters, all optional and independent: a CVE-id
    substring, an exact importance tier, and known-exploited-only. A `rank` column
    (1..n) is prepended so the table shows position after filtering.
    """
    view = scored
    if search:
        needle = str(search).strip().lower()
        if needle and "cve_id" in view.columns:
            view = view[view["cve_id"].astype(str).str.lower().str.contains(needle)]
    if tier and "importance_tier" in view.columns:
        want = str(tier).strip().lower()
        view = view[view["importance_tier"].astype(str).str.lower() == want]
    if kev_only and "kev_flag" in view.columns:
        view = view[view["kev_flag"].astype(bool)]

    view = view.reset_index(drop=True)
    view.insert(0, "rank", range(1, len(view) + 1))
    return view


# --- /api/plan payload: the whole recompute, JSON-ready ---------------------
#
# The FastAPI console recomputes the entire board on every control change, so one
# seam assembles the response the endpoint returns. It only *composes* the seams
# above (headline, top_picks, tier_spread, coverage, pool_utilization, plan_delta,
# rank_table + overrides) into native Python types the JSON layer can serialise —
# no scoring/packing logic lives here.

def _opt_num(value: object) -> float | None:
    """A pandas/NumPy scalar as a plain float, or None when missing — JSON-safe."""
    return float(value) if value is not None and pd.notna(value) else None


def _opt_str(value: object) -> str | None:
    return str(value) if value is not None and pd.notna(value) else None


def _finding_dict(row: pd.Series, **extra: object) -> dict:
    """One finding row as a JSON-ready dict for the plan lists and top picks."""
    has = row.index
    out = {
        "cve_id": _opt_str(row.get("cve_id")),
        "asset_id": _opt_str(row.get("asset_id")) if "asset_id" in has else None,
        "asset_name": _opt_str(row.get("asset_name")) if "asset_name" in has else None,
        "importance_tier": _opt_str(row.get("importance_tier")),
        "tier_color": tier_color(row.get("importance_tier")),
        "cvss_score": _opt_num(row.get("cvss_score")),
        "epss_score": _opt_num(row.get("epss_score")),
        "kev_flag": bool(row.get("kev_flag")),
        "pool": _opt_str(row.get("pool")),
        "effort": _opt_num(row.get("effort")),
        "composite_score": _opt_num(row.get("composite_score")),
        "hop_distance": (int(row["hop_distance"])
                         if "hop_distance" in has and pd.notna(row.get("hop_distance"))
                         else None),
    }
    out.update(extra)
    return out


def plan_payload(
    env: pd.DataFrame,
    *,
    weights: scoring.ScoringWeights = scoring.DEFAULT_WEIGHTS,
    pools: dict[str, capacity.CapacityPool] | None = None,
    asset_table: pd.DataFrame | None = None,
    override_log: "object | None" = None,
    top_limit: int = 8,
    scope: Callable[[pd.DataFrame], pd.DataFrame] | None = None,
    display_limit: int | None = None,
) -> dict:
    """
    Recompute the whole console for the current controls and shape it for the
    `/api/plan` endpoint. Runs the plan once, overlays any human overrides (which
    re-rank by `final_score`), and assembles KPIs, the top-picks list, the coverage
    donut, tier spread, the ranked findings table, pool utilisation, both plan
    columns with new/dropped markers, and the set of assets the plan touches.

    `scope` (a scored-frame -> scored-frame callable, e.g. `filter_findings` bound
    to the landing-page list-size / year inputs) narrows the whole board — both
    plans included — to the chosen slice; None plans over the whole environment.

    `display_limit` trims only the ranked findings *table* to its top N rows,
    leaving the optimizer, KPIs, and both plan columns over the fuller (scoped)
    universe — the "show me the top N but still weigh everything" mode. It applies
    after any `scope`, so year-range still narrows the whole board while the count
    only caps what's listed. None lists every row in scope.

    Pure over `env` (no I/O): the caller scans once and passes the cached frame.
    """
    result = plan(env, weights=weights, pools=pools, scope=scope)
    scored = result.scored

    # Overlay overrides so the table's final_score / ranking reflect human calls.
    if override_log is not None:
        import overrides
        final = overrides.apply_overrides(scored, override_log)
    else:
        final = scored.copy()
        final["final_score"] = final["composite_score"]
        final["is_overridden"] = False
        final["override_user"] = pd.NA
        final["override_reason"] = pd.NA

    name_by_id: dict[str, str] = {}
    if asset_table is not None and "asset_id" in asset_table.columns:
        name_by_id = dict(zip(asset_table["asset_id"], asset_table["name"]))

    ranked = final.reset_index(drop=True)
    if display_limit is not None:
        ranked = ranked.head(display_limit).reset_index(drop=True)
    ranked.insert(0, "rank", range(1, len(ranked) + 1))
    rank_rows = [
        {
            "rank": int(r["rank"]),
            "cve_id": _opt_str(r.get("cve_id")),
            "vendor": _opt_str(r.get("vendor")),
            "cvss_score": _opt_num(r.get("cvss_score")),
            "epss_score": _opt_num(r.get("epss_score")),
            "kev_flag": bool(r.get("kev_flag")),
            "importance_tier": _opt_str(r.get("importance_tier")),
            "tier_color": tier_color(r.get("importance_tier")),
            "asset_id": _opt_str(r.get("asset_id")) if "asset_id" in r.index else None,
            "asset_name": name_by_id.get(r.get("asset_id")) if "asset_id" in r.index else None,
            "composite_score": _opt_num(r.get("composite_score")),
            "final_score": _opt_num(r.get("final_score")),
            "is_overridden": bool(r.get("is_overridden")),
            "override_user": _opt_str(r.get("override_user")),
            "override_reason": _opt_str(r.get("override_reason")),
        }
        for _, r in ranked.iterrows()
    ]

    audit = []
    if override_log is not None:
        for e in reversed(override_log.history()):
            audit.append({
                "cve_id": e.key, "from": e.computed_score, "to": e.override_score,
                "user": e.user, "reason": e.reason, "timestamp": e.timestamp,
            })

    head = headline(result)
    coverage = (asset_coverage(asset_table, result.optimized)
                if asset_table is not None else {"covered": 0, "total": 0})
    kev_count = int(scored["kev_flag"].astype(bool).sum()) if "kev_flag" in scored else 0

    delta = plan_delta(result.baseline, result.optimized)
    opt_items = annotate_plan(result.optimized.items, asset_table)
    base_items = annotate_plan(result.baseline.items, asset_table)
    optimized_rows = [
        _finding_dict(r, is_new=(r.get("cve_id") in delta["added"]))
        for _, r in opt_items.iterrows()
    ]
    baseline_rows = [
        _finding_dict(r, dropped=(r.get("cve_id") in delta["dropped"]))
        for _, r in base_items.iterrows()
    ]

    picks = top_picks(result, asset_table, limit=top_limit)
    pick_rows = [_finding_dict(r) for _, r in picks.iterrows()]

    return {
        "kpis": {
            **head,
            "critical_covered": coverage["covered"],
            "critical_total": coverage["total"],
            "kev_count": kev_count,
        },
        "coverage": {
            **coverage,
            "pct": (coverage["covered"] / coverage["total"]
                    if coverage["total"] else 0.0),
        },
        "top_picks": pick_rows,
        "tier_spread": tier_spread(result),
        "pool_utilization": pool_utilization(result),
        "rank_table": rank_rows,
        "plans": {"baseline": baseline_rows, "optimized": optimized_rows},
        "in_plan_assets": sorted(in_plan_assets(result.optimized)),
        "audit": audit,
    }
