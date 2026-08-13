"""
CVE -> asset join (epic #47, story #50)

The real bridge between vulnerabilities and the company's environment. Each asset
in the asset graph declares the vendor/product it runs (the `vendor` column, #49).
NVD keyword search returns the CVEs for that software, so the vendor keyword *is*
the CVE->asset mapping — no hand-curated cve_id->asset_id list, no hashing.

A CVE's `importance_tier` is the tier of the asset(s) running the matching
software. When several assets share a vendor (e.g. many `microsoft` boxes), the
**highest** tier wins — the fix protects the most important thing it touches.
CVEs with no matching asset get an explicit null tier ("not in the environment"),
never dropped.

    build_environment_vulnerabilities(asset_table)
        -> one scored-ready frame: every CVE across every asset vendor, tier
           attached, deduped so a CVE shared by two vendors keeps the higher tier.

The pull is delegated to `combine_feeds_with_custom_inputs.fetch_merged`, which
caches to disk — so the whole environment scan replays offline for the demo.
"""
from __future__ import annotations

import sys

import pandas as pd

# Tier ordering, most important first. Mirrors asset_graph's tier labels.
TIER_RANK: dict[str, int] = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def highest_tier(tiers) -> str | None:
    """Return the most-important tier label in `tiers`, or None if empty."""
    known = [t for t in tiers if t in TIER_RANK]
    if not known:
        return None
    return max(known, key=lambda t: TIER_RANK[t])


def vendor_tiers(asset_table: pd.DataFrame) -> dict[str, str]:
    """
    Map each vendor to the highest importance tier among assets running it.

    A vendor on both a critical and a low asset resolves to `critical`: patching
    that software protects the critical asset, so the CVE inherits that weight.
    """
    required = {"vendor", "importance_tier"}
    missing = required - set(asset_table.columns)
    if missing:
        raise KeyError(f"asset_table missing column(s): {sorted(missing)}")

    result: dict[str, str] = {}
    for vendor, group in asset_table.groupby("vendor"):
        tier = highest_tier(group["importance_tier"].tolist())
        if tier is not None:
            result[str(vendor)] = tier
    return result


def _representative_asset(asset_table: pd.DataFrame, vendor: str) -> str | None:
    """The highest-tier asset running `vendor` — shown as the CVE's asset in views."""
    matches = asset_table[asset_table["vendor"] == vendor]
    if matches.empty:
        return None
    ranked = matches.assign(_rank=matches["importance_tier"].map(TIER_RANK).fillna(-1))
    return str(ranked.sort_values("_rank", ascending=False).iloc[0]["asset_id"])


def attach_importance_tier(
    vuln_df: pd.DataFrame,
    vendor: str,
    asset_table: pd.DataFrame,
) -> pd.DataFrame:
    """
    Annotate a single vendor's CVE frame with `vendor`, `asset_id`, and
    `importance_tier`. Returns a new frame; no rows are dropped. A vendor absent
    from the asset table yields a null tier (the CVE is "not in the environment").
    """
    out = vuln_df.copy()
    tier = vendor_tiers(asset_table).get(vendor)
    out["vendor"] = vendor
    out["asset_id"] = _representative_asset(asset_table, vendor)
    out["importance_tier"] = tier if tier is not None else pd.NA
    return out


def build_environment_vulnerabilities(
    asset_table: pd.DataFrame,
    *,
    fetch=None,
    max_results: int = 200,
    use_cache: bool = True,
    skip_errors: bool = True,
) -> pd.DataFrame:
    """
    Scan the whole environment: pull each distinct asset vendor's CVEs, attach
    the vendor's importance tier, and union into one scored-ready frame.

    A CVE returned under two vendors (keyword search is broad) is deduped to a
    single row keeping the **higher** tier. `fetch` defaults to the caching
    `fetch_merged`; inject a stub in tests to avoid the network.

    With `skip_errors` (default), a vendor whose pull raises (rate limit, network
    blip) is warned about and skipped rather than aborting the whole scan — so a
    live demo degrades gracefully to whatever vendors it could reach or cache.
    """
    own_store = None
    if fetch is None:
        # Imported lazily so importing this module never requires the network
        # stack (requests/dotenv) unless an actual pull is performed.
        from combine_feeds_with_custom_inputs import fetch_merged
        from corpus_store import CorpusStore

        # One corpus connection for the whole scan, not one per vendor: opening
        # the ~400MB SQLite file has real per-open overhead, and a scan queries
        # it once per distinct vendor.
        own_store = CorpusStore()

        def fetch(vendor, *, max_results, use_cache):
            return fetch_merged(vendor, max_results=max_results,
                                use_cache=use_cache, store=own_store)

    try:
        frames = []
        for vendor in sorted(set(asset_table["vendor"].dropna())):
            try:
                pulled = fetch(vendor, max_results=max_results, use_cache=use_cache)
            except Exception as exc:  # noqa: BLE001 - resilience over precision here
                if not skip_errors:
                    raise
                print(f"  [skip] vendor {vendor!r} pull failed: {exc}", file=sys.stderr)
                continue
            if pulled is None or pulled.empty:
                continue
            frames.append(attach_importance_tier(pulled, vendor, asset_table))
    finally:
        if own_store is not None:
            own_store.close()

    if not frames:
        return pd.DataFrame(
            columns=["cve_id", "cvss_score", "epss_score", "kev_flag",
                     "vendor", "asset_id", "importance_tier"]
        )

    combined = pd.concat(frames, ignore_index=True)

    # Dedup a CVE seen under multiple vendors: keep the highest-tier row.
    combined["_rank"] = combined["importance_tier"].map(TIER_RANK).fillna(-1)
    combined = (
        combined.sort_values("_rank", ascending=False)
        .drop_duplicates(subset="cve_id", keep="first")
        .drop(columns="_rank")
        .reset_index(drop=True)
    )
    return combined
