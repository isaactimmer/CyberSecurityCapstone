"""
One-off cache enrichment (rec #1): add the CVE-detail columns the ingestion step
used to discard onto the *existing* per-vendor cache CSVs, **in place**.

Why in place rather than a full refresh: a fresh keyword pull returns today's
top-N per vendor, which would shift the whole demo dataset (finding counts, KPIs,
the asset map). This tool keeps every cached CVE id exactly as it is and only
*fills new columns*:

    description            NVD's English "what's wrong" (per CVE)
    kev_vuln_name          CISA KEV vulnerability name        (KEV CVEs only)
    kev_short_description   CISA KEV short description          (KEV CVEs only)
    kev_required_action     CISA KEV authoritative "what to do" (KEV CVEs only)

Descriptions come from re-running each vendor's NVD keyword pull (fast: ~1 page
per vendor) and mapping onto the cached ids — an id the fresh pull no longer
returns simply gets a null description (the UI falls back to the out-link). The
KEV text comes from one catalog fetch, left-joined on cve_id.

The durable code change lives in `combine_feeds_with_custom_inputs.py` (the fetch
functions now keep these fields), so a future deliberate `--refresh` already
produces enriched CSVs; this script is only for back-filling the warm cache.

Run:
    python enrich_cache.py                 # enrich every cache CSV
    python enrich_cache.py --dry-run       # report coverage, write nothing
    python enrich_cache.py --vendor-delay 6
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import pandas as pd

import combine_feeds_with_custom_inputs as cf

CACHE_DIR = Path(cf.DEFAULT_CACHE_DIR)
KEV_TEXT_COLUMNS = ("kev_vuln_name", "kev_short_description", "kev_required_action")


def keyword_and_depth(path: Path) -> tuple[str, int]:
    """Recover the NVD keyword and pull depth from a cache filename
    (``apache_http_server__200`` -> ``("apache http server", 200)``). The cache
    slug lower-cased the vendor and turned runs of non-alphanumerics into ``_``;
    NVD keyword search is case-insensitive and space-separated, so undoing the
    underscores gets back a working query. Pulling at the *same* depth the cache
    was built with reproduces its exact top-N (verified 100% id coverage), so a
    single page per vendor suffices — which keeps us under NVD's keyless rate
    limit (5 requests / 30 s)."""
    stem = path.stem  # drop ".csv"
    vendor_slug, _, depth_str = stem.rpartition("__")
    if not vendor_slug:  # no "__200" suffix — treat the whole stem as the vendor
        vendor_slug, depth_str = stem, ""
    depth = int(depth_str) if depth_str.isdigit() else 200
    return vendor_slug.replace("_", " ").strip(), depth


def nvd_descriptions(keyword: str, max_results: int = 200) -> dict[str, str]:
    """{cve_id -> English description} for a vendor keyword, from a fresh NVD pull
    at the cache's own depth (one page). Empty on any failure (the caller keeps
    going and leaves those rows null)."""
    frame = cf.fetch_nvd_cves(keyword=keyword, max_results=max_results)
    if frame.empty or "description" not in frame.columns:
        return {}
    have = frame.dropna(subset=["description"])
    return dict(zip(have["cve_id"], have["description"]))


def kev_text_frame() -> pd.DataFrame:
    """The KEV catalog reduced to cve_id + the three text columns, deduped."""
    kev = cf.fetch_kev_flags()
    cols = ["cve_id", *KEV_TEXT_COLUMNS]
    present = [c for c in cols if c in kev.columns]
    return kev[present].drop_duplicates(subset="cve_id")


def enrich_frame(df: pd.DataFrame, desc: dict[str, str], kev: pd.DataFrame) -> pd.DataFrame:
    """Add the description + KEV-text columns to one cache frame, preserving its
    exact rows and order. Existing enrichment columns are replaced, not appended."""
    out = df.copy()
    out["description"] = out["cve_id"].map(desc)
    out = out.drop(columns=[c for c in KEV_TEXT_COLUMNS if c in out.columns])
    out = out.merge(kev, on="cve_id", how="left")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enrich the warm cache CSVs in place.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report coverage only; write nothing.")
    parser.add_argument("--vendor-delay", type=float, default=6.0,
                        help="Seconds between vendor NVD pulls (NVD rate limit; "
                             "lower it if you have an API key). Default 6.")
    parser.add_argument("--cache-dir", default=str(CACHE_DIR))
    args = parser.parse_args(argv)

    cache_dir = Path(args.cache_dir)
    files = sorted(cache_dir.glob("*.csv"))
    if not files:
        print(f"No cache CSVs found in {cache_dir}", file=sys.stderr)
        return 1

    print(f"Fetching CISA KEV catalog once…")
    kev = kev_text_frame()
    print(f"  KEV rows with text: {len(kev)}")

    total_rows = desc_hits = kev_hits = 0
    for i, path in enumerate(files):
        keyword, depth = keyword_and_depth(path)
        df = pd.read_csv(path)
        try:
            desc = nvd_descriptions(keyword, max_results=depth)
        except Exception as exc:  # noqa: BLE001 - resilience over one vendor
            print(f"  [skip] {path.name}: NVD pull failed ({exc})", file=sys.stderr)
            desc = {}

        enriched = enrich_frame(df, desc, kev)
        n_desc = int(enriched["description"].notna().sum())
        n_kev = int(enriched["kev_required_action"].notna().sum()) \
            if "kev_required_action" in enriched.columns else 0
        total_rows += len(enriched)
        desc_hits += n_desc
        kev_hits += n_kev
        print(f"  {path.name:<34} rows={len(enriched):>3} "
              f"desc={n_desc:>3} kev_action={n_kev:>2} (keyword={keyword!r})")

        if not args.dry_run:
            enriched.to_csv(path, index=False)

        if i < len(files) - 1:
            time.sleep(args.vendor_delay)

    verb = "would fill" if args.dry_run else "filled"
    print(f"\nDone. {verb} description on {desc_hits}/{total_rows} rows, "
          f"KEV requiredAction on {kev_hits} rows across {len(files)} files.")
    if args.dry_run:
        print("(dry run — no files written)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
