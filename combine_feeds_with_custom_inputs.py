"""
Data Pipeline & Vulnerability Ingestion (epic #47, story #48)
Fetches NVD (CVE/CVSS), EPSS, and CISA KEV data and merges them into one
clean pandas DataFrame keyed on CVE ID.

Importable *and* runnable. `fetch_merged(vendor, max_results)` is the one call
the rest of the tool (and the dashboard's live "custom input") depends on; it
caches each pull to disk so the tool and the demo run offline and
deterministically even if the network or the API key is unavailable.

Setup:
    pip install requests pandas python-dotenv
    Create a `.env` file (NOT committed to git) containing:
        NVD_API_KEY=your-key-here
    The key is OPTIONAL — NVD keyword search works without it at a lower rate
    limit; the key only raises that limit. EPSS and KEV are fully public.

Run:
    python combine_feeds_with_custom_inputs.py
"""

import os
import re
import time
import argparse
from pathlib import Path

import requests
import pandas as pd
from dotenv import load_dotenv

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Cached pulls live here so the demo replays offline. Committed (not gitignored)
# so the tool is reproducible on any machine without a key or network.
DEFAULT_CACHE_DIR = "data/cache"


def get_api_key() -> str | None:
    """
    Return the NVD API key from the environment, or None.

    Read at call time (not import time) so the module is importable and testable
    without a key. A missing key is not fatal — it only lowers the NVD rate limit.
    """
    load_dotenv()  # reads .env into environment variables if present
    return os.environ.get("NVD_API_KEY")


# ---------------------------------------------------------------------------
# 1. NVD client — pulls CVE records + CVSS scores
# ---------------------------------------------------------------------------
def fetch_nvd_cves(keyword: str = None, results_per_page: int = 200, max_results: int = 2000):
    """
    Fetch CVE records from the NVD 2.0 API.
    Uses keyword search or, if you already decided on CPE-based querying
    (per the 'Decide CVE-to-asset mapping method' ticket), swap this for a
    cpeName-based query instead.
    """
    api_key = get_api_key()
    headers = {"apiKey": api_key} if api_key else {}
    records = []
    start_index = 0

    while start_index < max_results:
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        if keyword:
            params["keywordSearch"] = keyword

        resp = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for item in vulns:
            cve = item["cve"]
            cve_id = cve["id"]

            # CVSS v3.1 preferred, fall back to v3.0, then v2
            metrics = cve.get("metrics", {})
            cvss_score = None
            cvss_severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get(
                        "baseSeverity", metrics[key][0].get("baseSeverity")
                    )
                    break

            # Plain-English "what's wrong" — NVD ships one description per
            # language; keep the English one for the finding detail modal. It is
            # the one enrichment field the UI's "what is this CVE" line needs.
            descriptions = cve.get("descriptions", [])
            description = next(
                (d.get("value") for d in descriptions if d.get("lang") == "en"),
                None,
            )

            records.append(
                {
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "cvss_severity": cvss_severity,
                    "published": cve.get("published"),
                    "description": description,
                }
            )

        total_results = data.get("totalResults", 0)
        start_index += results_per_page
        if start_index >= total_results:
            break

        time.sleep(0.6)  # stay under NVD rate limits even with an API key

    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# 2. EPSS client — exploitation-likelihood scores
# ---------------------------------------------------------------------------
def fetch_epss_scores(cve_ids: list[str]) -> pd.DataFrame:
    """
    Fetch EPSS scores for a list of CVE IDs. FIRST.org's EPSS API is public
    (no key required) and accepts comma-separated CVE lists, batched here
    to keep URLs a reasonable length.
    """
    all_records = []
    batch_size = 100

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i : i + batch_size]
        params = {"cve": ",".join(batch)}
        resp = requests.get(EPSS_BASE_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json().get("data", [])

        for row in data:
            all_records.append(
                {
                    "cve_id": row["cve"],
                    "epss_score": float(row["epss"]),
                    "epss_percentile": float(row["percentile"]),
                }
            )
        time.sleep(0.2)

    return pd.DataFrame(all_records)


# ---------------------------------------------------------------------------
# 3. CISA KEV feed — actively-exploited flag
# ---------------------------------------------------------------------------
_KEV_CACHE: pd.DataFrame | None = None


def fetch_kev_flags(*, use_memo: bool = True) -> pd.DataFrame:
    # KEV is one global catalog; memoize it so an environment scan over many
    # vendors downloads it once, not once per vendor.
    global _KEV_CACHE
    if use_memo and _KEV_CACHE is not None:
        return _KEV_CACHE.copy()

    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])

    records = [
        {
            "cve_id": v["cveID"],
            "kev_flag": True,
            "kev_date_added": v.get("dateAdded"),
            "kev_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
            # CISA's own words for a known-exploited CVE: a short "what it is"
            # and the authoritative "what to do". These are the one genuinely
            # actionable remediation strings we have (KEV CVEs only) — the
            # finding modal shows requiredAction as its recommendation.
            "kev_vuln_name": v.get("vulnerabilityName"),
            "kev_short_description": v.get("shortDescription"),
            "kev_required_action": v.get("requiredAction"),
        }
        for v in vulns
    ]
    kev_df = pd.DataFrame(records)
    if use_memo:
        _KEV_CACHE = kev_df
    return kev_df.copy()


# ---------------------------------------------------------------------------
# 4. Merge step — one clean DataFrame, one row per CVE
# ---------------------------------------------------------------------------
def combine_feeds(nvd_df: pd.DataFrame, epss_df: pd.DataFrame, kev_df: pd.DataFrame) -> pd.DataFrame:
    # An empty feed still needs its join key so the left-merge produces the
    # expected null columns instead of raising on a missing 'cve_id'.
    if epss_df.empty:
        epss_df = pd.DataFrame(columns=["cve_id", "epss_score", "epss_percentile"])
    if kev_df.empty:
        kev_df = pd.DataFrame(
            columns=["cve_id", "kev_flag", "kev_date_added", "kev_ransomware_use",
                     "kev_vuln_name", "kev_short_description", "kev_required_action"]
        )

    # Start from NVD as the base (it's the definitive CVE list)
    merged = nvd_df.merge(epss_df, on="cve_id", how="left")
    merged = merged.merge(kev_df, on="cve_id", how="left")

    # CVEs not in KEV are absent from the left-merge (NaN); make them explicit
    # False. `.eq(True)` maps the merged True/NaN column straight to bool without
    # the object-dtype fillna downcast warning.
    merged["kev_flag"] = merged["kev_flag"].eq(True)

    # Sanity check for the Tech Auditor checklist: no silently dropped CVEs
    assert len(merged) == len(nvd_df), "Row count changed during merge — check join keys"

    return merged


# ---------------------------------------------------------------------------
# 5. Orchestrated pull with a disk cache — the one entry point the tool uses
# ---------------------------------------------------------------------------
def _cache_path(vendor: str, max_results: int, cache_dir: str | Path) -> Path:
    """Deterministic cache filename for a (vendor, max_results) pull."""
    slug = re.sub(r"[^a-z0-9]+", "_", str(vendor).strip().lower()).strip("_")
    return Path(cache_dir) / f"{slug}__{max_results}.csv"


def cache_exists(
    vendor: str, max_results: int = 200, cache_dir: str | Path = DEFAULT_CACHE_DIR
) -> bool:
    """
    Whether a warm cache already exists for this (vendor, max_results) pull.

    Lets a caller (the dashboard's live "show me <vendor>" input, #53) tell the
    audience whether a result was served live or replayed from disk, without
    reaching into the cache-path internals.
    """
    return _cache_path(vendor, max_results, cache_dir).exists()


def fetch_merged(
    vendor: str,
    max_results: int = 200,
    *,
    use_cache: bool = True,
    cache_dir: str | Path = DEFAULT_CACHE_DIR,
    refresh: bool = False,
) -> pd.DataFrame:
    """
    Fetch + merge NVD/EPSS/KEV for a vendor/product keyword, one row per CVE.

    The result is cached to `cache_dir` keyed by (vendor, max_results). A warm
    cache is replayed with no network unless `refresh=True`. This is what lets
    the dashboard's live "show me <vendor>" input work offline during a demo.
    """
    path = _cache_path(vendor, max_results, cache_dir)
    if use_cache and not refresh and path.exists():
        return pd.read_csv(path)

    nvd_df = fetch_nvd_cves(keyword=vendor, max_results=max_results)
    if nvd_df.empty:
        return nvd_df

    epss_df = fetch_epss_scores(nvd_df["cve_id"].tolist())
    kev_df = fetch_kev_flags()
    merged = combine_feeds(nvd_df, epss_df, kev_df)

    if use_cache:
        path.parent.mkdir(parents=True, exist_ok=True)
        merged.to_csv(path, index=False)
        # Return the re-read copy so a fresh pull and a cached replay are
        # byte-identical (a CSV round-trip can shift column dtypes otherwise).
        return pd.read_csv(path)

    return merged


def parse_args():
    parser = argparse.ArgumentParser(
        description="Fetch and merge NVD, EPSS, and CISA KEV data for a given vendor/product."
    )
    parser.add_argument(
        "--vendor",
        type=str,
        default=None,
        help="Vendor or product keyword to search NVD for, e.g. 'microsoft', 'cisco', 'apache'. "
        "If omitted, you'll be prompted for it.",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=None,
        help="Maximum number of CVEs to fetch from NVD. NVD allows up to 2000 per page and will "
        "paginate automatically up to this total. If omitted, you'll be prompted for it.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output CSV filename. If omitted, you'll be prompted for it (default: merged_vulnerabilities.csv).",
    )
    return parser.parse_args()


def prompt_for_inputs(args):
    """
    Fill in any values not given as CLI flags by asking the user interactively.
    Lets someone just run `python combine_feeds.py` with no arguments at all.
    """
    if args.vendor is None:
        args.vendor = input("Vendor or product keyword to search (e.g. microsoft, cisco): ").strip()
        while not args.vendor:
            args.vendor = input("Please enter a non-empty vendor/keyword: ").strip()

    if args.max_results is None:
        raw = input("Max number of CVEs to fetch [default 200]: ").strip()
        if not raw:
            args.max_results = 200
        else:
            while not raw.isdigit() or int(raw) <= 0:
                raw = input("Please enter a positive whole number: ").strip()
            args.max_results = int(raw)

    if args.output is None:
        raw = input("Output CSV filename [default merged_vulnerabilities.csv]: ").strip()
        args.output = raw if raw else "merged_vulnerabilities.csv"

    return args


if __name__ == "__main__":
    args = parse_args()
    args = prompt_for_inputs(args)

    print(f"Fetching NVD data for vendor/keyword: '{args.vendor}' (max {args.max_results})...")
    nvd_df = fetch_nvd_cves(keyword=args.vendor, max_results=args.max_results)
    print(f"  {len(nvd_df)} CVEs retrieved")

    if nvd_df.empty:
        print(f"No CVEs found for '{args.vendor}'. Try a different keyword.")
        raise SystemExit(0)

    print("Fetching EPSS scores...")
    epss_df = fetch_epss_scores(nvd_df["cve_id"].tolist())
    print(f"  {len(epss_df)} EPSS records retrieved")

    print("Fetching CISA KEV feed...")
    kev_df = fetch_kev_flags()
    print(f"  {len(kev_df)} KEV entries retrieved (full current catalog)")

    print("Merging feeds...")
    final_df = combine_feeds(nvd_df, epss_df, kev_df)
    print(final_df.head())

    final_df.to_csv(args.output, index=False)
    print(f"Saved {len(final_df)} rows to {args.output}")
