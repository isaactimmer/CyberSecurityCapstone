"""
Data Pipeline & Vulnerability Ingestion
Fetches NVD (CVE/CVSS), EPSS, and CISA KEV data and merges them into one
clean pandas DataFrame keyed on CVE ID.

Setup:
    pip install requests pandas python-dotenv
    Create a `.env` file (NOT committed to git) containing:
        NVD_API_KEY=your-key-here

Run:
    python combine_feeds.py
"""

import os
import time
import argparse
import requests
import pandas as pd
from dotenv import load_dotenv

load_dotenv()  # reads .env into environment variables

NVD_API_KEY = os.environ.get("NVD_API_KEY")
if not NVD_API_KEY:
    raise RuntimeError(
        "NVD_API_KEY not found. Create a .env file with NVD_API_KEY=... "
        "(see .env.example)."
    )

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


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
    headers = {"apiKey": NVD_API_KEY}
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

            records.append(
                {
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "cvss_severity": cvss_severity,
                    "published": cve.get("published"),
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
def fetch_kev_flags() -> pd.DataFrame:
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])

    records = [
        {
            "cve_id": v["cveID"],
            "kev_flag": True,
            "kev_date_added": v.get("dateAdded"),
            "kev_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
        }
        for v in vulns
    ]
    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# 4. Merge step — one clean DataFrame, one row per CVE
# ---------------------------------------------------------------------------
def combine_feeds(nvd_df: pd.DataFrame, epss_df: pd.DataFrame, kev_df: pd.DataFrame) -> pd.DataFrame:
    # Start from NVD as the base (it's the definitive CVE list)
    merged = nvd_df.merge(epss_df, on="cve_id", how="left")
    merged = merged.merge(kev_df, on="cve_id", how="left")

    # CVEs not in KEV should be explicitly False, not NaN
    merged["kev_flag"] = merged["kev_flag"].fillna(False).astype(bool)

    # Sanity check for the Tech Auditor checklist: no silently dropped CVEs
    assert len(merged) == len(nvd_df), "Row count changed during merge — check join keys"

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
