"""
Data Pipeline & Vulnerability Ingestion (epic #47, story #48)
Fetches NVD (CVE/CVSS), EPSS, and CISA KEV data and merges them into one
clean pandas DataFrame keyed on CVE ID.

Importable *and* runnable. `fetch_merged(vendor, max_results)` is the one call
the rest of the tool (and the dashboard's live "custom input") depends on. As of
epic #56 it is a filter + score over the complete local NVD corpus
(`data/nvd_corpus.db`, populated by `nvd_ingest.py`) rather than a per-vendor,
200-capped live NVD pull — so a scan is fully offline and never truncates away a
KEV/high-EPSS critical. Its return schema is unchanged; see
`docs/adr/0003-full-corpus-nvd-ingest.md`. The NVD/EPSS/KEV clients below stay
in-tree as a documented live fallback (and drive the legacy CLI in `__main__`).

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
import sys
import time
import argparse

import requests
import pandas as pd
from dotenv import load_dotenv

from corpus_store import CorpusStore, CVE_COLUMNS

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Legacy per-vendor CSV cache dir. The scan path no longer reads or writes it
# (it queries the corpus, below); retained only for the one-off `enrich_cache.py`
# back-fill script. The `data/cache/*__200.csv` files are retired under epic #56.
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
# NVD's published rate limits: 5 requests / rolling 30s without an API key,
# 50 / 30s with one. NVD explicitly recommends spacing requests ~6s apart
# without a key. We enforce a minimum interval between *every* NVD request
# (across vendors, not just pagination pages) so an environment scan over many
# vendors doesn't fire a burst that trips a 429 cascade.
_NVD_MIN_INTERVAL_NO_KEY = 6.0
_NVD_MIN_INTERVAL_WITH_KEY = 0.6
_last_nvd_request_ts = 0.0


def _nvd_get(headers: dict, params: dict, *, max_retries: int = 5) -> requests.Response:
    """
    GET the NVD API with a global throttle and 429/503 retry+backoff.

    Enforces a minimum gap since the previous NVD call (module-global, so the
    throttle spans every vendor in a scan) and, on a 429/503, honours the
    server's Retry-After header, falling back to exponential backoff. This turns
    a transient rate-limit into a slower-but-complete pull instead of a skipped
    vendor.
    """
    global _last_nvd_request_ts
    min_interval = _NVD_MIN_INTERVAL_WITH_KEY if headers.get("apiKey") else _NVD_MIN_INTERVAL_NO_KEY

    for attempt in range(max_retries + 1):
        wait = min_interval - (time.monotonic() - _last_nvd_request_ts)
        if wait > 0:
            time.sleep(wait)

        resp = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=30)
        _last_nvd_request_ts = time.monotonic()

        if resp.status_code in (429, 503) and attempt < max_retries:
            retry_after = resp.headers.get("Retry-After")
            try:
                backoff = float(retry_after) if retry_after else 0.0
            except ValueError:
                backoff = 0.0
            # Exponential backoff floor if the server didn't tell us how long.
            backoff = max(backoff, min_interval * (2 ** attempt))
            print(
                f"  [nvd] {resp.status_code} rate-limited; backing off {backoff:.0f}s "
                f"(attempt {attempt + 1}/{max_retries})",
                file=sys.stderr,
            )
            time.sleep(backoff)
            continue

        resp.raise_for_status()
        return resp

    # Exhausted retries — surface the last status so the caller can skip/report.
    resp.raise_for_status()
    return resp


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

        resp = _nvd_get(headers, params)
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
# 5. Corpus-backed scan — the one entry point the tool uses (epic #56)
# ---------------------------------------------------------------------------
# A scan is now a filter + score over the complete local NVD corpus
# (`data/nvd_corpus.db`, pre-merged with EPSS/KEV at ingest by `nvd_ingest.py`)
# rather than a per-vendor, 200-capped live NVD pull. Only the guts change:
# `fetch_merged` still returns exactly `CVE_COLUMNS`, so `live_environment`,
# `build_environment_vulnerabilities`, and the dashboard are untouched.
# See docs/adr/0003-full-corpus-nvd-ingest.md.


def cache_exists(vendor: str = None, max_results: int | None = None, *, store: CorpusStore | None = None) -> bool:
    """
    Whether the local NVD corpus has been ingested (holds any CVEs).

    Formerly "is there a warm per-vendor cache CSV"; now "is the corpus loaded".
    The corpus is one dataset, not a per-vendor pull, so `vendor`/`max_results`
    are ignored — kept only so `dashboard.live_environment`'s `cache_probe(vendor,
    max_results)` call site is unchanged. Lets a caller tell the audience the scan
    ran against the local corpus (and lets the server warn to ingest first).
    """
    own = store is None
    store = store or CorpusStore()
    try:
        return store.is_loaded()
    finally:
        if own:
            store.close()


def fetch_merged(
    vendor: str,
    max_results: int | None = None,
    *,
    use_cache: bool = True,
    store: CorpusStore | None = None,
) -> pd.DataFrame:
    """
    Every CVE matching `vendor`, merged (NVD+EPSS+KEV), one row per CVE.

    Reads the local NVD corpus (matched on CPE vendor/product, description as a
    fallback) instead of hitting the NVD API, so a scan is complete and offline.
    Rows come back worst-first (KEV > EPSS > CVSS); `max_results` caps to the
    worst-N, and `None` (the default) returns the full matched set. The returned
    DataFrame's columns are exactly `CVE_COLUMNS`, so this is a drop-in for the
    old live pull. `store` is injectable for tests; `use_cache` is retained for
    caller compatibility (the corpus is always the source of truth now).
    """
    own = store is None
    store = store or CorpusStore()
    try:
        rows = store.query_vendor(vendor, limit=max_results)
        return pd.DataFrame(rows, columns=list(CVE_COLUMNS))
    finally:
        if own:
            store.close()


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
