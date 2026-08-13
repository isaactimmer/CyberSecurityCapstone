"""
Full-corpus ingest (epic #56, phases #58 NVD + #59 EPSS/KEV).

Populates the local `corpus_store` from three feeds so a scan can filter + score
over the complete NVD dataset offline, instead of a per-vendor, 200-capped live
pull (docs/adr/0003-full-corpus-nvd-ingest.md):

    NVD   fkie-cad/nvd-json-data-feeds release assets `CVE-YYYY.json.xz`, a
          daily community rebuild of the retired legacy feeds. Each file is
          `{cve_items: [<bare NVD 2.0 cve object>, ...]}`.
    EPSS  FIRST's daily full CSV (`epss_scores-current.csv.gz`) — every CVE in
          one gzip, rather than per-CVE API batches.
    KEV   CISA's single known-exploited-vulnerabilities JSON catalog.

The three are merged **at ingest time**, in order (NVD base → EPSS columns → KEV
columns), so a scan reads one already-joined row per CVE. The parse step is a
pure function (`parse_cve`) so it is unit-testable against a fixture with no
network. Downloaded feed files are cached under `data/nvd_feeds/` so a re-run
after a mid-download failure skips completed years rather than restarting.

    py nvd_ingest.py            # full ingest: all NVD years + EPSS + KEV
    py nvd_ingest.py --years 2023 2024   # just those years (+ EPSS + KEV)
    py nvd_ingest.py --no-epss --no-kev  # NVD only

Refresh flags (`--refresh` / `--update`) and the server empty-corpus guard are
Phase 4 (#61); this module provides the ingest primitives they build on.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import lzma
import sys
from collections.abc import Iterator
from datetime import date, datetime, timezone
from pathlib import Path

import requests

import runtime_paths
from corpus_store import CorpusStore

# fkie-cad publishes one release asset per CVE year at a stable "latest" URL.
_NVD_FEED_URL = (
    "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{year}.json.xz"
)
_EPSS_FULL_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# NVD's public CVE record begins in 1999.
_FIRST_CVE_YEAR = 1999

# Where downloaded feed files are cached (git-ignored). Keeping the raw .xz/.gz
# on disk is what makes a re-run resumable without re-downloading finished years.
FEEDS_DIR = runtime_paths.data_dir() / "nvd_feeds"


# ---------------------------------------------------------------------------
# NVD parse — pure, network-free (unit-tested against a fixture)
# ---------------------------------------------------------------------------
def _cvss_from_metrics(metrics: dict) -> tuple[float | None, str | None]:
    """Pick the preferred CVSS base score + severity from an NVD `metrics` block:
    v3.1, then v3.0, then v2. Severity lives in `cvssData` for v3 and one level
    up for v2 — mirror the fallback the live client already uses."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", entries[0].get("baseSeverity"))
            return score, severity
    return None, None


def parse_cpe_criteria(criteria: str) -> tuple[str, str] | None:
    """Extract (vendor, product) from a CPE 2.3 string
    (`cpe:2.3:<part>:<vendor>:<product>:...`). Returns None when the string is
    malformed or the vendor/product is a wildcard (`*` / `-`), which carries no
    filterable applicability."""
    parts = criteria.split(":")
    if len(parts) < 5:
        return None
    vendor, product = parts[3], parts[4]
    if vendor in ("*", "-") or product in ("*", "-"):
        return None
    return vendor, product


def parse_cve(cve: dict) -> tuple[dict, list[tuple[str, str, str]]]:
    """Turn one NVD 2.0 CVE object into a (cve_row, cpe_triples) pair.

    `cve_row` carries the NVD-base columns of the corpus schema; `cpe_triples`
    is a de-duplicated list of (cve_id, vendor, product) drawn from the CVE's
    configuration/applicability. EPSS and KEV columns are filled by their own
    loaders, not here."""
    cve_id = cve["id"]

    score, severity = _cvss_from_metrics(cve.get("metrics", {}))

    description = next(
        (
            d.get("value")
            for d in cve.get("descriptions", [])
            if d.get("lang") == "en"
        ),
        None,
    )

    row = {
        "cve_id": cve_id,
        "cvss_score": score,
        "cvss_severity": severity,
        "published": cve.get("published"),
        "description": description,
    }

    seen: set[tuple[str, str]] = set()
    triples: list[tuple[str, str, str]] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria")
                if not criteria:
                    continue
                parsed = parse_cpe_criteria(criteria)
                if parsed and parsed not in seen:
                    seen.add(parsed)
                    triples.append((cve_id, parsed[0], parsed[1]))

    return row, triples


def iter_year_cves(path: Path) -> Iterator[dict]:
    """Yield each NVD 2.0 CVE object from a downloaded `CVE-YYYY.json.xz`."""
    with lzma.open(path, "rt", encoding="utf-8") as fh:
        feed = json.load(fh)
    yield from feed.get("cve_items", [])


# ---------------------------------------------------------------------------
# Downloads
# ---------------------------------------------------------------------------
def _download(url: str, dest: Path, *, reuse: bool = True) -> Path:
    """Stream `url` to `dest`, creating parent dirs. If `reuse` and a non-empty
    file already exists, keep it (this is what makes a re-run skip finished
    downloads). Returns `dest`."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if reuse and dest.exists() and dest.stat().st_size > 0:
        return dest
    with requests.get(url, stream=True, timeout=120) as resp:
        resp.raise_for_status()
        tmp = dest.with_suffix(dest.suffix + ".part")
        with open(tmp, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=1 << 16):
                fh.write(chunk)
        tmp.replace(dest)  # atomic: a partial download never looks complete
    return dest


def _current_cve_year() -> int:
    return date.today().year


# ---------------------------------------------------------------------------
# Ingest steps
# ---------------------------------------------------------------------------
def ingest_nvd_years(
    store: CorpusStore,
    years: list[int],
    *,
    feeds_dir: Path = FEEDS_DIR,
    reuse: bool = True,
    batch_size: int = 5000,
) -> int:
    """Download + parse each year's feed and upsert into the corpus. Idempotent
    (per-CVE upsert) and resumable (finished downloads are reused). Returns the
    total CVEs written."""
    total = 0
    for year in years:
        url = _NVD_FEED_URL.format(year=year)
        path = feeds_dir / f"CVE-{year}.json.xz"
        try:
            _download(url, path, reuse=reuse)
        except requests.HTTPError as exc:
            # A year with no release asset (e.g. a future year) is skipped, not fatal.
            print(f"  [skip] CVE-{year}: {exc}", file=sys.stderr)
            continue

        cve_rows: list[dict] = []
        cpe_triples: list[tuple[str, str, str]] = []
        year_count = 0
        for cve in iter_year_cves(path):
            row, triples = parse_cve(cve)
            cve_rows.append(row)
            cpe_triples.extend(triples)
            if len(cve_rows) >= batch_size:
                store.upsert_cves(cve_rows)
                store.upsert_cpe(cpe_triples)
                year_count += len(cve_rows)
                cve_rows, cpe_triples = [], []
        if cve_rows:
            store.upsert_cves(cve_rows)
            store.upsert_cpe(cpe_triples)
            year_count += len(cve_rows)

        total += year_count
        print(f"  CVE-{year}: {year_count} CVEs", file=sys.stderr)

    store.set_meta("nvd", datetime.now(timezone.utc).isoformat())
    return total


def parse_epss_csv(raw: bytes) -> tuple[list[dict], str | None]:
    """Parse a gzipped EPSS full-CSV (`cve,epss,percentile`, preceded by a
    `#model_version:...,score_date:...` comment). Returns (rows, score_date),
    where each row is {cve_id, epss_score, epss_percentile}."""
    text = gzip.decompress(raw).decode("utf-8")
    score_date = None
    data_lines = []
    for line in text.splitlines(keepends=True):
        if line.startswith("#"):
            for field in line.lstrip("#").strip().split(","):
                if field.startswith("score_date:"):
                    score_date = field.split(":", 1)[1]
            continue
        data_lines.append(line)

    rows = []
    for r in csv.DictReader(io.StringIO("".join(data_lines))):
        rows.append(
            {
                "cve_id": r["cve"],
                "epss_score": float(r["epss"]),
                "epss_percentile": float(r["percentile"]),
            }
        )
    return rows, score_date


def ingest_epss(store: CorpusStore, *, url: str = _EPSS_FULL_CSV_URL) -> int:
    """Download the EPSS full CSV and attach scores to loaded CVEs. Returns the
    number of EPSS rows applied."""
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    rows, score_date = parse_epss_csv(resp.content)
    store.update_epss(rows)
    store.set_meta("epss", score_date or datetime.now(timezone.utc).isoformat())
    print(f"  EPSS: {len(rows)} scores (score_date {score_date})", file=sys.stderr)
    return len(rows)


def parse_kev_json(payload: dict) -> list[dict]:
    """Flatten CISA's KEV catalog into corpus KEV rows (mirrors the field names
    the live `fetch_kev_flags` produced)."""
    return [
        {
            "cve_id": v["cveID"],
            "kev_date_added": v.get("dateAdded"),
            "kev_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
            "kev_vuln_name": v.get("vulnerabilityName"),
            "kev_short_description": v.get("shortDescription"),
            "kev_required_action": v.get("requiredAction"),
        }
        for v in payload.get("vulnerabilities", [])
    ]


def ingest_kev(store: CorpusStore, *, url: str = _KEV_URL) -> int:
    """Download CISA KEV and flag loaded CVEs. Returns the number of KEV rows."""
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    rows = parse_kev_json(resp.json())
    store.update_kev(rows)
    store.set_meta("kev", datetime.now(timezone.utc).isoformat())
    print(f"  KEV: {len(rows)} known-exploited CVEs", file=sys.stderr)
    return len(rows)


def run_ingest(
    store: CorpusStore,
    *,
    years: list[int] | None = None,
    do_nvd: bool = True,
    do_epss: bool = True,
    do_kev: bool = True,
    reuse: bool = True,
) -> None:
    """Full ingest orchestration in dependency order: NVD base first, then the
    EPSS and KEV overlays (which UPDATE onto existing rows)."""
    if years is None:
        years = list(range(_FIRST_CVE_YEAR, _current_cve_year() + 1))

    if do_nvd:
        print("Ingesting NVD corpus...", file=sys.stderr)
        total = ingest_nvd_years(store, years, reuse=reuse)
        print(f"NVD: {total} CVEs into corpus ({store.count()} total).", file=sys.stderr)
    if do_epss:
        print("Ingesting EPSS scores...", file=sys.stderr)
        ingest_epss(store)
    if do_kev:
        print("Ingesting CISA KEV...", file=sys.stderr)
        ingest_kev(store)


def _parse_args(argv=None):
    p = argparse.ArgumentParser(description="Ingest the full NVD/EPSS/KEV corpus.")
    p.add_argument(
        "--years", type=int, nargs="+", default=None,
        help="CVE years to ingest (default: 1999 through the current year).",
    )
    p.add_argument("--no-nvd", action="store_true", help="Skip the NVD year feeds.")
    p.add_argument("--no-epss", action="store_true", help="Skip the EPSS overlay.")
    p.add_argument("--no-kev", action="store_true", help="Skip the KEV overlay.")
    p.add_argument(
        "--no-reuse", action="store_true",
        help="Re-download feed files even if a cached copy exists.",
    )
    return p.parse_args(argv)


def main(argv=None) -> None:
    args = _parse_args(argv)
    store = CorpusStore()
    run_ingest(
        store,
        years=args.years,
        do_nvd=not args.no_nvd,
        do_epss=not args.no_epss,
        do_kev=not args.no_kev,
        reuse=not args.no_reuse,
    )
    store.close()


if __name__ == "__main__":
    main()
