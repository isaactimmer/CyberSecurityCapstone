# ADR-0003 — Scan against a full local NVD corpus, not per-vendor live pulls

**Status:** Accepted · **Date:** 2026-08-13 · **Epic:** #56 (full-corpus ingest)

## Context

Scans pulled CVEs per vendor from the NVD 2.0 API at scan time, capped at
`max_results=200` and cached to `data/cache/<vendor>__200.csv` (the `__200`
suffix *is* the cap, baked into the cache key — see `_cache_path`).

Two problems:

1. **It is not a real slice.** The 200 rows are the first 200 NVD returns for a
   keyword in NVD's default ordering — not the 200 most severe or most
   exploitable. For a vendor with thousands of CVEs, the actual KEV-listed,
   high-EPSS criticals can fall outside the window. A prioritization tool that
   scores a truncated, arbitrary slice cannot be trusted — it undercuts the
   whole premise of the product.
2. **Live keyword pulls are slow and rate-limit-fragile** (see ADR context in
   the NVD 429 work). Raising the cap to "everything" per vendor makes the same
   flawed pattern 10× slower and 10× more likely to 429.

NVD's own bulk data feeds — the historical fix for this — **were retired on
2023-12-15** (all legacy JSON feeds and 1.0 APIs; everything now flows through
the 2.0 REST API). So "just download the feed" is no longer an option from NIST
directly.

## Decision

**Ingest the entire NVD corpus once into a local store, then make a scan a
filter + score over that store — no network at scan time.**

- **Source:** `fkie-cad/nvd-json-data-feeds`, a community project that rebuilds
  the retired legacy feeds daily from the NVD 2.0 API and publishes per-year
  `CVE-YYYY.json.xz` release assets (plus `CVE-Modified` / `CVE-Recent` deltas).
  Each record is a full NVD 2.0 CVE object, so **NVD's own CVSS enrichment is
  preserved** — the field our merge already depends on.
- **Store:** a dedicated, git-ignored `data/nvd_corpus.db` (SQLite, stdlib only)
  holding a pre-merged `cves` table (NVD + EPSS + KEV joined *at ingest*) and a
  `cve_cpe` table indexing vendor/product from each CVE's CPE applicability
  (`configurations[].nodes[].cpeMatch[].criteria`, e.g. `cpe:2.3:a:oracle:mysql`).
- **Matching:** a scan filters on **CPE vendor/product**, not a description
  substring — so "scan mysql" returns CVEs whose *applicability* is mysql. This
  is the realism win, not the row count. Description-LIKE remains a secondary
  fallback for CVEs with no CPE config (Rejected / Awaiting Analysis).
- **EPSS:** switch from per-CVE API batches to the **daily full CSV**
  (`epss_scores-YYYY-MM-DD.csv.gz`, every CVE in one gzip), loaded at ingest.
- **KEV:** keep the single-JSON catalog pull, loaded at ingest.

The one function contract the rest of the app depends on is preserved exactly:

```python
fetch_merged(vendor, max_results=None, use_cache=True) -> DataFrame[
    cve_id, cvss_score, cvss_severity, published, description,
    epss_score, epss_percentile, kev_flag, kev_date_added,
    kev_ransomware_use, kev_vuln_name, kev_short_description, kev_required_action
]
```

Only its **guts** change (query `nvd_corpus.db` instead of hitting NVD).
`max_results` becomes an optional cap defaulting to `None` (= all); callers that
still pass `200` keep working. The `__200` cache path, `_cache_path`, and the
`data/cache/*__200.csv` files are retired.

## Consequences

- **Trustworthy prioritization.** Every vendor is scored against *all* its CVEs,
  so KEV/high-EPSS criticals can no longer be truncated away. This closes the
  gap between this tool and real vulnerability-management products.
- **Fully offline at scan time**, and faster — no per-scan NVD round-trips, no
  429 exposure during a demo. Ingest/refresh is the only network step.
- **First ingest is a one-time cost:** download all year files (tens of MB
  compressed), parse ~377k CVE objects, populate SQLite (~a few hundred MB).
  Minutes, once. `lzma`/`gzip`/`sqlite3` are all stdlib — **no new dependencies**.
- **Third-party trust:** fkie-cad is a community mirror, *not* NIST-endorsed.
  This is accepted for a capstone/demo tool; the existing `fetch_nvd_cves` 2.0
  API client stays in-tree as a documented fallback and is not deleted.
- **Test rework:** `tests/test_ingest.py` is coupled to the old
  `fetch_nvd_cves`/`fetch_epss_scores`/`fetch_kev_flags` monkeypatches; those are
  rewritten to stub `corpus_store.query_vendor`, plus new parser tests over a
  small fixture CVE JSON.
- **Refresh UX:** `nvd_ingest.py --refresh` (full rebuild) / `--update`
  (`CVE-Modified` delta + fresh EPSS/KEV). `server.py` surfaces a clear "run
  ingest first" message when the corpus is empty instead of returning empty
  scans.

## Out of scope

No change to scoring/packing, the asset map, or the History tab. This is a
data-layer swap behind the existing `fetch_merged` contract.
