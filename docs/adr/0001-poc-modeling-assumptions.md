# ADR-0001 — POC modelling assumptions: what is real vs. modelled

**Status:** Accepted · **Date:** 2026-08-09 · **Epic:** #47 (closes the stand-in gaps)

## Context

Fulcrum prioritises vulnerability remediation by combining public threat data
with a company's own environment. For the capstone POC we must be explicit about
which inputs are **real** and which are **modelled**, so the demo and the report
are defensible rather than "everything looks synthetic."

## Decision

### Real (not synthetic)
- **NVD (CVSS), FIRST.org EPSS, and CISA KEV feeds.** Pulled live over HTTP and
  verified reachable. `combine_feeds_with_custom_inputs.fetch_merged(vendor)`
  returns one row per real CVE with real severity, exploit-probability, and
  active-exploitation flags. Pulls are cached to `data/cache/` so the tool and
  the demo replay offline and deterministically (the NVD API key only raises the
  rate limit; keyword search works without it).
- **The scoring formula and the capacity-aware optimizer.** Deterministic, unit-
  tested logic (epics #4, #5).

### Modelled (and why that is legitimate)
- **The asset environment (`assets.csv`).** A fictional mid-sized company
  (~37 assets: domain controllers, mail/DB/file servers, web tier, network edge,
  workstation fleet, etc.). In production this inventory is supplied by the
  customer's audit/asset team; no capstone team has a real company's inventory,
  so a representative environment is the correct stand-in — **labelled as such**
  in every output.

### CVE → asset mapping: vendor-keyword matching
- Each asset declares the **vendor/product** it runs. NVD keyword search returns
  that software's CVEs, so the vendor keyword *is* the CVE→asset bridge — no hand-
  curated `cve_id → asset_id` list and no hashing.
- A CVE's `importance_tier` is the tier of the asset(s) running the matching
  software; when several assets share a vendor, the **highest** tier wins.
- **Limitation:** keyword search is vendor-level, not version-level (CPE-precise).
  It is intentionally coarse — broader than a real CPE inventory match — which is
  acceptable for a bounded POC and keeps the demo deterministic. CPE-precise
  matching is the more general production path (see #9).

### Pool / effort heuristic
- The capacity **pool** a fix draws from is derived from the software's work-type
  (`capacity.pool_for_vendor`): network/security/DB/storage/mail infra →
  `change_window`; apps/web/dev/containers → `appsec`; OS/endpoints → `patching`.
  Rows with no vendor fall back to a deterministic hash stand-in.
- **Effort is constant within each pool** — a deliberate choice. It makes the
  optimizer's "never worse than the severity baseline" guarantee (#34) provable:
  within a pool, ratio-order equals score-order, so greedy takes the top-k scoring
  fixes the pool can hold. Allowing variable per-item effort would weaken that
  guarantee to a heuristic — which is exactly what the ILP comparison (#35)
  exists to measure. The vendor→pool rules are a documented modelling assumption,
  not a claim about any individual CVE's true remediation path.

## Consequences

- The demo can honestly say: **real threat data, real algorithms, a modelled
  environment.** The synthetic-looking parts (the old hashed pool, the missing
  CVE→asset join) are gone.
- The headline optimizer-vs-baseline number is now computed on real, vendor-
  mapped data. Checkpoint (2026-08-09, `pipeline.run`, 37 assets / 30 vendors,
  4,523 real CVEs, 48 KEV-flagged): optimizer **3,705.8** risk reduced vs.
  baseline **2,712.0** — **+36.6%**. The old stand-in run reported +66.5%; the
  direction held and the magnitude shifted once real mappings replaced the
  placeholders, as expected. The optimized plan's top fixes are real actively-
  exploited CVEs (e.g. CVE-2024-3400 PAN-OS, CVE-2021-26855 ProxyLogon,
  CVE-2018-13379 FortiOS, CVE-2023-27532 Veeam).
- Vendor-level matching over-includes CVEs relative to a version-precise CPE
  inventory; the plan reflects "software present in the environment," not "exact
  vulnerable versions installed." Noted as future work.
