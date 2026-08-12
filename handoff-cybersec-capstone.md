# Handoff — Recommendations doc (recs #1, #2, #4 shipped; #3/#5/#6 remain)

**Date:** 2026-08-12
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch:** `main` (tracks `origin/main`).
**Commits so far:** rec #1 `2ab853c` (pushed); rec #2 `5469ce4`; rec #4 `7d4b74f`
(the last two committed locally — **not yet pushed**).
**Next session's job:** work the remaining three recommendations (#3, #6, #5 below)
from `Recommendations for the Capacity Optimization Tool .md`. No blocking design
questions remain (rec #4's asset-description choice was resolved as **option (a),
derived** — see below).

## What this session did

The user brought a 6-item recommendations doc (now committed at repo root:
`Recommendations for the Capacity Optimization Tool .md`). We triaged all six,
then **built and shipped rec #1** — the CVE finding modal enrichment.

### The architecture decision behind rec #1 (don't relitigate — see memory)
The app runs **offline off `data/cache/*.csv`**, which held no description or
remediation text. We chose the **realistic "sync-to-store" pattern** (how real
tools like Tenable/Qualys work: a sync job pulls feeds into a local store, the UI
serves from it) over a live per-click fetch. Saved as memory
`enrichment-sync-to-store.md`.

### Rec #1 as built (see `git show 2ab853c`)
1. **Ingestion keeps more fields.** `combine_feeds_with_custom_inputs.py`:
   `fetch_nvd_cves` now keeps NVD's English `description`; `fetch_kev_flags` keeps
   CISA `kev_vuln_name` / `kev_short_description` / `kev_required_action`;
   `combine_feeds`'s empty-KEV fallback lists the new columns.
2. **`enrich_cache.py`** (new) back-filled the 30 warm cache CSVs **in place** —
   description on all 4,611 rows (100% id coverage), CISA `requiredAction` on the
   48 KEV rows — **without shifting the dataset** (env still 4,523 findings, KPIs
   unchanged). It re-pulls each vendor's NVD keyword page at the cache's own depth
   (200 = one page, rate-limit-safe with the built-in 6 s spacing; no API key) and
   maps descriptions onto the existing ids; KEV text comes from one catalog fetch.
   Re-runnable; `--dry-run` reports coverage.
3. **Engine helpers (pure, view-free), in `dashboard.py`:**
   - `finding_references(cve_id, kev_flag)` → deterministic authoritative links
     (NVD, MITRE/CVE.org, FIRST/EPSS; + CISA KEV **only** when exploited). Returns
     `[]` for a malformed id (regex-gated).
   - `finding_recommendation(row)` → CISA's `required_action` for KEV CVEs
     (`source="CISA KEV"`, `authoritative=True`, with a "known-exploited since"
     urgency line) **or** honest *derived* guidance otherwise
     (`source="derived"`, `authoritative=False`) — never fabricated fix steps.
     KEV-flagged-but-no-action falls back to derived (never a blank authoritative).
   - Both + `description` surfaced through `plan_item_detail`. **No `server.py`
     change** — the finding endpoint already returns `plan_item_detail`, so the new
     keys flow through automatically.
4. **Front end** (`web/app.js` `recommendationHtml`/`referencesHtml` + the
   `openFinding` modal body; `web/styles.css` `.cve-desc`/`.rec`/`.rec.auth`/
   `.rec.derived`/`.refs`/`.ref-link`): modal now shows **"What this is"**
   (description), a source-badged **Recommendation** (authoritative = KEV-red wash;
   derived = muted), and a **"Look it up"** link list (new tab, `rel=noopener`).
   `index.html` unchanged.

## State
- **259 tests passing** (251 prior + 8 new in `tests/test_dashboard.py` covering
  `finding_references`, `finding_recommendation`, and `plan_item_detail`'s new
  fields).
- Verified **live in the browser, light *and* dark theme**: top pick `CVE-2012-1823`
  (KEV) shows the NVD description, CISA "Apply updates per vendor instructions." with
  the 2022-03-25 exploited-since line, and all four links (NVD/MITRE/FIRST/CISA); a
  non-KEV finding shows derived guidance and three links. **No JS console errors.**
- A `uvicorn` on port 8000 was left running from verification (may be stale by next
  session — see the stale-server trap below).

## Done since rec #1
- **#2 — Max box/font design — SHIPPED (`5469ce4`).** The Plan-tab per-pool `max`
  input (`.capmax` in `web/styles.css`) was left-aligned below each full-width
  slider, disconnected from the right-aligned value. Now right-aligned so it tucks
  under the value (`40 hrs` / `MAX 160`), tightened, spinner arrows removed. Pure
  CSS. Verified light + dark.
- **#4 — Richer asset detail on click — SHIPPED (`7d4b74f`).** Resolved as **option
  (a), derived**: new pure `dashboard.asset_blurb(...)` synthesizes a one-sentence
  description from vendor + criticality + hops + crown-jewel name + mapped-neighbour
  count (no free-text column needed; works for uploads). `asset_map_data` carries
  vendor/criticality; `asset_map_layout` ships `vendor`/`criticality`/`desc` on every
  node so `app.js` `selectAsset` renders it with **no per-click fetch** (stays a pure
  renderer). 4 new tests; 263 passing. Verified live, crown + non-crown, no console
  errors. (Note: `/api/asset/{id}`/`asset_detail` still exists but the map now reads
  from the node set, not that endpoint.)

## Remaining recommendations (#3, #6, #5) — triaged, not yet started
From `Recommendations for the Capacity Optimization Tool .md`. Suggested order:
the feature work (#3, #6), then the theme (#5) last.

- **#3 — Dashboard mini asset-map (MODERATE).** A small "zoomed" asset-map card on
  the Dashboard centred on the crown jewel; clicking it jumps to the Attack-surface
  tab (`gotoTab('map')`). Reuses `ENV.asset_map` already shipped to the front end.
- **#6 — ⓘ hover-tooltips per section (MODERATE, mostly copy).** A circled-i icon on
  each area (Dashboard, Attack surface, Risk engine, Plan, Team capacity, Patching,
  AppSec, Change-window) with a hover explanation. Tooltip plumbing already exists
  (`app.js` `showTip`/`hideTip`, `.tip` in CSS) — mostly writing good short copy.
- **#5 — Dark theme → purple, not green (QUICK, CSS, do last).** Current dark theme
  (`:root[data-theme="dark"]` in `web/styles.css`) is a greenish-teal; the user wants
  a **dark purple-ish** background. Retune the ~20 dark-mode CSS vars (`--bg`,
  `--panel*`, `--accent*`, washes). The rec #1 modal blocks are theme-var-driven, so
  they follow automatically.

## Standing polish list (carried forward — not blocking)
- **Reweight latency:** ~180 ms debounced `/api/plan` on 4,523 rows.
- **No JS automated tests:** a Playwright smoke test remains the honest gap; all UI
  verification is manual.
- **CSV-upload follow-ups:** sample template, client size guard, surface
  silently-dropped vendors.
- **Year-filter silent-drop (latent):** `dashboard.filter_findings` uses
  `years.notna()`; narrowing drops CVEs whose id has no parseable year (harmless on
  the sample data — all ids parse).
- **Stale `AssetMapLayout` docstring** still says "Altair can draw directly".
- **GitHub issues stale/closeable:** #37 (Streamlit skeleton), #38/#39/#40
  (delivered by the rebuild). Offer to close.

## Run it
```
.\.venv\Scripts\python.exe -m uvicorn server:app --port 8000    # http://localhost:8000
.\.venv\Scripts\python.exe -m pytest -q                         # 263 passed
python enrich_cache.py --dry-run                                # re-check enrichment coverage
```
`py` launcher works too (`py -m pytest -q`). App runs offline off `data/cache/`.
**Stale-server trap:** if the UI looks dead or serves old behaviour, a leftover
uvicorn holds port 8000 with old code — kill the PID
(`Get-NetTCPConnection -LocalPort 8000 -State Listen` → `Stop-Process`), relaunch,
hard-refresh (Ctrl+Shift+R). Python changes need a server restart (no `--reload`);
static `web/` changes just need a hard refresh. Verify the API before the UI, e.g.
`POST /api/finding/CVE-2012-1823` should return `description`, `recommendation`
(`source:"CISA KEV"`), and four `references`.

## Reference (don't duplicate here)
- Recs doc: `Recommendations for the Capacity Optimization Tool .md` (repo root).
- ADR: `docs/adr/0002-web-console-over-fastapi.md` (FastAPI, not Streamlit).
- Run rule: `CLAUDE.md` — `web/app.js` is a **pure renderer**; all scoring/packing
  lives in the Python engine.
- Enrichment approach: memory `enrichment-sync-to-store.md`. Feeds live-reachable:
  memory `data-feeds-live.md`. Tool renamed Scryxen (code not renamed): memory
  `tool-rename-scryxen.md`.
- Engine seams touched this session: `combine_feeds_with_custom_inputs.py`
  (`fetch_nvd_cves`, `fetch_kev_flags`, `combine_feeds`); `dashboard.py`
  (`finding_references`, `finding_recommendation`, `plan_item_detail`);
  `enrich_cache.py` (new); front end `web/app.js` + `web/styles.css`.
- Memory index: `~/.claude/projects/.../memory/MEMORY.md`.

## Suggested skills for the next session
- **`run`** — launch the console to confirm UI changes (sidesteps the stale-server
  trap: start fresh, verify the API before debugging the UI).
- **`tdd`** — for any new engine seam (e.g. rec #4's asset-detail wiring).
- **`/code-review`** — review the diff on both axes before committing.
