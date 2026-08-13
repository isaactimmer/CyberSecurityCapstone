# Handoff — Recommendations doc (all six shipped ✓)

**Date:** 2026-08-12
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch:** `main` (tracks `origin/main`) — **all work pushed** through `c14855b`.
**Status:** Every item in `Recommendations for the Capacity Optimization Tool .md`
(the 6-bullet doc at repo root) is now built, verified live, and pushed.
No open recommendations remain.

## The six recommendations — all shipped
Commits (all on `origin/main`):

- **#1 — CVE finding-modal enrichment** — `2ab853c`. Description ("What this is"),
  a source-badged Recommendation (CISA KEV authoritative vs. derived), and
  authoritative out-links (NVD/MITRE/EPSS/+KEV). Backed by the **sync-to-store**
  ingestion pattern (feeds pulled into `data/cache/*.csv` by `enrich_cache.py`, UI
  serves from the store). Engine: `combine_feeds_with_custom_inputs.py`,
  `dashboard.finding_references` / `finding_recommendation` / `plan_item_detail`.
- **#2 — Per-pool `max` box/font restyle** — `5469ce4`. Pure CSS `.capmax`.
- **#3 — Dashboard mini asset-map** — `58cf716`. Compact "zoomed" card in the
  Dashboard right column centred on the crown jewel (nodes within 2 hops, from the
  real coords); clicking runs `gotoMap()` → jumps to the Attack-surface tab with the
  crown jewel selected. `app.js` `renderMiniMap`/`crownNode`/`gotoMap`; reuses
  `ENV.asset_map`; stays a pure renderer.
- **#4 — Richer asset click-detail** — `7d4b74f`. Resolved **option (a), derived**:
  `dashboard.asset_blurb(...)` synthesizes a one-sentence description; vendor /
  criticality / desc ship on every map node so `selectAsset` renders with no
  per-click fetch.
- **#5 — Dark theme → dark purple** — `c14855b`. The ~20 `:root[data-theme="dark"]`
  vars retuned from greenish-teal to violet (bg/panel/line/ink ramps + accent
  teal→`#8A6BFF`; `--on-accent` now white). Semantic status colours (crit/high/med/
  good, KEV) kept; only neutral `low` shifted to violet-gray. Light theme untouched.
- **#6 — Per-section ⓘ hover-tooltips** — `50bbe1a`. Circled-i on all eight named
  aspects (4 tabs + Team-capacity / Patching / AppSec / Change-window in the Plan
  control panel). Delegated `[data-tip]` handler over the existing `showTip`/
  `hideTip`/`.tip` plumbing; `.tip` now wraps to a max-width; each icon has an
  `aria-label`; the tabs' click handler ignores `.info` so a tooltip never switches
  tabs.

## State
- **263 tests passing** (`.\.venv\Scripts\python.exe -m pytest -q`). Recs #2/#3/#5/#6
  were front-end-only (no new Python); #1 (+8) and #4 (+4) added engine tests.
- Verified **live in the browser, light *and* dark theme**, **no JS console errors**,
  for every rec this session (#3, #6, #5) and prior (#1, #2, #4).
- **No JS automated tests** remains the honest gap — all UI checks are manual
  (Playwright smoke test still the standing suggestion).

## If more work comes
There's no pending rec. Likely next asks are polish or new features. Carry-forward
polish list (none blocking):
- **Reweight latency:** ~180 ms debounced `/api/plan` on 4,523 rows.
- **Playwright smoke test:** the one real test gap (front end is manually verified).
- **CSV-upload follow-ups:** sample template, client size guard, surface
  silently-dropped vendors.
- **Year-filter silent-drop (latent):** `dashboard.filter_findings` uses
  `years.notna()`; harmless on the sample data (all ids parse).
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
Press **Build my plan** on the intake screen to reach the console.
**Stale-server trap:** if the UI looks dead or serves old behaviour, a leftover
uvicorn holds port 8000 with old code — kill the PID
(`Get-NetTCPConnection -LocalPort 8000 -State Listen` → `Stop-Process`), relaunch,
hard-refresh (Ctrl+Shift+R). Python changes need a server restart (no `--reload`);
static `web/` changes just need a hard refresh.

## Reference (don't duplicate here)
- Recs doc: `Recommendations for the Capacity Optimization Tool .md` (repo root).
- ADR: `docs/adr/0002-web-console-over-fastapi.md` (FastAPI, not Streamlit).
- Run rule: `CLAUDE.md` — `web/app.js` is a **pure renderer**; all scoring/packing
  lives in the Python engine.
- Memory: `enrichment-sync-to-store.md` (rec #1 approach), `data-feeds-live.md`
  (feeds live-reachable), `tool-rename-scryxen.md` (tool renamed Scryxen, code not
  renamed). Index: `~/.claude/projects/.../memory/MEMORY.md`.
- Front-end seams: `web/index.html`, `web/app.js`, `web/styles.css`.
