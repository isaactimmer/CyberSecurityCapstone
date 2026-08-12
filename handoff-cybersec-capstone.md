# Handoff — Force-directed asset map (crown pinned to centre)

**Date:** 2026-08-12
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch:** `main` (tracks `origin/main`).
**Next session's job:** continue the console polish list — reweight latency and the
JS-test gap are the top remaining items (see "Open for the next session").

## What this session did

Replaced the asset map's rigid hop-distance columns with a **force-directed (spring)
layout, with the crown jewel pinned to the centre** as the visual anchor. This closes
open item #1 from the prior handoff (the top visual gap).

### What changed (see `git show` for the commit / `git diff` if uncommitted)
- **`dashboard.py`** — new `_force_directed_positions(amap)`: builds an `nx.Graph`
  from the asset map's nodes/edges, runs `nx.spring_layout` with the crown jewel
  **fixed at the origin** (module const `ASSET_MAP_SEED = 42` so the scatter is stable
  across reloads — a jittering map reads as "something changed"), then scales each side
  of each axis independently so the crown lands at exactly `(0.5, 0.5)` and the furthest
  node on every side reaches the box edge. That keeps the crown centred even when the
  graph's mass is lopsided (it usually is), and the emitted extremes mean the front
  end's own min/max normalisation can't push the crown back off-centre.
  `asset_map_layout` now uses those positions instead of the hop-column geometry. Hop
  distance still rides along on every node (for the click-detail panel and tier colour)
  — it just no longer drives the x-axis.
- **`tests/test_dashboard.py`** — updated `test_asset_map_layout_positions_nodes_and_pairs_edges`
  for the new contract (crown at `(0.5, 0.5)`, all coords in `[0, 1]`) and added
  `test_asset_map_layout_is_deterministic` (same seed ⇒ identical coordinates).
- **No front-end change** — `web/app.js` was already a pure renderer that min/max-
  normalises whatever x/y the engine sends, so it picked up the new coordinates for free.
  A nice side effect: importance now reads **radially** (crown centre, low-tier network
  gear at the edges) rather than left→right.

### Design decision (chosen with the user, via `/prototype`)
Offered pure force-directed vs. crown-pinned vs. keep-columns; user chose **crown
pinned to centre**. Prototypes rendered `spring_layout` output to SVG and eyeballed it
in the browser before wiring anything into the engine.

## State
Working tree changes this session: **`dashboard.py`**, **`tests/test_dashboard.py`**,
and this handoff — committed and pushed as part of this session (see latest commit on
`main`). Full suite: **241 passing** (240 prior + 1 new determinism test).

Verified end-to-end in the browser: built the plan → Attack surface tab shows the
organic scatter with the crown centred; clicked the crown (detail panel intact: 0 hops,
findings, neighbours, CVEs, focus-dimming); confirmed CVE rows on the Dashboard **and**
Plan tab open the "Why this finding ranks here" modal.

## Gotcha resolved this session — stale server, NOT a bug
The user reported "can't click on anything." Root cause: a **leftover `uvicorn` from a
prior session was still holding port 8000**, serving *old* code (its API returned the
crown at `x=0, y=0` — the old columns). Fix was to kill that PID and relaunch a fresh
server on 8000. **If interactivity looks dead, suspect a stale server / cached page
first** — hard-refresh (Ctrl+Shift+R) and check the API actually returns the new layout
(`curl http://localhost:8000/api/environment` → crown node should have `x: 0.5, y: 0.5`).

## Run it
```
.\.venv\Scripts\python.exe -m uvicorn server:app --port 8000    # http://localhost:8000
.\.venv\Scripts\python.exe -m pytest -q                         # 241 passed
```
Notes for this machine: the `py` launcher works too (`py -m pytest -q`). `pip`/any fetch
needs `dangerouslyDisableSandbox`; the app runs offline off `data/cache/`. `matplotlib`
is **not** installed — the layout prototypes rendered to SVG and were viewed by serving
the scratchpad over `python -m http.server` (Chrome blocks `file://` URLs).

## Open for the next session (all polish, nothing broken)
1. **Reweight latency** — ~180 ms debounced server call on the full 4,523-row set;
   consider caching the scored frame per-weight or trimming the payload if it feels heavy.
2. **JS has no automated tests** — a Playwright smoke test is the honest gap (would have
   caught nothing here, but covers the click paths the user cares about).
3. **CSV upload follow-ups (optional):** a downloadable sample-CSV template; a client
   size/row guard; surfacing skipped/uncached vendors from the scan back to the user
   (right now they're silently dropped, warned only to server stderr).
4. **Asset-map nice-to-haves (optional):** the `AssetMapLayout` dataclass docstring still
   says "Altair can draw directly" — stale since the FastAPI rebuild retired Streamlit/
   Altair; harmless but worth a one-line fix. Could also expose the spring `k`/iteration
   knobs if the scatter ever needs tuning per environment size.

## Reference (don't duplicate here)
- ADR: `docs/adr/0002-web-console-over-fastapi.md` (why FastAPI, not Streamlit).
- Run instructions live in `CLAUDE.md` ("Running the console").
- Engine seams: `dashboard.asset_map_data` (hop-column geometry + edges, still used to
  seed the graph), `dashboard.asset_map_layout` (now force-directed), `asset_graph`
  (imports `networkx`, builds the graph / hop distances / tiers).
- Memory index: `~/.claude/projects/.../memory/MEMORY.md`.

## Suggested skills for the next session
- **`run`** — launch the console to confirm a change in the real app (and to sidestep the
  stale-server trap: start fresh, verify the API before debugging the UI).
- **`prototype`** — for the reweight-caching approach, sanity-check timings before wiring.
- **`tdd`** — for the Playwright JS smoke tests or any new engine seam.
- **`/code-review`** — review the diff before committing.
