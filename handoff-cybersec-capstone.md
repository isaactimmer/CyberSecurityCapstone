# Handoff — Scryxen console is now a **FastAPI web app** (Streamlit retired)

**Date:** 2026-08-12
**Repo:** `C:\Users\sylhe\WorkProjects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch:** `epic-6-dashboard-intake-reshape`
**Next session's job:** polish/edit the console (the user plans more UI edits). It works and is committed.

## What changed this session — the UI shifted off Streamlit
The approved v2 design (artifact `8fcd343b-…`) is a bespoke web app that Streamlit
can't reproduce pixel-exact. So the console was **rebuilt as a FastAPI app** that
serves the real design and drives it from the existing engine. Decision + rationale
in **`docs/adr/0002-web-console-over-fastapi.md`**. The Streamlit `app.py` (and
`tests/test_app.py`, and the `streamlit` dependency) are **deleted**.

### New / changed files
- **`server.py`** — FastAPI app. `GET /` serves `web/index.html`; `GET /api/environment`
  (one-time asset map + presets + defaults); `POST /api/plan` (the whole board,
  recomputed per controls — the hot path); `POST /api/asset/{id}`,
  `POST /api/finding/{cve}`, `POST /api/override`, `POST /api/override/clear`.
  Scans once (cached, offline), holds the env + `OverrideLog` in memory (`_state`).
- **`web/index.html` · `web/styles.css` · `web/app.js`** — the artifact's design,
  split out. `app.js` is a **pure renderer**: it POSTs controls and draws the JSON;
  no scoring/packing in the view.
- **`dashboard.py`** — three new pure seams (tested): `plan_payload` (assembles the
  whole `/api/plan` response), `score_breakdown` (the modal's 4-way weighted split),
  `presets` (the risk-appetite weight sets, moved out of the old `app.py`).
- **`tests/test_console_payload.py`** (6) + **`tests/test_server.py`** (7) — new.
- **`requirements.txt`** — `+fastapi +uvicorn`, `-streamlit`.
- **`docs/adr/0002-…`**, **`CLAUDE.md`** ("Running the console"), this handoff.

## State — COMMITTED + PUSHED this session
Full suite: **237 passing** (was 259 before removing the 22 Streamlit `test_app.py`
tests). The `dashboard.py` pure-seam tests and the whole engine test set are intact.
Verified in the browser: intake, all four tabs, the working SVG node graph + node
drill-in, the risk table, presets/weights, and the override flow.

## Run it
```
.\.venv\Scripts\python.exe -m uvicorn server:app --port 8000    # http://localhost:8000
.\.venv\Scripts\python.exe -m pytest -q                         # 237 passed
```
`gh`: prepend `$env:Path += ";$env:LOCALAPPDATA\GitHubCLI\bin"`. Network commands
(pip / any fetch) need `dangerouslyDisableSandbox`; the app itself runs offline off
`data/cache/`.

## Open for the next session (all polish, nothing broken)
1. **Asset-map layout.** Currently the engine's hop-distance columns, not the
   artifact's organic scatter. `networkx` (already a dep) can do a force-directed
   layout — the most-noticeable visual gap from the artifact.
2. **CSV upload** is a stub in intake (sample environment only). The `/api` layer is
   ready for it (`dashboard.load_asset_table` already validates an uploaded CSV) —
   wire an upload endpoint if wanted.
3. **Reweight latency** — the slider recompute is a ~180 ms debounced server call.
   Fine, but if it feels heavy on the full 4,523-row set, consider caching the
   scanned/scored frame per-weight or trimming the payload.
4. **JS has no automated tests** — verified by driving the app. A Playwright smoke
   test is the honest gap to close if this grows.
5. Minor: `use_container_width` deprecation is gone with Streamlit; ignore old notes.

## Memory (`~/.claude/projects/.../memory/`)
- **`ui-architecture-shift.md`** — the decision + that it's now implemented.
- `dashboard-design-direction.md`, `dashboard-intake-reshape-wip.md` — prior design
  track (the Streamlit port they describe is retired).
- `environment-setup.md` — gh portable path, venv python, network-sandbox quirk.
Index in `MEMORY.md`.
