# ADR-0002 — The console is a FastAPI web app, not Streamlit

**Status:** Accepted · **Date:** 2026-08-11 · **Epic:** #6 (dashboard / UI)

## Context

Epic #6 delivered the console first as a Streamlit app (`app.py`) over the
`dashboard.py` seam. The approved v2 design, however, is a bespoke web app
(artifact `8fcd343b-…`): a specific light/teal design system, a custom SVG
node-link asset graph, inline score-bar tables, an override form, and a modal.

Streamlit could reproduce the *information architecture* but not the *design*.
Its levers — the config theme, CSS injection against obfuscated/unstable class
names, and sandboxed raw-HTML components that can't easily call back to Python —
top out well short of "looks exactly like the artifact," and the clickable graph
had to be a native Altair chart that threw a Vega parse error and rendered blank.

## Decision

**Serve the real design as static assets and expose the engine over a JSON API.**

- `server.py` (FastAPI) serves `web/` (`index.html` · `styles.css` · `app.js`,
  the artifact's HTML/CSS/JS) and offers a small API: `/api/environment` (one-time
  asset map + presets + defaults), `/api/plan` (the whole board recomputed for the
  current controls), `/api/asset/{id}`, `/api/finding/{cve}`, and the override
  endpoints.
- The front end is a **pure renderer**: it never scores or packs. It POSTs the
  controls and draws what `dashboard.plan_payload` returns. This keeps epic #6's
  rule (no business logic in the view) *stronger* than under Streamlit — the JS
  has no scoring maths at all, where the artifact prototype reimplemented it.
- The environment is scanned once (cached NVD/EPSS/KEV, offline) and held in
  memory; every recompute is pure pandas over that cache.

The Streamlit view (`app.py`) and its `streamlit` dependency and tests are
**retired**. The pure `dashboard.py` seams (and their tests) are reused unchanged;
the epic-#6 view/logic split is what made the swap cheap.

## Consequences

- Pixel-faithful to the approved design, with the clickable graph and live
  override flow actually working (no Vega crash).
- **Reweighting is a debounced server call (~180 ms), not instant client-side.**
  The engine is the single source of truth, so a slider release triggers a real
  re-score/re-pack rather than JS approximating it.
- **The asset map uses the engine's hop-distance layout (columns), not the
  artifact's hand-authored scatter.** The scatter positions were tuned for 20
  fixed nodes; real `assets.csv` has ~37. A force-directed layout (`networkx`,
  already a dependency) is the follow-up if the organic look is wanted.
- New runtime deps: `fastapi`, `uvicorn`. New test seams: `dashboard.plan_payload`,
  `score_breakdown`, `presets` (unit-tested), plus FastAPI TestClient smoke tests.
  The JS/visual layer has no automated tests — it is verified by driving the app.
