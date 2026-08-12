# Handoff — Scope-mode toggle + typed per-pool capacity max

**Date:** 2026-08-12
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch:** `main` (tracks `origin/main`).
**Commit this session:** `47e4b92` — committed to `main` **and pushed** (`dd7ea4d..47e4b92`).
**Next session's job:** no open design questions this time. Pick from the standing
polish list below, or whatever the user brings.

## What this session did

Closed the **two open questions** the prior handoff left for the user (they answered
both this session), then ran `/code-review` and fixed what it found before committing.

See `git show 47e4b92` for the full diff. Summary:

1. **Scope-mode toggle — "scope the plan, or just the display?"** (user chose
   *"Both, user-toggle"*). Default `"plan"` keeps the old behaviour: the top-N cut
   runs **before** optimization, so "list 25" shrinks the remediation universe and
   changes the KPIs. New `"display"` mode demotes the count to a **table-only cap**
   (`dashboard.plan_payload(display_limit=...)`): the optimizer, KPIs, and both plan
   columns still weigh the whole universe, while the **year range stays a real
   pre-optimization scope in both modes**. Wired through
   `server._display_only`/`_scope`/`_display_limit`, `Controls.scope_mode`
   (a `Literal["plan","display"]`), `app.js` `scope.mode`, and the intake **step-2
   checkbox** ("List the top N only — let the optimizer still weigh every finding").
2. **Typed per-pool capacity max** (user chose *"Yes, add max field"*). Each Plan-tab
   slider now has a small `max` number input. Blank tracks the adaptive ceiling (shown
   as the input's placeholder); a typed value sets the slider ceiling explicitly and
   **clamps the budget down** if it now exceeds the ceiling. Pure front-end
   (`app.js` `capMax`/`setCapMax`/`applyCapBounds` + `CAP_SLIDER`/`CAP_MAX_IN`/
   `CAP_DEFAULT_CEIL`, `.capmax` CSS, three `cm_*` inputs) — no engine change.

### `/code-review` fixes applied before the commit
- **Spec (real gap):** `/api/override` and `/api/override/clear` weren't forwarding
  `scope`/`display_limit`, so recording/clearing an override **silently un-trimmed the
  display cap** until the next `/api/plan`. Both now forward them. Regression test:
  `test_override_endpoint_keeps_the_display_cap`.
- **Standards (judgement call taken):** `scope_mode` is now `Literal["plan","display"]`
  (validation + self-documentation); `_display_only` simplified accordingly.
- Reviewer also noted the diff bundles two independent features (Divergent Change) —
  left as one commit because both features edit `app.js`/`index.html`, so a split
  would scatter half-features across commits (no interactive `git add -p` here).

## State
- **251 tests passing** (246 prior + 5 new: 2 engine `display_limit` in
  `tests/test_console_payload.py`, 3 API in `tests/test_server.py` — two `scope_mode`,
  one override-cap).
- Verified end-to-end in the browser **and** via the API: display mode → "15 of 4523"
  listed but 56 optimizer fixes (weighed everything); plan mode → 10 listed, 9 fixes
  (optimizer saw only top 10); year range still scopes in display mode; typed max 300
  raises the ceiling, max 20 clamps the 40 budget to 20; override in display mode keeps
  the table capped with the overridden CVE floated to rank 1; **no JS console errors**.
- A fresh `uvicorn` (started **after** the review fixes) is running on port 8000.

## Standing polish list (carried forward — not blocking)
- **Reweight latency:** ~180 ms debounced `/api/plan` on 4,523 rows — cache the scored
  frame per-weight or trim the payload.
- **No JS automated tests:** a Playwright smoke test (toggle, max field, override flow)
  is the honest gap. All UI verification is still manual.
- **CSV-upload follow-ups:** sample template, client size guard, surface
  silently-dropped vendors.
- **Year-filter silent-drop (latent):** `dashboard.filter_findings` uses `years.notna()`,
  so narrowing drops CVEs whose id has no parseable year. Harmless on the sample data
  (all ids parse); could bite an uploaded CSV with malformed ids.
- **Stale `AssetMapLayout` docstring** still says "Altair can draw directly" (stale
  post-rebuild).
- **GitHub issues stale/closeable:** #37 (Streamlit skeleton — obsolete), #38/#39/#40
  effectively delivered by the rebuild. Offer to close with a note.
- **Two features / one commit:** if the user cares about clean history, the scope-mode
  and capacity-max features could be split retroactively — but they're pushed now.

## Run it
```
.\.venv\Scripts\python.exe -m uvicorn server:app --port 8000    # http://localhost:8000
.\.venv\Scripts\python.exe -m pytest -q                         # 251 passed
```
`py` launcher works too (`py -m pytest -q`). App runs offline off `data/cache/`.
**Stale-server trap:** if the UI looks dead or serves old behaviour, a leftover uvicorn
is holding port 8000 with old code — kill the PID (`netstat -ano | grep :8000`), relaunch,
hard-refresh (Ctrl+Shift+R). Python changes need a server restart (no `--reload`); static
`web/` changes just need a hard refresh. Verify the API before debugging the UI, e.g.
`curl -X POST localhost:8000/api/plan -d '{"max_findings":3,"scope_mode":"display"}' -H "Content-Type: application/json"`
(should list 3 but report a much larger `optimized_fixes`).

## Reference (don't duplicate here)
- ADR: `docs/adr/0002-web-console-over-fastapi.md` (FastAPI, not Streamlit).
- Run instructions: `CLAUDE.md` ("Running the console"). Key rule: `web/app.js` is a
  **pure renderer** — all scoring/packing lives in the Python engine.
- Engine seams touched: `dashboard.plan_payload` (new `display_limit`); `server.py`
  (`Controls.scope_mode`, `_display_only`/`_scope`/`_display_limit`, override endpoints
  now forward `scope`+`display_limit`).
- Front end: `web/index.html` (intake step-2 toggle; three `cm_*` max inputs on the
  Plan tab), `web/app.js` (`scope.mode`, `capMax`/`setCapMax`, `applyCapBounds`,
  `readScope`), `web/styles.css` (`.capmax`).
- Memory index: `~/.claude/projects/.../memory/MEMORY.md`.

## Suggested skills for the next session
- **`run`** — launch the console to confirm changes in the real app (sidesteps the
  stale-server trap: start fresh, verify the API before debugging the UI).
- **`tdd`** — for any new engine seam, or the Playwright JS smoke tests.
- **`/code-review`** — review the diff on both axes before committing (worked well again
  this session — caught the override-cap gap).
