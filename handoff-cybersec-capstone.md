# Handoff — Intake scope inputs, adaptive capacity max, caveat strip

**Date:** 2026-08-12
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch:** `main` (tracks `origin/main`).
**Commit this session:** `6b8a645` — committed to `main`, **not pushed** (user pushes themselves).
**Next session's job:** the user has *more to add/fix*. Two design questions are open
(see "Open questions for the user") plus the standing polish list.

## What this session did

Worked through the freshest user feedback in **`Current Issues with the App and
Dashboard.md`** (a hands-on UX critique). Cross-checked every item against the current
app first — most were already resolved by the FastAPI rebuild (asset map exists,
Scryxen name in UI, dashboard is a summary board, click-to-drill finding modal, story
refs already stripped). Three items remained; all three shipped in commit `6b8a645`.

See `git show 6b8a645` for the full diff. Summary of what changed:

1. **Intake "how much to look at" inputs** (top-N list size + year range). Wired through
   as a `scope` callable: `Controls → dashboard.plan_payload → dashboard.plan →
   pipeline.build_plan`, applied to the **scored** frame (which is risk-ordered) so a
   top-N cut keeps the highest-risk findings and both plans re-pack over the slice.
   Reuses the previously-built-but-**unwired** `dashboard.filter_findings` seam. Year
   defaults are prefilled from `dashboard.year_bounds`. A full-span year range collapses
   to "all" **in the engine** (`server._year_range`, against the true env bounds) so no
   CVE with an unparseable/absent year is silently dropped.
2. **Adaptive capacity slider max** — the Plan-tab sliders raise their ceiling to fit the
   entered budget (`app.js applyCapBounds`/`niceCeil`), so a 200 hr pool works instead of
   the old hard-coded 160/80/30 caps.
3. **Stripped developer-facing caveat copy** from the UI — the dashboard `Note:` naming
   `scoring.py·capacity.py·optimizer.py`, the `server.py (FastAPI)`/`assets.csv`
   footnote, the `· overrides.py` ref, the "normalized 0–1…" line, and the "modelled
   mid-sized company" intake blurb. Detail that's still useful moved to `title=` hover
   text (the user explicitly OK'd hover-for-more).

### Code review before committing (`/code-review`, two parallel sub-agents)
All 5 **Standards** findings were fixed before the commit: consolidated a duplicated
scope-closure into one `scope` callable threaded uniformly through all three plan
endpoints, moved the "full span = all years" rule out of the view into the engine (the
pure-renderer breach — `web/app.js` must stay a pure renderer per `CLAUDE.md`), and
tightened `dashboard.plan`'s `scope` type to `Callable`. The two **Spec** findings were
left as product decisions → see open questions below.

## State
- **246 tests passing** (241 prior + 5 new: engine scope tests in
  `tests/test_console_payload.py`, API scope tests in `tests/test_server.py`).
- Verified end-to-end in the browser **and** via the API: full-span year range → all
  4,523 findings; narrowed `[2024,2026]` + top-N → only 2024–2026 rows; header shows
  "N of 4523" when scoped; Patching 200 hrs fits the slider; caveat copy gone; **no JS
  console errors**.
- A fresh `uvicorn` is (was) running on port 8000 from this session.

## Open questions for the user (raised this session, not yet answered)
1. **Should "vulnerabilities to list" scope the whole plan, or just the display?**
   Currently the top-N cut runs **before** optimization, so "list 25" also shrinks the
   remediation universe to 25 CVEs and changes the KPIs. Defensible as "focus on the top
   N", but a user may expect it to trim only what's *shown* while the optimizer still
   considers everything. If we change it: apply `max_findings` as a post-plan display cap
   instead of a pre-optimization `scope` (year range can stay a real scope).
2. **Explicit capacity max/limit.** The user said "customize the max **and limit**." We
   made the slider ceiling *adapt* to the entered budget, but the lead still can't *type*
   an explicit cap. A small per-pool max field would close this fully.

## Also worth a look (not blocking)
- **Year-filter silent-drop (latent):** `dashboard.filter_findings` uses `years.notna()`,
  so any narrowing drops CVEs whose id has no parseable year. Harmless on the sample data
  (all ids parse) but could bite an uploaded CSV with malformed ids.
- **Standing polish list (unchanged from prior handoff):** reweight latency (~180 ms
  debounced call on 4,523 rows — cache scored frame per-weight or trim payload); **no JS
  automated tests** (a Playwright smoke test is the honest gap); CSV-upload follow-ups
  (sample template, client size guard, surface silently-dropped vendors); the
  `AssetMapLayout` docstring still says "Altair can draw directly" (stale post-rebuild).
- **GitHub issues are stale/closeable:** #37 (Streamlit skeleton — obsolete), #38/#39/#40
  are effectively delivered by the rebuild. Offer to close with a note next session.

## Run it
```
.\.venv\Scripts\python.exe -m uvicorn server:app --port 8000    # http://localhost:8000
.\.venv\Scripts\python.exe -m pytest -q                         # 246 passed
```
`py` launcher works too (`py -m pytest -q`). App runs offline off `data/cache/`.
**Stale-server trap:** if the UI looks dead or serves old behaviour, a leftover uvicorn
is holding port 8000 with old code — kill the PID (`netstat -ano | grep :8000`), relaunch,
hard-refresh (Ctrl+Shift+R). Python changes need a server restart (no `--reload`); static
`web/` changes just need a hard refresh. Verify the API before debugging the UI, e.g.
`curl -X POST localhost:8000/api/plan -d '{"max_findings":3}' -H "Content-Type: application/json"`.

## Reference (don't duplicate here)
- Feedback source: `Current Issues with the App and Dashboard.md` (repo root).
- ADR: `docs/adr/0002-web-console-over-fastapi.md` (FastAPI, not Streamlit).
- Run instructions: `CLAUDE.md` ("Running the console").
- Engine seams touched: `pipeline.build_plan` (new `scope` param), `dashboard.plan` /
  `dashboard.plan_payload` (thread `scope`), `dashboard.filter_findings` (now wired),
  `server._scope`/`_year_range`/`_max_findings` (build the scope from `Controls`).
- Front end: `web/index.html` (intake step 2 "How much to look at"), `web/app.js`
  (`readScope`, `applyCapBounds`, `controls()` now sends `max_findings`/`year_range`).
- Memory index: `~/.claude/projects/.../memory/MEMORY.md`. Note: the `stand-in-joins`
  memory (epic #47) is about the `importance_tier`/`pool` **data** joins — a different
  concern from the `filter_findings` UI seam wired this session; it stays accurate.

## Suggested skills for the next session
- **`run`** — launch the console to confirm changes in the real app (and to sidestep the
  stale-server trap: start fresh, verify the API before debugging the UI).
- **`tdd`** — for any new engine seam, or the Playwright JS smoke tests.
- **`prototype`** — sanity-check the reweight-caching timings before wiring.
- **`/code-review`** — review the diff on both axes before committing (worked well here).
