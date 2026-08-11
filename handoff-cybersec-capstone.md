# Handoff — CyberSecurity Capstone (Scryxen risk-prioritization)

**Date:** 2026-08-11
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Next session's job:** **revise the Streamlit dashboard** — it works end-to-end but has real UX problems. The full, user-written punch-list is in **`Current Issues with the App and Dashboard.md`** (repo root, untracked) — read that first; it is the spec for the rework. This doc gives the state around it.

> **Naming:** the tool is now **Scryxen** (formerly "Fulcrum"). The code, page title, docstrings, and README still say "Fulcrum" everywhere — renaming to Scryxen is part of the rework, not yet done.

## What this project is
A vulnerability-prioritization tool. It merges NVD (CVSS) + EPSS + CISA KEV feeds, maps a company's asset graph to importance tiers, and produces one **composite risk score** per vulnerability so a "medium" CVE on a critical, actively-exploited asset outranks a "critical" CVE on the edge. A **capacity-aware optimizer** then packs fixes into the team's real work-time to maximise risk removed. Issue tracking = GitHub Issues via `gh` (`docs/agents/issue-tracker.md`).

## Build state
- **On `main`:** epic #4 (composite scoring, `scoring.py`), epic #5 (capacity-aware optimizer — `capacity.py`, `optimizer.py`, `optimizer_ilp.py`), asset graph (`asset_graph.py`), and **epic #47** — the real, live, vendor-mapped data layer (**PR #55 merged 2026-08-10**; `combine_feeds_with_custom_inputs.py`, `assets.csv`, `cve_asset_map.py`, `pipeline.py`, ADR-0001). Don't redo. The old handoff's "merge PR #55" decision is **done**.
- **Dashboard epic #6 — built this session, on branch `epic-6-dashboard`, NOT pushed, NOT merged.** Two commits:
  - `6596084` — story #37 skeleton.
  - `1ddf971` — stories #38 (sliders), #39 (findings/plans/headline), #40 (KEV trigger), #53 (live vendor input).
  Read the commit messages + diffs rather than re-summarizing.
- **Test status: 204 passed, 1 skipped** (`py -m pytest -q`). The skip is still the ILP path (`pulp` not installed).

### Dashboard architecture (keep this when reworking)
The one rule that must survive the rework: **no business logic in the view.**
- `app.py` — Streamlit view: widgets + layout only.
- `dashboard.py` — Streamlit-free logic seam (`normalize_weights`, `build_pools`, `plan`, `findings_view`, `headline`, `inject_kev`, `kev_candidates`, `live_environment`, `default_environment`). Calls `pipeline`/`scoring`/`capacity`/`optimizer`; never reimplements them. **This is the tested seam** (`tests/test_dashboard.py`, 16 tests).
- `tests/test_app.py` (13 tests) drives the app **headless via `streamlit.testing.v1.AppTest`** — the same code path `streamlit run` uses, so "launches cleanly" / "slider changes the plan" are real assertions. Keep this harness; it's how you verify the rework without a browser.
- `combine_feeds_with_custom_inputs.cache_exists()` was added so the view can label live-vs-cached without touching cache internals.
- `streamlit` was added to `requirements.txt`.

## THE REWORK — what the next session focuses on
Source of truth: **`Current Issues with the App and Dashboard.md`**. Themes, in the user's words:
1. **Rename to Scryxen** across the app/UI/docs.
2. **Drop the story labels** in the UI ("Story #53 — …"). Explain what each control *does*, briefly; put detail behind hover/tooltip.
3. **Declutter / redesign as a summary-first dashboard.** The sidebar inputs are all crammed together; the plans + findings are just stacked tables and hard to navigate. Design for *who actually uses this* (a security lead), not for the story list.
4. **Add the asset map** — currently missing, and the user considers it *key* to the app. Reference `fulcrum_interactive_poc_with_asset_map.html` (repo root) — the system map with hop-distance from crown-jewel assets and a score-breakdown panel is the idea to extend.
5. **Input-first landing.** On open, meet the user with inputs (with sensible defaults if they don't know): "Insert your assets" (so they can build/see an asset map), "How many vulnerabilities to list?" (a number or all), a "Year-to-Year" range (or blank = all).
6. **Plans need decision-support, not data dumps.** Too much raw info, not enough "what do I do." Make a plan row **click-to-expand** into an extended summary / score breakdown (like the POC HTML, extended).
7. **Team-capacity inputs in hours** (e.g. 200 hours/week), with a customizable max/limit — not the current mixed hours/slots sliders with fixed ranges.
8. **Remove the verbose caveat text** (the "Feed data (NVD/EPSS/KEV) is real … modelled mid-sized company … See ADR-0001" banner). Keep the real-vs-modelled honesty (ADR-0001 still governs) but not as a wall of text on screen.

### Design references (UX spec)
- **NEW look artifact** the user shared (partial concept, not the full tool): https://claude.ai/code/artifact/94a6e9d0-541f-474d-9519-369237e478fc
- **Clickable POC with asset map** (in repo): `fulcrum_interactive_poc_with_asset_map.html` — the asset-map + score-breakdown idea to extend.
- Earlier mockup + system dossier (scratchpad artifacts): https://claude.ai/code/artifact/e505193c-35e3-453d-a060-5fce26fc979a · https://claude.ai/code/artifact/d83e5c5f-047a-4bcf-8117-14555e07068c

> **Note on issue #6 stories:** #37–#40/#53 are implemented but the rework changes the UX substantially. Decide with the user whether the rework is new stories under epic #6, or edits to the existing ones. The stories are still **OPEN** (convention: close on merge, not before) — nothing has been merged.

## Running the app
- Launch: `py -m streamlit run app.py` → http://localhost:8501 (streamlit isn't on PATH; go through `py -m`). Ctrl+C to stop.
- **An instance may still be running from this session** on port 8501 (launched headless/detached under `python.exe`, not `streamlit.exe`). To kill it: `netstat -ano | grep :8501` then `Stop-Process -Id <pid> -Force`.
- First paint is ~1–2s (warm-cache scan of the modelled environment). Runs fully **offline** off `data/cache/` (30 committed vendor pulls). A never-queried live vendor needs network, falling back to cache.
- **Perf watch for the rework:** every widget interaction re-runs the whole script, which re-scores ~4,523 rows via a row-wise `apply`. Fine now, but the input-first/asset-map redesign should keep an eye on responsiveness (cache `build_plan` by inputs, or reduce the default row count per the user's "how many to list?" input).

## Checkpoint (#36) — on real data
Recorded on the [#36 issue](https://github.com/isaactimmer/CyberSecurityCapstone/issues/36) and ADR-0001: 37 assets / 30 vendors / **4,523 real CVEs** / 48 KEV-flagged → optimizer **3,705.8** vs baseline **2,712.0** = **+36.6%**. The dashboard reproduces this exactly.

## Environment / gotchas (carried forward)
- **Python:** use `py` (`python`/`python3` not on PATH). Tests: `py -m pytest -q` from repo root. Pytest only, no typechecker. (Memory: `python-launcher.md`.)
- **Data is real & live.** NVD keyword search works keyless (lower rate limit), EPSS + KEV live. Warm cache makes `pipeline.run(use_cache=True)` instant offline. Cold full scan is ~30 paced NVD pulls (~6.5s/vendor or it 429s). (Memory: `data-feeds-live.md`.)
- **NVD API key** → `.env` (git-ignored; only `.env.example` tracked). No `.env` in repo; the key only raises the rate limit. The user has one for live-demo runs.
- **`max_results` is page-granular** — NVD returns a full 200-row page minimum.
- **Real vs. modelled** is in ADR-0001: real = feeds + scoring + optimizer; modelled = the asset environment (customer-supplied in production) + the vendor→pool heuristic. Keep the honesty even as the verbose on-screen caveat goes.

## Other open work (after the rework)
- Push `epic-6-dashboard` + open a PR (once the rework lands, or as-is first — user's call).
- Remaining epics: **#7 Demo Prep** (#41–#43), **#8 Documentation & Report** (#44–#45), plus process/ceremony issues (#3, #18–#26).

## Open decisions for the user (ask, don't assume)
1. Is the rework **new stories** under epic #6, or **edits to #37–#40/#53**? File issues accordingly?
2. **Rename to Scryxen**: scope — UI only, or code/module/README/docs too?
3. **Asset-map input**: what asset format does the user want to accept ("Insert your assets")? CSV upload matching `assets.csv` columns, a paste box, or a form? Confirm before building.
4. Push `epic-6-dashboard` now (share current state) or wait until the rework is done?
5. Should `Current Issues with the App and Dashboard.md` be committed/tracked (it's the rework spec) or stay a scratch note?

## Suggested skills for the next session
- **`prototype`** — the rework is UX-led and under-specified (asset-map layout, input-first landing, click-to-expand plan). Prototype the layout/flow before committing to the Streamlit build.
- **`domain-modeling`** / **`AskUserQuestion`** — pin down the asset-input format and the Scryxen rename scope (decisions 2–3) up front.
- **`implement`** — build the reworked dashboard (TDD on any new `dashboard.py` seams + `AppTest` wiring + full suite + `code-review` + commit).
- **`run`** — relaunch and eyeball/screenshot each iteration (`py -m streamlit run app.py`).
- **`code-review`** — after implementing, against `main` as the fixed point; re-check the "no business logic in the view" rule survives.

## Memory (`~/.claude/projects/.../memory/`)
- `python-launcher.md` — use `py`, tests via `py -m pytest -q`.
- `data-feeds-live.md` — NVD/EPSS/KEV live-reachable; merged CSV is real.
- `stand-in-joins.md` — the two placeholders + how epic #47 resolved them.
- `tool-rename-scryxen.md` — the tool is now **Scryxen** (was Fulcrum); code not yet renamed.
Index in `MEMORY.md`. Add durable facts as they emerge.
