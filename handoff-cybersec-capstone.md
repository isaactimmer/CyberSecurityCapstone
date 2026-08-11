# Handoff — CyberSecurity Capstone (Scryxen risk-prioritization)

**Date:** 2026-08-11
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Next session's job:** **review + land the dashboard rework** (branch `epic-6-dashboard-rework`, committed, NOT pushed) — then decide PR/issue bookkeeping and move on to the remaining epics (#7 Demo Prep, #8 Docs). The rework itself is **done** and verified; what's left is the user's call on pushing, an optional `/code-review`, and two small polish items.

> **Naming:** the tool is **Scryxen** (formerly "Fulcrum"). Renamed this session **where it names the tool** — app UI, `pipeline.py` docstring/CLI, ADR-0001. Deliberately kept: `fulcrum_*` file names (incl. the POC concept file) and internal identifiers. The `handoff` history and `Current Issues…` note still say Fulcrum by design.

## What this project is
A vulnerability-prioritization tool. It merges NVD (CVSS) + EPSS + CISA KEV feeds, maps a company's asset graph to importance tiers, and produces one **composite risk score** per vulnerability so a "medium" CVE on a critical, actively-exploited asset outranks a "critical" CVE on the edge. A **capacity-aware optimizer** then packs fixes into the team's real work-time to maximise risk removed. Issue tracking = GitHub Issues via `gh` (`docs/agents/issue-tracker.md`).

## Build state
- **On `main`:** epics #4 (scoring), #5 (optimizer — `capacity.py`/`optimizer.py`/`optimizer_ilp.py`), asset graph (`asset_graph.py`), #47 (real live vendor-mapped data — `combine_feeds_with_custom_inputs.py`, `assets.csv`, `cve_asset_map.py`, `pipeline.py`, ADR-0001), **and the original epic #6 dashboard** (commits `6596084`, `1ddf971` — these landed on `main` since the previous handoff was written).
- **Dashboard rework — built this session, on branch `epic-6-dashboard-rework`, committed `c651890`, NOT pushed, NOT merged.** This is the response to the user's punch-list. Read the commit message + diff rather than re-summarizing. Branched off `main`.
- **Test status: 221 passed, 1 skipped** (`py -m pytest -q`); was 204. Skip is still the ILP path (`pulp` not installed).

## What the rework did (this session) — spec was `Current Issues with the App and Dashboard.md`
Full rewrite of the **view** (`app.py`); **grew** `dashboard.py` with new pure/tested seams; engine untouched. The plan is at `C:\Users\rocketboy\.claude\plans\lively-wandering-plum.md`. Highlights (see diff for detail):
- **Input-first landing:** "1 · Your environment" (sample vs **upload assets** CSV — same schema as `assets.csv`, bad upload → friendly error + sample fallback), "How many vulnerabilities to list?" + "list all" toggle, optional **disclosure-year range** (parsed from `cve_id`).
- **Team capacity** as free-typed `number_input`s (hours / slots) so the ceiling is user-set — no fixed slider range. Defaults track `capacity.DEFAULT_POOL_CAPACITY` (40 / 16 / 8) **on purpose** so the #36 checkpoint reproduces.
- **Summary strip:** optimizer lift, risk removed, severity-first baseline, **Critical assets addressed (n of m)**.
- **Asset map restored** (the user's "key" feature): SVG laid out left→right by hop-distance from the crown jewel, tier-colored, crown-jewel + scheduled-fix (green) markers; a **"Focus a system"** selectbox highlights the node and filters findings.
- **Plans = decision-support:** each finding is a click-to-expand (`st.expander`) score breakdown + a plain-English "Ranked here because…" sentence (extends the POC's `detailHtml`).
- **Decluttered:** story labels gone, verbose ADR caveat banner gone (honesty is now a single tooltip on the tagline), live vendor scan + KEV simulation moved to a tidy sidebar.

### Dashboard architecture (the rule that MUST survive) — **no business logic in the view**
- `app.py` — Streamlit view: widgets + layout only. Every widget that a test drives has a stable `key=`.
- `dashboard.py` — the tested Streamlit-free seam. Existing seams kept (`normalize_weights`, `build_pools`, `plan`, `findings_view`, `headline`, `inject_kev`, `kev_candidates`, `live_environment`, `default_environment`). **New this session:** `cve_year`, `year_bounds`, `filter_findings`, `load_asset_table`, `asset_map_data`, `asset_map_svg`, `asset_map_height`, `annotate_plan`, `plan_item_detail`, `asset_coverage`, `in_plan_assets`. The SVG string is **built here, not the view.**
- `tests/test_dashboard.py` — the seam tests (now ~33). `tests/test_app.py` — headless `AppTest` wiring (13), rewritten for the new view (asserts Scryxen title, no "Story #" labels, no caveat banner, capacity inputs re-plan, map/summary render, focus selectbox, live-scan + KEV still work).

## Verification done this session
- `py -m pytest -q` → **221 passed / 1 skipped.**
- App boots headless clean (HTTP 200, no errors); **eyeballed in Chrome** — landing, asset map (37 assets across 7 hop-columns, single crown jewel `customer-database`, 49 edges), and an expanded plan finding all render as intended.
- **#36 checkpoint reproduces exactly:** optimizer **3,705.8** vs baseline **2,712.0** = **+36.6%** at default capacity.

## What's left / open (next session)
- **Push `epic-6-dashboard-rework` + open PR** — held per the user's decision to wait until the rework landed. It has landed; confirm and push when ready.
- **Optional `/code-review`** against `main` — re-confirm the "no business logic in the view" rule held (offered, not yet run).
- **Issue bookkeeping:** epic #6 stories #37–#40/#53 are still **OPEN**. Decide with the user: are the reworked UX changes *edits* to those, or *new* stories? Convention: close on merge, not before.
- **Two small polish items the user was shown** (not blocking): (1) long asset names truncate on the map ("Internal API Gate…") — widen node boxes or add a hover `<title>`; (2) the widest hop-column (11 nodes) makes the map tall — a more compact layout is possible for slides.
- **Remaining epics:** #7 Demo Prep (#41–#43), #8 Documentation & Report (#44–#45), plus process/ceremony issues (#3, #18–#26).

## Running the app
- Launch: `py -m streamlit run app.py` → http://localhost:8501 (streamlit isn't on PATH; go through `py -m`).
- **An instance is likely STILL running from this session on port 8501** (launched headless/detached under `python.exe`). Kill it: `netstat -ano | grep :8501` then `Stop-Process -Id <pid> -Force`.
- Runs fully **offline** off `data/cache/` (30 committed vendor pulls). Uploaded assets with un-cached vendors will try live NVD pulls (degrades gracefully via `skip_errors`).
- **Perf note (carried):** every widget interaction re-runs the script and re-scores ~4,523 rows via a row-wise `apply`. The view now caches the environment scans (`st.cache_data`), so it's responsive; the "how many to list?" cap also trims the rendered table.

## Environment / gotchas (carried forward)
- **Python:** use `py` (`python`/`python3` not on PATH). Tests: `py -m pytest -q` from repo root. Pytest only, no typechecker. (Memory: `python-launcher.md`.)
- **Data is real & live.** NVD keyless keyword search (lower rate limit), EPSS + KEV live. Warm cache = instant offline. Cold full scan ≈ 30 paced NVD pulls (~6.5s/vendor or it 429s). (Memory: `data-feeds-live.md`.)
- **NVD API key** → `.env` (git-ignored; only `.env.example` tracked). Key only raises the rate limit; the user has one for live-demo runs.
- **Real vs. modelled** (ADR-0001): real = feeds + scoring + optimizer; modelled = the asset environment (customer-supplied in production) + the vendor→pool heuristic. The on-screen honesty is now the tagline tooltip.

## Design references (UX spec)
- Punch-list / spec: `Current Issues with the App and Dashboard.md` (repo root).
- Approved plan: `C:\Users\rocketboy\.claude\plans\lively-wandering-plum.md`.
- Asset-map concept extended: `fulcrum_interactive_poc_with_asset_map.html` (repo root).
- Artifacts the user shared (concepts, not the tool): https://claude.ai/code/artifact/94a6e9d0-541f-474d-9519-369237e478fc · https://claude.ai/code/artifact/e505193c-35e3-453d-a060-5fce26fc979a · https://claude.ai/code/artifact/d83e5c5f-047a-4bcf-8117-14555e07068c

## Suggested skills for the next session
- **`code-review`** — run against `main` before pushing; re-check "no business logic in the view."
- **`run`** — relaunch/eyeball if polishing the map (`py -m streamlit run app.py`).
- **`implement`** / **`tdd`** — for the two polish items (node-label width / compact map) or any new UX, TDD on `dashboard.py` seams + `AppTest`.
- **`AskUserQuestion`** — settle the issue-bookkeeping (new stories vs edits) and the push decision.

## Memory (`~/.claude/projects/.../memory/`)
- `python-launcher.md` — use `py`, tests via `py -m pytest -q`.
- `data-feeds-live.md` — NVD/EPSS/KEV live-reachable; merged CSV is real.
- `stand-in-joins.md` — the two placeholders + how epic #47 resolved them.
- `tool-rename-scryxen.md` — Scryxen (was Fulcrum); **updated** this session to reflect the logical-scope rename actually applied.
Index in `MEMORY.md`. Add durable facts as they emerge.
