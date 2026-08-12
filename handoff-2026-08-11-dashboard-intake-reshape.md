# Handoff — Dashboard intake reshape (Scryxen, epic #6)

**Date:** 2026-08-11
**Repo:** `C:\Users\sylhe\WorkProjects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Machine:** this session ran on `sylhe` (the prior `handoff-cybersec-capstone.md` was written on `rocketboy` — paths there are stale).
**Next session's job:** decide the two held code-review items, apply the three confirmed fixes, then push `epic-6-dashboard-intake-reshape` + open a PR (or merge) and do issue bookkeeping for #6/#37–#40/#53.

## Branch / commit state
- **On `main` (`911d20b`):** the previous dashboard rework (Scryxen, input-first, asset map, decision-support plans) is already landed. See `handoff-cybersec-capstone.md`.
- **This session's work — branch `epic-6-dashboard-intake-reshape`, commit `b9a7e00`, NOT pushed, NOT merged.** Branched off `main`. 5 files changed, +318/−100.
- **Uncommitted in the working tree (intentionally NOT part of the commit):**
  - `CLAUDE.md` — modified (a newer local copy with an extra "Triage labels" section; it is *ahead* of the repo's version and references `docs/agents/triage-labels.md`). Decide whether to commit this.
  - `docs/agents/triage-labels.md` — untracked, local-only (referenced by the newer CLAUDE.md; not on `main`).
  - `docs/issues/` — untracked snapshots (`issues.json`, `README.md`) pulled from GitHub Issues this session; convenience only, safe to delete or commit.

## What this session did
1. **Environment bring-up on a fresh machine** (see the `environment-setup` memory):
   - Installed `gh` CLI as a **portable extract** at `%LOCALAPPDATA%\GitHubCLI\bin\gh.exe` (winget MSI was blocked by a stuck UAC prompt). On the **user PATH** — new terminals see it; in tool calls prepend `$env:Path += ";$env:LOCALAPPDATA\GitHubCLI\bin"`. Authenticated as GitHub user `hotoloude686` (keyring; scopes gist/read:org/repo/workflow).
   - Pulled the repo (`git pull`, fast-forward from the near-empty initial commit to `911d20b`).
   - Created `.venv` (Python 3.13.7) and installed `requirements.txt` (incl. `pulp`, `streamlit 1.61.1`). Added `.venv/` to `.gitignore`.
   - **Network sandbox quirk:** Bash/PowerShell tool calls are sandboxed and cannot resolve DNS; any network command (pip, downloads) needs `dangerouslyDisableSandbox`.
2. **Dashboard reshape (commit `b9a7e00`)** — the response to `Current Issues with the App and Dashboard.md`, building on the already-landed rework. **View-only change; engine untouched.**

## What the reshape changed (`app.py` + one `dashboard.py` seam)
- **Intake gate (load-in page).** The app now opens on **"Set up your scan"** — inputs only, nothing computed — and holds until **"Build my plan ▶"** (`build_btn`). State flag: `st.session_state["plan_built"]`.
- **Assets default to CSV upload** (the demo path): the radio is reordered so **"Upload your assets"** is first; with no file it gracefully falls back to the sample and says so.
- **"List every vulnerability" defaults ON** (= show all), per the punch-list; toggle off to cap with `max_results`.
- **Summary board.** On build, the inputs move to the **sidebar** (still live — a slider re-plans in place, preserving #38), and the body renders **Summary → Asset map → Remediation plans → findings**.
- **Click-through detail via `st.dialog`.** Each finding is a button that opens a modal breakdown (`_finding_dialog`); a focused system opens `_asset_dialog` (name, tier, hops, neighbours, scheduled CVEs). **"◀ Edit inputs"** (`edit_btn`) returns to intake.
- **New tested seam:** `dashboard.asset_detail(asset_id, asset_table, result)` — pure, view-free, backs the system modal. Keeps the "no business logic in the view" rule.

## Test status
- **`.\.venv\Scripts\python.exe -m pytest -q` → 232 passed** (was 225; +2 `asset_detail` seam tests, net +5 in `test_app.py` after rewriting it for the gate). `test_app.py` now has `_run(built=True)` to jump to the summary board; asserts the intake gate, "list all" default, the finding-detail dialog opening without crashing, and all prior #38/#40/#53 wiring.
- The 20 warnings are `pulp` 3.x deprecations (code uses the pre-4.0 API) — harmless.

## Code review (ran `/mp-code-review since main`, two axes) — ADDRESS NEXT SESSION
**Standards axis (4 findings):**
1. *(hard-leaning)* **Business logic in the view.** `_asset_dialog` (and `_render_detail`) resolve `dashboard.TIER_COLORS.get(tier, ...["low"])` inline — the "unknown tier ⇒ low" fallback is a domain rule that belongs in the seam. Fix: have `asset_detail` (and `plan_item_detail`) return a resolved `tier_color`; the view just paints it.
2. **Dead parameter (real).** `collect_inputs(env)` never uses `env` (both call sites) — `environment_inputs()` re-scans internally. Drop the param. *(Both axes flagged this — clearest fix.)*
3. *(judgement)* **Private-API reach.** `dashboard.py` calls `asset_graph._parse_connections(...)`. Add a public `asset_graph.parse_connections` and call that.
4. *(judgement)* **Duplicated Code.** The gray-label span in `_render_detail` and the styled span in `_asset_dialog` both hand-roll `unsafe_allow_html` colour spans — factor a small helper.

**Spec axis (3 findings):**
1. **System click-through is partial.** Findings are genuinely click-to-open. But you can't click a **system on the asset map** — the only path to the system modal is the `focus_asset` selectbox + a separate `asset_detail_btn`. Streamlit can't natively make an embedded SVG click back into Python; a clickable map needs a **custom component** (real work). HELD for the user's call.
2. **#53 live-vs-cached indicator** is still a plain text line (`st.info(source)`), not an explicit badge. Quick polish. HELD for the user's call.
3. **Redundant double scan on intake** (same root cause as Standards #2 — the dead `env`): `intake_page` calls `_scan_sample()` then `collect_inputs(env)` which scans again. Cached, harmless, but reads as a mistake.

## Confirmed plan for next session (agreed direction)
- Apply the **3 confirmed fixes** (TDD on the seam): drop dead `env` param; move tier→colour into `asset_detail`/`plan_item_detail`; add public `asset_graph.parse_connections`. (The duplicated-span helper is optional cleanup.)
- **Two held judgement calls** (user to decide): clickable asset-map nodes (custom component) and the #53 live/cached badge.
- Then: push branch + PR/merge; close/relabel epic #6 stories per convention (close on merge, not before).
- **Open UX questions raised but not yet answered by the user:** (1) bump capacity defaults toward ~200h? (currently 40/16/8 so the #36 "+36.6%" checkpoint reproduces — free-typed so any value works); (2) keep the disclosure-year range on the intake page (current) vs. as a results refinement.

## Running the app
- Launch: `.\.venv\Scripts\python.exe -m streamlit run app.py --server.headless true --server.port 8501` → http://localhost:8501. Runs fully **offline** off `data/cache/` (30 committed vendor pulls); no NVD key needed. (`.env` holds `NVD_API_KEY` only to raise the live rate limit for #53.)
- **An instance is STILL RUNNING on port 8501** from this session (backgrounded). Kill it: `Get-NetTCPConnection -LocalPort 8501 -State Listen | %{ Stop-Process -Id $_.OwningProcess -Force }`.

## Environment / gotchas (this machine)
- **Python:** use the venv directly — `.\.venv\Scripts\python.exe` (system `python` is 3.13 but the deps live in the venv). Tests: `.\.venv\Scripts\python.exe -m pytest -q`. No typechecker configured — pytest only.
- **`gh`:** prepend `$env:Path += ";$env:LOCALAPPDATA\GitHubCLI\bin"` in tool calls (portable install, not on the machine PATH for tools).
- **Network commands need `dangerouslyDisableSandbox`** (DNS is blocked in the default sandbox).

## Design references (UX spec)
- Punch-list / spec: `Current Issues with the App and Dashboard.md` (repo root).
- Asset-map concept: `fulcrum_interactive_poc_with_asset_map.html` (repo root).
- Prior handoff: `handoff-cybersec-capstone.md`.

## Memory (`~/.claude/projects/.../memory/`)
- `environment-setup` — gh portable path, venv, network sandbox quirk (added this session).
- Prior: `python-launcher`, `data-feeds-live`, `stand-in-joins`, `tool-rename-scryxen` (from the earlier `rocketboy` sessions; the `python-launcher` note's `py` launcher differs on this machine — use the venv python here).
