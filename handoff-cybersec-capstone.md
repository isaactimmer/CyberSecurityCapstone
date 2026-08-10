# Handoff — CyberSecurity Capstone (Fulcrum risk-prioritization)

**Date:** 2026-08-09
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch state:** work for epic #47 is on **`epic-47-real-data-mapping`**, pushed, and open as **[PR #55](https://github.com/isaactimmer/CyberSecurityCapstone/pull/55)** — **NOT yet merged to `main`**. `main` still ends at `c373dff`. First decision next session: review + merge PR #55.

## What this project is
A vulnerability-prioritization tool ("Fulcrum"). It merges NVD (CVSS) + EPSS + CISA KEV feeds, maps a company's asset graph to importance tiers, and produces one **composite risk score** per vulnerability so a "medium" CVE on a critical, actively-exploited asset can outrank a "critical" CVE on the edge. A **capacity-aware optimizer** then packs fixes into the team's real work-time to maximise risk removed. Issue tracking = GitHub Issues via `gh` (`docs/agents/issue-tracker.md`).

## Build state (what exists on `main` vs. in PR #55)
- **On `main` already:** epic #4 (composite scoring, `scoring.py`), epic #5 (capacity-aware optimizer — `capacity.py`, `optimizer.py`, `optimizer_ilp.py`), asset graph (`asset_graph.py`). Don't redo.
- **In PR #55 (epic #47 — closes the two "stand-in join" gaps):** the data layer is now **real, live, and vendor-mapped**. Details are in the [PR description](https://github.com/isaactimmer/CyberSecurityCapstone/pull/55), the commit (`f6ed248`), and **ADR-0001** (`docs/adr/0001-poc-modeling-assumptions.md`). Read those rather than re-summarizing. In brief:
  - **#48** `combine_feeds_with_custom_inputs.fetch_merged(vendor)` — importable, keyless-capable, disk-cached to `data/cache/` (committed for offline demo). KEV memoized.
  - **#49** `assets.csv` — 37-asset mid-sized company + a `vendor` column; connections symmetrized; tiers spread critical/high/medium/low.
  - **#50** `cve_asset_map.py` — real CVE→asset join by **vendor keyword**; highest-tier-wins; unmatched→null tier; skips a failing vendor.
  - **#51** `capacity.pool_for_vendor` — pool from software work-type; **effort still constant per pool**; hash stand-in kept as fallback.
  - **#52** `pipeline.py` — end-to-end `scan_environment` → `build_plan`, no manual tier/pool injection.
  - **#54** ADR-0001 — real-vs-modelled assumptions.
- **Stories #48–#52, #54 are OPEN on purpose** — close them when PR #55 merges (convention: close on merge, not before).

**Test status: 176 passed, 1 skipped** (`py -m pytest -q`). The 1 skip is still the ILP path (`pulp` not installed).

## Checkpoint (#36) — refreshed on real data
Recorded on the [#36 issue](https://github.com/isaactimmer/CyberSecurityCapstone/issues/36) and in ADR-0001. 37 assets / 30 vendors / **4,523 real CVEs** / 48 KEV-flagged: optimizer **3,705.8** vs baseline **2,712.0** = **+36.6%**. The old stand-in run was +66.5%; direction held, magnitude shifted once real mappings replaced placeholders — as predicted. Top optimized fixes are real actively-exploited CVEs (CVE-2024-3400 PAN-OS, CVE-2021-26855 ProxyLogon, CVE-2018-13379 FortiOS, CVE-2023-27532 Veeam).

## Data realism — the important correction to the *previous* handoff
- **The network IS reachable here and the data is REAL.** NVD (keyword search works **without** a key at a lower rate limit), EPSS, and KEV are all live. The prior handoff's "no network / can't run the pipeline" note was wrong. (Saved to memory: `data-feeds-live.md`.)
- **`merged_vulnerabilities.csv` is gitignored / not tracked** — a local ~8,296-row Microsoft keyword pull. Not the demo's source of truth anymore; `data/cache/*.csv` (30 committed vendor pulls) is.
- **NVD API key** belongs in `.env` (git-ignored; only `.env.example` is tracked). No `.env` exists in the repo now. The key only raises the rate limit — the user has one for higher-throughput/live-demo runs.
- **What is modelled vs. real** is documented in ADR-0001: real = feeds + scoring + optimizer; modelled = the asset environment (customer-supplied in production) and the vendor→pool heuristic. Keep labelling the environment as modelled in any output.

## Environment / gotchas
- **Python:** use `py` (`python`/`python3` not on PATH). Tests: `py -m pytest -q` from repo root. Pytest only, no typechecker. (Memory: `python-launcher.md`.)
- **Full environment scan is ~30 paced NVD pulls.** Keyless NVD is ~5 req/30s, so a cold scan must pace (~6.5s/vendor) or it 429s. The cache is already warm (`data/cache/`), so `pipeline.run(use_cache=True)` is instant offline. `build_environment_vulnerabilities` skips a vendor whose pull fails rather than aborting.
- **`max_results` is page-granular** — NVD returns a full 200-row page minimum regardless of a smaller `max_results`.

## Next work — Dashboard epic #6 (Streamlit app for real)
The logical next `/implement` target. Fetch acceptance criteria fresh (`gh issue view <n> --json title,body`). The dashboard is a **thin view over `pipeline.py`** — call `pipeline.scan_environment` / `pipeline.build_plan` (and `scoring`/`optimizer`/`capacity`), never reimplement logic.
- **#37** Streamlit skeleton / app entry point (blocks the rest).
- **#38** capacity + weighting sliders wired to the real modules.
- **#39** findings table + naive-vs-optimized view + headline metric.
- **#40** KEV-alert demo trigger (re-optimize when a new KEV lands).
- **#53** the demo's headline feature — a **live "show me `<vendor>`" input** that calls `fetch_merged` → `build_plan` in front of the audience (cached fallback offline).

A **clickable dashboard mockup** (private Claude artifact, scratchpad-only, not in repo) is the UX spec: https://claude.ai/code/artifact/e505193c-35e3-453d-a060-5fce26fc979a — re-render via WebFetch if the scratchpad HTML is gone. Also a system dossier: https://claude.ai/code/artifact/d83e5c5f-047a-4bcf-8117-14555e07068c

Other open epics: **#7 Demo Prep** (#41–#43), **#8 Documentation & Report** (#44–#45), plus process/ceremony issues (#3, #18–#26).

## Open decisions for the user (ask, don't assume)
1. **Merge PR #55** into `main` (then close #48–#52, #54)?
2. Streamlit is **not yet a dependency** — add `streamlit` to `requirements.txt` when starting #37.
3. Whether to commit the dashboard mockup HTML into the repo (e.g. `docs/`) as the reference design, or leave it a scratchpad artifact.
4. This handoff rewrite is currently an **uncommitted working-tree change** on `epic-47-real-data-mapping` — decide whether to add it to PR #55 or commit separately.

## Suggested skills for the next session
- **`implement`** — build the #37–#40/#53 dashboard stories (TDD + single-file runs + full suite + `code-review` + commit).
- **`run`** — launch the Streamlit app once #37 stands it up (verify it renders, screenshot).
- **`tdd`** — for any new pure-logic seams.
- **`code-review`** — after implementing, against `main` (post-merge) as the fixed point.
- **`resolving-merge-conflicts`** — only if PR #55 conflicts at merge.

## Memory (`~/.claude/projects/.../memory/`)
- `python-launcher.md` — use `py`, tests via `py -m pytest -q`.
- `data-feeds-live.md` — NVD/EPSS/KEV are live-reachable; the merged CSV is real, not synthetic.
- `stand-in-joins.md` — the two placeholders + how epic #47 resolves them (vendor keyword join; role-based constant-effort pools).
Index in `MEMORY.md`. Add durable facts as they emerge.
