# Handoff — CyberSecurity Capstone (Fulcrum risk-prioritization)

**Date:** 2026-08-09
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch:** `main` — everything below is committed **and pushed** to `origin/main`. Working tree clean. Only `main` exists now (feature branches deleted after merge).

## What this project is
A vulnerability-prioritization tool ("Fulcrum"). It merges NVD (CVSS) + EPSS + CISA KEV feeds, maps a company's asset graph to importance tiers, and produces one **composite risk score** per vulnerability so a "medium" CVE on a critical, actively-exploited asset can outrank a "critical" CVE on the edge. On top of the scores, a **capacity-aware optimizer** packs fixes into the team's real work-time to maximise risk removed.

Issue tracking = GitHub Issues via `gh` CLI (see `docs/agents/issue-tracker.md`). Sprints/epics live as issues.

## What got DONE this session — Epic #5 "Capacity-Aware Optimizer" (fully complete, merged, closed)
All six stories implemented test-first, reviewed via `code-review`, committed, merged to `main`, pushed, and **closed** (incl. the epic #5 issue). Do not redo.

- **#31** capacity-pool structure — `capacity.py` (`CapacityPool`, `default_pools`, stand-in `assign_remediation_effort`)
- **#32** greedy optimizer — `optimizer.greedy_optimize`
- **#33** naive severity-first baseline — `optimizer.severity_baseline`
- **#34** headline improvement metric — `optimizer.improvement_metric`
- **#35** (stretch) ILP optimum via PuLP — `optimizer_ilp.py` (import-guarded; tests skip when `pulp` absent)
- **#36** mid-sprint checkpoint — **GO** decision + numbers documented on the issue (`gh issue view 36 --comments`)

Commits (don't re-summarize the diff — read it): `a91b76c` (epic #5 impl), `8be8681` (merge), plus `c373dff` (this handoff doc). Epic #4 (`01bb7ec`, `c17fc4e`) was already on `main`.

**Test status: 152 passed, 1 skipped** (`py -m pytest -q`). The 1 skip is the ILP path — `pulp` is not installed here and there's no network to install it, so `optimizer_ilp.py` was never run live (logic verified by inspection + import-guard/skip only). `pulp` added to `requirements.txt` as an optional dep.

### Key design decision (already baked in — don't relitigate)
Effort is **constant within each pool** (`capacity.DEFAULT_POOL_EFFORT`). This is deliberate: it makes the #34 invariant "optimizer total ≥ baseline total" **provably true** (within a pool, ratio-order = score-order, so greedy takes the top-k scoring fixes each pool can hold — a per-pool maximum the baseline can only tie). The data model still allows variable per-item effort; that heuristic gap is exactly what #35's ILP measures. Both code-review sub-agents independently confirmed the guarantee is real.

### Code-review fixes applied before commit
- Promoted cross-module private imports to public: `optimizer.validate_optimizer_input`, `optimizer.load_ready_frame` (were `_`-prefixed and imported by `optimizer_ilp.py`).
- Extracted `optimizer._order_by` helper (removed duplicated sort/tie-break block).
- Replaced a vacuous #31 distinctness test in `tests/test_capacity.py`.

## Checkpoint result (#36) — the headline
On `merged_vulnerabilities.csv` (8,296 CVEs), same capacity pools:
- Optimizer: **4,736.7** risk reduced (56 fixes) · Baseline: **2,844.0** (56 fixes) · **+66.5%**, all pools fully consumed.
- Direction is structural; **magnitude will shift** once real mappings replace the stand-ins (below).

## Environment notes / gotchas
- **Python:** use `py` (`python`/`python3` not on PATH). Tests from repo root: `py -m pytest -q`. Pytest-only, no typechecker. (Saved to project memory — see below.)
- **Data pipeline needs an NVD API key + network** — absent here, so `combine_feeds_with_custom_inputs.py` is never run live; the committed `merged_vulnerabilities.csv` (8,296 CVEs) is used for all demos.
- **Stand-in joins (not ground truth):** two per-CVE joins are deterministic placeholders — real mappings are separate, not-yet-built tickets. Flag in any real output.
  - `importance_tier` — scoring expects it joined per CVE; CVE→asset mapping doesn't exist yet.
  - `pool` + `effort` — `capacity.assign_remediation_effort` hashes `cve_id` → pool.
  - (Both captured in project memory — see below.)

## Artifacts built this session (scratchpad only — NOT in the repo, private Claude artifacts)
Visual mirrors of the Python logic, not the real app:
- **System dossier** (architecture + build-state overview): https://claude.ai/code/artifact/d83e5c5f-047a-4bcf-8117-14555e07068c
- **Interactive dashboard mockup** (attack map + live weight sliders + capacity sliders + optimizer plan + KEV-alert demo + row-click override): https://claude.ai/code/artifact/e505193c-35e3-453d-a060-5fce26fc979a — this is effectively a **clickable spec for the sprint-3 Streamlit epic**. Runs on a 16-CVE synthetic sample with scaled-down capacities so scarcity is visible.

Scratchpad dir: `%LOCALAPPDATA%\Temp\claude\C--Users-rocketboy-Desktop-Projects-CyberSecurityCapstone\...\scratchpad` (session-specific; source HTML lives there as `fulcrum-status.html` / `fulcrum-dashboard.html` — may be gone next session; re-render from the artifact URLs via WebFetch if needed).

## Next work — Sprint-3 dashboard epic (#37–#40): build the Streamlit app for real
The logical next `/implement` target. Fetch acceptance criteria fresh: `gh issue view <n> --json title,body`. Rough shape (confirm against tickets):
- **#37** Streamlit skeleton / app entry point
- **#38** capacity + weighting sliders wired to the real `scoring` / `optimizer` modules
- **#39** findings table + naive-vs-optimized view
- **#40** KEV-alert demo trigger

The dashboard artifact above shows the intended UX; the real build should call the existing Python (`scoring.score_dataframe`, `optimizer.greedy_optimize` / `severity_baseline` / `improvement_metric`, `capacity.default_pools`) rather than reimplementing logic. Note there is **no confirmed epic number** for this dashboard work — verify via `gh issue list`.

## Open decisions for the user (ask, don't assume)
1. Whether to build the **Streamlit app for real** (#37–#40) now, or first close the **stand-in gap** (build the real CVE→asset and CVE→pool/effort mapping tickets) so the dashboard shows meaningful asset/plan data.
2. Whether the dashboard mockup HTML should be **committed into the repo** (e.g. `docs/`) as the reference design for #37–#40, or left as a scratchpad artifact.

## Suggested skills for the next session
- **`implement`** — to build the sprint-3 dashboard stories (drives TDD + single-file test runs + full-suite + `code-review` + commit).
- **`run`** — to actually launch the Streamlit app once #37 stands it up (verify it renders, screenshot).
- **`tdd`** — for any new pure-logic seams (e.g. a real CVE→asset/pool mapping module).
- **`code-review`** — after implementing, against `main` as the fixed point.
- **`domain-modeling`** — if the CVE→asset / remediation-mapping terminology needs pinning down before coding.

## Memory
Project memory dir (`~/.claude/projects/.../memory/`) now holds:
- `python-launcher.md` — use `py`, tests via `py -m pytest -q`.
- `stand-in-joins.md` — `importance_tier` and `pool`/`effort` are placeholders, not real data.
Index in `MEMORY.md`. Add to these if new durable facts emerge.
