C# Handoff — CyberSecurity Capstone (Fulcrum risk-prioritization)

**Date:** 2026-08-09
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch this session worked on:** `feat/27-scoring-formula` (pushed to origin, **not merged to `main`**)

## What this project is
A vulnerability-prioritization tool ("Fulcrum"). It merges NVD (CVSS) + EPSS + CISA KEV feeds, maps a company's asset graph to importance tiers, and produces one **composite risk score** per vulnerability so a "medium" CVE on a critical, actively-exploited asset can outrank a "critical" CVE on the edge. A later epic adds a capacity-aware remediation optimizer.

Issue tracking = GitHub Issues via `gh` CLI (see `docs/agents/issue-tracker.md`). Sprints/epics live as issues.

## What got DONE this session — Epic #4 "Composite Risk Scoring" (fully complete)
All four stories implemented, reviewed, committed, pushed, and **closed**. Do not redo them.

- **#27** composite formula — `scoring.py`
- **#28** adjustable weighting — `ScoringWeights` dataclass (rejects negative weights)
- **#29** security-lead override + audit log — `overrides.py`
- **#30** unit tests — `tests/test_scoring.py`, `tests/test_overrides.py`
- **Epic #4** closed (all children done).

Commits on the branch (see `git log main..feat/27-scoring-formula` for detail — don't re-summarize the diff):
- `01bb7ec` — #27
- `c17fc4e` — #28/#29/#30

Test status: **119 passing** (`py -m pytest -q`). No typechecker is configured (pytest-only repo).

Design/behaviour details are already captured — read those rather than re-deriving:
- Formula + weight tables: comment on issue **#27** (`gh issue view 27 --comments`).
- Code review findings + fixes: this was run via the `code-review` skill; the one real fix (negative-weight guard protecting #30's KEV invariant) is in `c17fc4e`.

## Environment notes / gotchas
- **Python:** use `py` (the `python`/`python3` aliases are not on PATH here). Run tests from repo root: `py -m pytest -q`.
- **Data pipeline needs an NVD API key** (`.env` with `NVD_API_KEY=...`) + network — NOT present in this environment, so `combine_feeds_with_custom_inputs.py` was never run live. A pre-generated `merged_vulnerabilities.csv` (8,296 CVEs) already exists in the repo and was used for all demos.
- **Missing link:** there is **no CVE→asset mapping** yet (it's a separate, not-yet-built ticket). `scoring.score_dataframe()` expects an `importance_tier` column already joined per CVE. All demos used a *deterministic stand-in* join (hash of `cve_id` → asset) purely so scoring could run end-to-end. Which asset a CVE truly lives on is not meaningful yet — flag this in any real output.

## Throwaway artifacts built this session (NOT in the repo — scratchpad only)
Interactive tool spanning epic #2 + #4, published as Claude artifacts (private):
- Static dashboard: https://claude.ai/code/artifact/d07bec6c-2126-4058-8209-2305c6d24775
- **Interactive app** (asset map + live weight sliders + overrides): https://claude.ai/code/artifact/94a6e9d0-541f-474d-9519-369237e478fc

These are visual mirrors of the Python logic, not the real app. The scratchpad dir for this project is under `%LOCALAPPDATA%\Temp\claude\C--Users-rocketboy-Desktop-Projects-CyberSecurityCapstone\...\scratchpad` (session-specific; may be gone next session — regenerate with `export_full.py` if needed).

## Open decisions for the user (ask, don't assume)
1. **Open a PR** `feat/27-scoring-formula` → `main`? Issues were closed but code is unmerged. GitHub PR link was offered on push.
2. Whether to build the **Streamlit app** for real (sprint-3 #37–#40) vs. keep the artifact demos.

## Next work — Epic #5 "Capacity-Aware Optimizer" (sprint-2, consumes the composite scores)
The logical next `/implement` target. Child stories (all `ready-for-agent` unless noted):
- **#31** Define capacity-pool data structure
- **#32** Build greedy optimizer
- **#33** Build naive severity-first baseline
- **#34** Compute headline improvement metric
- **#35** (Stretch) PuLP/ILP comparison
- **#36** Mid-sprint checkpoint: optimizer beats baseline
Fetch acceptance criteria fresh: `gh issue view <n> --json title,body`. Likely start order: #31 → #33 → #32 → #34.

Sprint-3 dashboard epic (#37–#40) comes after: Streamlit skeleton, capacity/weighting sliders, findings table + naive-vs-optimized view, KEV-alert demo trigger.

## Suggested skills for the next session
- **`implement`** — to build epic #5 stories (it drives TDD + single-file test runs + full-suite + `code-review` + commit; this session used it for epic #4).
- **`tdd`** — the optimizer (#32) and baseline (#33) are pure-logic seams ideal for test-first.
- **`code-review`** — run after implementing, against `main` as the fixed point.
- **`run`** — if/when standing up the Streamlit app (#37) to actually launch it.
- **`domain-modeling`** — if the "capacity pool" concept (#31) needs its terminology pinned down before coding.

## Memory
Project memory dir (`~/.claude/projects/.../memory/`) is currently **empty** — nothing persisted. Consider saving the "use `py` not `python`" and "CVE→asset mapping is missing / stand-in join" facts if they keep recurring.
