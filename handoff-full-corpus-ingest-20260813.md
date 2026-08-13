# Handoff — Full-corpus NVD ingest (epic #56)

**Date:** 2026-08-13 · **Repo:** `isaactimmer/CyberSecurityCapstone` (branch `main`)
**Next session focus:** Phase 3 (#60) — flip the app over to read from the local corpus.

---

## What this epic is

Scans used to pull CVEs per vendor from the NVD 2.0 API, capped at
`max_results=200` (the `__200` in `data/cache/<vendor>__200.csv` *is* the cap).
That cap is an arbitrary, often-wrong slice — real KEV/high-EPSS criticals can
fall outside it. We are replacing it with a one-time **full local NVD corpus**
matched on **CPE vendor/product**, so a scan filters + scores the complete
dataset offline.

Full rationale, decision, and schema: **`docs/adr/0003-full-corpus-nvd-ingest.md`**.
Epic + phase breakdown + native `blocked_by` gating: **GitHub issue #56**
(children #57–#62).

**The invariant that keeps this contained:** the
`fetch_merged(vendor) -> DataFrame` contract is preserved exactly; only its guts
change. Every caller above the ingest layer (`live_environment`,
`build_environment_vulnerabilities`, `dashboard`) stays untouched.

---

## Done this session (committed to `main`)

| Phase | Issue | Commit | What landed |
|-------|-------|--------|-------------|
| ADR   | —     | `db895d9` | ADR-0003 recording the decision |
| 0     | #57 ✅ | `698efea` | `corpus_store.py` — SQLite corpus wrapper + 14 tests |
| 1 & 2 | #58 ✅ #59 ✅ | `3fdbe47` | `nvd_ingest.py` — NVD year-file ingest + EPSS/KEV overlays + 13 tests |

Read the commit messages (`git show <hash> --stat`) and the two modules for
detail — not duplicated here. Key facts a fresh agent needs:

- **`corpus_store.py`** — `data/nvd_corpus.db` (git-ignored). Writes:
  `upsert_cves`, `upsert_cpe`, `update_epss`, `update_kev`, `set_meta`
  (overlays are column-only UPDATEs so NVD→EPSS→KEV compose without clobber).
  Reads: `query_vendor(keyword, limit=None)` returns the **exact `fetch_merged`
  column set** (`CVE_COLUMNS`), ordered worst-first (KEV > EPSS > CVSS), plus
  `is_loaded` / `count` / `last_refresh`.
- **`nvd_ingest.py`** — pure `parse_cve` / `parse_cpe_criteria` / `parse_epss_csv`
  / `parse_kev_json` (all network-free, unit-tested), plus downloaders and
  `run_ingest(store, years=None, do_nvd/do_epss/do_kev)`. Downloaded feed files
  cache under `data/nvd_feeds/` (git-ignored) → re-runs are resumable. CLI:
  `py nvd_ingest.py [--years ...] [--no-nvd/--no-epss/--no-kev] [--no-reuse]`.

**Verification:** full suite **307 passed**. Live end-to-end smoke (year 1999):
1579 CVEs + 358k EPSS scores + 1665 KEV, and a `bsdi` query returned merged
CVSS+EPSS rows. Formats confirmed empirically:
- fkie-cad year file = `{timestamp, cve_count, feed_name, source, cve_items:[<bare NVD 2.0 cve obj>]}`.
- CPE parse: `cpe:2.3:<part>:<vendor>:<product>:...` → `parts[3]`, `parts[4]`.
- EPSS `epss_scores-current.csv.gz` = `#…score_date:…` comment line, then `cve,epss,percentile`.

---

## IMPORTANT: corpus not yet populated on this machine

The tests use `:memory:`. **`data/nvd_corpus.db` does not exist locally yet.**
Before Phase 3 manual verification, run a real ingest (few minutes, ~hundreds of MB):

```
py nvd_ingest.py
```

(Optional: set `NVD_API_KEY` in `.env` — not needed for fkie-cad, only the
legacy live path. See memory `[[nvd-429-fix]]`.)

---

## Next session — Phase 3 (#60), now unblocked

Goal: swap `fetch_merged`'s guts to `corpus_store.query_vendor`; **return schema
must stay byte-identical.** Acceptance + specifics are in **issue #60**. Concrete
edits in `combine_feeds_with_custom_inputs.py`:

- `fetch_merged(vendor, max_results=None, ...)` → build a `CorpusStore`, return
  `pd.DataFrame(store.query_vendor(vendor, limit=max_results), columns=CVE_COLUMNS)`.
  `max_results` becomes optional (`None` = all); callers passing `200` still work.
- `cache_exists` → "is the corpus loaded" (drives `LiveScan.source` badge in
  `dashboard.py:715–755`; reword live/cached → corpus/stale).
- Delete `_cache_path` + the `__200` CSV write/read path.
- `dashboard.py:37` `DEFAULT_MAX_RESULTS = 200` → `None`.
- Watch: existing `tests/test_ingest.py` monkeypatches `fetch_nvd_cves/…` — those
  break and are formally reworked in **Phase 5 (#62)**, but keep an eye on them.

Then **#61** (refresh `--refresh`/`--update` flags + server empty-corpus guard)
and **#62** (rework `test_ingest.py`, delete the ~90 `data/cache/*__200.csv`,
mark ADR accepted, refresh memory). Dependencies already wired so they gate.

---

## Workflow conventions (this repo)

- Python launcher is **`py`**; tests `py -m pytest -q` (memory `[[python-launcher]]`).
- Issues via `gh` CLI; on close, comment then `gh issue close`, then tick the
  epic #56 checkbox (`gh issue view 56 --json body --jq .body` → edit → `--body-file -`).
- Claim before building: `gh issue edit <n> --add-assignee @me`.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
  Commit only when asked; `main` is the working branch here.
- Auth note: `gh`/git user is `hotoloude686` (has write to `isaactimmer/…`).

## Suggested skills for the next session

- **`tdd`** — Phase 3 is a behavior-preserving swap; keep the contract green
  test-first (and Phase 5's test rework is inherently test-driven).
- **`code-review`** — run before wrapping Phase 3/4 to check the diff against
  ADR-0003's invariant (no caller above the ingest layer changed).
- **`run`** — after Phase 3, drive the real app (`uvicorn server:app --port 8000`)
  to confirm a live scan renders from the corpus, not just that tests pass.

## Live-memory pointers (already saved, auto-loaded next session)

`[[full-corpus-ingest]]` (this epic's status) · `[[nvd-429-fix]]` ·
`[[data-feeds-live]]` · `[[python-launcher]]` · `[[run-history-db]]`.
