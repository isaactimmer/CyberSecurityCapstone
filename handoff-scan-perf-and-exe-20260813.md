# Handoff — scan-perf fix + corpus-in-exe (2026-08-13)

**Repo:** `isaactimmer/CyberSecurityCapstone` (branch `main`) · git user `hotoloude686`
**This session followed** the Phase 5 handoff (`handoff-full-corpus-ingest-phase5-20260813.md`).

---

## What landed this session (read the commits, not a re-summary)

All on `main`, pushed:

| Commit | One-liner |
|--------|-----------|
| (Phase 5, closed epic #56 — see below) | retire `__200` cache CSVs + `enrich_cache.py` + `DEFAULT_CACHE_DIR`; ADR-0003 → Accepted |
| `bd9d94a` | **Scan-perf fix**: index the CPE match + FTS5 description fallback + one shared `CorpusStore` per scan |
| `6e86e4c` | **Corpus-in-exe**: bundle `data/nvd_corpus.db` + seed it into `data_dir()` on first launch |

### 1. Phase 5 (#62) + epic #56 — DONE and closed
- Deleted ~89 tracked + untracked `data/cache/*__200.csv`, stray root `assets2_1.csv`/`assets4.csv`,
  the obsolete `enrich_cache.py`, and `DEFAULT_CACHE_DIR`. ADR-0003 marked Accepted (Epic #56).
- Tests were already complete from Phases 1–3 — no new ones needed. #62 + epic #56 **closed**.
- Memory `[[full-corpus-ingest]]` updated to "epic complete".

### 2. Scan-perf fix (`bd9d94a`)
- **Symptom the user hit:** uploading their own asset CSV "never loaded". Root cause: `query_vendor`
  ran two full-table scans over the 376k-row corpus **per vendor, per asset** (~2s each):
  `REPLACE(vendor,'_',' ')` defeated `idx_cpe_vendor`, and the description fallback was a
  `LOWER(...) LIKE '%kw%'` scan. 22-asset CSV = 47s.
- **Fix** (`corpus_store.py`): fold the *keyword* to underscore form and compare the raw indexed
  column; replace the LIKE with an **external-content FTS5 index** (`cve_fts`) kept in sync by
  triggers; `PRAGMA recursive_triggers = ON` so `INSERT OR REPLACE` fires the delete trigger;
  a flag-gated (`ingest_meta.fts_backfilled`) one-time backfill for a pre-existing corpus.
- Also `cve_asset_map.build_environment_vulnerabilities` now reuses **one** connection for the whole scan.
- **Result:** upload 47s → **0.33s**; sample scan ~0.7s; suite **317 passed**. Finding counts barely
  move (sample 4749 → **4731** — FTS is word-granular vs old substring; the intended precision trade).
- The **local corpus was backfilled** in place: `data/nvd_corpus.db` is now ~481MB (was 395MB — the
  +86MB is the FTS index) with `fts_backfilled=1` set.

### 3. Corpus-in-exe (`6e86e4c`)
- **Discovery:** the packaged app had been broken since epic #56 — the scan reads
  `data_dir()/nvd_corpus.db` (packaged = `%LOCALAPPDATA%\Scryxen`), nothing ever put a corpus there,
  and there is no in-app ingest. A rebuild alone would ship a non-scanning exe.
- **Chosen approach (user picked "Bundle + seed on first run"):** `scryxen.spec` bundles the corpus
  read-only under `data/`; `launcher._seed_corpus()` copies it to `data_dir()` once, before the server
  opens it (no-op from source). `PACKAGING.md` updated; retired `data/cache` bundling dropped.
- **Verified against a rebuilt exe from an empty `%LOCALAPPDATA%\Scryxen`:** seeds 481MB in ~1s,
  sample scan 4731 findings, `assets3.csv` upload **0.55s** in the packaged app.
- `dist/Scryxen/` is rebuilt on disk (git-ignored build artifact). Zip that folder to distribute.

---

## Live state / servers
- A dev server was left **running on port 8000** (fresh code, `./.venv/Scripts/python.exe -m uvicorn
  server:app --port 8000`). Started in this session's shell; may or may not still be up next session.
  Restart on a clean port if unsure (`run` skill). The old pre-fix 8000 instance was killed.
- Browser tab was pointed at `http://127.0.0.1:8000/`. The Chrome screenshot tool was glitching
  at end of session (extension quirk, not the app) — the server itself was healthy via `curl`.

## Open loose end (needs a decision)
- **`assets.csv` has an uncommitted change**: a **GitLab Server** asset (vendor `gitlab`, High, wired
  into `ci-cd`) added earlier as a live test of "add a new asset". It was deliberately kept out of both
  fix commits. Options: commit it (strong demo — KEV RCE CVE-2021-22205 @ CVSS 10.0), revert
  (`git checkout assets.csv`), or leave as-is. **Confirm with the user before acting.**

## Possible next-session work (none committed to yet)
- Resolve the `assets.csv` GitLab-asset decision above.
- The seeded corpus bundle makes `dist/Scryxen/` ~500MB. If distribution size matters, revisit the
  "first-run ingest in-app" option (needs a GUI ingest trigger) — was offered and not chosen.
- `nvd_ingest.py --refresh`/`--update` still has no GUI surface; the packaged app can't refresh its
  corpus without a rebuild. Consider exposing refresh if the demo needs fresh data.
- `PACKAGING.md` "Rebuilding after code changes" note is now slightly incomplete — a corpus refresh
  before packaging (`python nvd_ingest.py --refresh`) is a real pre-build step worth calling out.

## Workflow conventions (unchanged)
- Python launcher **`py`**; tests `py -m pytest -q` ([[python-launcher]]).
- `main` is the working branch; commit only when asked. Commit trailer
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Issues via `gh` on `isaactimmer/CyberSecurityCapstone`.
- Rebuild exe: `./.venv/Scripts/python.exe -m PyInstaller scryxen.spec --noconfirm` (needs
  `requirements-desktop.txt`; corpus must exist at `data/nvd_corpus.db` to be bundled).

## Suggested skills for next session
- **`run`** — drive `uvicorn server:app` on a clean port (or the rebuilt `dist/Scryxen/Scryxen.exe`)
  to reconfirm scans after any change.
- **`code-review`** — review the `bd9d94a`/`6e86e4c` diff if a second pass is wanted before more work
  (FTS trigger correctness, seed-on-first-run edge cases).
- **`tdd`** — if exposing a GUI refresh/ingest path, that's naturally test-first.

## Live-memory pointers (auto-loaded next session)
`[[full-corpus-ingest]]` (now "epic complete") · `[[nvd-429-fix]]` · `[[data-feeds-live]]`
(both background, not the scan path) · `[[python-launcher]]` · `[[run-history-db]]`.
