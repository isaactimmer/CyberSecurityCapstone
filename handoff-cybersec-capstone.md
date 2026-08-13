# Handoff — NVD rate-limit fix + desktop packaging shipped ✓; History tab UI still next

**Date:** 2026-08-13
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch:** `main` (tracks `origin/main`) — this session's work committed + pushed (`3cbbeea`).
**Status:** Two things shipped this session — a **fix for the NVD 429 rate-limit
cascade** and a **double-click Windows desktop build** (`Scryxen.exe`). Both are
done, verified, committed, and pushed. The **History tab UI** (back end shipped last
session) is still the main unbuilt piece.

## What's done (no further action needed)

### 1. NVD 429 rate-limit fix — `combine_feeds_with_custom_inputs.py`
Uploading a CSV with many new vendors used to 429-cascade: `fetch_nvd_cves` had no
retry and only paused between pagination pages, so an environment scan fired a burst
that tripped NVD's limit (5 req/30s keyless, 50/30s with a key) and each rate-limited
vendor was silently `[skip]`-ped.
- All NVD requests now go through `_nvd_get()`: a **module-global throttle** (min
  interval between *every* NVD call — 6.0s keyless, 0.6s with a key) plus
  **429/503 retry with `Retry-After`-aware exponential backoff** (logs `[nvd] …
  backing off`). Turns a transient limit into a slower-but-complete pull.
- Removed the old per-page `time.sleep(0.6)` (the throttle owns spacing now).
- **`NVD_API_KEY` in `.env`** (gitignored, read via `get_api_key()`→`load_dotenv()`)
  switches to 0.6s spacing. Verified live: `assets3.csv` (22 fresh uncached vendors)
  pulled clean, 0 skips, ~1 vendor/sec.
- Memory note: `nvd-429-fix.md`.

### 2. Desktop packaging — `Scryxen.exe` (onedir PyInstaller build)
The FastAPI + `web/` console now runs as a native app: local uvicorn on a background
thread + a `pywebview` window, no browser tab, no manual `uvicorn` command. **Fully
backward-compatible — from source, everything (`uvicorn server:app`, tests) is
unchanged.**
- New files: `runtime_paths.py` (resolves `resource_dir()` bundled/read-only vs
  `data_dir()` writable per-user, source-vs-frozen), `launcher.py` (packaged entry
  point), `scryxen.spec` (build recipe), `requirements-desktop.txt` (`pywebview` +
  `pyinstaller`, build-only). Full writeup in `PACKAGING.md`.
- 3 tiny source edits, all no-ops from source: `store.py` (`DEFAULT_DB_PATH` →
  `data_dir()`, so packaged run history lives at `%LOCALAPPDATA%\Scryxen\scryxen.db`
  and survives reinstalls), `server.py` (`WEB_DIR` → `resource_dir()`).
- **onedir not onefile** — onefile re-extracts to temp each launch and would discard
  freshly-pulled CVE caches; onedir persists them and starts faster.
- **Current build (`dist\Scryxen\`)** bundles: the 429 fix, 89 vendor caches (incl.
  this session's new pulls), and — **by explicit choice** — the `.env` NVD key, so a
  packaged copy runs at fast spacing with zero setup. **Trade-offs accepted:** the
  key ships inside any zip you hand out, and all recipients share its one 50/30s
  budget. Key is free/revocable at nvd.nist.gov. `.env` stays **gitignored** — bundle
  it into a local build, never commit it.
- To share: zip the whole `dist\Scryxen` folder; recipient unzips + double-clicks,
  no Python/key needed.

### 3. (Prior session) Persistence layer — shipped
`store.py` (`Store` over one SQLite file, table `runs`, one row per saved entry:
inputs = raw `asset_csv` BLOB + `controls_json`; snapshot = env/plan/overrides JSON)
and the `/api/runs*` endpoints (`POST`/`GET`/`GET {id}`/`POST {id}/open`/`DELETE`).
Snapshots stay frozen for auditability; reopen rebuilds live `_state` so a past run
is interactive again. DB is per-machine, git-ignored, self-creating.

## What's NOT done — pick up here

### Main: the History tab UI (`web/`)
Back end is ready to render against. Keep `web/app.js` a **pure renderer** (per
`CLAUDE.md`) — it paints what the API returns, no scoring in the browser.
1. `GET /api/runs` → list saved runs (name, source, date, finding_count) + delete.
2. A **Save** action → `POST /api/runs` with current controls (+ optional name).
3. Click a run → `POST /api/runs/{id}/open`, repaint from returned `env_payload` +
   `plan_payload`, restore control values from `controls`.

### Productization follow-ups (raised this session)
- **Per-user in-app API key** — the scalable alternative to the bundled shared key:
  a Settings panel where each user pastes their own key, saved to
  `%LOCALAPPDATA%\Scryxen` (the `data_dir()` plumbing already exists) and read by
  `get_api_key()` (order: env/`.env` → saved setting). Sidesteps both the shared
  rate-limit and the key-in-zip leak. Small change when you outgrow the bundled key.
- **Per-user history** + **history export/import** — deferrals already in the recs
  doc; `runs` schema left room for a `user` column.

### Carry-forward polish (none blocking)
- **Playwright smoke test** — still the one real automated-test gap (front end is
  manually verified).
- **Reweight latency** — ~180 ms debounced `/api/plan` on ~4,500 rows.
- **CSV-upload follow-ups** — sample template, client size guard, and *surface
  silently-dropped vendors in the UI* (the 429 fix stops the cascade at the engine;
  the UI could still show which vendors a scan couldn't reach).

## Working on another machine
Committed + pushed in `3cbbeea` (source, packaging recipe, 89 vendor caches,
`assets2/assets3.csv`, this handoff). `dist/`/`build/` are now gitignored. After a
clone/pull:
```
py -m venv .venv
.\.venv\Scripts\pip.exe install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn server:app --port 8000
```
Two things don't travel via git and need recreating locally:
- **`.env` with `NVD_API_KEY`** (gitignored) — app runs fine without it (offline from
  `data/cache/`, live pulls fall back to safe 6s spacing); recreate it for fast pulls.
- **The `.exe`** — rebuild with `pip install -r requirements-desktop.txt` then
  `pyinstaller scryxen.spec`.

## Run it
```
.\.venv\Scripts\python.exe -m uvicorn server:app --port 8000    # http://localhost:8000  (dev)
.\.venv\Scripts\python.exe -m pytest -q                         # tests (py -m pytest -q works too)
dist\Scryxen\Scryxen.exe                                        # the packaged app
```
App runs offline off `data/cache/`. Run-history DB self-creates (git-ignored:
`data/scryxen.db` from source, `%LOCALAPPDATA%\Scryxen\scryxen.db` packaged).
**Stale-server trap:** if the dev UI looks dead / serves old behaviour, a leftover
uvicorn holds port 8000 — kill the PID (`Get-NetTCPConnection -LocalPort 8000 -State
Listen` → `Stop-Process`), relaunch, hard-refresh (Ctrl+Shift+R). Python changes need
a server restart (no `--reload`); static `web/` changes just need a hard refresh.
**Rebuild trap:** if `pyinstaller scryxen.spec` fails with `PermissionError [WinError
5]`, a running `Scryxen.exe` is locking `dist\` — close it (or `taskkill /PID <id> /F`)
and rebuild.

## Reference (don't duplicate here)
- Packaging: `PACKAGING.md` (build steps, onedir rationale, `.env`/key handling).
- 429 fix: `combine_feeds_with_custom_inputs.py` (`_nvd_get`), memory `nvd-429-fix.md`.
- Persistence: `store.py`, `server.py` (`/api/runs*`).
- ADR: `docs/adr/0002-web-console-over-fastapi.md` (FastAPI, not Streamlit).
- Run rule: `CLAUDE.md` — `web/app.js` is a **pure renderer**; scoring lives in Python.
- Memory index: `~/.claude/projects/.../memory/MEMORY.md`.
- Front-end seams: `web/index.html`, `web/app.js`, `web/styles.css`.
