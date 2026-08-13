# Handoff — Database + run-history (DB layer shipped ✓; History tab UI next)

**Date:** 2026-08-13
**Repo:** `C:\Users\rocketboy\Desktop\Projects\CyberSecurityCapstone` · GitHub `isaactimmer/CyberSecurityCapstone`
**Branch:** `main` (tracks `origin/main`) — this session's work committed and pushed.
**Status:** The tool was fully in-memory/ephemeral (uploads lived in one global
`_state`, nothing persisted, no way to look back at a past asset map / plan). This
session added a **SQLite persistence layer + run-history API**. Per the agreed
sequencing (**DB layer first, then UI**), the back end is done and tested; the
**History tab in `web/` is the next phase and is not yet built.**

## What we did this session

### The ask (`Inquiry Regarding Project and Tool.md`)
"We need a place to store our inputs/data — a database — and a history tab so a
user can look back at previous asset maps / plans." Decisions taken with the user:
- **History entry = inputs + result snapshot** (reproducible *and* auditable).
- **Single-user for now**; per-user history deferred to the recommendations doc.
- **DB layer first, then the UI.**

### Persistence layer — `store.py` (new)
A thin `Store` class over a single SQLite file (`data/scryxen.db`, stdlib
`sqlite3`, **no new dependencies**). One table, `runs`, one row per saved entry:

| Column | Kind | Holds |
|---|---|---|
| `id`, `created_at`, `name`, `source`, `finding_count` | metadata | index/list fields |
| `asset_csv` (BLOB) | **input** | the raw uploaded `assets.csv` bytes (NULL for the sample env) |
| `controls_json` | **input** | weights / capacity / filters in force at save time |
| `env_payload_json` | **snapshot** | environment (asset map, year bounds, presets) |
| `plan_payload_json` | **snapshot** | the computed board, frozen |
| `overrides_json` | **snapshot** | the override audit log at save time |

API: `save_run(...) -> id`, `list_runs()` (newest-first `RunSummary` rows, no heavy
payloads), `get_run(id)` (full inputs + snapshot, or `None`), `delete_run(id)`.
Pass `db_path=":memory:"` for a disk-free store (tests use this). The `_SCHEMA` runs
`CREATE TABLE IF NOT EXISTS` on every construction, so the DB **self-creates on
first use** on any machine.

### API endpoints — `server.py`
- `ConsoleState` now retains the raw uploaded CSV (`asset_csv`) as the *input of
  record*; the upload endpoint stores it.
- Lazy `run_store()` accessor mirrors the existing `state()` pattern (tests set
  `server._store` to an in-memory store).
- `_plan_payload(controls, st)` factored out so `/api/plan` and the save endpoint
  freeze the identical board shape.

| Endpoint | Does |
|---|---|
| `POST /api/runs` | Save current env + controls as a history entry (auto-names if blank); returns the summary |
| `GET /api/runs` | History index, newest-first |
| `GET /api/runs/{id}` | One run's frozen snapshot — **pure read**, doesn't disturb live state |
| `POST /api/runs/{id}/open` | **Reopen** — rebuilds live `_state` (re-scans the saved CSV or the sample, replays overrides) so controls work again, returns the snapshot to repaint |
| `DELETE /api/runs/{id}` | Remove an entry |

Key verified property: a saved snapshot **stays frozen** even if controls change
later or the engine changes — that's the auditability the user asked for.

### Design decisions locked in
- **DB is per-machine and git-ignored** (`data/scryxen.db` added to `.gitignore`).
  The **schema is code** (`store.py`), so a fresh clone rebuilds an empty DB
  automatically — the `.db` file never needs to travel. Committing a binary DB to
  git is the anti-pattern we're avoiding. History accumulates locally per install.
- **Raw CSV bytes** (not the parsed table) are the stored input — they re-validate
  cleanly on reopen.
- **Reopen restores live state**, so a past run is interactive again, not a dead
  screenshot.

### Recommendations doc — two deferrals added
`Recommendations for the Capacity Optimization Tool .md` now carries:
- **Per-user history** — tag each run with who saved it; needs a `user` column
  (schema left room) + lightweight identity.
- **History export / import** — a portable "download my history" / "restore from
  file" pair, so per-machine history can move without committing a DB or standing
  up a hosted database. (This is the answer to "how do I move it between
  computers": you don't ship the file — you'd export/import.)

## State
- **280 tests passing** (`py -m pytest -q`) — **+17 this session**: `tests/test_store.py`
  (7, round-trip save/list/get/delete + file-durability) and history endpoints in
  `tests/test_server.py` (10). All offline (in-memory store + injected env).
- No front-end work this session. The **History tab UI is the next phase.**

## If more work comes — next up: the History tab (`web/`)
The back end is ready to render against. A History tab would:
1. `GET /api/runs` → list saved runs (name, source, date, finding_count) with
   delete buttons.
2. A **Save** action on the console → `POST /api/runs` with the current controls
   (+ an optional name prompt).
3. Click a run → `POST /api/runs/{id}/open`, then repaint the console from the
   returned `env_payload` + `plan_payload` and restore the control values from
   `controls`.
Keep `web/app.js` a **pure renderer** (per `CLAUDE.md`) — it paints what the API
returns; no scoring in the browser.

Carry-forward polish (none blocking, from prior sessions):
- **Playwright smoke test** — still the one real automated-test gap (front end is
  manually verified).
- **Reweight latency** — ~180 ms debounced `/api/plan` on ~4,500 rows.
- **CSV-upload follow-ups** — sample template, client size guard, surface
  silently-dropped vendors.

## Run it
```
.\.venv\Scripts\python.exe -m uvicorn server:app --port 8000    # http://localhost:8000
.\.venv\Scripts\python.exe -m pytest -q                         # 280 passed
```
`py` launcher works too (`py -m pytest -q`). App runs offline off `data/cache/`.
The run-history DB self-creates at `data/scryxen.db` on first save (git-ignored).
**Stale-server trap:** if the UI looks dead or serves old behaviour, a leftover
uvicorn holds port 8000 with old code — kill the PID
(`Get-NetTCPConnection -LocalPort 8000 -State Listen` → `Stop-Process`), relaunch,
hard-refresh (Ctrl+Shift+R). Python changes need a server restart (no `--reload`);
static `web/` changes just need a hard refresh.

## Reference (don't duplicate here)
- Inquiry: `Inquiry Regarding Project and Tool.md` (this session's driver).
- Recs doc: `Recommendations for the Capacity Optimization Tool .md` (repo root) —
  now includes per-user history + export/import deferrals.
- Persistence: `store.py` (schema + API), `server.py` (`/api/runs*` endpoints).
- ADR: `docs/adr/0002-web-console-over-fastapi.md` (FastAPI, not Streamlit).
- Run rule: `CLAUDE.md` — `web/app.js` is a **pure renderer**; all scoring/packing
  lives in the Python engine.
- Memory: `tool-rename-scryxen.md`, `data-feeds-live.md`, `stand-in-joins.md`.
  Index: `~/.claude/projects/.../memory/MEMORY.md`.
- Front-end seams: `web/index.html`, `web/app.js`, `web/styles.css`.
