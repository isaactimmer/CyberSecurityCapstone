# Packaging Scryxen as a desktop app

Turns the FastAPI + `web/` console you already have into a double-click
Windows app: a background local server plus a native app window, no browser
tab, no manual `uvicorn` command.

## What changed in the source

Three small, backward-compatible edits — all no-ops when running from source
the normal way (`uvicorn server:app`, `python pipeline.py`, the test suite):

- **`runtime_paths.py`** (new) — resolves two kinds of paths correctly both
  from source and from a packaged `.exe`: `resource_dir()` for bundled
  read-only files (`web/`, `data/cache/`, `assets.csv`), `data_dir()` for a
  writable per-user folder that survives across launches.
- **`store.py`** — `DEFAULT_DB_PATH` now comes from `runtime_paths.data_dir()`
  instead of `Path(__file__).parent / "data"`. From source this resolves to
  the same `data/scryxen.db` as before. Packaged, it resolves to a per-user
  app-data folder (`%LOCALAPPDATA%\Scryxen\scryxen.db` on Windows) — kept
  outside the bundle so run history isn't lost every launch or blocked by a
  read-only install location.
- **`server.py`** — `WEB_DIR` now comes from `runtime_paths.resource_dir()`
  instead of `Path(__file__).parent`. Same resolution, same behavior from
  source; correct inside a PyInstaller bundle too.

New files, none of which touch the existing app: **`launcher.py`** (the
packaged entry point — starts uvicorn on a background thread, opens a
`pywebview` window at it), **`scryxen.spec`** (the PyInstaller build recipe),
**`requirements-desktop.txt`** (`pywebview` + `pyinstaller`, build-only).

## Why "onedir," not a single-file exe

PyInstaller's single-file (`--onefile`) mode re-extracts the whole bundle to
a temp folder *every time the app launches*, and deletes it on exit. Since
`combine_feeds_with_custom_inputs.py` writes newly-pulled CVE data into
`data/cache` relative to cwd, anything fetched fresh during a session would
be silently lost the next launch. The `.spec` here builds "onedir" instead —
a folder (`dist/Scryxen/`) containing `Scryxen.exe` plus its files — so both
the bundled cache and anything the app writes during use persist normally.
Startup is also noticeably faster with onedir (no re-extraction step).

If you'd rather have a single file and don't care about persisting new
pulls between sessions, add `--onefile` and drop the `COLLECT(...)` block in
`scryxen.spec` in favor of building `exe` directly — happy to do that
version too if you want it.

## Build steps

From the repo root, with your existing venv activated:

```
.\.venv\Scripts\pip.exe install -r requirements-desktop.txt
.\.venv\Scripts\pyinstaller.exe scryxen.spec
```

Output: `dist\Scryxen\Scryxen.exe`. Double-click it, or run it from a shell
to see console output if something's wrong (temporarily set `console=True`
in `scryxen.spec` and rebuild if you need visible tracebacks).

To hand it to someone else: zip the whole `dist\Scryxen` folder. They unzip
and run `Scryxen.exe` — no Python install required on their machine.
pywebview's default Windows backend uses the WebView2 runtime, which ships
with Windows 10/11 already, so nothing extra to install there either.

## Data & offline behavior

- The cache under `data/cache/` (NVD/EPSS/KEV pulls) is bundled in, so the
  packaged app scores the sample environment fully offline on first launch —
  same as it does from source today.
- If you later add a "refresh data" path that calls out to NVD, an
  `NVD_API_KEY` still needs to reach the process the same way it does now
  (`.env`, loaded via `python-dotenv`) — the spec bundles `.env` in if one
  exists at build time. Don't commit a real key to source control; keep using
  `.env` (gitignored) and only add it to `datas` in `scryxen.spec` when
  you're building for yourself, not when sharing the build.
- Run history (the History tab / `scryxen.db`) now lives outside the app
  bundle at `%LOCALAPPDATA%\Scryxen\scryxen.db`, so it survives reinstalls
  and app updates. Delete that file (or the whole `Scryxen` folder under
  `%LOCALAPPDATA%`) to reset history.

## Rebuilding after code changes

Just re-run `pyinstaller scryxen.spec` — it always bundles the current
source tree. No spec changes needed unless you add a new *runtime*
dependency (edit `requirements.txt`, reinstall, rebuild) or a new bundled
resource folder (add it to `datas` in `scryxen.spec`).
