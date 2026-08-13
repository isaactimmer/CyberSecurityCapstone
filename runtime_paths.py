"""
Resolves file locations correctly whether Scryxen is running from source or as
the PyInstaller-packaged desktop app (`launcher.py` / `scryxen.spec`).

Two kinds of paths:
    resource_dir()  bundled, read-only resources (web/, assets.csv) -- ship with
                     the app; also doubles as the process cwd for the packaged
                     app, since a module (asset_graph.DEFAULT_ASSET_CSV) resolves
                     its default path relative to cwd rather than __file__.
    data_dir()       a writable, per-user folder for things that must survive
                     across launches — right now just scryxen.db (run history).
                     Kept outside the bundle so it isn't lost on a onefile
                     build's per-run temp extraction, and isn't blocked by
                     read-only install locations (e.g. Program Files).

Both fall back to the repo root when running from source (`uvicorn
server:app`, `python pipeline.py`, the test suite, ...) — nothing changes for
normal development; only the frozen `.exe` takes the alternate paths.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def resource_dir() -> Path:
    """Where bundled, read-only resources live."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).parent


def data_dir() -> Path:
    """A writable, per-user folder that survives across launches. Created on
    first use. From source this is just the repo's own `data/` folder, same
    as today; packaged, it's a per-user app-data folder."""
    if getattr(sys, "frozen", False):
        if os.name == "nt":
            base = Path(os.environ.get("LOCALAPPDATA", Path.home()))
        else:
            base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        d = base / "Scryxen"
    else:
        d = Path(__file__).parent / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d
