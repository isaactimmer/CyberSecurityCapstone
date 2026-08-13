"""
Scryxen desktop launcher — the packaged entry point (see scryxen.spec).

Not used for normal development — that's still
`uvicorn server:app --reload`. This is only what `Scryxen.exe` runs:

  1. anchor the process at the bundled resources (web/, assets.csv) so the
     modules that read them with relative paths (asset_graph) find them
     regardless of where the user launched the exe from
  2. seed the bundled NVD corpus into the writable per-user data dir on first
     launch, so the app has something to scan without an in-app ingest step
  3. start the existing FastAPI app (server.py, unchanged) on a background
     thread, on a free localhost port
  4. open a native app window (pywebview) pointed at it — no browser tab,
     no address bar

Closing the window shuts the server down and exits.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time

import runtime_paths

# Bundled resources are read relative to cwd in a couple of modules
# (asset_graph.DEFAULT_ASSET_CSV) rather than relative to __file__ — anchor cwd
# there before anything imports them.
os.chdir(runtime_paths.resource_dir())
sys.path.insert(0, str(runtime_paths.resource_dir()))

import uvicorn  # noqa: E402  (import after the chdir/sys.path setup, deliberately)
import webview  # noqa: E402

HOST = "127.0.0.1"


def _seed_corpus() -> None:
    """First-run: copy the bundled read-only NVD corpus into the writable per-user
    data dir, so the packaged app has a corpus to scan without an in-app ingest.
    The scan opens the corpus at data_dir()/nvd_corpus.db (writable, so the FTS
    backfill can run); the bundle ships it read-only under resource_dir()/data/.

    Idempotent, and a no-op from source: there data_dir() *is* the repo's data/
    folder, so dest already exists (and src resolves to the same file)."""
    import shutil

    dest = runtime_paths.data_dir() / "nvd_corpus.db"
    src = runtime_paths.resource_dir() / "data" / "nvd_corpus.db"
    if dest.exists() or not src.exists():
        return
    shutil.copy2(src, dest)  # ~480MB, a few seconds, once


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


def _wait_until_up(port: int, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Scryxen server did not start in time")


def main() -> None:
    _seed_corpus()  # ensure a corpus exists before server import opens it
    from server import app  # imported after path setup, deliberately late

    port = _free_port()
    config = uvicorn.Config(app, host=HOST, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    _wait_until_up(port)

    webview.create_window(
        "Scryxen — Remediation Console",
        f"http://{HOST}:{port}",
        width=1440, height=900, min_size=(1024, 700),
    )
    webview.start()  # blocks until the window is closed

    server.should_exit = True
    thread.join(timeout=5)


if __name__ == "__main__":
    main()
