"""
Scryxen desktop launcher — the packaged entry point (see scryxen.spec).

Not used for normal development — that's still
`uvicorn server:app --reload`. This is only what `Scryxen.exe` runs:

  1. anchor the process at the bundled resources (web/, data/cache/,
     assets.csv) so the modules that read them with relative paths
     (asset_graph, combine_feeds_with_custom_inputs) find them regardless of
     where the user launched the exe from
  2. start the existing FastAPI app (server.py, unchanged) on a background
     thread, on a free localhost port
  3. open a native app window (pywebview) pointed at it — no browser tab,
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
