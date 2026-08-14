# How to run Scryxen on another computer

A step-by-step guide to get the console running from a fresh clone. If you can
open a terminal and type a few commands, you can do this. The whole thing runs
**offline** once the corpus is downloaded.

---

## What you need first

- **Python 3.11 or newer** — check with `py --version`. If it's missing, install
  it from <https://www.python.org/downloads/> and tick *"Add Python to PATH"*
  during setup.
- **Git** — check with `git --version`. If missing, get it from
  <https://git-scm.com/downloads>.
- **~1 GB of free disk space** (the vulnerability corpus is ~481 MB).
- An internet connection **for setup only** — cloning and downloading the
  corpus. After that, the app runs without internet.

> All commands below are for **Windows** in the VS Code terminal (PowerShell).
> On macOS/Linux, swap `.venv\Scripts\python.exe` for `.venv/bin/python` and
> `py` for `python3`.

---

## Step 1 — Get the code

Clone the repo, then move into its folder:

```powershell
git clone https://github.com/isaactimmer/CyberSecurityCapstone.git
cd CyberSecurityCapstone
```

If you already cloned it before, just update instead:

```powershell
git pull
```

---

## Step 2 — Set up the environment (once)

Create an isolated Python environment and install the app's dependencies:

```powershell
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

This takes a minute or two the first time. You only do it once per computer.

---

## Step 3 — Download the vulnerability corpus (once)

The corpus (`data/nvd_corpus.db`) is the offline dataset every scan reads. It's
too big for git, so it lives as a GitHub Release download. Fetch it with:

```powershell
.venv\Scripts\python.exe fetch_corpus.py
```

It downloads ~142 MB and unpacks it into `data\nvd_corpus.db` automatically.
It skips the download if the file is already there (add `--force` to re-download).

**Manual fallback** if the script can't reach GitHub: download
`Scryxen-corpus.zip` from the
[corpus-v1 release](https://github.com/isaactimmer/CyberSecurityCapstone/releases/tag/corpus-v1),
then unzip `nvd_corpus.db` into a `data` folder at the project root so the path
is `data\nvd_corpus.db`.

---

## Step 4 — Run the console

```powershell
.venv\Scripts\python.exe -m uvicorn server:app --port 8000
```

Leave that terminal open (it's the running server), then open your browser to:

**<http://localhost:8000>**

You should see the Scryxen console with its planner-compass logo. Press
**Build my plan** to run a scan against the sample environment.

To stop the server, click the terminal and press `Ctrl + C`.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **"No local vulnerability corpus found"** in the app | Step 3 didn't complete. Re-run `.venv\Scripts\python.exe fetch_corpus.py` and confirm `data\nvd_corpus.db` exists (~481 MB). |
| `py` **is not recognized** | Python isn't installed or not on PATH. Reinstall from python.org with *"Add Python to PATH"* checked, then reopen the terminal. |
| `git` **is not recognized** | Install Git from git-scm.com, then reopen the terminal. |
| **Port 8000 already in use** | Run it on another port, e.g. `--port 8001`, and browse to `http://localhost:8001`. |
| **`ModuleNotFoundError`** when starting | Step 2 was skipped or used the wrong Python. Re-run the `pip install -r requirements.txt` command using `.venv\Scripts\python.exe`. |

---

## The two ways to run — which is which?

- **From source (this guide)** — clone + `uvicorn`. Best for development or any
  machine with Python. Reads the corpus from the repo's `data\` folder.
- **Packaged desktop app** — the double-click `Scryxen.exe`. No Python needed,
  but it's a large download and installed differently. See
  [`PACKAGING.md`](PACKAGING.md) to build it and for how it stores its corpus
  under `%LOCALAPPDATA%\Scryxen`.

You do **not** need both. For running on another computer with a terminal, the
from-source path above is the simplest.
