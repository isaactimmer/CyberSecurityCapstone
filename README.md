# CyberSecurityCapstone

Scryxen — a capacity-aware vulnerability remediation console. It scores every
vulnerability on your attack surface against a local NVD · EPSS · CISA KEV
corpus, then packs the fixes that remove the most risk per hour of your team's
time. Runs fully offline once the corpus is in place.

## Run from source (e.g. on another computer)

Requires Python 3.11+ and git. In a terminal (the VS Code terminal is fine):

```bash
# 1. Clone
git clone https://github.com/isaactimmer/CyberSecurityCapstone.git
cd CyberSecurityCapstone

# 2. Create a virtual env and install dependencies
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt   # Windows
# (macOS/Linux: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)

# 3. Fetch the offline NVD corpus (~481MB, not stored in git — see below)
.venv\Scripts\python.exe fetch_corpus.py

# 4. Run the console
.venv\Scripts\python.exe -m uvicorn server:app --port 8000
```

Then open <http://localhost:8000>.

### The corpus (`data/nvd_corpus.db`)

Scans read a local, pre-merged NVD+EPSS+KEV corpus. It's ~481MB — too large for
git — so it ships as a **GitHub Release asset** (release
[`corpus-v1`](https://github.com/isaactimmer/CyberSecurityCapstone/releases/tag/corpus-v1)).
`fetch_corpus.py` downloads and unpacks it into `data/nvd_corpus.db` for you
(stdlib only, no extra tools). It skips the download if the file is already
there; pass `--force` to re-download.

If you'd rather not run the script, download `Scryxen-corpus.zip` from the
release page and unzip `nvd_corpus.db` into a `data/` folder at the repo root.

To (re)build a fresh corpus yourself instead: `py nvd_ingest.py --refresh`.

## Run the tests

```bash
.venv\Scripts\python.exe -m pytest -q
```

## Packaged desktop app

To build the double-click Windows app (`dist/Scryxen/Scryxen.exe`) instead of
running from source, see [`PACKAGING.md`](PACKAGING.md).
