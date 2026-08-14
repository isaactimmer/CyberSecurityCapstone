"""
Fetch the offline NVD corpus into data/nvd_corpus.db.

The corpus (~481MB) is too large for git, so it ships as a GitHub Release
asset (see release `corpus-v1`). Run this once after cloning to pull it down
so scans work offline from source:

    py fetch_corpus.py

It downloads the zipped corpus from the public release, extracts
data/nvd_corpus.db, and skips the download if that file is already present
(pass --force to re-download). Stdlib only — no gh CLI or extra deps needed.
"""
from __future__ import annotations

import argparse
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ASSET_URL = (
    "https://github.com/isaactimmer/CyberSecurityCapstone"
    "/releases/download/corpus-v1/Scryxen-corpus.zip"
)
DEST = Path(__file__).parent / "data" / "nvd_corpus.db"
MEMBER = "nvd_corpus.db"


def _download(url: str, dest: Path) -> None:
    """Stream the URL to dest, printing a simple percent progress line."""
    def hook(block: int, block_size: int, total: int) -> None:
        if total > 0:
            pct = min(100, block * block_size * 100 // total)
            print(f"\r  downloading… {pct}%", end="", flush=True)
    urllib.request.urlretrieve(url, dest, reporthook=hook)
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch the offline NVD corpus.")
    ap.add_argument("--force", action="store_true",
                    help="re-download even if data/nvd_corpus.db already exists")
    args = ap.parse_args()

    if DEST.exists() and not args.force:
        mb = DEST.stat().st_size / (1024 * 1024)
        print(f"Corpus already present: {DEST} ({mb:.0f} MB). Use --force to re-download.")
        return 0

    DEST.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / "Scryxen-corpus.zip"
        print(f"Fetching corpus from {ASSET_URL}")
        try:
            _download(ASSET_URL, zip_path)
        except Exception as exc:  # network, 404, etc.
            print(f"Download failed: {exc}", file=sys.stderr)
            print("Check your connection, or download the asset manually from the "
                  "repo's Releases page and unzip nvd_corpus.db into data/.",
                  file=sys.stderr)
            return 1
        print("Extracting nvd_corpus.db…")
        with zipfile.ZipFile(zip_path) as zf:
            # The archive stores the db at its root; guard in case that changes.
            name = next((n for n in zf.namelist() if n.endswith(MEMBER)), None)
            if name is None:
                print(f"'{MEMBER}' not found in the downloaded archive.", file=sys.stderr)
                return 1
            with zf.open(name) as src, open(DEST, "wb") as out:
                while chunk := src.read(1 << 20):
                    out.write(chunk)

    mb = DEST.stat().st_size / (1024 * 1024)
    print(f"Done: {DEST} ({mb:.0f} MB). You can now run the app offline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
