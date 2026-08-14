# PyInstaller spec for the Scryxen desktop app.
#
# Build (from the repo root, venv activated, requirements-desktop.txt installed):
#     pyinstaller scryxen.spec
#
# Output: dist/Scryxen/Scryxen.exe  (a folder — "onedir" build, see PACKAGING.md
# for why that's recommended over a single-file exe for this app). Zip the whole
# dist/Scryxen folder to share it; nothing outside that folder is needed.

from pathlib import Path

block_cipher = None
ROOT = Path(SPECPATH)

# Bundled, read-only resources the app needs at runtime.
datas = [
    (str(ROOT / "web"), "web"),
    (str(ROOT / "assets.csv"), "."),
]

# The full NVD corpus (git-ignored, ~480MB) is bundled read-only and seeded into
# the writable per-user data dir on first launch (launcher._seed_corpus), so the
# packaged app scans offline with no in-app ingest step. Guarded on existence so
# a build without a local corpus still succeeds (it just ships without one — run
# `python nvd_ingest.py --refresh` to build it before packaging). The retired
# data/cache CSVs are no longer bundled: the scan reads this corpus now.
_corpus = ROOT / "data" / "nvd_corpus.db"
if _corpus.exists():
    datas.append((str(_corpus), "data"))
# .env (holding NVD_API_KEY) is bundled into the build by choice, so a packaged
# copy works with a key out of the box — no per-user setup. TRADE-OFFS you accept
# by shipping this: (1) the key travels inside any zip you hand out, and (2) every
# copy shares that one key's 50-req/30s NVD budget, so heavy concurrent use across
# recipients can throttle each other. The key is free and revocable at
# nvd.nist.gov if it ever leaks. NEVER commit .env to git (it stays gitignored);
# bundling a local build is fine, pushing the key to the repo is not. Without a
# key the app still runs — offline scoring from data/cache, plus safe 6s-spaced
# live pulls with 429 backoff (combine_feeds_with_custom_inputs._nvd_get).
if (ROOT / ".env").exists():
    datas.append((str(ROOT / ".env"), "."))

a = Analysis(
    ["launcher.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        # uvicorn's auto-detected loop/protocol implementations aren't always
        # picked up by PyInstaller's static import scan.
        "uvicorn.logging",
        "uvicorn.loop.auto",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan.on",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Scryxen",
    debug=False,
    strip=False,
    upx=False,
    console=False,  # no console window; flip to True temporarily if a build
                     # needs debugging (prints/tracebacks become visible)
    icon=str(ROOT / "scryxen.ico"),  # planner-compass app icon (generated from web/logo.svg)
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="Scryxen",
)
