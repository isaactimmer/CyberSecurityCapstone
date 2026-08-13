"""
Full NVD corpus store (epic #56: full-corpus ingest).

A thin persistence layer over a single SQLite file holding the *entire* NVD
corpus, pre-merged with EPSS and CISA KEV at ingest time. This is what lets a
scan be a filter + score over a complete local dataset instead of a per-vendor,
200-capped live pull (see docs/adr/0003-full-corpus-nvd-ingest.md).

Two roles, cleanly split:

    ingest  (nvd_ingest.py, #58/#59) *writes* — bulk-loads year files and the
            EPSS/KEV feeds via `upsert_cves` / `upsert_cpe` / `set_meta`.
    scan    (fetch_merged, #60) *reads* — `query_vendor(vendor)` returns one row
            per matching CVE in the exact column set `fetch_merged` has always
            returned, so nothing above the ingest layer changes.

The store owns *only* storage — no downloading, parsing, or scoring. `sqlite3`
from the stdlib, no new dependencies; the DB lives at `data/nvd_corpus.db` and
is git-ignored (it is regenerable reference data, not source or user data).

    store = CorpusStore()                     # opens/creates data/nvd_corpus.db
    store.upsert_cves(rows)                    # ingest: one dict per CVE
    store.upsert_cpe(pairs)                    # ingest: (cve_id, vendor, product)
    store.query_vendor("mysql")               # scan:  every mysql CVE, merged
    store.is_loaded()                          # has the corpus been ingested?
    store.last_refresh("nvd")                  # when was each feed last loaded?
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path

import runtime_paths

DEFAULT_DB_PATH = runtime_paths.data_dir() / "nvd_corpus.db"

# The exact column set fetch_merged has always returned (NVD base + EPSS + KEV).
# query_vendor selects these in this order so a corpus read is a drop-in for the
# old live pull. Keep in sync with combine_feeds() in
# combine_feeds_with_custom_inputs.py.
CVE_COLUMNS = (
    "cve_id",
    "cvss_score",
    "cvss_severity",
    "published",
    "description",
    "epss_score",
    "epss_percentile",
    "kev_flag",
    "kev_date_added",
    "kev_ransomware_use",
    "kev_vuln_name",
    "kev_short_description",
    "kev_required_action",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id                TEXT PRIMARY KEY,
    cvss_score            REAL,
    cvss_severity         TEXT,
    published             TEXT,
    description           TEXT,
    epss_score            REAL,          -- from the EPSS full feed (#59)
    epss_percentile       REAL,
    kev_flag              INTEGER NOT NULL DEFAULT 0,   -- from CISA KEV (#59)
    kev_date_added        TEXT,
    kev_ransomware_use    TEXT,
    kev_vuln_name         TEXT,
    kev_short_description TEXT,
    kev_required_action   TEXT
);

-- Vendor/product applicability, parsed from each CVE's CPE match criteria
-- (cpe:2.3:a:<vendor>:<product>:...). A scan filters here, not on description
-- substrings. UNIQUE keeps re-ingest idempotent (INSERT OR IGNORE).
CREATE TABLE IF NOT EXISTS cve_cpe (
    cve_id  TEXT NOT NULL,
    vendor  TEXT NOT NULL,
    product TEXT NOT NULL,
    UNIQUE (cve_id, vendor, product)
);
CREATE INDEX IF NOT EXISTS idx_cpe_vendor  ON cve_cpe (vendor);
CREATE INDEX IF NOT EXISTS idx_cpe_product ON cve_cpe (product);

-- Free-form per-feed bookkeeping: last-refresh timestamps, source versions, etc.
CREATE TABLE IF NOT EXISTS ingest_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _norm(token: str) -> str:
    """Fold a vendor/product token to a comparable form: lowercase, and treat
    '_' and ' ' as the same separator (CPE uses `http_server`, users type
    `http server`)."""
    return str(token).strip().lower().replace("_", " ")


class CorpusStore:
    """A connection to the NVD corpus database. Cheap to construct; safe to hold
    for the process lifetime. Pass `db_path=":memory:"` in tests for an isolated,
    disk-free store."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: FastAPI may serve reads on a threadpool. Writes
        # are bulk ingest runs, serialized by SQLite's own locking.
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- writes (ingest) -----------------------------------------------------

    def upsert_cves(self, rows: Iterable[dict]) -> int:
        """Insert or replace CVE rows. Each dict may carry any subset of
        CVE_COLUMNS; missing keys default to NULL (kev_flag to 0). Returns the
        number of rows written. Idempotent — re-ingesting the same CVE overwrites
        it rather than duplicating."""
        payload = [
            tuple(
                _coerce(col, row.get(col))
                for col in CVE_COLUMNS
            )
            for row in rows
        ]
        if not payload:
            return 0
        placeholders = ", ".join("?" for _ in CVE_COLUMNS)
        cols = ", ".join(CVE_COLUMNS)
        self._conn.executemany(
            f"INSERT OR REPLACE INTO cves ({cols}) VALUES ({placeholders})",
            payload,
        )
        self._conn.commit()
        return len(payload)

    def upsert_cpe(self, pairs: Iterable[tuple[str, str, str]]) -> int:
        """Record (cve_id, vendor, product) applicability triples. Vendor and
        product are stored lowercased for stable lookup. Duplicate triples are
        ignored (the UNIQUE constraint), so re-ingest stays idempotent. Returns
        the number of triples supplied."""
        payload = [
            (cve_id, str(vendor).strip().lower(), str(product).strip().lower())
            for cve_id, vendor, product in pairs
        ]
        if not payload:
            return 0
        self._conn.executemany(
            "INSERT OR IGNORE INTO cve_cpe (cve_id, vendor, product) VALUES (?, ?, ?)",
            payload,
        )
        self._conn.commit()
        return len(payload)

    def set_meta(self, key: str, value: str) -> None:
        """Upsert one bookkeeping value (e.g. set_meta('nvd', <ISO timestamp>))."""
        self._conn.execute(
            "INSERT OR REPLACE INTO ingest_meta (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._conn.commit()

    # -- reads (scan) --------------------------------------------------------

    def query_vendor(self, keyword: str, limit: int | None = None) -> list[dict]:
        """Every CVE matching `keyword`, one dict per CVE in CVE_COLUMNS order.

        Primary match is CPE vendor/product equality (separator-insensitive);
        the fallback is a description substring, so CVEs with no CPE config
        (Rejected / Awaiting Analysis) still surface. Rows are ordered worst
        first — KEV-listed, then higher EPSS, then higher CVSS — so a `limit`
        keeps the most urgent CVEs rather than an arbitrary slice. `limit=None`
        (default) returns the complete set. `kev_flag` is returned as a bool."""
        kw = _norm(keyword)
        cols = ", ".join(f"c.{col}" for col in CVE_COLUMNS)
        sql = f"""
            SELECT {cols}
            FROM cves c
            WHERE c.cve_id IN (
                SELECT cve_id FROM cve_cpe
                WHERE REPLACE(vendor, '_', ' ') = :kw
                   OR REPLACE(product, '_', ' ') = :kw
            )
               OR LOWER(c.description) LIKE :like
            ORDER BY c.kev_flag DESC,
                     c.epss_score DESC,
                     c.cvss_score DESC,
                     c.cve_id
        """
        params: dict = {"kw": kw, "like": f"%{kw}%"}
        if limit is not None:
            sql += " LIMIT :limit"
            params["limit"] = int(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]

    def is_loaded(self) -> bool:
        """Whether the corpus holds any CVEs — i.e. an ingest has run. The
        server (#61) uses this to warn 'run ingest first' instead of returning
        empty scans."""
        row = self._conn.execute("SELECT 1 FROM cves LIMIT 1").fetchone()
        return row is not None

    def count(self) -> int:
        """Number of CVEs currently in the corpus."""
        return int(self._conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0])

    def last_refresh(self, key: str) -> str | None:
        """The stored bookkeeping value for `key` (e.g. 'nvd', 'epss', 'kev'),
        or None if never set."""
        row = self._conn.execute(
            "SELECT value FROM ingest_meta WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row is not None else None

    def close(self) -> None:
        self._conn.close()


def _coerce(col: str, value):
    """Normalize a value for storage: kev_flag to 0/1, everything else as-is
    (None stays NULL)."""
    if col == "kev_flag":
        return 1 if value else 0
    return value


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Turn a cves row into the fetch_merged dict, with kev_flag as a real bool."""
    d = {col: row[col] for col in CVE_COLUMNS}
    d["kev_flag"] = bool(d["kev_flag"])
    return d
