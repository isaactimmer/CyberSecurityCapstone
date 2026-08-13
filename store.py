"""
Run history store (epic: database + history).

A thin persistence layer over a single SQLite file so the console can *save* an
asset map / plan and *reopen* it later. Each saved entry — a "run" — captures
both the inputs the user handed us and a frozen snapshot of the computed result,
so history is reproducible and auditable even if the scoring engine changes:

    inputs   : the raw uploaded asset CSV bytes, plus the control settings
               (weights / capacity / filters) in force at save time.
    snapshot : the environment payload (asset map, bounds, presets) and the
               plan payload (the whole board) exactly as the console rendered
               them — plus the override audit log at that moment.

Single-user for now: there is no identity on a run. The schema leaves room for a
`user` column later (see the per-user-history recommendation) without a rewrite.

The store owns *only* storage — it does no scanning or scoring. `sqlite3` from
the stdlib, no new dependencies; the DB file lives at `data/scryxen.db` and is
git-ignored (it holds user uploads, not source).

    store = Store()                 # opens/creates data/scryxen.db
    run_id = store.save_run(...)    # persist the current state
    store.list_runs()               # newest-first index for the History tab
    store.get_run(run_id)           # full inputs + snapshot to reopen
    store.delete_run(run_id)
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import runtime_paths

DEFAULT_DB_PATH = runtime_paths.data_dir() / "scryxen.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at        TEXT    NOT NULL,   -- ISO-8601 UTC, when the run was saved
    name              TEXT    NOT NULL,   -- user label, or a generated default
    source            TEXT    NOT NULL,   -- e.g. "Uploaded: assets.csv" / "Sample"
    finding_count     INTEGER NOT NULL,
    asset_csv         BLOB,               -- input: raw uploaded CSV (NULL for sample)
    controls_json     TEXT    NOT NULL,   -- input: weights/capacity/filters at save
    env_payload_json  TEXT    NOT NULL,   -- snapshot: environment (asset map, bounds)
    plan_payload_json TEXT    NOT NULL,   -- snapshot: the computed board
    overrides_json    TEXT    NOT NULL    -- snapshot: override audit log at save time
);
"""


@dataclass(frozen=True)
class RunSummary:
    """One row of the history index — everything the History *list* needs, without
    hauling the (large) payloads."""

    id: int
    created_at: str
    name: str
    source: str
    finding_count: int


class Store:
    """A connection to the run-history database. Cheap to construct; safe to hold
    for the process lifetime. Pass `db_path=":memory:"` in tests for an isolated,
    disk-free store."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: FastAPI may serve requests on a threadpool; the
        # writes here are small and serialized by SQLite's own locking.
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # -- writes --------------------------------------------------------------

    def save_run(
        self,
        *,
        name: str,
        source: str,
        finding_count: int,
        controls: dict,
        env_payload: dict,
        plan_payload: dict,
        asset_csv: bytes | None = None,
        overrides: list | None = None,
        created_at: str | None = None,
    ) -> int:
        """Persist one history entry and return its new id.

        `controls` and `asset_csv` are the inputs; `env_payload` / `plan_payload`
        are the frozen result snapshot; `overrides` is the audit log at save time.
        `created_at` defaults to now (UTC, ISO-8601) — tests may pin it."""
        stamp = created_at or datetime.now(timezone.utc).isoformat()
        cur = self._conn.execute(
            """INSERT INTO runs
               (created_at, name, source, finding_count, asset_csv,
                controls_json, env_payload_json, plan_payload_json, overrides_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                stamp,
                name,
                source,
                int(finding_count),
                asset_csv,
                json.dumps(controls),
                json.dumps(env_payload),
                json.dumps(plan_payload),
                json.dumps(overrides or []),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def delete_run(self, run_id: int) -> bool:
        """Remove a run. Returns True if a row was deleted, False if no such id."""
        cur = self._conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        self._conn.commit()
        return cur.rowcount > 0

    # -- reads ---------------------------------------------------------------

    def list_runs(self) -> list[RunSummary]:
        """The history index, newest first — light rows for the list view."""
        rows = self._conn.execute(
            """SELECT id, created_at, name, source, finding_count
               FROM runs ORDER BY datetime(created_at) DESC, id DESC"""
        ).fetchall()
        return [
            RunSummary(
                id=r["id"],
                created_at=r["created_at"],
                name=r["name"],
                source=r["source"],
                finding_count=r["finding_count"],
            )
            for r in rows
        ]

    def get_run(self, run_id: int) -> dict | None:
        """Everything needed to reopen a run — inputs + frozen snapshot — or None
        if the id is unknown. `asset_csv` is returned as raw bytes (or None for a
        saved sample environment)."""
        r = self._conn.execute(
            "SELECT * FROM runs WHERE id = ?", (run_id,)
        ).fetchone()
        if r is None:
            return None
        return {
            "id": r["id"],
            "created_at": r["created_at"],
            "name": r["name"],
            "source": r["source"],
            "finding_count": r["finding_count"],
            "asset_csv": r["asset_csv"],
            "controls": json.loads(r["controls_json"]),
            "env_payload": json.loads(r["env_payload_json"]),
            "plan_payload": json.loads(r["plan_payload_json"]),
            "overrides": json.loads(r["overrides_json"]),
        }

    def close(self) -> None:
        self._conn.close()
