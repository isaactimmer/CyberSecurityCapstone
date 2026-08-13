"""
Scryxen remediation console — FastAPI server (epic #6 UI reshape).

Serves the console front end in `web/` and exposes the real engine over a small
JSON API. The design is a bespoke web app (ported from the approved v2 artifact);
this server is the seam between it and the Python engine, so the front end never
re-implements scoring — it renders what `dashboard.plan_payload` returns.

    GET  /                     the console (web/index.html)
    GET  /api/environment      one-time: asset map, presets, defaults, bounds
    POST /api/plan             recompute for the current controls (the hot path)
    POST /api/asset/{id}       one system's drill-in for a clicked map node
    POST /api/finding/{cve}    a finding's score breakdown for the modal
    POST /api/override         record a security-lead override (audited)
    POST /api/override/clear   drop the override on a CVE

The environment is scanned once (cached NVD/EPSS/KEV pulls, offline) and held in
memory; every recompute is pure pandas over that cache.

Run:
    uvicorn server:app --port 8000
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import asset_graph
import capacity
import dashboard
import overrides
import pipeline
import runtime_paths
import scoring
import store
from combine_feeds_with_custom_inputs import cache_exists as corpus_loaded

WEB_DIR = runtime_paths.resource_dir() / "web"

# Intake defaults — the console opens on these until the user changes a control.
DEFAULT_CAPACITY = {"patching": 40.0, "appsec": 16.0, "change_window": 8.0}


@dataclass
class ConsoleState:
    """The scanned environment held in memory for the session, plus the audit log
    of security-lead overrides. Built once by `load_state`."""

    env: pd.DataFrame
    asset_table: pd.DataFrame | None
    override_log: overrides.OverrideLog
    source: str = "Sample environment"
    asset_csv: bytes | None = None   # raw uploaded CSV, kept as the input of record
    #                                  for history (None = the sample environment)


def load_state() -> ConsoleState:
    """Scan the sample environment (cached, offline) — the one I/O step, run once."""
    asset_table = asset_graph.build_asset_table(asset_graph.DEFAULT_ASSET_CSV)
    env = pipeline.scan_environment(asset_table=asset_table, use_cache=True)
    return ConsoleState(env=env, asset_table=asset_table,
                        override_log=overrides.OverrideLog())


_state: ConsoleState | None = None


def state() -> ConsoleState:
    """The cached console state, scanning on first use. Tests may pre-set `_state`
    to a fixture to avoid the scan."""
    global _state
    if _state is None:
        _state = load_state()
    return _state


_store: store.Store | None = None


def run_store() -> store.Store:
    """The run-history store, opened on first use. Tests may pre-set `_store` to an
    in-memory store to avoid touching the on-disk DB."""
    global _store
    if _store is None:
        _store = store.Store()
    return _store


# --- request models ---------------------------------------------------------

class Controls(BaseModel):
    """The console's live controls, sent with every recompute."""

    weights: dict[str, float] | None = None       # cvss/epss/kev/importance, raw
    capacity: dict[str, float] | None = None       # patching/appsec/change_window
    kev_sim: list[str] = Field(default_factory=list)  # CVEs flipped to KEV
    max_findings: int | None = None                # "how many to list?" — top-N, None=all
    year_range: list[int] | None = None            # [from, to] CVE years, None=all
    scope_mode: Literal["plan", "display"] = "plan"  # "plan": top-N scopes the plan;
    #                                                  "display": top-N caps only the table


class OverrideRequest(Controls):
    """An override plus the controls to recompute the board against."""

    cve_id: str
    score: float
    user: str
    reason: str


def _weights(controls: Controls) -> scoring.ScoringWeights:
    w = controls.weights or {}
    d = scoring.DEFAULT_WEIGHTS
    return dashboard.normalize_weights(
        cvss=w.get("cvss", d.cvss), epss=w.get("epss", d.epss),
        kev=w.get("kev", d.kev), importance=w.get("importance", d.importance),
    )


def _pools(controls: Controls) -> dict[str, capacity.CapacityPool]:
    c = controls.capacity or {}
    return dashboard.build_pools(
        patching=c.get("patching", DEFAULT_CAPACITY["patching"]),
        appsec=c.get("appsec", DEFAULT_CAPACITY["appsec"]),
        change_window=c.get("change_window", DEFAULT_CAPACITY["change_window"]),
    )


def _env(controls: Controls) -> pd.DataFrame:
    env = state().env
    return dashboard.inject_kev(env, controls.kev_sim) if controls.kev_sim else env


def _year_range(controls: Controls) -> tuple[int, int] | None:
    """The landing-page year filter as a normalized (low, high) tuple, or None.

    A range that already spans the whole environment is "all years" — return None
    so no CVE with an unparseable/absent year is filtered out. The front end sends
    the raw picker values; collapsing a full span is the engine's call, made here
    against the environment's true bounds."""
    yr = controls.year_range
    if not yr or len(yr) != 2:
        return None
    low, high = min(int(yr[0]), int(yr[1])), max(int(yr[0]), int(yr[1]))
    bounds = dashboard.year_bounds(state().env)
    if bounds and low <= bounds[0] and high >= bounds[1]:
        return None
    return (low, high)


def _max_findings(controls: Controls) -> int | None:
    """List-size cap; a non-positive value means 'all' (same as None)."""
    n = controls.max_findings
    return n if n and n > 0 else None


def _display_only(controls: Controls) -> bool:
    """True when the list-size cap should trim only the *displayed* table, leaving
    the optimizer to weigh the whole (year-scoped) universe; False keeps the default
    plan-scoping behaviour."""
    return controls.scope_mode == "display"


def _scope(controls: Controls):
    """A scored-frame narrowing callable for the drill-in endpoints (asset/finding)
    so they see the same scoped universe as the board, or None for the whole set.
    The year range always scopes; the top-N cut scopes the plan only in the default
    "plan" mode — in "display" mode the count is demoted to a table cap (see
    `_display_limit`) so the optimizer still weighs every in-range finding."""
    n = None if _display_only(controls) else _max_findings(controls)
    yr = _year_range(controls)
    if n is None and yr is None:
        return None
    return lambda s: dashboard.filter_findings(s, max_results=n, year_range=yr)


def _display_limit(controls: Controls) -> int | None:
    """The list-size cap as a table-only trim — set only in "display" mode, where
    the count doesn't narrow the plan. None in the default "plan" mode (there the
    count already rode in through `_scope`)."""
    return _max_findings(controls) if _display_only(controls) else None


# --- app --------------------------------------------------------------------

app = FastAPI(title="Scryxen remediation console")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


def _environment_payload(st: ConsoleState) -> dict:
    """Everything static about the environment the console needs on first paint.
    Shared by `/api/environment` (sample) and `/api/upload` (user CSV) so both
    hand the front end the same shape."""
    layout = dashboard.asset_map_layout(st.asset_table) if st.asset_table is not None \
        else dashboard.AssetMapLayout(nodes=pd.DataFrame(), edges=pd.DataFrame())
    bounds = dashboard.year_bounds(st.env)
    d = scoring.DEFAULT_WEIGHTS
    return {
        "source": st.source,
        # False when the local NVD corpus has never been ingested — every scan
        # comes back empty, so the console shows a "run ingest first" notice
        # instead of a silent blank board (epic #56, Phase 4).
        "corpus_loaded": corpus_loaded(),
        "finding_count": int(len(st.env)),
        "year_bounds": list(bounds) if bounds else None,
        "presets": dashboard.presets(),
        "default_weights": {"cvss": d.cvss, "epss": d.epss, "kev": d.kev,
                            "importance": d.importance},
        "default_capacity": DEFAULT_CAPACITY,
        "pools": {name: pool.unit
                  for name, pool in capacity.default_pools().items()},
        "asset_map": {
            "nodes": layout.nodes.to_dict("records"),
            "edges": layout.edges.to_dict("records"),
        },
    }


@app.get("/api/environment")
def environment() -> dict:
    """The sample environment payload for first paint."""
    return _environment_payload(state())


@app.post("/api/reset")
def reset() -> dict:
    """Restore the sample environment — used when the user switches back to it
    after uploading their own assets. Cheap: the sample scan is cached/offline."""
    global _state
    _state = load_state()
    return _environment_payload(_state)


@app.post("/api/upload")
def upload(file: UploadFile = File(...)) -> dict:
    """Replace the sample environment with an uploaded asset CSV.

    Validates the CSV (schema + graph integrity) via `dashboard.load_asset_table`,
    rescans offline against the cached feeds, and swaps the in-memory state for a
    fresh one (new override log). Returns the same shape as `/api/environment` so
    the front end can re-paint without a second round trip. A bad file yields a
    422 with the plain-English reason the loader raised."""
    global _state
    raw = file.file.read()
    try:
        asset_table = dashboard.load_asset_table(io.BytesIO(raw))
    except ValueError as exc:                     # missing columns, bad graph, etc.
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:                       # not a CSV / unparseable bytes
        raise HTTPException(
            status_code=422,
            detail=f"Could not read that file as a CSV: {exc}",
        ) from exc

    env = pipeline.scan_environment(asset_table=asset_table, use_cache=True)
    source = f"Uploaded: {file.filename}" if file.filename else "Uploaded assets"
    _state = ConsoleState(env=env, asset_table=asset_table,
                          override_log=overrides.OverrideLog(), source=source,
                          asset_csv=raw)
    return _environment_payload(_state)


def _plan_payload(controls: Controls, st: ConsoleState) -> dict:
    """The computed board for `controls` against state `st` — shared by the live
    `/api/plan` hot path and the history-save endpoint so both freeze the same
    shape."""
    return dashboard.plan_payload(
        _env(controls), weights=_weights(controls), pools=_pools(controls),
        asset_table=st.asset_table, override_log=st.override_log,
        scope=_scope(controls), display_limit=_display_limit(controls),
    )


@app.post("/api/plan")
def recompute(controls: Controls) -> dict:
    """Recompute the whole board for the current controls — the hot path."""
    return _plan_payload(controls, state())


@app.post("/api/asset/{asset_id}")
def asset(asset_id: str, controls: Controls) -> dict:
    """One system's drill-in for a clicked map node, against the current plan."""
    st = state()
    result = dashboard.plan(_env(controls), weights=_weights(controls),
                            pools=_pools(controls), scope=_scope(controls))
    detail = dashboard.asset_detail(asset_id, st.asset_table, result)
    detail.pop("scheduled", None)   # a DataFrame — the ids list is what the UI needs
    return detail


@app.post("/api/finding/{cve_id}")
def finding(cve_id: str, controls: Controls) -> dict:
    """A finding's plain-English breakdown + weighted score split for the modal."""
    st = state()
    env = _env(controls)
    weights = _weights(controls)
    result = dashboard.plan(env, weights=weights, pools=_pools(controls),
                            scope=_scope(controls))
    items = dashboard.annotate_plan(result.scored, st.asset_table)
    match = items[items["cve_id"] == cve_id]
    if match.empty:
        raise HTTPException(status_code=404, detail=f"No finding {cve_id!r}")
    row = match.iloc[0]
    detail = dashboard.plan_item_detail(row)
    detail["breakdown"] = dashboard.score_breakdown(row, weights)
    detail["scheduled"] = cve_id in set(result.optimized.items["cve_id"]) \
        if "cve_id" in result.optimized.items.columns else False
    return detail


@app.post("/api/override")
def add_override(req: OverrideRequest) -> dict:
    """Record an audited security-lead override, then return the re-ranked board."""
    st = state()
    env = _env(req)
    weights = _weights(req)
    scored = dashboard.plan(env, weights=weights, pools=_pools(req)).scored
    match = scored[scored["cve_id"] == req.cve_id]
    computed = float(match.iloc[0]["composite_score"]) if not match.empty else 0.0
    try:
        st.override_log.record(req.cve_id, computed_score=computed,
                               override_score=req.score, user=req.user,
                               reason=req.reason)
    except ValueError as exc:               # blank user/reason — the audit guard
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return dashboard.plan_payload(env, weights=weights, pools=_pools(req),
                                  asset_table=st.asset_table,
                                  override_log=st.override_log,
                                  scope=_scope(req), display_limit=_display_limit(req))


@app.post("/api/override/clear")
def clear_override(req: OverrideRequest) -> dict:
    """Revert a CVE to its computed score. The audit log is append-only and has no
    delete, so we rebuild it without this CVE's entries — `latest()` then drops it
    and the finding reverts (its prior audit lines go with it, as in the design)."""
    st = state()
    fresh = overrides.OverrideLog()
    for e in st.override_log.history():
        if e.key != req.cve_id:
            fresh.record(e.key, e.computed_score, e.override_score,
                         e.user, e.reason, e.timestamp)
    st.override_log = fresh
    return dashboard.plan_payload(_env(req), weights=_weights(req), pools=_pools(req),
                                  asset_table=st.asset_table,
                                  override_log=st.override_log,
                                  scope=_scope(req), display_limit=_display_limit(req))


# --- run history ------------------------------------------------------------

class SaveRunRequest(Controls):
    """Save the current environment + these controls as a history entry. `name`
    is the user's label; blank falls back to a generated default."""

    name: str | None = None


def _default_run_name(st: ConsoleState) -> str:
    """A friendly fallback label when the user doesn't name the run, e.g.
    'Uploaded: assets.csv — 2026-08-13 14:05'."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"{st.source} — {stamp}"


def _restore_state(rec: dict) -> ConsoleState:
    """Rebuild a live ConsoleState from a stored run: re-scan its saved asset CSV
    (or the sample environment) and replay its override audit log, so reopening a
    run puts the console back into that working state — live controls included."""
    if rec["asset_csv"] is not None:
        asset_table = dashboard.load_asset_table(io.BytesIO(rec["asset_csv"]))
    else:
        asset_table = asset_graph.build_asset_table(asset_graph.DEFAULT_ASSET_CSV)
    env = pipeline.scan_environment(asset_table=asset_table, use_cache=True)

    log = overrides.OverrideLog()
    for e in rec["overrides"]:
        log.record(e["key"], e["computed_score"], e["override_score"],
                   e["user"], e["reason"], e["timestamp"])

    return ConsoleState(env=env, asset_table=asset_table, override_log=log,
                        source=rec["source"], asset_csv=rec["asset_csv"])


def _run_view(rec: dict) -> dict:
    """A stored run shaped for the API — the frozen snapshot the console repaints,
    minus the raw CSV bytes (an internal input, not JSON)."""
    return {
        "id": rec["id"],
        "created_at": rec["created_at"],
        "name": rec["name"],
        "source": rec["source"],
        "finding_count": rec["finding_count"],
        "controls": rec["controls"],
        "env_payload": rec["env_payload"],
        "plan_payload": rec["plan_payload"],
        "overrides": rec["overrides"],
    }


@app.post("/api/runs")
def save_run(req: SaveRunRequest) -> dict:
    """Save the current environment and these controls as a history entry — the
    inputs (uploaded CSV + controls) plus a frozen snapshot of the environment and
    computed board. Returns the new run's summary."""
    st = state()
    controls = Controls(**req.model_dump(exclude={"name"}))
    name = req.name.strip() if req.name and req.name.strip() else _default_run_name(st)
    run_id = run_store().save_run(
        name=name,
        source=st.source,
        finding_count=int(len(st.env)),
        controls=req.model_dump(exclude={"name"}),
        env_payload=_environment_payload(st),
        plan_payload=_plan_payload(controls, st),
        asset_csv=st.asset_csv,
        overrides=[e.to_dict() for e in st.override_log.history()],
    )
    rec = run_store().get_run(run_id)
    return {"id": rec["id"], "created_at": rec["created_at"], "name": rec["name"],
            "source": rec["source"], "finding_count": rec["finding_count"]}


@app.get("/api/runs")
def list_runs() -> dict:
    """The history index, newest first — light rows for the History tab list."""
    return {"runs": [vars(r) for r in run_store().list_runs()]}


@app.get("/api/runs/{run_id}")
def get_run(run_id: int) -> dict:
    """One run's frozen snapshot for viewing, without disturbing live state."""
    rec = run_store().get_run(run_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"No run {run_id}")
    return _run_view(rec)


@app.post("/api/runs/{run_id}/open")
def open_run(run_id: int) -> dict:
    """Reopen a run: restore it as the live console state (so controls work again)
    and return its frozen snapshot to repaint."""
    global _state
    rec = run_store().get_run(run_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"No run {run_id}")
    _state = _restore_state(rec)
    return _run_view(rec)


@app.delete("/api/runs/{run_id}")
def delete_run(run_id: int) -> dict:
    """Remove a history entry."""
    if not run_store().delete_run(run_id):
        raise HTTPException(status_code=404, detail=f"No run {run_id}")
    return {"deleted": run_id}


# Static assets (app.js, styles.css). Mounted last so it never shadows the API.
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
