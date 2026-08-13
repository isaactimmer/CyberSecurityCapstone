"""Round-trip tests for the run-history store (store.Store)."""
from __future__ import annotations

import store


def _make_store():
    """An isolated, disk-free store for each test."""
    return store.Store(db_path=":memory:")


def _sample_run(**overrides):
    """A minimal but complete save_run() kwargs bundle; override any field."""
    base = dict(
        name="Plan — Aug 13",
        source="Uploaded: assets.csv",
        finding_count=42,
        controls={"weights": {"cvss": 1.0}, "capacity": {"patching": 40.0}},
        env_payload={"asset_map": {"nodes": [], "edges": []}, "year_bounds": [2015, 2025]},
        plan_payload={"kpis": {"total": 42}, "findings": [{"cve_id": "CVE-1"}]},
        asset_csv=b"asset_id,name\nA,Crown\n",
        overrides=[{"cve_id": "CVE-1", "user": "lead", "reason": "risk accepted"}],
    )
    base.update(overrides)
    return base


def test_save_returns_id_and_get_round_trips():
    st = _make_store()
    run_id = st.save_run(**_sample_run())
    assert run_id > 0

    got = st.get_run(run_id)
    assert got is not None
    assert got["name"] == "Plan — Aug 13"
    assert got["source"] == "Uploaded: assets.csv"
    assert got["finding_count"] == 42
    # inputs survive verbatim
    assert got["asset_csv"] == b"asset_id,name\nA,Crown\n"
    assert got["controls"]["capacity"]["patching"] == 40.0
    # frozen snapshot survives verbatim
    assert got["plan_payload"]["findings"][0]["cve_id"] == "CVE-1"
    assert got["env_payload"]["year_bounds"] == [2015, 2025]
    assert got["overrides"][0]["reason"] == "risk accepted"


def test_get_unknown_id_returns_none():
    st = _make_store()
    assert st.get_run(999) is None


def test_list_is_newest_first():
    st = _make_store()
    id1 = st.save_run(**_sample_run(name="first", created_at="2026-08-13T10:00:00+00:00"))
    id2 = st.save_run(**_sample_run(name="second", created_at="2026-08-13T11:00:00+00:00"))

    rows = st.list_runs()
    assert [r.id for r in rows] == [id2, id1]
    assert rows[0].name == "second"
    # summaries carry the light fields, not the heavy payloads
    assert rows[0].finding_count == 42
    assert not hasattr(rows[0], "plan_payload")


def test_delete_removes_run():
    st = _make_store()
    run_id = st.save_run(**_sample_run())
    assert st.delete_run(run_id) is True
    assert st.get_run(run_id) is None
    assert st.list_runs() == []


def test_delete_unknown_id_is_false():
    st = _make_store()
    assert st.delete_run(123) is False


def test_sample_run_may_have_no_csv():
    """A saved sample environment has no uploaded CSV — asset_csv is None."""
    st = _make_store()
    run_id = st.save_run(**_sample_run(source="Sample environment", asset_csv=None))
    assert st.get_run(run_id)["asset_csv"] is None


def test_persists_across_connections(tmp_path):
    """A real file-backed store survives being reopened (restart-durable)."""
    db = tmp_path / "scryxen.db"
    st = store.Store(db_path=db)
    run_id = st.save_run(**_sample_run(name="durable"))
    st.close()

    reopened = store.Store(db_path=db)
    assert reopened.get_run(run_id)["name"] == "durable"
