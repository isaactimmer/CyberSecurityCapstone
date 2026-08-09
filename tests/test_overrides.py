"""
Tests for the security-lead override mechanism (epic #4, ticket #29).

An override lets a human adjust a computed composite score, but never silently:
every override is recorded with who / when / why, persisted, and the resulting
score stays clearly distinguishable from the machine-computed one.
"""
import pandas as pd
import pytest

import overrides


# ---------------------------------------------------------------------------
# OverrideLog.record — who / when / why is mandatory
# ---------------------------------------------------------------------------
class TestRecord:
    def test_record_captures_user_reason_and_timestamp(self):
        log = overrides.OverrideLog()
        entry = log.record(
            key="CVE-1",
            computed_score=42.0,
            override_score=90.0,
            user="alice",
            reason="active incident on this host",
        )
        assert entry.user == "alice"
        assert entry.reason == "active incident on this host"
        assert entry.computed_score == 42.0
        assert entry.override_score == 90.0
        assert entry.timestamp  # non-empty ISO timestamp
        assert len(log) == 1

    def test_missing_user_is_rejected(self):
        log = overrides.OverrideLog()
        with pytest.raises(ValueError):
            log.record("CVE-1", 10.0, 20.0, user="  ", reason="because")

    def test_missing_reason_is_rejected(self):
        log = overrides.OverrideLog()
        with pytest.raises(ValueError):
            log.record("CVE-1", 10.0, 20.0, user="alice", reason="")

    def test_explicit_timestamp_is_preserved(self):
        log = overrides.OverrideLog()
        entry = log.record(
            "CVE-1", 10.0, 20.0, user="alice", reason="x",
            timestamp="2026-08-09T12:00:00+00:00",
        )
        assert entry.timestamp == "2026-08-09T12:00:00+00:00"


# ---------------------------------------------------------------------------
# History — overrides accumulate; the latest per key wins
# ---------------------------------------------------------------------------
class TestHistory:
    def test_history_returns_all_entries_in_order(self):
        log = overrides.OverrideLog()
        log.record("CVE-1", 10.0, 20.0, user="alice", reason="first")
        log.record("CVE-1", 20.0, 30.0, user="bob", reason="second")
        history = log.history("CVE-1")
        assert [e.reason for e in history] == ["first", "second"]

    def test_latest_takes_the_most_recent_override_per_key(self):
        log = overrides.OverrideLog()
        log.record("CVE-1", 10.0, 20.0, user="alice", reason="first")
        log.record("CVE-1", 20.0, 30.0, user="bob", reason="second")
        latest = log.latest()
        assert latest["CVE-1"].override_score == 30.0
        assert latest["CVE-1"].user == "bob"


# ---------------------------------------------------------------------------
# Persistence — override history survives a reload (audit trail)
# ---------------------------------------------------------------------------
class TestPersistence:
    def test_overrides_persist_to_file_and_reload(self, tmp_path):
        path = tmp_path / "overrides.jsonl"
        log = overrides.OverrideLog(path=path)
        log.record("CVE-1", 10.0, 20.0, user="alice", reason="incident")
        log.record("CVE-2", 5.0, 60.0, user="bob", reason="threat intel")

        reloaded = overrides.OverrideLog(path=path)
        assert len(reloaded) == 2
        assert reloaded.latest()["CVE-2"].user == "bob"
        assert reloaded.latest()["CVE-2"].reason == "threat intel"


# ---------------------------------------------------------------------------
# apply_overrides — overridden score is distinguishable from the computed one
# ---------------------------------------------------------------------------
def _scored_frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"cve_id": "CVE-A", "composite_score": 80.0},
            {"cve_id": "CVE-B", "composite_score": 30.0},
            {"cve_id": "CVE-C", "composite_score": 50.0},
        ]
    )


class TestApplyOverrides:
    def test_final_score_reflects_override_and_flags_it(self):
        log = overrides.OverrideLog()
        log.record("CVE-B", 30.0, 95.0, user="alice", reason="crown-jewel exposure")
        result = overrides.apply_overrides(_scored_frame(), log)

        row_b = result.set_index("cve_id").loc["CVE-B"]
        assert row_b["final_score"] == 95.0
        assert row_b["is_overridden"]
        assert row_b["composite_score"] == 30.0  # computed value preserved
        assert row_b["override_user"] == "alice"
        assert row_b["override_reason"] == "crown-jewel exposure"

    def test_non_overridden_rows_keep_computed_score(self):
        log = overrides.OverrideLog()
        log.record("CVE-B", 30.0, 95.0, user="alice", reason="x")
        result = overrides.apply_overrides(_scored_frame(), log)

        row_a = result.set_index("cve_id").loc["CVE-A"]
        assert row_a["final_score"] == 80.0
        assert not row_a["is_overridden"]

    def test_override_re_sorts_by_final_score(self):
        log = overrides.OverrideLog()
        log.record("CVE-B", 30.0, 99.0, user="alice", reason="x")
        result = overrides.apply_overrides(_scored_frame(), log)
        # CVE-B was lowest computed but overridden to the top
        assert result.iloc[0]["cve_id"] == "CVE-B"
        scores = result["final_score"].tolist()
        assert scores == sorted(scores, reverse=True)

    def test_does_not_mutate_input(self):
        log = overrides.OverrideLog()
        log.record("CVE-A", 80.0, 10.0, user="alice", reason="false positive")
        frame = _scored_frame()
        overrides.apply_overrides(frame, log)
        assert "final_score" not in frame.columns
