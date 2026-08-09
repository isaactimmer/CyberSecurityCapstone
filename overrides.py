"""
Security-lead override (epic #4, ticket #29)

The scoring engine computes a composite risk score, but the proposal promises a
security lead retains final authority. This module lets a human override a
computed score without doing it silently: every override is logged with who
changed it, when, and why, the history is persisted, and the overridden score
stays clearly marked apart from the machine-computed one.

Usage:
    log = OverrideLog(path="overrides.jsonl")           # persists as it goes
    log.record("CVE-2024-1234", computed_score=42.0, override_score=90.0,
               user="alice", reason="active incident on this host")

    final = apply_overrides(scored_df, log)             # adds final_score etc.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class Override:
    """One audited adjustment of a computed score."""

    key: str
    computed_score: float
    override_score: float
    user: str
    reason: str
    timestamp: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Override":
        return cls(
            key=data["key"],
            computed_score=float(data["computed_score"]),
            override_score=float(data["override_score"]),
            user=data["user"],
            reason=data["reason"],
            timestamp=data["timestamp"],
        )


class OverrideLog:
    """
    Append-only audit log of score overrides.

    Entries are kept in memory and, if a `path` is given, mirrored to a JSONL
    file (one override per line) so the history survives a restart. Loading an
    existing file rebuilds the full history. The latest override per key wins
    when applied to a scored table.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._entries: list[Override] = []
        self.path = Path(path) if path is not None else None
        if self.path is not None and self.path.exists():
            self._load()

    def _load(self) -> None:
        assert self.path is not None
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    self._entries.append(Override.from_dict(json.loads(line)))

    def record(
        self,
        key: str,
        computed_score: float,
        override_score: float,
        user: str,
        reason: str,
        timestamp: str | None = None,
    ) -> Override:
        """
        Record an override. `user` and `reason` are mandatory — an override with
        no accountable owner or justification is exactly what this ticket exists
        to prevent, so an empty/blank value raises.
        """
        if not user or not str(user).strip():
            raise ValueError("An override requires a non-empty user (who changed it).")
        if not reason or not str(reason).strip():
            raise ValueError("An override requires a non-empty reason (why it changed).")

        entry = Override(
            key=key,
            computed_score=float(computed_score),
            override_score=float(override_score),
            user=str(user).strip(),
            reason=str(reason).strip(),
            timestamp=timestamp or _utc_now_iso(),
        )
        self._entries.append(entry)

        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry.to_dict()) + "\n")

        return entry

    def history(self, key: str | None = None) -> list[Override]:
        """Full override history, or just the entries for one key, in order."""
        if key is None:
            return list(self._entries)
        return [e for e in self._entries if e.key == key]

    def latest(self) -> dict[str, Override]:
        """The most recent override per key (later records supersede earlier)."""
        latest: dict[str, Override] = {}
        for entry in self._entries:
            latest[entry.key] = entry
        return latest

    def __len__(self) -> int:
        return len(self._entries)


def apply_overrides(
    scored: pd.DataFrame,
    log: OverrideLog,
    key_column: str = "cve_id",
    computed_column: str = "composite_score",
    final_column: str = "final_score",
) -> pd.DataFrame:
    """
    Overlay a scored table with any recorded overrides.

    Returns a new DataFrame that keeps the machine-computed `composite_score`
    untouched and adds:
        final_score          the score to act on (override if present, else computed)
        is_overridden        True where a human adjusted the score
        override_user        who made the override
        override_reason      why
        override_timestamp   when
    The result is re-sorted by `final_score`, highest risk first.
    """
    if key_column not in scored.columns:
        raise KeyError(f"Scored frame has no key column {key_column!r}")
    if computed_column not in scored.columns:
        raise KeyError(f"Scored frame has no computed-score column {computed_column!r}")

    latest = log.latest()
    df = scored.copy()
    df[final_column] = df[computed_column]
    df["is_overridden"] = False
    df["override_user"] = pd.NA
    df["override_reason"] = pd.NA
    df["override_timestamp"] = pd.NA

    for idx, key in df[key_column].items():
        entry = latest.get(key)
        if entry is not None:
            df.at[idx, final_column] = entry.override_score
            df.at[idx, "is_overridden"] = True
            df.at[idx, "override_user"] = entry.user
            df.at[idx, "override_reason"] = entry.reason
            df.at[idx, "override_timestamp"] = entry.timestamp

    return df.sort_values(final_column, ascending=False).reset_index(drop=True)
