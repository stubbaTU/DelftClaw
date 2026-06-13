from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class MutableJSONLog:
    """
    Plain JSONL log with no cryptohgraphy (so mutable hashes, exposes functions to manipulate log)
    """

    def __init__(self, log_path: str | Path) -> None:
        self.log_path = str(log_path)
        Path(self.log_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.log_path).touch(exist_ok=True)
        self._sequence = len(self.read_entries())

    def append_event(
        self,
        reporter_id: str,
        subject_id: str,
        action: str,
        details: dict[str, Any],
        severity: int = 0,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._sequence += 1
        entry = {
            "entry_hash": f"mutable-{self._sequence}",
            "reporter_id": reporter_id,
            "subject_id": subject_id,
            "action": action,
            "severity": severity,
            "details": details,
            "evidence": evidence or {},
        }
        with Path(self.log_path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def read_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for line in Path(self.log_path).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                entries.append(value)
        return entries

    def erase_last_event(self) -> bool:
        entries = self.read_entries()
        if not entries:
            return False
        entries.pop()
        self._rewrite(entries)
        return True

    def _rewrite(self, entries: list[dict[str, Any]]) -> None:
        with Path(self.log_path).open("w", encoding="utf-8") as handle:
            for entry in entries:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")


class ReplayLog:
    """In-memory append/scan adapter for post-hoc estimator replay to save money on API Costs (no need to run B1/B2)."""

    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self._source = list(entries)
        self._derived: list[dict[str, Any]] = []

    def read_entries(self) -> list[dict[str, Any]]:
        return [*self._source, *self._derived]

    def append_event(self, **entry: Any) -> dict[str, Any]:
        value = dict(entry)
        value.setdefault("entry_hash", f"replay-derived-{len(self._derived) + 1}")
        self._derived.append(value)
        return value
