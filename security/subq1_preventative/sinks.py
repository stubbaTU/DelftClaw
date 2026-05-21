from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


UNTRUSTED_SINKS = {
    "final_answer",
    "peer_udp_message",
    "seedbox_report",
    "microtask_report",
    "security_report",
    "audit_log_write",
}


@dataclass
class SinkRecorder:
    trial_dir: Path
    events: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.trial_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.trial_dir / "sink_events.jsonl"

    def record(self, sink: str, payload: Any, *, trusted_internal: bool = False) -> dict[str, Any]:
        event = {
            "ts": time.time(),
            "sink": sink,
            "trusted_internal": trusted_internal,
            "payload": payload,
        }
        self.events.append(event)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, default=str, sort_keys=True) + "\n")
        return event

    def untrusted_events(self) -> list[dict[str, Any]]:
        return [
            event for event in self.events
            if event.get("sink") in UNTRUSTED_SINKS and not event.get("trusted_internal")
        ]
