import os
import json
import hashlib
from datetime import datetime

class AppendOnlyLog:
    """
    Host-Level Append-Only Log.
    Records agent actions/tool calls outside the agent's execution environment.
    """
    HEADER = "=== OpenClaw Append-Only Security Log v2 ==="

    def __init__(self, log_path: str = "agent_actions.log"):
        self.log_path = log_path
        # Ensure the file exists (create it if not)
        if not os.path.exists(self.log_path):
            with open(self.log_path, 'a') as f:
                f.write(f"{self.HEADER}\n")

    def append(
        self,
        agent_id: str,
        action: str,
        details: dict,
        subject_id: str | None = None,
        severity: int = 0,
        evidence: dict | None = None,
    ):
        """
        Backward-compatible append helper.

        agent_id is the reporter. subject_id is the agent whose behavior is
        being recorded. If omitted, the reporter is also treated as the subject.
        """
        return self.append_event(
            reporter_id=agent_id,
            subject_id=subject_id or agent_id,
            action=action,
            details=details,
            severity=severity,
            evidence=evidence,
        )

    def append_event(
        self,
        reporter_id: str,
        subject_id: str,
        action: str,
        details: dict,
        severity: int = 0,
        evidence: dict | None = None,
    ):
        """Append one accountability event to the end of the log."""
        timestamp = datetime.utcnow().isoformat()
        previous_hash = self.latest_hash()
        entry = {
            "version": 2,
            "timestamp": timestamp,
            "reporter_id": reporter_id,
            "subject_id": subject_id,
            "action": action,
            "severity": severity,
            "details": details,
            "evidence": evidence or {},
            "previous_hash": previous_hash,
        }
        entry["entry_hash"] = self._entry_hash(entry)
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def latest_hash(self) -> str:
        latest = "GENESIS"
        for entry in self.read_entries():
            latest = entry.get("entry_hash", latest)
        return latest

    def read_entries(self) -> list[dict]:
        if not os.path.exists(self.log_path):
            return []

        entries = []
        with open(self.log_path, 'r') as f:
            for line in f:
                if line.startswith("===") or not line.strip():
                    continue
                try:
                    entry = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue

                if entry.get("version") == 2:
                    entries.append(entry)
        return entries

    def verify_integrity(self) -> tuple[bool, list[str]]:
        errors = []
        previous_hash = "GENESIS"
        for index, entry in enumerate(self.read_entries(), start=1):
            if entry.get("previous_hash") != previous_hash:
                errors.append(f"entry {index}: previous_hash mismatch")

            expected_hash = self._entry_hash(entry)
            if entry.get("entry_hash") != expected_hash:
                errors.append(f"entry {index}: entry_hash mismatch")

            previous_hash = entry.get("entry_hash", previous_hash)

        return len(errors) == 0, errors

    @staticmethod
    def _entry_hash(entry: dict) -> str:
        hashable = dict(entry)
        hashable.pop("entry_hash", None)
        encoded = json.dumps(hashable, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
