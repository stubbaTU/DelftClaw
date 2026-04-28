import os
import json
from datetime import datetime

class AppendOnlyLog:
    """
    Host-Level Append-Only Log.
    Records agent actions/tool calls outside the agent's execution environment.
    """
    def __init__(self, log_path: str = "agent_actions.log"):
        self.log_path = log_path
        # Ensure the file exists (create it if not)
        if not os.path.exists(self.log_path):
            with open(self.log_path, 'a') as f:
                f.write("=== OpenClaw Append-Only Security Log ===\n")

    def append(self, agent_id: str, action: str, details: dict):
        """Strictly appends to the end of the log; no reading or editing allowed here."""
        timestamp = datetime.utcnow().isoformat()
        entry = {
            "timestamp": timestamp,
            "agent_id": agent_id,
            "action": action,
            "details": details
        }
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(entry) + "\n")

