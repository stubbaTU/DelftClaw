import json
import os

class ReputationEngine:
    """
    Parses the append-only log, calculates trust score, and expels malicious agents.
    """
    def __init__(self, log_path: str = "agent_actions.log"):
        self.log_path = log_path
        self.banned_agents = set()

    def scan_log(self, udp_endpoint):
        """
        Reads the log and triggers expulsion if malicious actions are detected.
        """
        if not os.path.exists(self.log_path):
            return

        with open(self.log_path, 'r') as f:
            for line in f:
                if line.startswith("==="):
                    continue
                try:
                    entry = json.loads(line.strip())
                    agent_id = entry.get("agent_id")
                    action = entry.get("action")

                    # Policy Hook: If unauthorized tool use is detected, ban the agent.
                    if action == "unauthorized_tool_use":
                        print(f"[REPUTATION] Malicious action detected for agent {agent_id}. Expelling!")
                        self.banned_agents.add(agent_id)
                        # Optionally, we might need to filter the drop based on UDP endpoint callbacks,
                        # but typically we drop incoming packets from this agent address.
                except json.JSONDecodeError:
                    pass

    def is_banned(self, agent_id: str) -> bool:
        return agent_id in self.banned_agents

