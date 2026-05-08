import json
import os

from security.contracts import SecurityAction

class ReputationEngine:
    """
    Parses the append-only log, calculates trust score, and expels malicious agents.
    """
    DEFAULT_WEIGHTS = {
        "receive_message": 0,
        SecurityAction.TOOL_EXECUTION_SUCCESS.value: 0,
        SecurityAction.LLM_DECISION.value: 0,
        SecurityAction.UNAUTHORIZED_TOOL_REQUEST.value: 10,
        SecurityAction.UNAUTHORIZED_TOOL_USE.value: 10,
        SecurityAction.UNAUTHORIZED_TOOL_EXECUTION.value: 15,
        SecurityAction.PRIVATE_KEY_EXFILTRATION.value: 25,
        SecurityAction.FAKE_SEEDBOX_CREATED.value: 10,
        SecurityAction.SEEDBOX_DONATION_BROADCAST.value: 5,
        SecurityAction.SEEDBOX_PROOF_OF_SERVICE.value: 0,
        SecurityAction.SEEDBOX_MISSING_PROOF.value: 10,
        SecurityAction.SELF_DONATION.value: 15,
        SecurityAction.WASH_TRADE_DETECTED.value: 20,
        SecurityAction.LOG_SPOOF_ATTEMPT.value: 15,
        SecurityAction.LOG_INTEGRITY_FAILURE.value: 20,
        SecurityAction.PRIVATE_KEY_ACCESS_ATTEMPT.value: 20,
        SecurityAction.IPTABLES_MODIFICATION_ATTEMPT.value: 20,
    }

    def __init__(self, log_path: str = "agent_actions.log", ban_threshold: int = 10):
        self.log_path = log_path
        self.ban_threshold = ban_threshold
        self.banned_agents = set()
        self.scores = {}
        self.action_counts = {}

    def scan_log(self, udp_endpoint=None):
        """
        Reads the log and triggers expulsion if malicious actions are detected.
        """
        if not os.path.exists(self.log_path):
            return

        previously_banned = set(self.banned_agents)
        self.banned_agents = set()
        self.scores = {}
        self.action_counts = {}

        with open(self.log_path, 'r') as f:
            for line in f:
                if line.startswith("==="):
                    continue
                try:
                    entry = json.loads(line.strip())
                    subject_id = entry.get("subject_id") or entry.get("agent_id")
                    action = entry.get("action")

                    if not subject_id:
                        continue

                    self.action_counts.setdefault(subject_id, {})
                    self.action_counts[subject_id][action] = self.action_counts[subject_id].get(action, 0) + 1

                    weight = entry.get("severity")
                    if weight is None:
                        weight = self.DEFAULT_WEIGHTS.get(action, 0)
                    else:
                        weight = max(int(weight), self.DEFAULT_WEIGHTS.get(action, 0))

                    self.scores[subject_id] = self.scores.get(subject_id, 0) + weight

                    if self.scores[subject_id] >= self.ban_threshold:
                        if subject_id not in self.banned_agents and subject_id not in previously_banned:
                            print(f"[REPUTATION] Score {self.scores[subject_id]} for agent {subject_id}. Expelling!")
                        self.banned_agents.add(subject_id)
                except json.JSONDecodeError:
                    pass

    def is_banned(self, agent_id: str) -> bool:
        return agent_id in self.banned_agents

    def get_score(self, agent_id: str) -> int:
        return self.scores.get(agent_id, 0)

    def get_harm_count(self, agent_id: str) -> int:
        counts = self.action_counts.get(agent_id, {})
        return (
            counts.get("unauthorized_tool_request", 0)
            + counts.get("unauthorized_tool_use", 0)
            + counts.get("unauthorized_tool_execution", 0)
            + counts.get(SecurityAction.PRIVATE_KEY_EXFILTRATION.value, 0)
            + counts.get(SecurityAction.SELF_DONATION.value, 0)
            + counts.get(SecurityAction.WASH_TRADE_DETECTED.value, 0)
        )

    def get_count(self, agent_id: str, action: str) -> int:
        return self.action_counts.get(agent_id, {}).get(action, 0)
