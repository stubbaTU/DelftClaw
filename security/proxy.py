from .append_log import AppendOnlyLog

class IsolationProxy:
    """
    gVisor / Sandbox Preparation Proxy.
    The agent inside the sandbox interacts ONLY with this proxy.
    """
    def __init__(self, agent_id: str, logger: AppendOnlyLog):
        self.agent_id = agent_id
        self._logger = logger

    def log_action(self, action: str, details: dict):
        """
        The only exposed method for the sandboxed agent to write to the log.
        The agent has no access to read, modify, or delete the log.
        """
        # We can implement basic validation or sanitization here before logging
        self._logger.append(self.agent_id, action, details)

