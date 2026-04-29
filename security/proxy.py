from .append_log import AppendOnlyLog

class IsolationProxy:
    """
    gVisor / Sandbox Preparation Proxy.
    The agent inside the sandbox interacts ONLY with this proxy.
    """
    def __init__(self, agent_id: str, logger: AppendOnlyLog):
        self.agent_id = agent_id
        self._logger = logger

    def log_action(
        self,
        action: str,
        details: dict,
        subject_id: str | None = None,
        severity: int = 0,
        evidence: dict | None = None,
    ):
        """
        The only exposed method for the sandboxed agent to write to the log.
        The agent has no access to read, modify, or delete the log.
        """
        # We can implement basic validation or sanitization here before logging
        return self._logger.append(
            self.agent_id,
            action,
            details,
            subject_id=subject_id,
            severity=severity,
            evidence=evidence,
        )

    def report_violation(self, subject_id: str, action: str, details: dict, evidence: dict | None = None):
        """Record a security-relevant event where another agent is the subject."""
        return self.log_action(
            action=action,
            details=details,
            subject_id=subject_id,
            severity=10,
            evidence=evidence,
        )
