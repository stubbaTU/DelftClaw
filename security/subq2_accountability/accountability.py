from typing import Any

from security.contracts import AccountabilityMetrics
from security.subq2_accountability.append_log import AppendOnlyLog
from security.subq2_accountability.reputation import ReputationEngine


class AccountabilityMonitor:
    """
    Host-side accountability controller for post-factum security experiments.

    A real OpenClaw integration should call should_drop() before accepting an
    action from a peer, and record_unauthorized_execution() after a harmful
    action bypasses preventative defenses.
    """
    def __init__(
        self,
        log: AppendOnlyLog,
        reputation: ReputationEngine,
        reporter_id: str,
    ):
        self.log = log
        self.reputation = reputation
        self.reporter_id = reporter_id
        self.attempted_actions: dict[str, int] = {}
        self.unauthorized_executions: dict[str, int] = {}
        self.blocked_actions: dict[str, int] = {}
        self.expulsion_steps: dict[str, int] = {}
        self.current_step = 0

    def next_step(self) -> int:
        self.current_step += 1
        return self.current_step

    def should_drop(self, subject_id: str) -> bool:
        return self.reputation.is_banned(subject_id)

    def record_blocked_action(self, subject_id: str):
        self.attempted_actions[subject_id] = self.attempted_actions.get(subject_id, 0) + 1
        self.blocked_actions[subject_id] = self.blocked_actions.get(subject_id, 0) + 1

    def record_unauthorized_execution(
        self,
        subject_id: str,
        tool_name: str,
        details: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
    ):
        self.attempted_actions[subject_id] = self.attempted_actions.get(subject_id, 0) + 1
        self.unauthorized_executions[subject_id] = self.unauthorized_executions.get(subject_id, 0) + 1
        self.log.append_event(
            reporter_id=self.reporter_id,
            subject_id=subject_id,
            action="unauthorized_tool_execution",
            severity=ReputationEngine.DEFAULT_WEIGHTS["unauthorized_tool_execution"],
            details={
                "step": self.current_step,
                "tool": tool_name,
                **(details or {}),
            },
            evidence=evidence,
        )

    def record_unauthorized_request(
        self,
        subject_id: str,
        tool_name: str,
        details: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
    ):
        self.attempted_actions[subject_id] = self.attempted_actions.get(subject_id, 0) + 1
        self.log.append_event(
            reporter_id=self.reporter_id,
            subject_id=subject_id,
            action="unauthorized_tool_request",
            severity=ReputationEngine.DEFAULT_WEIGHTS["unauthorized_tool_request"],
            details={
                "step": self.current_step,
                "tool": tool_name,
                **(details or {}),
            },
            evidence=evidence,
        )

    def scan(self):
        self.reputation.scan_log()
        for subject_id in self.reputation.banned_agents:
            self.expulsion_steps.setdefault(subject_id, self.current_step)

    def get_metrics(self, subject_id: str, accountability_enabled: bool) -> AccountabilityMetrics:
        integrity_ok, integrity_errors = self.log.verify_integrity()
        return AccountabilityMetrics(
            subject_id=subject_id,
            accountability_enabled=accountability_enabled,
            attempted_actions=self.attempted_actions.get(subject_id, 0),
            unauthorized_executions=self.unauthorized_executions.get(subject_id, 0),
            blocked_actions=self.blocked_actions.get(subject_id, 0),
            final_score=self.reputation.get_score(subject_id),
            expelled=self.reputation.is_banned(subject_id),
            expulsion_step=self.expulsion_steps.get(subject_id),
            integrity_ok=integrity_ok,
            integrity_errors=integrity_errors,
        )


def run_harm_until_expulsion_experiment(
    accountability_enabled: bool,
    total_malicious_actions: int,
    threshold: int,
    scan_interval: int = 1,
    subject_id: str = "compromised-agent",
    reporter_id: str = "honest-monitor",
    log_path: str = "accountability.log",
) -> AccountabilityMetrics:
    """
    Compare accountability versus no accountability before real OpenClaw wiring.

    The compromised subject attempts the same number of malicious tool
    executions in both conditions. Without accountability, nothing blocks it.
    With accountability, reputation scans can expel it and block later actions.
    """
    log = AppendOnlyLog(log_path=log_path)
    reputation = ReputationEngine(log_path=log.log_path, ban_threshold=threshold)
    monitor = AccountabilityMonitor(log=log, reputation=reputation, reporter_id=reporter_id)

    for action_index in range(1, total_malicious_actions + 1):
        monitor.next_step()

        if accountability_enabled and monitor.should_drop(subject_id):
            monitor.record_blocked_action(subject_id)
            continue

        monitor.record_unauthorized_execution(
            subject_id=subject_id,
            tool_name="dangerous_tool",
            details={"sequence": action_index},
        )

        if accountability_enabled and action_index % scan_interval == 0:
            monitor.scan()

    if accountability_enabled:
        monitor.scan()

    return monitor.get_metrics(subject_id, accountability_enabled=accountability_enabled)
