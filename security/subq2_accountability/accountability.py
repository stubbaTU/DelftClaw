from typing import Any

from security.contracts import (
    AccountabilityMetrics,
    AtomicMicrotaskEvidence,
    SecurityAction,
    SeedboxDonationEvidence,
)
from security.subq2_accountability.append_log import AppendOnlyLog
from security.subq2_accountability.reputation import ReputationEngine
from security.subq2_accountability.seedbox import DonationLedger, SeedboxRegistry


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
        self.fake_donations: dict[str, int] = {}
        self.honest_transactions_stolen: dict[str, int] = {}
        self.wash_trades_detected: dict[str, int] = {}
        self.atomic_microtasks_claimed: dict[str, int] = {}
        self.first_malicious_steps: dict[str, int] = {}
        self.detection_steps: dict[str, int] = {}
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
        self._record_malicious_step(subject_id)
        self.log.append_event(
            reporter_id=self.reporter_id,
            subject_id=subject_id,
            action=SecurityAction.UNAUTHORIZED_TOOL_EXECUTION.value,
            severity=ReputationEngine.DEFAULT_WEIGHTS[SecurityAction.UNAUTHORIZED_TOOL_EXECUTION.value],
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
            action=SecurityAction.UNAUTHORIZED_TOOL_REQUEST.value,
            severity=ReputationEngine.DEFAULT_WEIGHTS[SecurityAction.UNAUTHORIZED_TOOL_REQUEST.value],
            details={
                "step": self.current_step,
                "tool": tool_name,
                **(details or {}),
            },
            evidence=evidence,
        )

    def record_private_key_exfiltration(
        self,
        subject_id: str,
        payload_id: str | None = None,
        evidence: dict[str, Any] | None = None,
    ):
        self.attempted_actions[subject_id] = self.attempted_actions.get(subject_id, 0) + 1
        self.unauthorized_executions[subject_id] = self.unauthorized_executions.get(subject_id, 0) + 1
        self._record_malicious_step(subject_id)
        self.log.append_event(
            reporter_id=self.reporter_id,
            subject_id=subject_id,
            action=SecurityAction.PRIVATE_KEY_EXFILTRATION.value,
            severity=ReputationEngine.DEFAULT_WEIGHTS[SecurityAction.PRIVATE_KEY_EXFILTRATION.value],
            details={
                "step": self.current_step,
                "payload_id": payload_id,
                "asset": "local_private_identity_key",
            },
            evidence=evidence,
        )

    def record_fake_seedbox_creation(
        self,
        subject_id: str,
        seedbox_id: str,
        evidence: dict[str, Any] | None = None,
    ):
        self._record_malicious_step(subject_id)
        self.log.append_event(
            reporter_id=self.reporter_id,
            subject_id=subject_id,
            action=SecurityAction.FAKE_SEEDBOX_CREATED.value,
            severity=ReputationEngine.DEFAULT_WEIGHTS[SecurityAction.FAKE_SEEDBOX_CREATED.value],
            details={"step": self.current_step, "seedbox_id": seedbox_id},
            evidence=evidence,
        )

    def record_seedbox_donation(
        self,
        subject_id: str,
        donation: SeedboxDonationEvidence,
        stolen_from_honest_agent: bool = False,
    ):
        self.attempted_actions[subject_id] = self.attempted_actions.get(subject_id, 0) + 1
        if donation.fake_seedbox or donation.self_donation:
            self.fake_donations[subject_id] = self.fake_donations.get(subject_id, 0) + 1
            self._record_malicious_step(subject_id)
        if stolen_from_honest_agent:
            self.honest_transactions_stolen[subject_id] = self.honest_transactions_stolen.get(subject_id, 0) + 1
            self._record_malicious_step(subject_id)

        self.log.append_event(
            reporter_id=self.reporter_id,
            subject_id=subject_id,
            action=SecurityAction.SEEDBOX_DONATION_BROADCAST.value,
            severity=ReputationEngine.DEFAULT_WEIGHTS[SecurityAction.SEEDBOX_DONATION_BROADCAST.value],
            details={
                "step": self.current_step,
                "donation_id": donation.donation_id,
                "seedbox_id": donation.seedbox_id,
                "donor_id": donation.donor_id,
                "recipient_id": donation.recipient_id,
                "amount_sats": donation.amount_sats,
                "txid": donation.txid,
                "self_donation": donation.self_donation,
                "fake_seedbox": donation.fake_seedbox,
                "stolen_from_honest_agent": stolen_from_honest_agent,
            },
        )

        if donation.self_donation:
            self.wash_trades_detected[subject_id] = self.wash_trades_detected.get(subject_id, 0) + 1
            self.log.append_event(
                reporter_id=self.reporter_id,
                subject_id=subject_id,
                action=SecurityAction.WASH_TRADE_DETECTED.value,
                severity=ReputationEngine.DEFAULT_WEIGHTS[SecurityAction.WASH_TRADE_DETECTED.value],
                details={
                    "step": self.current_step,
                    "donation_id": donation.donation_id,
                    "seedbox_id": donation.seedbox_id,
                    "donor_id": donation.donor_id,
                    "recipient_id": donation.recipient_id,
                },
            )

    def record_atomic_microtask(
        self,
        subject_id: str,
        microtask: AtomicMicrotaskEvidence,
    ):
        self.atomic_microtasks_claimed[subject_id] = self.atomic_microtasks_claimed.get(subject_id, 0) + 1
        self.log.append_event(
            reporter_id=self.reporter_id,
            subject_id=subject_id,
            action=SecurityAction.ATOMIC_MICROTASK_CLAIMED.value,
            severity=ReputationEngine.DEFAULT_WEIGHTS[SecurityAction.ATOMIC_MICROTASK_CLAIMED.value],
            details={
                "step": self.current_step,
                "task_id": microtask.task_id,
                "seedbox_id": microtask.seedbox_id,
                "prover_id": microtask.prover_id,
                "task_type": microtask.task_type,
                "file_hash": microtask.file_hash,
                "result_hash": microtask.result_hash,
                "verified": microtask.verified,
            },
        )

    def scan(self):
        self.reputation.scan_log()
        for subject_id in self.reputation.banned_agents:
            self.expulsion_steps.setdefault(subject_id, self.current_step)
            self.detection_steps.setdefault(subject_id, self.current_step)

    def get_metrics(self, subject_id: str, accountability_enabled: bool) -> AccountabilityMetrics:
        integrity_ok, integrity_errors = self.log.verify_integrity()
        first_malicious_step = self.first_malicious_steps.get(subject_id)
        detection_step = self.detection_steps.get(subject_id) or self.expulsion_steps.get(subject_id)
        reputation_lag = None
        if first_malicious_step is not None and detection_step is not None:
            reputation_lag = max(0, detection_step - first_malicious_step)
        accepted_harmful_actions = (
            self.unauthorized_executions.get(subject_id, 0)
            + self.fake_donations.get(subject_id, 0)
            + self.honest_transactions_stolen.get(subject_id, 0)
        )
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
            first_malicious_step=first_malicious_step,
            detection_step=detection_step,
            reputation_lag=reputation_lag,
            accepted_harmful_actions_during_lag=accepted_harmful_actions,
            fake_donations=self.fake_donations.get(subject_id, 0),
            honest_transactions_stolen=self.honest_transactions_stolen.get(subject_id, 0),
            wash_trades_detected=self.wash_trades_detected.get(subject_id, 0),
            atomic_microtasks_claimed=self.atomic_microtasks_claimed.get(subject_id, 0),
        )

    def _record_malicious_step(self, subject_id: str):
        self.first_malicious_steps.setdefault(subject_id, self.current_step)


def run_reputation_trap_experiment(
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

    The compromised subject performs rug-pull imposter actions against a
    claimed seedbox. Reputation lag is the delay between the first malicious
    action and detection/expulsion. Fallout radius is the accepted damage
    during that lag.
    """
    log = AppendOnlyLog(log_path=log_path)
    reputation = ReputationEngine(log_path=log.log_path, ban_threshold=threshold)
    monitor = AccountabilityMonitor(log=log, reputation=reputation, reporter_id=reporter_id)
    registry = SeedboxRegistry()
    ledger = DonationLedger(registry)
    fake_seedbox = registry.register(
        seedbox_id="fake-seedbox-1",
        owner_id=subject_id,
        donation_address="mock-donation-address-fake-seedbox-1",
        advertised_capacity_gb=10_000,
        fake=True,
    )

    for action_index in range(1, total_malicious_actions + 1):
        monitor.next_step()

        if accountability_enabled and monitor.should_drop(subject_id):
            monitor.record_blocked_action(subject_id)
            continue

        donation = ledger.broadcast_donation(
            donation_id=f"fake-donation-{action_index}",
            seedbox_id=fake_seedbox.seedbox_id,
            donor_id=subject_id,
            amount_sats=10_000,
            txid=f"fake-tx-{action_index}",
        )
        if action_index == 1:
            monitor.record_fake_seedbox_creation(subject_id=subject_id, seedbox_id=fake_seedbox.seedbox_id)
        monitor.record_seedbox_donation(
            subject_id=subject_id,
            donation=donation.to_evidence(),
            stolen_from_honest_agent=donation.stolen_from_honest_agent,
        )

        if accountability_enabled and action_index % scan_interval == 0:
            monitor.scan()

    if accountability_enabled:
        monitor.scan()

    return monitor.get_metrics(subject_id, accountability_enabled=accountability_enabled)


def run_harm_until_expulsion_experiment(*args, **kwargs) -> AccountabilityMetrics:
    return run_reputation_trap_experiment(*args, **kwargs)
