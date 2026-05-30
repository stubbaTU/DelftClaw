from __future__ import annotations

from security.subq3_containment.compromised_runner import AttackTrialResult
from security.subq3_containment.metrics import results_by_condition


def _result(condition: str, success: bool, score: int) -> AttackTrialResult:
    return AttackTrialResult(
        attack_id=f"{condition}_{success}",
        family="A1_filesystem_read",
        variant="001",
        target_asset="identity_key",
        condition=condition,
        profile_name=condition,
        uses_gvisor=False,
        uses_docker=False,
        uses_iptables=False,
        attack_type="python_snippet",
        success=success,
        blocked=not success,
        fallout_score=score,
        canary_observed=success,
        canary_exfiltrated=False,
        protected_file_modified=False,
        protected_file_deleted=False,
        log_chain_valid_after=True,
        unauthorized_network_received=False,
        proxy_abuse_success=False,
        resource_integrity_preserved=not success,
    )


def test_metrics_compute_fallout_success_rate_correctly() -> None:
    rows = [_result("C0_uncontained", True, 3), _result("C0_uncontained", False, 1)]
    by_condition = results_by_condition(rows)
    c0 = by_condition[0]
    assert c0["trials"] == 2
    assert c0["successful_unauthorized_accesses"] == 1
    assert c0["fallout_success_rate"] == 0.5
    assert c0["mean_fallout_score"] == 2

