from __future__ import annotations

from pathlib import Path

from security.subq3_containment import CONDITION_C0, CONDITION_C1
from security.subq3_containment.attack_schema import ContainmentAttack
from security.subq3_containment.compromised_runner import run_attack_trial
from security.subq3_containment.containment_profiles import build_containment_profile
from security.subq3_containment.generate_attack_suite import generate_default_attacks
from security.subq3_containment.network_guard import NetworkGuard
from security.subq3_containment.protected_resources import create_protected_fixture, destroy_fixture, verify_fixture_integrity


def _attack(attack_id: str) -> ContainmentAttack:
    return next(attack for attack in generate_default_attacks() if attack.attack_id == attack_id)


def test_c0_smoke_trial_can_read_reachable_baseline_canary(tmp_path: Path) -> None:
    fixture = create_protected_fixture("c0_read", tmp_path)
    guard = NetworkGuard.start()

    try:
        profile = build_containment_profile(CONDITION_C0, fixture, network_guard=guard)
        result = run_attack_trial(_attack("A1_wallet_read_002"), profile, fixture)
        assert result.success is True
        assert result.canary_observed is True
    finally:
        guard.stop()
        destroy_fixture(fixture)


def test_c1_smoke_trial_cannot_read_protected_canary_directly(tmp_path: Path) -> None:
    fixture = create_protected_fixture("c1_read", tmp_path)
    guard = NetworkGuard.start()

    try:
        profile = build_containment_profile(CONDITION_C1, fixture, network_guard=guard)
        result = run_attack_trial(_attack("A1_wallet_read_002"), profile, fixture)
        assert result.success is False
        assert result.canary_observed is False
        assert verify_fixture_integrity(fixture).ok is True
    finally:
        guard.stop()
        destroy_fixture(fixture)


def test_denied_proxy_abuse_does_not_modify_protected_state(tmp_path: Path) -> None:
    fixture = create_protected_fixture("proxy_abuse", tmp_path)
    guard = NetworkGuard.start()

    try:
        profile = build_containment_profile(CONDITION_C1, fixture, network_guard=guard)
        result = run_attack_trial(_attack("A6_proxy_identity_key_001"), profile, fixture)
        assert result.success is False
        assert result.proxy_abuse_success is False
        assert verify_fixture_integrity(fixture).ok is True
    finally:
        guard.stop()
        destroy_fixture(fixture)


def test_network_exfil_to_unauthorized_endpoint_is_detected_if_it_occurs(tmp_path: Path) -> None:
    fixture = create_protected_fixture("net_c0", tmp_path)
    guard = NetworkGuard.start()

    try:
        profile = build_containment_profile(CONDITION_C0, fixture, network_guard=guard)
        result = run_attack_trial(_attack("A9_network_identity_exfil_001"), profile, fixture)
        assert result.success is True
        assert result.unauthorized_network_received is True
        assert result.canary_exfiltrated is True
    finally:
        guard.stop()
        destroy_fixture(fixture)


def test_c1_network_exfil_to_unauthorized_endpoint_is_blocked(tmp_path: Path) -> None:
    fixture = create_protected_fixture("net_c1", tmp_path)
    guard = NetworkGuard.start()

    try:
        profile = build_containment_profile(CONDITION_C1, fixture, network_guard=guard)
        result = run_attack_trial(_attack("A9_network_identity_exfil_001"), profile, fixture)
        assert result.success is False
        assert result.network_blocked is True
        assert guard.unauthorized_exfil_endpoint.messages == []
    finally:
        guard.stop()
        destroy_fixture(fixture)
