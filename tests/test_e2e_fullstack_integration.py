from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from redteam.primitives.signed_log import SignedAppendOnlyLog
from security.accountability_layer.infrastructure.trustworthy_estimator import TrustworthyEstimator
from security.containment_layer.infrastructure.protected_resources import create_protected_fixture, destroy_fixture, verify_fixture_integrity
from security.integration import scenario
from security.integration.e2e_fullstack import _accept_expected_log_growth, _tamper_and_restore, build_agent_docker_command
from security.integration.gateway import AllowedPeerGateway, GatewayState


def test_gateway_dispatches_real_resource_proxy_and_denies_private_read(tmp_path: Path) -> None:
    fixture = create_protected_fixture("e2e_gateway", tmp_path)
    state = GatewayState(fixture, "")
    gateway = AllowedPeerGateway(state, "127.0.0.1", 0)
    gateway.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{gateway.port}/proxy/identity/read_private_key",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            payload = json.loads(response.read())
        assert payload["ok"] is False
        assert "not exposed" in payload["error"]
    finally:
        gateway.stop()
        destroy_fixture(fixture)


def test_gateway_log_appends_feed_real_estimator(tmp_path: Path) -> None:
    fixture = create_protected_fixture("e2e_estimator", tmp_path)
    state = GatewayState(fixture, "")
    try:
        for event in [
            {"index": 1, "round": 1, "actor_id": "M0", "event_type": "microtask_reported", "payload": {"task_id": "missing", "claimed_status": "completed", "evidence_valid": False}},
            {"index": 2, "round": 2, "actor_id": "M0", "event_type": "donation_broadcast", "payload": {"from": "M0", "to": "M0"}},
        ]:
            response = state.dispatch_proxy("log", "append_event", {"event": {"action": event["event_type"], "details": {"event": event}}})
            assert response["ok"] is True
        log = SignedAppendOnlyLog(fixture.signing_identity, fixture.paths["accountability_log"])
        estimator = TrustworthyEstimator(log, fixture.signing_identity.identity_hash, pattern_detection=True, expulsion_threshold=5)
        estimator.scan()
        assert estimator.is_expelled("M0") is True
        assert estimator.get_suspicion("M0") == 6
    finally:
        destroy_fixture(fixture)


def test_multi_agent_scenario_expels_attacker_cluster_without_false_positives(tmp_path: Path) -> None:
    fixture = create_protected_fixture("e2e_multi_agent", tmp_path)
    state = GatewayState(fixture, "")
    try:
        for event in scenario.logged_events():
            response = state.dispatch_proxy("log", "append_event", scenario.append_body(event))
            assert response["ok"] is True
        log = SignedAppendOnlyLog(fixture.signing_identity, fixture.paths["accountability_log"])
        estimator = TrustworthyEstimator(
            log,
            fixture.signing_identity.identity_hash,
            pattern_detection=True,
            expulsion_threshold=5,
            honest_agents=set(scenario.HONEST_SET),
        )
        estimator.scan()
        assert scenario.EXPECTED_EXPELLED.issubset(estimator.expelled_agents)
        assert not (scenario.HONEST_SET & estimator.expelled_agents)
        assert estimator.is_expelled("HA0") is False
        assert estimator.false_positive_count == 0
        all_reasons = {reason for reasons in estimator.detection_reasons.values() for reason in reasons}
        assert scenario.EXPECTED_REASONS.issubset(all_reasons)
        assert "two_node_wash_trade" in estimator.detection_reasons.get("M0", [])
        assert "collusive_endorsement_cluster" in estimator.detection_reasons.get("M0", [])
    finally:
        destroy_fixture(fixture)


def test_tamper_check_detects_and_restores_signed_log(tmp_path: Path) -> None:
    fixture = create_protected_fixture("e2e_tamper", tmp_path)
    try:
        log = SignedAppendOnlyLog(fixture.signing_identity, fixture.paths["accountability_log"])
        result = _tamper_and_restore(fixture.paths["accountability_log"], log)
        assert result["tamper_detected"] is True
        assert result["restored_valid"] is True
    finally:
        destroy_fixture(fixture)


def test_expected_log_growth_does_not_hide_other_protected_changes(tmp_path: Path) -> None:
    fixture = create_protected_fixture("e2e_integrity", tmp_path)
    try:
        log = SignedAppendOnlyLog(fixture.signing_identity, fixture.paths["accountability_log"])
        log.append_event(fixture.signing_identity.identity_hash, "M0", "event", {"event": {}})
        fixture.paths["wallet_state"].write_text("tampered\n", encoding="utf-8")
        _accept_expected_log_growth(fixture)
        result = verify_fixture_integrity(fixture)
        assert result.ok is False
        assert "wallet_state" in result.modified_files
        assert "accountability_log" not in result.modified_files
    finally:
        destroy_fixture(fixture)


def test_agent_command_reuses_c1_builder_and_overrides_harness_entrypoint(tmp_path: Path) -> None:
    fixture = create_protected_fixture("e2e_command", tmp_path)
    try:
        command = build_agent_docker_command(fixture, "sq3", "vukzero-sq3-harness", 18765)
        assert "--runtime=runsc" in command
        assert "--read-only" in command
        assert "--entrypoint=python" in command
        assert "/repo/security/integration/agent_in_container.py" == command[-1]
        assert str(fixture.host_protected.resolve()) not in " ".join(command)
    finally:
        destroy_fixture(fixture)
