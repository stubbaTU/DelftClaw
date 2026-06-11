from __future__ import annotations

import time
from pathlib import Path

from security.containment_layer.infrastructure.network_guard import NetworkGuard
from security.containment_layer.infrastructure.protected_resources import create_protected_fixture, destroy_fixture, verify_fixture_integrity
from security.containment_layer.infrastructure.resource_proxies import (
    AppendOnlyLogProxy,
    IdentityProxy,
    NetworkProxy,
    ReputationProxy,
    SeedboxProxy,
    WalletProxy,
)


def test_identity_proxy_never_returns_private_key_canary(tmp_path: Path) -> None:
    fixture = create_protected_fixture("proxy_identity", tmp_path)

    try:
        proxy = IdentityProxy(fixture)
        assert fixture.canaries["identity_key"] not in str(proxy.get_public_identity().to_dict())
        assert proxy.read_private_key().ok is False
    finally:
        destroy_fixture(fixture)


def test_wallet_proxy_never_returns_wallet_canary(tmp_path: Path) -> None:
    fixture = create_protected_fixture("proxy_wallet", tmp_path)

    try:
        proxy = WalletProxy(fixture)
        assert fixture.canaries["wallet_state"] not in str(proxy.get_public_wallet_status().to_dict())
        assert proxy.read_wallet_seed().ok is False
    finally:
        destroy_fixture(fixture)


def test_append_only_log_proxy_rejects_rewrite_delete_truncate(tmp_path: Path) -> None:
    fixture = create_protected_fixture("proxy_log", tmp_path)

    try:
        proxy = AppendOnlyLogProxy(fixture)
        assert proxy.rewrite_log("x").ok is False
        assert proxy.delete_log().ok is False
        assert proxy.truncate_log().ok is False
        assert proxy.verify_log().ok is True
    finally:
        destroy_fixture(fixture)


def test_valid_proxy_operations_still_work_without_leaking_canaries(tmp_path: Path) -> None:
    fixture = create_protected_fixture("proxy_valid", tmp_path)
    guard = NetworkGuard.start()

    try:
        identity = IdentityProxy(fixture)
        wallet = WalletProxy(fixture)
        network = NetworkProxy(fixture, guard)

        signed = identity.sign_nonce("challenge-123")
        status = wallet.get_public_wallet_status()
        sent = network.send_to_allowed_peer("hello peer")

        assert signed.ok is True
        assert status.ok is True
        assert sent.ok is True
        combined = str(signed.to_dict()) + str(status.to_dict()) + str(sent.to_dict())
        assert all(canary not in combined for canary in fixture.canaries.values())
        for _ in range(20):
            if guard.allowed_peer_endpoint.messages:
                break
            time.sleep(0.01)
        assert guard.allowed_peer_endpoint.messages == ["hello peer"]
    finally:
        guard.stop()
        destroy_fixture(fixture)


def test_reputation_proxy_rejects_direct_score_mutation(tmp_path: Path) -> None:
    fixture = create_protected_fixture("proxy_rep", tmp_path)

    try:
        proxy = ReputationProxy(fixture)
        assert proxy.set_score_directly("attacker", 999).ok is False
        assert verify_fixture_integrity(fixture).ok is True
    finally:
        destroy_fixture(fixture)


def test_seedbox_proxy_rejects_direct_acl_grants(tmp_path: Path) -> None:
    fixture = create_protected_fixture("proxy_seedbox", tmp_path)

    try:
        proxy = SeedboxProxy(fixture)
        assert proxy.grant_access_directly("attacker").ok is False
        assert fixture.canaries["seedbox_acl"] not in str(proxy.get_public_task_status("task").to_dict())
    finally:
        destroy_fixture(fixture)


def test_network_proxy_rejects_unauthorized_endpoint(tmp_path: Path) -> None:
    fixture = create_protected_fixture("proxy_net", tmp_path)
    guard = NetworkGuard.start()

    try:
        proxy = NetworkProxy(fixture, guard)
        assert proxy.send_to_arbitrary_host("x", "127.0.0.1", guard.unauthorized_exfil_endpoint.port).ok is False
        assert guard.unauthorized_exfil_endpoint.messages == []
    finally:
        guard.stop()
        destroy_fixture(fixture)
