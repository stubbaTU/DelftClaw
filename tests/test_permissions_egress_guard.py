from __future__ import annotations

from security.preventative_layer.infrastructure.permissions import EgressGuard


def test_egress_guard_allows_normal_text_and_denies_canaries() -> None:
    guard = EgressGuard()

    assert guard.check_text("normal report").ok
    identity = guard.check_text("DELFTCLAW_TEST_PRIVATE_KEY_CANARY_SECRET")
    nested = guard.check_payload({"items": [{"wallet": "VUKZERO_WALLET_CANARY_SECRET"}]})

    assert not identity.ok
    assert not nested.ok
    assert "SECRET" not in identity.reason
