from __future__ import annotations

from security.preventative_layer.permissions import Subject
from security.preventative_layer.permissions.proxies import AppendOnlyLogProxy, IdentityProxy, ReputationProxy, SeedboxProxy, WalletProxy


def test_safe_proxies_do_not_return_raw_secret_state() -> None:
    subject = Subject("agent_A0", "normal_agent")

    identity = IdentityProxy().sign_nonce(subject, "challenge")
    wallet = WalletProxy(address="tb1q-public", balance_sats=5).get_public_wallet_status(subject)
    log = AppendOnlyLogProxy()
    reputation = ReputationProxy()
    seedbox = SeedboxProxy().request_seedbox_task(subject, "task_001")

    assert identity["ok"] is True
    assert "private" not in identity
    assert wallet == {"ok": True, "address": "tb1q-public", "balance_sats": 5}
    assert log.append_event(subject, {"event_type": "security_report"})["appended"] is True
    assert reputation.update_reputation_from_engine(subject, {"subject_id": "agent_A0"})["blocked"] is True
    assert seedbox["task_id"] == "task_001"
