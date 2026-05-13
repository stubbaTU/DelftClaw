from __future__ import annotations

from pathlib import Path

import identity.verification as verification
from identity.agent_identity import AgentIdentity
from identity.verification import VerificationChallenge, is_verified, simulate_regtest_payment
from shared.credentials import issue_credential, verify_credential


def test_issue_verify_credential() -> None:
    issuer = AgentIdentity(network="REGTEST", agent_index=0)
    vc = issue_credential(issuer, {"role": "seedbox"})
    assert verify_credential(vc, issuer.get_identity_hash()) is True


def test_verification_challenge_success(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(verification, "_LOG_PATH", tmp_path / "verification_log.json")
    monkeypatch.setattr(verification, "_TX_LEDGER_PATH", tmp_path / "verification_txs.json")

    identity = AgentIdentity(network="REGTEST", agent_index=0)
    challenge = VerificationChallenge.create(identity, "REGTEST")
    txid = simulate_regtest_payment(identity, challenge)
    result = challenge.verify(txid, identity, "REGTEST")

    assert result.verified is True
    assert is_verified(identity.get_identity_hash()) is True

