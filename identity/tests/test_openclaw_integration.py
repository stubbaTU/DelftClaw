from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import identity.verification as verification
from identity.mcp_server import IdentityMCPServer


def _call(client: TestClient, tool_name: str, args: dict | None = None) -> dict:
    response = client.post(f"/mcp/tool/{tool_name}", json={"args": args or {}})
    assert response.status_code == 200
    return response.json()


def test_openclaw_mcp_tool_flow(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(verification, "_LOG_PATH", tmp_path / "verification_log.json")
    monkeypatch.setattr(verification, "_TX_LEDGER_PATH", tmp_path / "verification_txs.json")

    identity_path = tmp_path / "agent_identity.json"
    server = IdentityMCPServer.boot(identity_path=identity_path, network="REGTEST")
    client = TestClient(server.create_app())

    identity = _call(client, "get_identity")
    assert identity["agent_id"]
    assert identity["wallet_address"]

    balance = _call(client, "get_wallet_balance")
    assert "balance_satoshis" in balance

    signed = _call(client, "sign_message", {"message": "hello"})
    verified_msg = _call(
        client,
        "verify_message",
        {
            "message": "hello",
            "signature_hex": signed["signature_hex"],
            "agent_id": signed["agent_id"],
        },
    )
    assert verified_msg["valid"] is True

    vc = _call(client, "issue_credential", {"claims": {"role": "seedbox"}})
    vc_check = _call(client, "verify_credential", {"vc": vc, "expected_issuer_id": identity["agent_id"]})
    assert vc_check["valid"] is True

    challenge = _call(client, "create_verification_challenge")
    assert challenge["amount_satoshis"] == 1000

    sim = _call(client, "simulate_regtest_payment")
    submit = _call(client, "submit_verification", {"txid": sim["txid"]})
    assert submit["verified"] is True

    status = _call(client, "check_verification_status", {"agent_id": identity["agent_id"]})
    assert status["verified"] is True

