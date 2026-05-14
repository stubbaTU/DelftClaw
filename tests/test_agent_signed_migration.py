"""Red-step TDD tests for Phase C: migrating ``P2PAgent`` (agent.py) onto
``SignedAppendOnlyLog``.

These tests assert the post-Phase-C contract:

1. ``OpenClawIdentity`` exposes a ``from_agent_identity`` factory that
   adapts an in-memory ``AgentIdentity`` (which ``P2PAgent`` already
   builds from a mnemonic seed) into an ``OpenClawIdentity`` without
   round-tripping through a file-based key path.
2. ``P2PAgent.host_log`` is a ``SignedAppendOnlyLog`` (not the unsigned
   legacy ``AppendOnlyLog``).
3. Entries written via ``agent.proxy.log_action`` are properly signed
   *and* identity-bound: ``verify_integrity()`` must pass, which means
   the proxy's ``agent_id`` matches ``SHA256(reporter_pubkey || network)``.

All three tests are expected to FAIL before the Green step is
implemented. The ``on_message`` ``log_broadcast`` path is intentionally
not exercised here — that path writes entries with ``reporter_id`` set to
a *peer's* id while the local identity signs, which is an
identity-binding mismatch that requires a witness-entry refactor; it is
explicitly out of scope for Phase C.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from bitcoinlib.mnemonic import Mnemonic

from agent import P2PAgent
from identity.agent_identity import AgentIdentity
from identity.openclaw_identity import OpenClawIdentity
from redteam.primitives.signed_log import SignedAppendOnlyLog


def test_openclaw_identity_from_agent_identity_factory_exists() -> None:
    """OpenClawIdentity must expose an in-memory factory off an AgentIdentity.

    P2PAgent already holds an ``AgentIdentity`` (derived from its mnemonic
    seed). The Green step adds ``OpenClawIdentity.from_agent_identity`` so
    callers in that situation can produce a compatible OpenClawIdentity
    without writing a JSON key file or re-deriving keys.
    """
    agent_identity = AgentIdentity(network="TESTNET")

    wrapped = OpenClawIdentity.from_agent_identity(agent_identity)

    assert isinstance(wrapped, OpenClawIdentity), (
        f"factory must return OpenClawIdentity, got {type(wrapped).__name__}"
    )
    assert wrapped.network == agent_identity.network, (
        f"network mismatch: wrapped={wrapped.network!r} "
        f"agent={agent_identity.network!r}"
    )
    assert wrapped.public_key == agent_identity.ipv8.raw_pubkey, (
        "wrapped.public_key must equal the underlying ipv8 raw_pubkey"
    )
    expected_hash = hashlib.sha256(
        agent_identity.ipv8.raw_pubkey + wrapped.network.encode("utf-8")
    ).hexdigest()
    assert wrapped.identity_hash == expected_hash, (
        "OpenClawIdentity.identity_hash must equal SHA256(raw_ed25519_pubkey || network_utf8)"
    )

    # Ed25519 signatures are deterministic, so both signers operating on
    # the same key material over the same message must produce identical
    # signature bytes. This is the strongest available assertion that the
    # factory bound the *same* underlying key rather than a fresh one.
    payload = b"hello"
    assert wrapped.sign(payload) == agent_identity.ipv8.sign(payload), (
        "wrapped.sign must produce identical bytes to "
        "agent_identity.ipv8.sign (same underlying key)"
    )


def test_p2p_agent_host_log_is_signed(tmp_path: Path) -> None:
    """After Phase C, P2PAgent.host_log must be a SignedAppendOnlyLog."""
    seed_phrase = Mnemonic().generate()
    log_path = tmp_path / "agent.log"

    agent = P2PAgent(
        host="127.0.0.1",
        port=18301,
        seed_phrase=seed_phrase,
        log_path=str(log_path),
    )

    assert isinstance(agent.host_log, SignedAppendOnlyLog), (
        "P2PAgent.host_log must be SignedAppendOnlyLog after Phase C, "
        f"got {type(agent.host_log).__name__}"
    )


def test_p2p_agent_proxy_writes_verifiable_signed_entries(tmp_path: Path) -> None:
    """proxy.log_action must produce a signed, identity-bound entry.

    This is the key behavior bet of Phase C: after migration, the
    IsolationProxy's ``agent_id`` (which becomes the entry's
    ``reporter_id``) must derive from the same key/network the
    SignedAppendOnlyLog signs with — otherwise verify_integrity's
    identity-binding check fails.
    """
    seed_phrase = Mnemonic().generate()
    log_path = tmp_path / "agent.log"

    agent = P2PAgent(
        host="127.0.0.1",
        port=18302,
        seed_phrase=seed_phrase,
        log_path=str(log_path),
    )

    agent.proxy.log_action("tool_execution_success", {"tool": "noop"})

    entries = agent.host_log.read_entries()
    assert len(entries) == 1, (
        f"expected exactly 1 entry, got {len(entries)}"
    )

    entry = entries[0]
    assert isinstance(entry.get("signature"), str) and entry["signature"], (
        "entry is missing a non-empty signature field"
    )
    assert (
        isinstance(entry.get("reporter_pubkey"), str)
        and entry["reporter_pubkey"]
    ), (
        "entry is missing a non-empty reporter_pubkey field"
    )
    assert entry.get("version") == 2, (
        f"expected version 2, got {entry.get('version')!r}"
    )

    ok, errors = agent.host_log.verify_integrity()
    assert (ok, errors) == (True, []), (
        f"verify_integrity failed: ok={ok}, errors={errors}. "
        "This indicates the proxy's agent_id does not match "
        "SHA256(reporter_pubkey || network) — the Phase C migration "
        "must derive reporter_id from the OpenClawIdentity, not from "
        "P2PAgent.security_id (which is the raw SECP pubkey hex)."
    )
