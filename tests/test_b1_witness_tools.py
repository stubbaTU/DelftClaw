"""Red-phase tests for B1: community_donate_and_join claim envelope +
community_witness_donation tool.

All tests in this file are expected to FAIL until the Green phase lands the
two production changes:
  (a) community_donate_and_join returns subject_claim / subject_signature_hex /
      subject_pubkey_hex on its success path.
  (b) community_witness_donation is registered in build_tools.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio

from agent import AgentConfig, OpenClawAgent, build_tools
from communication.bittorrent import StubBitTorrentService
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol import StubLLMClient
from redteam.primitives.signed_log import (
    _canonical_bytes,
    _stable_hash,
)

# ---------------------------------------------------------------------------
# Manifest template (same shape as test_community_tools.py)
# ---------------------------------------------------------------------------

MANIFEST_TEMPLATE = """\
# Identity

- name: b1_witness_test
- version: 1.0.0
- description: Manifest for B1 witness tool tests.

# Admission

- gatekeeper_address: {gatekeeper_address}
- min_sats: 10000
- min_confirmations: 0
- bootstrap_cap_sats: 100000
- max_agents_per_seedbox: 3
- seedbox_cost_sats: 50000

# Genesis Peers

| host | port | pubkey_hex |
|------|------|------------|
| 127.0.0.1 | 8190 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |

# Default Overlays

- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a
"""

# Mnemonics used throughout — distinct from test_community_tools.py to avoid
# any accidental cross-test state.
_MNEMONIC_DONOR = (
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
)
_MNEMONIC_WITNESS = (
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_agent(tmp_path: Path, mnemonic: str, subdir: str, balance: int = 200_000) -> OpenClawAgent:
    save_dir = tmp_path / subdir
    save_dir.mkdir(parents=True, exist_ok=True)
    seed = MnemonicSeedSource(mnemonic).load()
    return OpenClawAgent(
        identity=AgentIdentity.from_seed(seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=save_dir,
            initial_balance_sats=balance,
            community_log_path=save_dir / "community.log",
            peer_log_dir=save_dir / "peer_logs",
        ),
        bt_service=StubBitTorrentService(save_dir=save_dir),
    )


@pytest_asyncio.fixture
async def agent(tmp_path):
    """Single donor agent with manifest loaded (mirrors test_community_tools.py)."""
    a = _make_agent(tmp_path, _MNEMONIC_DONOR, "donor")
    await a.start()
    a.load_manifest(MANIFEST_TEMPLATE.format(gatekeeper_address=a.wallet.address()))
    yield a
    await a.stop()


@pytest_asyncio.fixture
async def donor_and_witness(tmp_path):
    """Two full OpenClawAgent instances: alice=donor, bob=witness.

    Both have independent community logs and manifests. Both manifests point
    at alice's wallet address as gatekeeper so community_donate_and_join can
    debit alice's wallet without a bech32 mismatch. Bob's manifest also points
    at alice's address — this matches the demo's single-network setup.
    """
    alice = _make_agent(tmp_path, _MNEMONIC_DONOR, "alice")
    bob = _make_agent(tmp_path, _MNEMONIC_WITNESS, "bob")

    await alice.start()
    await bob.start()

    gatekeeper_addr = alice.wallet.address()
    manifest_md = MANIFEST_TEMPLATE.format(gatekeeper_address=gatekeeper_addr)
    alice.load_manifest(manifest_md)
    bob.load_manifest(manifest_md)

    yield alice, bob

    await alice.stop()
    await bob.stop()


# ---------------------------------------------------------------------------
# (a) community_donate_and_join — claim envelope tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_donate_and_join_returns_claim_envelope_on_success(agent):
    """Success result must contain the three new claim-envelope fields."""
    tools = build_tools(agent)
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})

    # Existing fields still present.
    assert "entry_hash" in result, result
    assert result["amount_sats"] == 50_000

    # New fields must be present on success.
    assert "subject_claim" in result, f"subject_claim missing from result: {result}"
    assert "subject_signature_hex" in result, f"subject_signature_hex missing from result: {result}"
    assert "subject_pubkey_hex" in result, f"subject_pubkey_hex missing from result: {result}"

    # Type checks.
    assert isinstance(result["subject_claim"], dict)
    assert isinstance(result["subject_signature_hex"], str)
    assert isinstance(result["subject_pubkey_hex"], str)

    # Length checks: ed25519 sig = 64 bytes = 128 hex chars; pubkey = 32 bytes = 64 hex chars.
    assert len(result["subject_signature_hex"]) == 128, (
        f"expected 128-char sig hex, got {len(result['subject_signature_hex'])}"
    )
    assert len(result["subject_pubkey_hex"]) == 64, (
        f"expected 64-char pubkey hex, got {len(result['subject_pubkey_hex'])}"
    )


@pytest.mark.asyncio
async def test_donate_and_join_claim_envelope_shape(agent):
    """Claim dict must have the exact structure expected by append_witness_event."""
    tools = build_tools(agent)
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})

    assert "subject_claim" in result, result
    claim = result["subject_claim"]

    assert claim["kind"] == "claim"
    assert claim["version"] == 1
    assert claim["action"] == "donation_intent"
    assert claim["subject_id"] == agent.community_reporter_id

    # claim_timestamp must parse as an ISO-8601 UTC timestamp.
    ts_str = claim["claim_timestamp"]
    dt = datetime.fromisoformat(ts_str)  # raises ValueError on bad format
    assert dt.tzinfo is not None, "claim_timestamp must be timezone-aware"

    # nonce must be 32 hex chars (secrets.token_hex(16) → 16 bytes → 32 chars).
    nonce = claim["nonce"]
    assert isinstance(nonce, str)
    assert len(nonce) == 32, f"nonce should be 32 hex chars, got {len(nonce)}"
    int(nonce, 16)  # raises ValueError if not valid hex


@pytest.mark.asyncio
async def test_donate_and_join_claim_details_hash_matches(agent):
    """The claim's details_hash must equal _stable_hash of the donation details dict."""
    from protocol.manifest import parse_manifest
    tools = build_tools(agent)
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})

    assert "subject_claim" in result, result
    claim = result["subject_claim"]

    manifest = agent.network_manifest
    expected_details = {
        "amount_sats": 50_000,
        "network_id_hex": manifest.network_id.hex(),
    }
    expected_hash = _stable_hash(expected_details)
    assert claim["details_hash"] == expected_hash, (
        f"details_hash mismatch: claim has {claim['details_hash']!r}, "
        f"expected {expected_hash!r}"
    )


@pytest.mark.asyncio
async def test_donate_and_join_claim_signature_verifies(agent):
    """subject_signature_hex must verify over canonical(subject_claim) against subject_pubkey_hex."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    tools = build_tools(agent)
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})

    assert "subject_claim" in result, result
    claim = result["subject_claim"]
    sig_bytes = bytes.fromhex(result["subject_signature_hex"])
    pubkey_bytes = bytes.fromhex(result["subject_pubkey_hex"])

    # Use the same verify path that signed_log.py uses internally.
    verify_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    try:
        verify_key.verify(sig_bytes, _canonical_bytes(claim))
    except InvalidSignature:
        pytest.fail("subject_signature_hex does not verify over canonical(subject_claim)")


@pytest.mark.asyncio
async def test_donate_and_join_subject_id_matches_pubkey_and_network(agent):
    """subject_id == SHA256(pubkey_bytes || network.encode()).hex()."""
    tools = build_tools(agent)
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})

    assert "subject_claim" in result, result
    claim = result["subject_claim"]
    pubkey_bytes = bytes.fromhex(result["subject_pubkey_hex"])

    # Network for TESTNET agents: "TESTNET" (OpenClawIdentity uppercases it).
    network = agent.identity.network.upper()
    expected_subject_id = hashlib.sha256(pubkey_bytes + network.encode("utf-8")).hexdigest()
    assert claim["subject_id"] == expected_subject_id, (
        f"subject_id {claim['subject_id']!r} != SHA256(pubkey||network) {expected_subject_id!r}"
    )


@pytest.mark.asyncio
async def test_donate_and_join_two_calls_have_distinct_nonces(donor_and_witness, tmp_path):
    """Two separate donate_and_join calls produce different nonces.

    We use two separate agents (donor + witness) to avoid the already_admitted
    guard on the second call from the same agent.
    """
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    result_a = await tools_a.dispatch("community_donate_and_join", {"amount_sats": 50_000})
    result_b = await tools_b.dispatch("community_donate_and_join", {"amount_sats": 50_000})

    assert "subject_claim" in result_a, result_a
    assert "subject_claim" in result_b, result_b

    nonce_a = result_a["subject_claim"]["nonce"]
    nonce_b = result_b["subject_claim"]["nonce"]
    assert nonce_a != nonce_b, "Two separate calls produced the same nonce — bad RNG or cached result"


@pytest.mark.asyncio
async def test_donate_and_join_error_path_omits_claim(agent):
    """Error results (amount below min_sats) must NOT include claim envelope fields."""
    tools = build_tools(agent)
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": 1_000})

    assert "error" in result, f"expected error, got: {result}"
    assert "subject_claim" not in result, f"subject_claim must not appear on error path: {result}"
    assert "subject_signature_hex" not in result, f"subject_signature_hex must not appear on error path: {result}"
    assert "subject_pubkey_hex" not in result, f"subject_pubkey_hex must not appear on error path: {result}"


@pytest.mark.asyncio
async def test_donate_and_join_input_schema_unchanged(agent):
    """The tool's parameter schema must still only require amount_sats — no new required fields."""
    tools = build_tools(agent)
    specs = {s["function"]["name"]: s for s in tools.specs()}
    assert "community_donate_and_join" in specs

    params = specs["community_donate_and_join"]["function"]["parameters"]
    required = params.get("required", [])
    assert required == ["amount_sats"], (
        f"community_donate_and_join required fields changed: {required}"
    )


# ---------------------------------------------------------------------------
# (b) community_witness_event — generic witness tool tests
# ---------------------------------------------------------------------------


async def _do_donate(tools, amount_sats: int = 50_000) -> dict:
    """Helper: call community_donate_and_join and assert it produced a claim."""
    result = await tools.dispatch("community_donate_and_join", {"amount_sats": amount_sats})
    assert "subject_claim" in result, (
        f"donate_and_join did not return subject_claim: {result}"
    )
    return result


def _witness_payload(donate_result: dict, **overrides) -> dict:
    """Build the standard witness payload from a donor's donate_and_join result.

    ``overrides`` replaces any of the five fields (action, details,
    subject_claim, subject_signature_hex, subject_pubkey_hex).
    """
    payload = {
        "action": "donation_intent",
        "details": {
            "amount_sats": donate_result["amount_sats"],
            "network_id_hex": donate_result["network_id_hex"],
        },
        "subject_claim": donate_result["subject_claim"],
        "subject_signature_hex": donate_result["subject_signature_hex"],
        "subject_pubkey_hex": donate_result["subject_pubkey_hex"],
    }
    payload.update(overrides)
    return payload


@pytest.mark.asyncio
async def test_witness_event_appends_witness_entry_to_log(donor_and_witness):
    """Donor's envelope flows verbatim into witness's log as a 'witness' kind entry."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a)
    before = list(bob.community_log.read_entries())

    witness_result = await tools_b.dispatch(
        "community_witness_event", _witness_payload(donate_result)
    )

    assert "error" not in witness_result, f"witness tool returned error: {witness_result}"

    after = list(bob.community_log.read_entries())
    assert len(after) == len(before) + 1, "expected exactly one new entry in witness log"

    new_entry = after[-1]
    assert new_entry["kind"] == "witness", f"expected kind==witness, got {new_entry['kind']!r}"
    assert new_entry["subject_id"] == alice.community_reporter_id, (
        f"subject_id mismatch: {new_entry['subject_id']!r} != {alice.community_reporter_id!r}"
    )
    assert new_entry["action"] == "donation_intent"


@pytest.mark.asyncio
async def test_witness_event_returns_entry_hash_and_subject_id(donor_and_witness):
    """Success return must be {entry_hash: <hex>, subject_id: <hex>}."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a)
    witness_result = await tools_b.dispatch(
        "community_witness_event", _witness_payload(donate_result)
    )

    assert "error" not in witness_result, witness_result
    assert "entry_hash" in witness_result
    assert "subject_id" in witness_result

    entries = list(bob.community_log.read_entries())
    latest_hash = entries[-1]["entry_hash"]
    assert witness_result["entry_hash"] == latest_hash
    assert witness_result["subject_id"] == alice.community_reporter_id


@pytest.mark.asyncio
async def test_witness_event_rejects_tampered_signature(donor_and_witness):
    """Flipping one hex char in subject_signature_hex must cause an error, log unchanged."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a)

    original_sig = donate_result["subject_signature_hex"]
    flipped_char = "1" if original_sig[0] != "1" else "0"
    tampered_sig = flipped_char + original_sig[1:]

    before = list(bob.community_log.read_entries())

    witness_result = await tools_b.dispatch(
        "community_witness_event",
        _witness_payload(donate_result, subject_signature_hex=tampered_sig),
    )

    assert "error" in witness_result, f"expected error with tampered sig, got: {witness_result}"
    after = list(bob.community_log.read_entries())
    assert len(after) == len(before), "log must not grow when signature is invalid"


@pytest.mark.asyncio
async def test_witness_event_rejects_mismatched_details(donor_and_witness):
    """Passing details with a different amount than the claim signed-over must fail
    the subject_claim.details_hash == _stable_hash(details) check."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a, amount_sats=50_000)

    bad_details = {
        "amount_sats": 49_999,
        "network_id_hex": donate_result["network_id_hex"],
    }
    witness_result = await tools_b.dispatch(
        "community_witness_event",
        _witness_payload(donate_result, details=bad_details),
    )

    assert "error" in witness_result, (
        f"expected error when details don't match claim, got: {witness_result}"
    )


@pytest.mark.asyncio
async def test_witness_event_rejects_mismatched_action(donor_and_witness):
    """Passing an action that doesn't match subject_claim.action must fail
    the subject_claim.action == action check."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a)

    witness_result = await tools_b.dispatch(
        "community_witness_event",
        _witness_payload(donate_result, action="seedbox_purchase_intent"),
    )

    assert "error" in witness_result, (
        f"expected error when action mismatches claim, got: {witness_result}"
    )


@pytest.mark.asyncio
async def test_witness_event_rejects_subject_id_not_matching_pubkey(donor_and_witness):
    """Mutating envelope's subject_id to a fake hash must cause an error."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a)

    tampered_claim = dict(donate_result["subject_claim"])
    tampered_claim["subject_id"] = "a" * 64

    witness_result = await tools_b.dispatch(
        "community_witness_event",
        _witness_payload(donate_result, subject_claim=tampered_claim),
    )

    assert "error" in witness_result, (
        f"expected error for mismatched subject_id, got: {witness_result}"
    )


@pytest.mark.asyncio
async def test_witness_event_works_without_manifest(tmp_path, donor_and_witness):
    """The witness tool is manifest-independent: a fresh agent with no manifest
    can still witness a foreign claim, since witnessing only consumes the
    counterparty's signed envelope."""
    alice, _ = donor_and_witness
    tools_a = build_tools(alice)
    donate_result = await _do_donate(tools_a)

    bare = _make_agent(tmp_path, _MNEMONIC_WITNESS, "bare_witness")
    await bare.start()
    try:
        tools = build_tools(bare)
        result = await tools.dispatch(
            "community_witness_event", _witness_payload(donate_result)
        )
        assert "error" not in result, f"witness should succeed without manifest: {result}"
        assert "entry_hash" in result
    finally:
        await bare.stop()


@pytest.mark.asyncio
async def test_witness_event_rejects_non_dict_details(donor_and_witness):
    """``details`` must be a dict; passing a string yields an error."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a)
    before = list(bob.community_log.read_entries())

    result = await tools_b.dispatch(
        "community_witness_event",
        _witness_payload(donate_result, details="not-a-dict"),
    )
    assert "error" in result, result
    after = list(bob.community_log.read_entries())
    assert len(after) == len(before), "log must not grow when details type is invalid"


@pytest.mark.asyncio
async def test_witness_event_registered_in_registry(agent):
    """community_witness_event must appear in the registry with a correct spec."""
    tools = build_tools(agent)

    assert "community_witness_event" in tools.names(), (
        "community_witness_event not found in tool registry"
    )

    specs = {s["function"]["name"]: s for s in tools.specs()}
    assert "community_witness_event" in specs

    spec = specs["community_witness_event"]
    assert spec["type"] == "function"

    params = spec["function"]["parameters"]
    required = set(params.get("required", []))
    expected_required = {
        "action", "details", "subject_claim",
        "subject_signature_hex", "subject_pubkey_hex",
    }
    assert required == expected_required, (
        f"required params mismatch: got {required}, expected {expected_required}"
    )

    properties = params.get("properties", {})
    for field in expected_required:
        assert field in properties, f"property {field!r} missing from spec"


# ---------------------------------------------------------------------------
# Review-pass additions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_witness_event_rejects_pubkey_not_matching_subject_id(donor_and_witness):
    """Swapping subject_pubkey_hex to a different agent's pubkey must fail
    the SHA256(pubkey||network)==subject_id binding (validation #2)."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a)

    from identity.openclaw_identity import OpenClawIdentity
    bob_pubkey_hex = OpenClawIdentity.from_agent_identity(bob.identity).public_key.hex()

    before = list(bob.community_log.read_entries())

    witness_result = await tools_b.dispatch(
        "community_witness_event",
        _witness_payload(donate_result, subject_pubkey_hex=bob_pubkey_hex),
    )

    assert "error" in witness_result, (
        f"expected error when pubkey doesn't match subject_id, got: {witness_result}"
    )
    after = list(bob.community_log.read_entries())
    assert len(after) == len(before), "log must not grow when pubkey binding fails"


@pytest.mark.asyncio
async def test_witness_event_success_entry_has_correct_details_hash(donor_and_witness):
    """A successfully appended witness entry must carry the correct details_hash
    so the audit trail can be re-verified."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a, amount_sats=50_000)

    witness_result = await tools_b.dispatch(
        "community_witness_event", _witness_payload(donate_result)
    )
    assert "error" not in witness_result, witness_result

    expected_details = {
        "amount_sats": 50_000,
        "network_id_hex": donate_result["network_id_hex"],
    }
    expected_hash = _stable_hash(expected_details)

    entries = list(bob.community_log.read_entries())
    new_entry = entries[-1]
    assert new_entry["details_hash"] == expected_hash, (
        f"persisted details_hash {new_entry['details_hash']!r} != expected {expected_hash!r}"
    )


@pytest.mark.asyncio
async def test_donate_and_join_already_admitted_omits_claim(agent):
    """Re-calling donate_and_join after admission must error AND omit claim fields."""
    tools = build_tools(agent)

    first = await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})
    assert "subject_claim" in first, f"first call should succeed: {first}"

    second = await tools.dispatch("community_donate_and_join", {"amount_sats": 50_000})

    assert "error" in second, f"second call should error, got: {second}"
    assert "subject_claim" not in second, f"claim must not leak on already_admitted: {second}"
    assert "subject_signature_hex" not in second
    assert "subject_pubkey_hex" not in second


@pytest.mark.asyncio
async def test_witness_event_rejects_invalid_hex_signature(donor_and_witness):
    """Non-hex characters in subject_signature_hex must yield {"error": ...}."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a)

    witness_result = await tools_b.dispatch(
        "community_witness_event",
        _witness_payload(donate_result, subject_signature_hex="ZZ" + "a" * 126),
    )
    assert "error" in witness_result, witness_result
    assert "subject_signature_hex" in witness_result["error"], witness_result


@pytest.mark.asyncio
async def test_witness_event_rejects_invalid_hex_pubkey(donor_and_witness):
    """Non-hex characters in subject_pubkey_hex must yield {"error": ...}."""
    alice, bob = donor_and_witness
    tools_a = build_tools(alice)
    tools_b = build_tools(bob)

    donate_result = await _do_donate(tools_a)

    witness_result = await tools_b.dispatch(
        "community_witness_event",
        _witness_payload(donate_result, subject_pubkey_hex="ZZ" + "a" * 62),
    )
    assert "error" in witness_result, witness_result
    assert "subject_pubkey_hex" in witness_result["error"], witness_result
