"""Tests for ``protocol.manifest`` + the manifest wire messages on SeedboxCommunity.

Covers:

  * Schema-failure paths (missing sections, malformed hashes, bad
    ports, bad name formats).
  * Canonicalization stability (same content under different whitespace
    produces the same network_id).
  * Positive parse of the bundled example.
  * SeedboxCommunity publish/offer/fetch round-trip + defensive re-hash
    on delivery (mirroring the OVERLAY_* tests in test_overlay_registry.py).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio
from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.community import (
    MAX_OVERLAY_BYTES,
    SeedboxCommunity,
    manifest_id,
)
from protocol.manifest import (
    AdmissionPolicy,
    GenesisPeer,
    ManifestParseError,
    NetworkManifest,
    network_id_from_manifest,
    parse_manifest,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


# A minimal valid manifest used as a fixture — kept here so test bodies
# can mutate one section at a time without rewriting the whole thing.
GOOD_MANIFEST = """\
# Identity

- name: testnet
- version: 1.0.0
- description: A small test network.

# Admission

- gatekeeper_address: tb1qexamplexxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
- min_sats: 10000
- min_confirmations: 0

# Genesis Peers

| host | port | pubkey_hex |
|------|------|------------|
| 127.0.0.1 | 8190 | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |

# Default Overlays

- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a  (content_community v1)
"""


# ---------------------------------------------------------------------------
# Positive parse
# ---------------------------------------------------------------------------

def test_parse_good_manifest_extracts_every_field():
    manifest = parse_manifest(GOOD_MANIFEST)

    assert isinstance(manifest, NetworkManifest)
    assert manifest.identity["name"] == "testnet"
    assert manifest.identity["version"] == "1.0.0"
    assert manifest.identity["description"].startswith("A small test")
    assert isinstance(manifest.admission, AdmissionPolicy)
    assert manifest.admission.min_sats == 10000
    assert manifest.admission.min_confirmations == 0
    assert manifest.admission.gatekeeper_address.startswith("tb1q")
    assert len(manifest.genesis_peers) == 1
    peer = manifest.genesis_peers[0]
    assert isinstance(peer, GenesisPeer)
    assert peer.host == "127.0.0.1"
    assert peer.port == 8190
    assert peer.pubkey_hex.startswith("aaaa")
    assert manifest.default_overlays == (
        "a3455e9cec3b78bc281f1c495b0a08baa733833a",
    )
    assert len(manifest.network_id) == 20


def test_parse_bundled_example_manifest():
    """The example manifest the repo ships parses cleanly."""
    text = (REPO_ROOT / "protocol" / "examples" / "delftclaw_network.md").read_text(
        encoding="utf-8"
    )
    manifest = parse_manifest(text)
    assert manifest.identity["name"] == "delftclaw_seek_cc"
    assert manifest.default_overlays == (
        "a3455e9cec3b78bc281f1c495b0a08baa733833a",
    )


# ---------------------------------------------------------------------------
# Section ordering + presence
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("section", ["Identity", "Admission", "Genesis Peers", "Default Overlays"])
def test_missing_required_section_rejected(section: str):
    """A manifest without one of the four required headings is rejected."""
    text = GOOD_MANIFEST.replace(f"# {section}", f"## {section}_renamed")
    with pytest.raises(ManifestParseError, match="missing required sections"):
        parse_manifest(text)


def test_required_sections_out_of_order_rejected():
    """Permuting the required headings produces an error pointing at order."""
    # Swap Admission and Identity.
    swapped = (
        "# Admission\n\n- gatekeeper_address: tb1qexamplexxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
        "- min_sats: 10000\n- min_confirmations: 0\n\n"
        "# Identity\n\n- name: testnet\n- version: 1.0.0\n- description: x\n\n"
        "# Genesis Peers\n\n| host | port | pubkey_hex |\n|---|---|---|\n"
        "| 127.0.0.1 | 8190 | "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |\n\n"
        "# Default Overlays\n\n- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a\n"
    )
    with pytest.raises(ManifestParseError, match="in order"):
        parse_manifest(swapped)


# ---------------------------------------------------------------------------
# # Identity validation
# ---------------------------------------------------------------------------

def test_identity_name_not_snake_case_rejected():
    text = GOOD_MANIFEST.replace("- name: testnet", "- name: TestNet")
    with pytest.raises(ManifestParseError, match="snake_case"):
        parse_manifest(text)


def test_identity_version_not_semver_rejected():
    text = GOOD_MANIFEST.replace("- version: 1.0.0", "- version: 1.0")
    with pytest.raises(ManifestParseError, match="semver"):
        parse_manifest(text)


# ---------------------------------------------------------------------------
# # Admission validation
# ---------------------------------------------------------------------------

def test_admission_address_must_be_bech32():
    text = GOOD_MANIFEST.replace(
        "- gatekeeper_address: tb1qexamplexxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "- gatekeeper_address: 1NotABech32Address",
    )
    with pytest.raises(ManifestParseError, match="bech32"):
        parse_manifest(text)


def test_admission_min_sats_must_be_positive():
    text = GOOD_MANIFEST.replace("- min_sats: 10000", "- min_sats: 0")
    with pytest.raises(ManifestParseError, match=">= 1"):
        parse_manifest(text)


def test_admission_min_confirmations_must_be_in_range():
    text = GOOD_MANIFEST.replace(
        "- min_confirmations: 0", "- min_confirmations: 70000"
    )
    with pytest.raises(ManifestParseError, match=r"\[0, 65535\]"):
        parse_manifest(text)


# ---------------------------------------------------------------------------
# # Admission — community-treasury / seedbox-growth optional fields
# ---------------------------------------------------------------------------

def test_admission_optional_fields_default_to_zero():
    """Pre-v5.2 manifests (without the 3 new fields) still parse; defaults are 0."""
    manifest = parse_manifest(GOOD_MANIFEST)
    assert manifest.admission.bootstrap_cap_sats == 0
    assert manifest.admission.max_agents_per_seedbox == 0
    assert manifest.admission.seedbox_cost_sats == 0


def test_admission_bootstrap_cap_falls_back_to_10x_min_sats_when_omitted():
    """The default bootstrap cap is 10 * min_sats when the field is absent or 0."""
    manifest = parse_manifest(GOOD_MANIFEST)
    assert manifest.admission.effective_bootstrap_cap_sats == 10 * 10000


def test_admission_seedbox_growth_disabled_when_either_field_zero():
    """Both max_agents_per_seedbox AND seedbox_cost_sats must be > 0 to enable growth."""
    manifest = parse_manifest(GOOD_MANIFEST)
    assert manifest.admission.seedbox_growth_enabled is False


def test_admission_parses_all_three_new_fields():
    text = GOOD_MANIFEST.replace(
        "- min_confirmations: 0",
        "- min_confirmations: 0\n"
        "- bootstrap_cap_sats: 100000\n"
        "- max_agents_per_seedbox: 3\n"
        "- seedbox_cost_sats: 50000",
    )
    manifest = parse_manifest(text)
    assert manifest.admission.bootstrap_cap_sats == 100000
    assert manifest.admission.effective_bootstrap_cap_sats == 100000
    assert manifest.admission.max_agents_per_seedbox == 3
    assert manifest.admission.seedbox_cost_sats == 50000
    assert manifest.admission.seedbox_growth_enabled is True


def test_admission_bootstrap_cap_below_min_sats_rejected():
    text = GOOD_MANIFEST.replace(
        "- min_confirmations: 0",
        "- min_confirmations: 0\n- bootstrap_cap_sats: 5000",  # min_sats is 10_000
    )
    with pytest.raises(ManifestParseError, match=">= min_sats"):
        parse_manifest(text)


def test_admission_negative_bootstrap_cap_rejected():
    text = GOOD_MANIFEST.replace(
        "- min_confirmations: 0",
        "- min_confirmations: 0\n- bootstrap_cap_sats: -1",
    )
    with pytest.raises(ManifestParseError, match=">= 0"):
        parse_manifest(text)


def test_admission_non_int_max_agents_per_seedbox_rejected():
    text = GOOD_MANIFEST.replace(
        "- min_confirmations: 0",
        "- min_confirmations: 0\n- max_agents_per_seedbox: many",
    )
    with pytest.raises(ManifestParseError, match="max_agents_per_seedbox"):
        parse_manifest(text)


def test_admission_max_agents_per_seedbox_out_of_range_rejected():
    text = GOOD_MANIFEST.replace(
        "- min_confirmations: 0",
        "- min_confirmations: 0\n- max_agents_per_seedbox: 70000",
    )
    with pytest.raises(ManifestParseError, match="<= 65535"):
        parse_manifest(text)


def test_admission_only_one_of_two_growth_fields_set_means_disabled():
    """Setting max_agents_per_seedbox without seedbox_cost_sats keeps growth off."""
    text = GOOD_MANIFEST.replace(
        "- min_confirmations: 0",
        "- min_confirmations: 0\n- max_agents_per_seedbox: 3",
    )
    manifest = parse_manifest(text)
    assert manifest.admission.max_agents_per_seedbox == 3
    assert manifest.admission.seedbox_cost_sats == 0
    assert manifest.admission.seedbox_growth_enabled is False


def test_bundled_example_manifest_parses_with_growth_enabled():
    """The seek_cc example manifest now declares the growth fields."""
    text = (REPO_ROOT / "protocol" / "examples" / "delftclaw_network.md").read_text(
        encoding="utf-8"
    )
    manifest = parse_manifest(text)
    assert manifest.admission.bootstrap_cap_sats == 100000
    assert manifest.admission.max_agents_per_seedbox == 3
    assert manifest.admission.seedbox_cost_sats == 50000
    assert manifest.admission.seedbox_growth_enabled is True


# ---------------------------------------------------------------------------
# # Genesis Peers validation
# ---------------------------------------------------------------------------

def test_genesis_peer_port_must_be_in_range():
    text = GOOD_MANIFEST.replace(
        "| 127.0.0.1 | 8190 |", "| 127.0.0.1 | 80 |"
    )
    with pytest.raises(ManifestParseError, match=r"\[1024, 65535\]"):
        parse_manifest(text)


def test_genesis_peer_pubkey_must_be_hex():
    text = GOOD_MANIFEST.replace(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    )
    with pytest.raises(ManifestParseError, match="hex"):
        parse_manifest(text)


def test_duplicate_genesis_peers_rejected():
    text = GOOD_MANIFEST.replace(
        "| 127.0.0.1 | 8190 | "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |\n",
        "| 127.0.0.1 | 8190 | "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |\n"
        "| 127.0.0.1 | 8190 | "
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb |\n",
    )
    with pytest.raises(ManifestParseError, match="duplicate"):
        parse_manifest(text)


def test_genesis_peers_empty_table_rejected():
    text = GOOD_MANIFEST.replace(
        "| host | port | pubkey_hex |\n"
        "|------|------|------------|\n"
        "| 127.0.0.1 | 8190 | "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa |\n",
        "(no peers wired up)\n",
    )
    with pytest.raises(ManifestParseError, match="contained no table"):
        parse_manifest(text)


# ---------------------------------------------------------------------------
# # Default Overlays validation
# ---------------------------------------------------------------------------

def test_default_overlays_section_may_be_empty():
    """A network with no default overlays is legal — admission alone is enough."""
    text = GOOD_MANIFEST.replace(
        "- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a  (content_community v1)\n",
        "(none — joiners discover overlays via OVERLAY_OFFER)\n",
    )
    manifest = parse_manifest(text)
    assert manifest.default_overlays == ()


def test_duplicate_default_overlay_hashes_rejected():
    text = GOOD_MANIFEST.replace(
        "- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a  (content_community v1)\n",
        "- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a  (a)\n"
        "- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a  (b)\n",
    )
    with pytest.raises(ManifestParseError, match="duplicate"):
        parse_manifest(text)


# ---------------------------------------------------------------------------
# Canonicalization / network_id stability
# ---------------------------------------------------------------------------

def test_network_id_stable_across_whitespace_permutations():
    """Trailing whitespace, CRLF, and extra blank lines must not change network_id."""
    a = parse_manifest(GOOD_MANIFEST)
    b = parse_manifest(GOOD_MANIFEST.replace("\n", "\r\n"))
    c = parse_manifest(GOOD_MANIFEST + "\n\n\n")
    d = parse_manifest(
        # Add trailing spaces to every non-empty line.
        "\n".join(
            line + ("   " if line.strip() else "") for line in GOOD_MANIFEST.split("\n")
        )
    )
    assert a.network_id == b.network_id == c.network_id == d.network_id


def test_network_id_changes_when_admission_changes():
    a = parse_manifest(GOOD_MANIFEST)
    different = GOOD_MANIFEST.replace("- min_sats: 10000", "- min_sats: 20000")
    b = parse_manifest(different)
    assert a.network_id != b.network_id


def test_network_id_from_manifest_matches_parse():
    a = parse_manifest(GOOD_MANIFEST).network_id
    b = network_id_from_manifest(GOOD_MANIFEST)
    assert a == b


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------

def test_non_str_input_rejected():
    with pytest.raises(ManifestParseError, match="must be str"):
        parse_manifest(b"# Identity")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# SeedboxCommunity manifest publish / offer / fetch round-trip
# ---------------------------------------------------------------------------

def _build_node(port: int, key_path: Path) -> IPv8:
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(port)
    builder.set_address("127.0.0.1")
    builder.add_key("anchor", "curve25519", str(key_path))
    builder.add_overlay("SeedboxCommunity", "anchor", [], [], {}, [("started",)])
    return IPv8(
        builder.finalize(),
        extra_communities={"SeedboxCommunity": SeedboxCommunity},
    )


@pytest_asyncio.fixture
async def two_seedboxes(tmp_path):
    """Two IPv8 nodes running only SeedboxCommunity, pre-introduced to each other."""
    from ipv8.keyvault.crypto import default_eccrypto

    key_a = tmp_path / "a.key"
    key_b = tmp_path / "b.key"
    key_a.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())
    key_b.write_bytes(default_eccrypto.generate_key("curve25519").key_to_bin())

    svc_a = _build_node(port=0, key_path=key_a)
    svc_b = _build_node(port=0, key_path=key_b)
    await svc_a.start()
    await svc_b.start()

    sb_a = next(o for o in svc_a.overlays if isinstance(o, SeedboxCommunity))
    sb_b = next(o for o in svc_b.overlays if isinstance(o, SeedboxCommunity))

    addr_a = sb_a.endpoint.get_address()
    addr_b = sb_b.endpoint.get_address()
    peer_b_for_a = Peer(sb_b.my_peer.public_key, address=addr_b)
    peer_a_for_b = Peer(sb_a.my_peer.public_key, address=addr_a)
    sb_a.network.add_verified_peer(peer_b_for_a)
    sb_b.network.add_verified_peer(peer_a_for_b)

    yield sb_a, sb_b, peer_a_for_b, peer_b_for_a

    await svc_a.stop()
    await svc_b.stop()


def test_manifest_id_matches_parse_manifest():
    """The bytes the community uses on the wire match the parser's derivation."""
    parsed = parse_manifest(GOOD_MANIFEST)
    assert manifest_id(GOOD_MANIFEST) == parsed.network_id


@pytest.mark.asyncio
async def test_manifest_publish_and_fetch_round_trip(two_seedboxes):
    sb_a, sb_b, peer_a_for_b, _ = two_seedboxes
    md_hash = sb_a.publish_manifest(GOOD_MANIFEST)
    assert md_hash in sb_a.published_manifests

    fut = sb_b.fetch_manifest(peer_a_for_b, md_hash)
    md_bytes = await asyncio.wait_for(fut, timeout=2.0)
    assert md_bytes.decode("utf-8") == GOOD_MANIFEST


@pytest.mark.asyncio
async def test_manifest_offer_callback_fires(two_seedboxes):
    sb_a, sb_b, _, peer_b_for_a = two_seedboxes
    seen: list[bytes] = []
    sb_b.configure(manifest_offer_callback=lambda peer, h: seen.append(h))
    md_hash = manifest_id(GOOD_MANIFEST)
    sb_a.offer_manifest(peer_b_for_a, md_hash)
    for _ in range(40):
        if seen:
            break
        await asyncio.sleep(0.05)
    assert seen == [md_hash]


@pytest.mark.asyncio
async def test_manifest_fetch_unknown_hash_times_out(two_seedboxes):
    sb_a, sb_b, peer_a_for_b, _ = two_seedboxes
    fut = sb_b.fetch_manifest(peer_a_for_b, b"\x00" * 20)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(fut, timeout=0.4)


@pytest.mark.asyncio
async def test_manifest_delivery_with_wrong_hash_dropped(two_seedboxes):
    """If a peer's body doesn't re-hash to the claimed id, the future stays pending."""
    sb_a, sb_b, peer_a_for_b, _ = two_seedboxes

    # Publish manifest A; have B request a different hash; manually push a
    # delivery payload through with a body that does NOT match the requested hash.
    fake_hash = b"\xde" * 20
    fut = sb_b.fetch_manifest(peer_a_for_b, fake_hash)

    from communication.community import ManifestDeliveryPayload
    real_text = GOOD_MANIFEST  # canonical id is network_id_from_manifest(GOOD_MANIFEST), not fake_hash
    sb_a.ez_send(
        Peer(sb_b.my_peer.public_key, address=sb_b.endpoint.get_address()),
        ManifestDeliveryPayload(fake_hash, real_text.encode("utf-8")),
    )

    await asyncio.sleep(0.2)
    assert not fut.done(), "delivery whose body does not match claimed hash must be dropped"
    fut.cancel()


def test_manifest_publish_returns_canonical_id():
    """Two whitespace variants of the same manifest produce the same id."""
    md1 = GOOD_MANIFEST
    md2 = GOOD_MANIFEST + "\n\n\n"
    assert manifest_id(md1) == manifest_id(md2)
