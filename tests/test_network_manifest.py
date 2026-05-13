"""Tests for ``protocol.manifest.parse_manifest``.

Covers schema-failure paths (missing sections, malformed hashes, bad
ports, bad name formats), canonicalization stability (same content
under different whitespace produces the same network_id), and a
positive parse of the bundled example.

Step 2's publish/offer/fetch round-trip lives in
``test_peer_intro.py`` to keep this file focused on the parser.
"""

from __future__ import annotations

from pathlib import Path

import pytest

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

- sha1: 0b5cafdd65c3e0021949bdc8f071d830ef5ce66f  (content_community v1)
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
        "0b5cafdd65c3e0021949bdc8f071d830ef5ce66f",
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
        "0b5cafdd65c3e0021949bdc8f071d830ef5ce66f",
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
        "# Default Overlays\n\n- sha1: 0b5cafdd65c3e0021949bdc8f071d830ef5ce66f\n"
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
        "- sha1: 0b5cafdd65c3e0021949bdc8f071d830ef5ce66f  (content_community v1)\n",
        "(none — joiners discover overlays via OVERLAY_OFFER)\n",
    )
    manifest = parse_manifest(text)
    assert manifest.default_overlays == ()


def test_duplicate_default_overlay_hashes_rejected():
    text = GOOD_MANIFEST.replace(
        "- sha1: 0b5cafdd65c3e0021949bdc8f071d830ef5ce66f  (content_community v1)\n",
        "- sha1: 0b5cafdd65c3e0021949bdc8f071d830ef5ce66f  (a)\n"
        "- sha1: 0b5cafdd65c3e0021949bdc8f071d830ef5ce66f  (b)\n",
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
