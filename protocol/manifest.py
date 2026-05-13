"""Parse + validate a DelftClaw network manifest (`*_network.md`).

A network manifest is the bootstrap artefact that tells a joining agent
who the admission gatekeeper is, what donation it expects, which peers
to introduce locally, and which overlay protocols the network speaks
by default. The schema is specified in ``protocol/network_schema.md``.

``parse_manifest(text)`` raises ``ManifestParseError`` on any deviation
from the schema. The 20-byte ``network_id`` is derived as
``sha1(canonicalize_md(text))[:20]`` using the same canonicalization
function as the overlay compiler — see ``protocol.compiler.canonicalize_md``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable

from protocol.compiler import canonicalize_md


REQUIRED_SECTIONS = ("Identity", "Admission", "Genesis Peers", "Default Overlays")


class ManifestParseError(Exception):
    """Raised when a network manifest fails schema validation."""


# ---------------------------------------------------------------------------
# Typed model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AdmissionPolicy:
    gatekeeper_address: str
    min_sats: int
    min_confirmations: int


@dataclass(frozen=True)
class GenesisPeer:
    host: str
    port: int
    pubkey_hex: str


@dataclass(frozen=True)
class NetworkManifest:
    identity: dict[str, str]                # name, version, description
    admission: AdmissionPolicy
    genesis_peers: tuple[GenesisPeer, ...]
    default_overlays: tuple[str, ...]       # 40-char lowercase hex sha1s
    canonical_md_bytes: bytes
    network_id: bytes                       # sha1(canonical)[:20]

    @property
    def network_id_hex(self) -> str:
        return self.network_id.hex()


# ---------------------------------------------------------------------------
# Section splitter — same convention as protocol.compiler._split_top_sections
# ---------------------------------------------------------------------------

def _split_top_sections(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    order: list[str] = []
    current_name: str | None = None
    current_lines: list[str] = []
    for line in text.split("\n"):
        if line.startswith("# ") and not line.startswith("## "):
            if current_name is not None:
                sections[current_name] = "\n".join(current_lines)
            current_name = line[2:].strip()
            current_lines = []
            order.append(current_name)
        else:
            current_lines.append(line)
    if current_name is not None:
        sections[current_name] = "\n".join(current_lines)
    sections["__order__"] = "\n".join(order)
    return sections


def _check_required_sections(sections: dict[str, str]) -> None:
    order = sections.get("__order__", "").split("\n")
    # Keep only the required sections that actually appear, in document order.
    relevant = [name for name in order if name in REQUIRED_SECTIONS]
    if relevant != list(REQUIRED_SECTIONS):
        missing = [s for s in REQUIRED_SECTIONS if s not in sections]
        if missing:
            raise ManifestParseError(f"missing required sections: {missing}")
        raise ManifestParseError(
            f"required sections must appear in order {list(REQUIRED_SECTIONS)}; "
            f"got {relevant}"
        )


# ---------------------------------------------------------------------------
# Per-section parsers
# ---------------------------------------------------------------------------

_KV_RE = re.compile(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_BECH32_RE = re.compile(r"^(tb1|bc1)[02-9ac-hj-np-z]+$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_SHA1_LINE_RE = re.compile(r"^\s*-\s*sha1\s*:\s*([0-9a-f]{40})\b")


def _parse_kv_list(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in body.split("\n"):
        m = _KV_RE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _parse_identity(body: str) -> dict[str, str]:
    kv = _parse_kv_list(body)
    for required in ("name", "version", "description"):
        if required not in kv:
            raise ManifestParseError(f"# Identity missing key: {required!r}")
    name = kv["name"]
    if not _NAME_RE.match(name):
        raise ManifestParseError(f"# Identity name not snake_case: {name!r}")
    if not _SEMVER_RE.match(kv["version"]):
        raise ManifestParseError(
            f"# Identity version not semver (X.Y.Z): {kv['version']!r}"
        )
    if not kv["description"].strip():
        raise ManifestParseError("# Identity description is empty")
    return kv


def _parse_admission(body: str) -> AdmissionPolicy:
    kv = _parse_kv_list(body)
    for required in ("gatekeeper_address", "min_sats", "min_confirmations"):
        if required not in kv:
            raise ManifestParseError(f"# Admission missing key: {required!r}")
    addr = kv["gatekeeper_address"]
    if not _BECH32_RE.match(addr):
        raise ManifestParseError(
            f"# Admission gatekeeper_address must be bech32 (tb1.../bc1...); got {addr!r}"
        )
    try:
        min_sats = int(kv["min_sats"])
    except ValueError as exc:
        raise ManifestParseError(
            f"# Admission min_sats not an integer: {kv['min_sats']!r}"
        ) from exc
    if min_sats < 1:
        raise ManifestParseError(
            f"# Admission min_sats must be >= 1; got {min_sats}"
        )
    try:
        min_confs = int(kv["min_confirmations"])
    except ValueError as exc:
        raise ManifestParseError(
            f"# Admission min_confirmations not an integer: {kv['min_confirmations']!r}"
        ) from exc
    if not 0 <= min_confs <= 65535:
        raise ManifestParseError(
            f"# Admission min_confirmations must be in [0, 65535]; got {min_confs}"
        )
    return AdmissionPolicy(
        gatekeeper_address=addr,
        min_sats=min_sats,
        min_confirmations=min_confs,
    )


def _parse_genesis_peers(body: str) -> tuple[GenesisPeer, ...]:
    rows = _read_table(body)
    if not rows:
        raise ManifestParseError("# Genesis Peers section contained no table rows")
    header = [c.lower() for c in rows[0]]
    if header != ["host", "port", "pubkey_hex"]:
        raise ManifestParseError(
            f"# Genesis Peers table header must be host|port|pubkey_hex; got {header}"
        )

    peers: list[GenesisPeer] = []
    seen: set[tuple[str, int]] = set()
    for row in rows[1:]:
        if len(row) != 3:
            raise ManifestParseError(
                f"# Genesis Peers row must have 3 cells; got {row}"
            )
        host, port_str, pubkey = row
        if not host:
            raise ManifestParseError("# Genesis Peers row has empty host")
        try:
            port = int(port_str)
        except ValueError as exc:
            raise ManifestParseError(
                f"# Genesis Peers row has non-integer port {port_str!r}"
            ) from exc
        if not 1024 <= port <= 65535:
            raise ManifestParseError(
                f"# Genesis Peers row port must be in [1024, 65535]; got {port}"
            )
        pubkey = pubkey.lower()
        if len(pubkey) == 0 or len(pubkey) % 2 != 0 or not _HEX_RE.match(pubkey):
            raise ManifestParseError(
                f"# Genesis Peers row pubkey_hex must be even-length lowercase hex; got {pubkey!r}"
            )
        key = (host, port)
        if key in seen:
            raise ManifestParseError(
                f"# Genesis Peers duplicate (host, port): {host}:{port}"
            )
        seen.add(key)
        peers.append(GenesisPeer(host=host, port=port, pubkey_hex=pubkey))

    if not peers:
        raise ManifestParseError("# Genesis Peers requires at least one peer")
    return tuple(peers)


def _parse_default_overlays(body: str) -> tuple[str, ...]:
    hashes: list[str] = []
    seen: set[str] = set()
    for line in body.split("\n"):
        m = _SHA1_LINE_RE.match(line)
        if not m:
            continue
        h = m.group(1).lower()
        if h in seen:
            raise ManifestParseError(
                f"# Default Overlays duplicate sha1: {h}"
            )
        seen.add(h)
        hashes.append(h)
    return tuple(hashes)


# ---------------------------------------------------------------------------
# Table reader — same shape conventions as protocol.compiler._parse_field_table
# ---------------------------------------------------------------------------

def _read_table(body: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw in body.split("\n"):
        ln = raw.strip()
        if not ln.startswith("|"):
            continue
        cells = [c.strip() for c in ln.strip("|").split("|")]
        # Skip the |---|---|---| separator row that markdown tables require.
        if cells and all(set(c) <= set("- ") for c in cells):
            continue
        rows.append(cells)
    return rows


# ---------------------------------------------------------------------------
# Top-level entry
# ---------------------------------------------------------------------------

def parse_manifest(text: str) -> NetworkManifest:
    """Parse + validate a network-manifest `.md`. Raise ``ManifestParseError`` on any deviation."""
    if not isinstance(text, str):
        raise ManifestParseError(f"manifest must be str; got {type(text).__name__}")

    sections = _split_top_sections(text)
    _check_required_sections(sections)

    identity = _parse_identity(sections["Identity"])
    admission = _parse_admission(sections["Admission"])
    genesis_peers = _parse_genesis_peers(sections["Genesis Peers"])
    default_overlays = _parse_default_overlays(sections["Default Overlays"])

    canonical = canonicalize_md(text)
    network_id = hashlib.sha1(canonical).digest()[:20]

    return NetworkManifest(
        identity=identity,
        admission=admission,
        genesis_peers=genesis_peers,
        default_overlays=default_overlays,
        canonical_md_bytes=canonical,
        network_id=network_id,
    )


def network_id_from_manifest(text: str) -> bytes:
    """Convenience: derive the 20-byte ``network_id`` without parsing the rest."""
    return hashlib.sha1(canonicalize_md(text)).digest()[:20]
