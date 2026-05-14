"""``PeerDirectory`` — load ``peers.yaml``, resolve aliases to IPv8 Peer objects.

The directory is the LLM-friendly addressing layer: tools take aliases like
``"alice"`` and the directory translates them to the IPv8 ``Peer`` object the
underlying ``TrustroomCommunity`` needs.

YAML format (frozen)::

    peers:
      alice:
        agent_id: qiuv6jd3t42b6nqp
        pubkey_bin_hex: 4c69624e61434c504b3a... (148 hex chars; 74 bytes)
        ip: 127.0.0.1
        ipv8_port: 9091
      bob:
        agent_id: m34dffgcgoadzsog
        pubkey_bin_hex: <148 hex chars>
        ip: 127.0.0.1
        ipv8_port: 9092

Why ``pubkey_bin_hex`` is the full 74-byte form
-----------------------------------------------
IPv8's identity for a peer is the SHA1 of ``pubkey.key_to_bin()`` — a 74-byte
form ``b"LibNaCLPK:" + 32-byte encryption-key + 32-byte verify-key``. We need
the *exact* bytes the remote agent uses, otherwise our local Peer's ``mid``
differs from the remote's actual mid and IPv8 looks up the wrong record on
incoming datagrams.

Each agent generates its 74-byte ``pubkey_bin_hex`` once at boot via
``identity.ipv8.key.pub().key_to_bin().hex()`` and shares it (via the demo's
shared ``peers.yaml`` or out-of-band) with everyone else.

The ``agent_id`` field is **display-only** — derived from the verify-key
slice — and helpful for logs and LLM messaging. We sanity-check that the
declared ``agent_id`` matches the one derived from ``pubkey_bin_hex`` and log
a warning on mismatch (using ``pubkey_bin_hex`` as authoritative).

The directory holds *static* metadata at boot. IPv8 ``Peer`` objects (one per
alias) are constructed lazily by :meth:`resolve` once a community is
available. Cached after first resolution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shared.ids import AgentId
from shared.logging import get_logger

_log = get_logger("peer_directory")


_LIBNACLPK_PREFIX = b"LibNaCLPK:"
_PUBKEY_BIN_LEN = len(_LIBNACLPK_PREFIX) + 32 + 32  # 74


@dataclass(frozen=True)
class PeerEntry:
    alias: str
    agent_id: str       # base32 string from AgentId.__str__ (display only)
    pubkey_bin_hex: str  # 74-byte LibNaCLPK form, hex-encoded (148 chars)
    ip: str
    ipv8_port: int

    def pubkey_bin(self) -> bytes:
        """Decode ``pubkey_bin_hex`` to 74 raw bytes; raise ValueError on bad shape."""
        raw = bytes.fromhex(self.pubkey_bin_hex)
        if len(raw) != _PUBKEY_BIN_LEN:
            raise ValueError(
                f"peer {self.alias!r}: pubkey_bin_hex must decode to "
                f"{_PUBKEY_BIN_LEN} bytes, got {len(raw)}"
            )
        if not raw.startswith(_LIBNACLPK_PREFIX):
            raise ValueError(
                f"peer {self.alias!r}: pubkey_bin_hex must begin with "
                f"{_LIBNACLPK_PREFIX!r}"
            )
        return raw

    def raw_verify_key(self) -> bytes:
        """The 32-byte Ed25519 verify-key slice of the IPv8 pubkey."""
        return self.pubkey_bin()[len(_LIBNACLPK_PREFIX) + 32:]

    def expected_agent_id(self) -> AgentId:
        """The ``AgentId`` IPv8 will derive from ``pubkey_bin_hex`` at runtime."""
        return AgentId.from_pubkey(self.raw_verify_key())


@dataclass
class PeerDirectory:
    """In-memory directory loaded from ``peers.yaml``.

    Holds static metadata keyed by alias. IPv8 ``Peer`` objects (one per
    alias) are populated lazily by :meth:`resolve` once a community is
    available.
    """

    entries: dict[str, PeerEntry] = field(default_factory=dict)
    _peer_cache: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "PeerDirectory":
        """Parse a YAML file from disk; raise FileNotFoundError or ValueError on bad input."""
        text = Path(path).expanduser().read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        peers_block = data.get("peers")
        if not isinstance(peers_block, dict):
            raise ValueError(f"{path}: missing or invalid top-level 'peers' map")

        entries: dict[str, PeerEntry] = {}
        for alias, info in peers_block.items():
            if not isinstance(info, dict):
                raise ValueError(f"{path}: peer '{alias}' must be a mapping")
            try:
                entry = PeerEntry(
                    alias=alias,
                    agent_id=str(info["agent_id"]),
                    pubkey_bin_hex=str(info["pubkey_bin_hex"]),
                    ip=str(info["ip"]),
                    ipv8_port=int(info["ipv8_port"]),
                )
            except KeyError as exc:
                raise ValueError(
                    f"{path}: peer '{alias}' missing required key {exc}"
                ) from exc

            # Validate hex shape early.
            entry.pubkey_bin()

            # Sanity-check: derived agent_id must match declared.
            derived = str(entry.expected_agent_id())
            if derived != entry.agent_id:
                _log.warning(
                    "peer_directory_mismatch",
                    alias=alias,
                    declared_agent_id=entry.agent_id,
                    derived_agent_id=derived,
                    note="agent_id and pubkey_bin_hex disagree; pubkey is authoritative",
                )
            entries[alias] = entry
        _log.info(
            "peer_directory_loaded",
            path=str(path),
            count=len(entries),
            aliases=list(entries),
        )
        return cls(entries=entries)

    def lookup(self, alias: str) -> PeerEntry:
        """Return the ``PeerEntry`` for ``alias``; raise ``KeyError`` if unknown."""
        if alias not in self.entries:
            raise KeyError(
                f"unknown peer alias {alias!r}; known: {sorted(self.entries)}"
            )
        return self.entries[alias]

    def lookup_by_agent_id(self, agent_id_str: str) -> PeerEntry | None:
        """Reverse lookup by display agent_id; return ``None`` if no entry matches."""
        for entry in self.entries.values():
            if entry.agent_id == agent_id_str:
                return entry
        return None

    def all(self) -> list[PeerEntry]:
        return list(self.entries.values())

    # --- IPv8 attachment (lazy) -------------------------------------------

    def resolve(self, alias: str, community: Any) -> Any:
        """Resolve ``alias`` to an IPv8 ``Peer`` attached to ``community.network``.

        On first call for an alias we construct a Peer from the directory's
        full ``pubkey_bin_hex`` and ``(ip, ipv8_port)``, then register it via
        ``community.network.add_verified_peer`` and ``discover_services``.
        Subsequent calls return the cached Peer.
        """
        # Lazy import to avoid pulling IPv8 at module load time.
        from ipv8.keyvault.crypto import default_eccrypto
        from ipv8.peer import Peer

        if alias in self._peer_cache:
            return self._peer_cache[alias]

        entry = self.lookup(alias)
        try:
            pub = default_eccrypto.key_from_public_bin(entry.pubkey_bin())
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"peer {alias!r}: failed to construct IPv8 pubkey: {exc}"
            ) from exc

        peer = Peer(pub, address=(entry.ip, entry.ipv8_port))
        community.network.add_verified_peer(peer)
        community.network.discover_services(peer, [type(community).community_id])

        _log.debug(
            "peer_resolved",
            alias=alias,
            agent_id=entry.agent_id,
            address=f"{entry.ip}:{entry.ipv8_port}",
        )
        self._peer_cache[alias] = peer
        return peer


__all__ = ["PeerEntry", "PeerDirectory"]
