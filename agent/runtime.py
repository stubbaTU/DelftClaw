"""``OpenClawAgent`` — single-process owner of the per-node stack.

Holds the AgentIdentity, a running IPv8 instance with the bootstrap
``SeedboxCommunity``, an HD Bitcoin wallet, a BitTorrent service, an
``OverlayRegistry`` for runtime-compiled overlays, and an ``LLMClient``
the tool-call loop drives. The ``agent.tools`` and ``agent.loop`` modules
operate against this object.
"""

from __future__ import annotations

import asyncio
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.bittorrent import BitTorrentService, build_default_service
from communication.community import SeedboxCommunity
from identity.agent_identity import AgentIdentity
from identity.wallet import Wallet
from protocol import OverlayRegistry
from protocol.llm import LLMClient
from protocol.manifest import NetworkManifest, parse_manifest
from admission.donation_verifier import DonationVerifier


@dataclass
class AgentConfig:
    """Construction-time knobs for one node."""

    port: int = 0
    address: str = "127.0.0.1"
    btc_network: str = "testnet"
    save_dir: Path = Path("./downloads")
    seedbox_min_sats: int = 10_000      # gatekeeper-side: minimum donation to admit
    seedbox_min_confirmations: int = 0  # 0 = accept zero-conf for demos


class OpenClawAgent:
    """Per-node container. ``await start()`` once; ``await stop()`` on shutdown."""

    def __init__(
        self,
        identity: AgentIdentity,
        llm: LLMClient,
        config: AgentConfig | None = None,
        bt_service: BitTorrentService | None = None,
    ) -> None:
        self.identity = identity
        self.llm = llm
        self.config = config or AgentConfig()
        # ``AgentIdentity.from_seed`` already builds ``self.wallet`` from the
        # same seed; alias it here so callers don't have to dig through identity.
        self.wallet: Wallet = identity.wallet

        self.bittorrent: BitTorrentService = (
            bt_service if bt_service is not None
            else build_default_service(save_dir=self.config.save_dir)
        )

        # IPv8 instance + bootstrap community are populated in start().
        self._ipv8: Optional[IPv8] = None
        self._seedbox: Optional[SeedboxCommunity] = None
        self._registry: Optional[OverlayRegistry] = None
        self._key_file: Optional[Path] = None

        # Network manifest (None until --manifest, --genesis, network_join,
        # or agent_inject_manifest loads one).
        self._manifest: Optional[NetworkManifest] = None
        self._manifest_md: Optional[str] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._ipv8 is not None:
            return

        # Persist the IPv8 transport key alongside a tempfile so ConfigBuilder
        # can load it. We write the existing AgentIdentity key, not a fresh one,
        # so the on-the-wire IPv8 peer identity matches the agent's BIP-32 chain.
        tmp = tempfile.NamedTemporaryFile(prefix="openclaw_", suffix=".key", delete=False)
        tmp.write(self.identity.ipv8.key.key_to_bin())
        tmp.close()
        self._key_file = Path(tmp.name)

        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.set_port(self.config.port)
        builder.set_address(self.config.address)
        builder.add_key("anchor", "curve25519", str(self._key_file))
        builder.add_overlay("SeedboxCommunity", "anchor", [], [], {}, [("started",)])

        self._ipv8 = IPv8(
            builder.finalize(),
            extra_communities={"SeedboxCommunity": SeedboxCommunity},
        )
        await self._ipv8.start()

        self._seedbox = next(
            o for o in self._ipv8.overlays if isinstance(o, SeedboxCommunity)
        )
        verifier = DonationVerifier(
            seedbox_address=self.wallet.address(),
            min_sats=self.config.seedbox_min_sats,
            min_confirmations=self.config.seedbox_min_confirmations,
            network=self.config.btc_network,
        )
        self._seedbox.configure(
            verifier=verifier,
            wallet_address=self.wallet.address(),
        )
        self._registry = OverlayRegistry(self._ipv8, self.llm)

    async def stop(self) -> None:
        if self._ipv8 is not None:
            await self._ipv8.stop()
            self._ipv8 = None
        if self._key_file is not None and self._key_file.exists():
            try:
                self._key_file.unlink()
            except OSError:
                pass
            self._key_file = None
        try:
            self.bittorrent.stop()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Accessors used by the tool layer + tests
    # ------------------------------------------------------------------

    @property
    def ipv8(self) -> IPv8:
        if self._ipv8 is None:
            raise RuntimeError("OpenClawAgent.start() has not been awaited yet")
        return self._ipv8

    @property
    def seedbox(self) -> SeedboxCommunity:
        if self._seedbox is None:
            raise RuntimeError("OpenClawAgent.start() has not been awaited yet")
        return self._seedbox

    @property
    def registry(self) -> OverlayRegistry:
        if self._registry is None:
            raise RuntimeError("OpenClawAgent.start() has not been awaited yet")
        return self._registry

    @property
    def address(self) -> tuple[str, int]:
        """The IPv8 endpoint's (host, port) — useful for cross-introducing peers."""
        return self.seedbox.endpoint.get_address()

    @property
    def pubkey_hex(self) -> str:
        """Hex of this agent's IPv8 serialized public key — the form a remote peer needs to construct a Peer for us."""
        return self.identity.ipv8.pubkey.hex()

    def known_peers(self) -> list[Peer]:
        """All peers verified on any overlay this agent runs."""
        seen: dict[bytes, Peer] = {}
        for overlay in self.ipv8.overlays:
            for peer in overlay.network.verified_peers:
                seen[peer.mid] = peer
        return list(seen.values())

    def add_peer(self, host: str, port: int, pubkey_hex: str) -> Peer:
        """Pre-introduce a peer by serialized IPv8 pubkey hex + (host, port).

        Adds the peer to **every currently-loaded overlay**'s network so the
        new peer is reachable on the bootstrap community and any later
        overlays can discover it. Returns the constructed ``Peer``.
        """
        from ipv8.keyvault.crypto import default_eccrypto

        pub = default_eccrypto.key_from_public_bin(bytes.fromhex(pubkey_hex))
        peer = Peer(pub, address=(host, port))
        for overlay in self.ipv8.overlays:
            overlay.network.add_verified_peer(peer)
        return peer

    def publish_overlay(self, md_text: str):
        """Load + serve an overlay descriptor. Returns its 20-byte md_hash."""
        md_hash = self.seedbox.publish_overlay(md_text)
        # Compile + register so we also speak the protocol locally.
        self.registry.load(md_text)
        return md_hash

    # ------------------------------------------------------------------
    # Network manifest
    # ------------------------------------------------------------------

    @property
    def network_manifest(self) -> Optional[NetworkManifest]:
        """The currently-loaded network manifest, or None."""
        return self._manifest

    @property
    def network_manifest_md(self) -> Optional[str]:
        """The raw markdown text of the currently-loaded manifest, or None."""
        return self._manifest_md

    def load_manifest(self, md_text: str) -> NetworkManifest:
        """Parse + cache a network manifest and pre-introduce every genesis peer.

        Idempotent: loading the same manifest twice is a no-op after the
        first parse. Loading a *different* manifest replaces the cached
        one (the agent runs one network at a time). Genesis peers whose
        pubkey matches this agent's own ipv8 pubkey are skipped to avoid
        the runtime adding itself as a peer.
        """
        manifest = parse_manifest(md_text)
        if self._manifest is not None and self._manifest.network_id == manifest.network_id:
            return self._manifest  # idempotent: same network already loaded

        own_pubkey_hex = self.pubkey_hex.lower()
        for gp in manifest.genesis_peers:
            if gp.pubkey_hex.lower() == own_pubkey_hex:
                continue  # don't add self
            try:
                self.add_peer(gp.host, gp.port, gp.pubkey_hex)
            except Exception:
                # Bad pubkey hex is a parser-time concern; an add-peer failure
                # at runtime (e.g. unreachable host) is non-fatal — IPv8 will
                # surface it when traffic is actually sent.
                pass

        self._manifest = manifest
        self._manifest_md = md_text
        return manifest


