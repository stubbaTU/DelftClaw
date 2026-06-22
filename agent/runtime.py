"""``OpenClawAgent`` — single-process owner of the per-node stack.

Holds the AgentIdentity, a running IPv8 instance with the bootstrap
``SeedboxCommunity``, an HD Bitcoin wallet, a BitTorrent service, an
``OverlayRegistry`` for runtime-compiled overlays, and an ``LLMClient``
the tool-call loop drives. The ``agent.tools`` and ``agent.loop`` modules
operate against this object.
"""

from __future__ import annotations

import asyncio
import os
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


@dataclass
class AgentConfig:
    """Construction-time knobs for one node."""

    port: int = 0
    address: str = "127.0.0.1"
    btc_network: str = "mock"           # synthetic; flip to "testnet" for real bitcoinlib
    save_dir: Path = Path("./downloads")
    initial_balance_sats: int = 0
    community_log_path: Optional[Path] = None
    peer_log_dir: Optional[Path] = None
    peer_log_urls: tuple[str, ...] = ()
    pull_interval_s: float = 5.0
    pull_batch: int = 100


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

        # Late-bind the per-deploy synthetic balance the LLM will see via
        # ``wallet_balance``. AgentIdentity.from_seed doesn't take this
        # (it's deploy-time policy, not identity-time crypto), so we set
        # it on the constructed wallet here.
        if self.config.initial_balance_sats > 0:
            self.wallet.set_initial_balance(self.config.initial_balance_sats)

        # IPv8 instance + bootstrap community are populated in start().
        self._ipv8: Optional[IPv8] = None
        self._seedbox: Optional[SeedboxCommunity] = None
        self._registry: Optional[OverlayRegistry] = None
        self._key_file: Optional[Path] = None

        # OVERLAY_OFFERs received for hashes we don't yet run. Populated by
        # ``_on_overlay_offer`` (wired as the seedbox offer_callback in
        # start()); surfaced in the state snapshot as ``pending_overlay_offers``
        # so the LLM can decide whether to adopt a peer-authored overlay via
        # ``overlay_fetch_and_load``. md_hash (bytes) -> peer.mid hex.
        self._pending_offers: dict[bytes, str] = {}

        # Network manifest (None until --manifest, --genesis, or
        # agent_inject_manifest loads one).
        self._manifest: Optional[NetworkManifest] = None

        # Community signed log + peer-log cache. Lazily constructed on
        # first access so unit tests that don't care about the community
        # layer can construct an OpenClawAgent without paying for log
        # directories. See the ``community_log`` / ``peer_log`` properties.
        self._community_log = None  # type: ignore[assignment]
        self._peer_log = None  # type: ignore[assignment]

        # Phase 6: pull-loop background task + transport handle (httpx
        # AsyncClient). Both populated by ``start()`` when
        # ``config.peer_log_urls`` is non-empty; ``stop()`` cancels the
        # task and aclose()-s the client.
        self._pull_task: Optional[asyncio.Task] = None
        self._pull_stop_event: Optional[asyncio.Event] = None
        self._pull_transport_handle: Any = None

        # Memoised ``CommunityState`` keyed by the union of chain heads
        # (own log + per-source peer logs). ``None`` = no cached state
        # yet. Invalidated implicitly when any head advances. Cheap
        # because head lookup is O(1) after the signed-log + peer-log
        # head caches landed.
        self._community_state_cache: tuple[Any, Any] | None = None

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
        self._seedbox.configure(
            wallet_address=self.wallet.address(),
            community_join_callback=self._handle_community_join,
            offer_callback=self._on_overlay_offer,
        )
        # Persist LLM-generated overlay sources under the agent's save
        # dir so a watchdog restart doesn't re-pay the compiler-LLM
        # round-trip for overlays we've already seen. One file per
        # (canonical_md_sha1, model_id) pair.
        compile_cache = self.config.save_dir / "overlay_compile_cache"
        # Per-demo overlay spec archive + ledger. Env-gated (set by
        # deploy.scenario_boot for every scenario); unset in unit tests and
        # ad-hoc runs so no archive is written. See protocol.overlay_archive.
        archive_env = os.environ.get("OVERLAY_ARCHIVE_DIR")
        archive_dir = Path(archive_env) if archive_env else None
        # Fleet-wide version history (one file per scenario, shared by every
        # agent in it). Env-gated like the per-agent archive; when set, each
        # ``authored`` event is also appended to <history_dir>/version_history.jsonl
        # and the rendered markdown summary is rewritten. See
        # protocol.version_history.
        history_env = os.environ.get("VERSION_HISTORY_DIR")
        history_dir = Path(history_env) if history_env else None
        self._registry = OverlayRegistry(
            self._ipv8, self.llm, cache_dir=compile_cache, archive_dir=archive_dir,
            history_dir=history_dir,
        )

        # Phase 6: start the pull loop iff peer URLs were declared.
        # Empty list (the default) → no background task; pure read-only
        # community state from the local log only.
        if self.config.peer_log_urls:
            await self._start_pull_loop()

    async def _start_pull_loop(self) -> None:
        """Spawn the signed_log pull-loop task pointed at ``config.peer_log_urls``.

        Lazy imports keep ``import agent.runtime`` cheap on tests that
        don't exercise the pull layer. Uses the agent's own ``peer_log``
        (which is built from the same directory ``signed_log.integration.server``
        uses if the operator runs it for outbound serving — fine to
        share via filesystem, each ``PeerLog`` instance owns its own
        in-process lock and ``accept_entry`` is idempotent on entry_hash).
        """
        import httpx
        from signed_log.integration.peer_transport import HttpPeerTransport
        from signed_log.integration.pull_loop import run_pull_loop

        self._pull_stop_event = asyncio.Event()
        self._pull_transport_handle = httpx.AsyncClient(timeout=10.0)
        transport = HttpPeerTransport(self._pull_transport_handle)
        # Touch ``peer_log`` so its dir exists before the loop runs.
        _ = self.peer_log
        self._pull_task = asyncio.create_task(
            run_pull_loop(
                transport=transport,
                peer_urls=list(self.config.peer_log_urls),
                peer_log=self.peer_log,
                interval=self.config.pull_interval_s,
                batch=self.config.pull_batch,
                stop_event=self._pull_stop_event,
            ),
            name=f"pull_loop:{self.pubkey_hex[:16]}",
        )

    async def _stop_pull_loop(self) -> None:
        """Cancel the pull loop + close the httpx transport.

        Signals via ``stop_event`` (drives a clean exit within one
        ``pull_interval_s``); falls back to ``task.cancel()`` if the loop
        doesn't honour the signal within 5s. Always closes the
        httpx.AsyncClient.
        """
        if self._pull_task is not None and self._pull_stop_event is not None:
            self._pull_stop_event.set()
            try:
                await asyncio.wait_for(self._pull_task, timeout=5.0)
            except asyncio.TimeoutError:
                self._pull_task.cancel()
                try:
                    await self._pull_task
                except (asyncio.CancelledError, Exception):
                    pass
            except (asyncio.CancelledError, Exception):
                pass
        self._pull_task = None
        self._pull_stop_event = None
        if self._pull_transport_handle is not None:
            try:
                await self._pull_transport_handle.aclose()
            except Exception:
                pass
            self._pull_transport_handle = None

    async def stop(self) -> None:
        # Stop the pull loop FIRST so we're not pulling after the
        # signed-log writes have stopped.
        await self._stop_pull_loop()
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

    def publish_overlay(self, md_text: str, *, llm_source: str | None = None):
        """Load + serve an overlay descriptor. Returns its 20-byte md_hash.

        ``llm_source`` (when set) hands a pre-canned compiled Python source
        to the registry so the compile step skips the LLM round-trip. Used by
        ``agent.cli._publish_overlays`` for ``*_stub.py`` siblings — keeps
        boot fast AND routes the seeder through the same archive + lifecycle
        path the fetchers use.
        """
        md_hash = self.seedbox.publish_overlay(md_text)
        # Compile + register so we also speak the protocol locally.
        self.registry.load(md_text, provenance="published", llm_source=llm_source)
        return md_hash

    def _overlay_offers_path(self) -> Path:
        """Shared on-disk offers file. ``save_dir`` is shared by an agent's MCP
        and watchdog processes, so an offer received in one is visible to the
        other (same bridge pattern as the BitTorrent download ledger)."""
        return self.config.save_dir / ".overlay_offers.jsonl"

    def _on_overlay_offer(self, peer: Peer, md_hash: bytes) -> None:
        """Seedbox offer_callback: record offers for overlays we don't run yet.

        Fires when a peer sends OVERLAY_OFFER. We deliberately do NOT auto-fetch
        — adoption is the LLM's decision. We remember who offered what so the
        next state snapshot surfaces it as ``pending_overlay_offers``, AND
        append it to a shared on-disk file so the SEPARATE watchdog snapshot
        process (which builds the prompt) sees the offer too — without that
        bridge, the offer is invisible to the LLM and the agent never adopts.
        Offers for an overlay we already run are ignored (nothing to adopt).
        """
        if self._registry is not None and self._registry.get(md_hash) is not None:
            return
        self._pending_offers[md_hash] = peer.mid.hex()
        try:
            import json as _json
            self.config.save_dir.mkdir(parents=True, exist_ok=True)
            with open(self._overlay_offers_path(), "a", encoding="utf-8") as handle:
                handle.write(_json.dumps({
                    "md_hash_hex": md_hash.hex(),
                    "from_peer_mid": peer.mid.hex(),
                }) + "\n")
        except OSError:
            pass

    def _overlay_already_held(self, md_hash: bytes) -> bool:
        """Whether we've loaded OR fully adopted ``md_hash``.

        The archive check is cross-process: if the MCP process adopted the
        overlay (fetched + compiled + INSTALLED + archived it), the watchdog
        snapshot process sees the populated meta.json and stops re-offering.

        Uses ``is_installed`` not ``has``: a hung post-compile leaves the
        ``.md`` archived as ``seen`` but install never completes, and we want
        the agent to retry the adopt on the next tick rather than treat the
        stranded spec as "done." Verified by the 2026-05-30 ~19:07 incident
        where two parallel fresh-Haiku compiles for the same cid both hung
        in the post-compile section and the agents went idle forever.
        """
        if self._registry is not None and self._registry.get(md_hash) is not None:
            return True
        archive = getattr(self._registry, "_archive", None) if self._registry else None
        if archive is not None:
            try:
                return archive.is_installed(md_hash.hex())
            except Exception:
                pass
        return False

    def pending_overlay_offers(self) -> list[dict[str, str]]:
        """Offers for overlays not yet loaded: ``[{md_hash_hex, from_peer_mid}]``.

        Merges in-memory offers with the shared on-disk offers file (so the
        watchdog snapshot process sees offers received by the MCP process), and
        drops any whose overlay is already held (loaded or adopted, via the
        shared archive) so the list only shows actionable offers.
        """
        merged: dict[str, str] = {}
        for md_hash, peer_mid in self._pending_offers.items():
            merged[md_hash.hex()] = peer_mid
        try:
            import json as _json
            text = self._overlay_offers_path().read_text(encoding="utf-8")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                h = rec.get("md_hash_hex")
                if h:
                    merged.setdefault(h, rec.get("from_peer_mid", ""))
        except OSError:
            pass

        out: list[dict[str, str]] = []
        for md_hash_hex, peer_mid in merged.items():
            try:
                already = self._overlay_already_held(bytes.fromhex(md_hash_hex))
            except ValueError:
                continue
            if already:
                continue
            out.append({"md_hash_hex": md_hash_hex, "from_peer_mid": peer_mid})
        return out

    # ------------------------------------------------------------------
    # Network manifest
    # ------------------------------------------------------------------

    @property
    def network_manifest(self) -> Optional[NetworkManifest]:
        """The currently-loaded network manifest, or None."""
        return self._manifest

    def load_manifest(self, md_text: str) -> NetworkManifest:
        """Parse + cache a network manifest and pre-introduce every genesis peer.

        The manifest arrives out-of-band (the ``--manifest``/``--genesis`` CLI
        flag, the disk ``MANIFEST_FILE``, or the ``agent_inject_manifest`` MCP
        call) — it is not fetched over the wire. Idempotent: loading the same
        manifest twice is a no-op after the first parse. Loading a *different*
        manifest replaces the cached one (one network at a time). Genesis peers
        whose pubkey matches this agent's own ipv8 pubkey are skipped to avoid
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
        return manifest

    async def ensure_default_overlays_loaded(
        self,
        *,
        timeout_s: float = 10.0,
    ) -> tuple[list[str], list[dict[str, str]]]:
        """Ensure every overlay named in ``manifest.default_overlays`` is loaded.

        For each ``community_id`` listed in the cached manifest's
        ``default_overlays`` field that is not already in
        ``self.registry``, the helper sends ``OVERLAY_REQUEST`` to a
        reachable genesis peer (via ``self._seedbox.fetch_overlay``),
        waits up to ``timeout_s`` for the ``OVERLAY_DELIVERY`` reply,
        and runs the canonical ``.md`` bytes through the registry's
        compile + register pipeline.

        Returns ``(loaded, errors)`` where ``loaded`` is the list of
        community-id hex strings now present in the registry (already
        loaded plus newly fetched) and ``errors`` is a list of
        ``{"sha1": <hex>, "error": <message>}`` records for each
        descriptor that could not be obtained. The helper never raises
        on a per-overlay failure — boot continues with whatever loaded
        successfully; the snapshot will simply not include the missing
        overlays. The caller can decide whether to retry.

        No-ops cleanly when no manifest is loaded or the manifest has
        no default overlays (returns ``([], [])``).
        """
        manifest = self._manifest
        if manifest is None or not manifest.default_overlays:
            return ([], [])
        if self._seedbox is None:
            return ([], [])

        genesis_pubkey_set = {
            gp.pubkey_hex.lower() for gp in manifest.genesis_peers
        }
        own_pubkey_hex = self.pubkey_hex.lower()
        genesis_peers = [
            p
            for p in self.known_peers()
            if p.public_key.key_to_bin().hex().lower() in genesis_pubkey_set
            and p.public_key.key_to_bin().hex().lower() != own_pubkey_hex
        ]

        loaded: list[str] = []
        errors: list[dict[str, str]] = []
        for h_hex in manifest.default_overlays:
            h = bytes.fromhex(h_hex)
            if self.registry.get(h) is not None:
                loaded.append(h_hex)
                continue
            if not genesis_peers:
                errors.append({
                    "sha1": h_hex,
                    "error": "no_genesis_peers_reachable",
                })
                continue
            primary = genesis_peers[0]
            try:
                fut = self._seedbox.fetch_overlay(primary, h)
                md_bytes = await asyncio.wait_for(fut, timeout=timeout_s)
                await self.registry.aload(
                    md_bytes.decode("utf-8"),
                    provenance=f"received_from:{primary.mid.hex()[:12]}",
                )
                loaded.append(h_hex)
            except Exception as exc:
                errors.append({
                    "sha1": h_hex,
                    "error": f"{type(exc).__name__}: {exc}",
                })
        return loaded, errors

    # ------------------------------------------------------------------
    # Community log (own chain) + peer-log cache (foreign chains)
    # ------------------------------------------------------------------

    @property
    def community_log(self):
        """The local agent's own signed append-only log.

        Lazily constructed on first access using ``config.community_log_path``
        (defaults to ``<save_dir>/community.log``). The log is keyed by an
        ``OpenClawIdentity`` adapted from this agent's ``AgentIdentity`` —
        same Ed25519 key, so signatures verify under ``self.pubkey_hex``.

        The tool layer writes community events (donation_intent) here;
        the signed_log pull loop (Phase 6) is responsible for shipping them
        to peers.
        """
        if self._community_log is None:
            from identity.openclaw_identity import OpenClawIdentity
            from signed_log.primitives.signed_log import SignedAppendOnlyLog
            path = self.config.community_log_path or (self.config.save_dir / "community.log")
            path.parent.mkdir(parents=True, exist_ok=True)
            oc_identity = OpenClawIdentity.from_agent_identity(self.identity)
            self._community_log = SignedAppendOnlyLog(oc_identity, str(path))
        return self._community_log

    @property
    def peer_log(self):
        """The per-source cache of foreign community-log entries.

        Lazily constructed on first access using ``config.peer_log_dir``
        (defaults to ``<save_dir>/peer_logs/``). Each peer's chain lives
        at ``<dir>/<peer_id>.jsonl``; entries are deposited by the signed_log
        pull loop after passing ``SignedAppendOnlyLog.verify_foreign_entry``.

        The PeerLog's network parameter is the **identity network**
        (TESTNET/MAINNET/REGTEST) — not the BTC network — because that's
        what ``identity_hash = SHA256(pubkey || network)`` was bound with.
        """
        if self._peer_log is None:
            from signed_log.primitives.peer_log import PeerLog
            directory = self.config.peer_log_dir or (self.config.save_dir / "peer_logs")
            directory.mkdir(parents=True, exist_ok=True)
            from identity.openclaw_identity import OpenClawIdentity
            oc_identity = OpenClawIdentity.from_agent_identity(self.identity)
            self._peer_log = PeerLog(
                peer_log_dir=directory,
                network=oc_identity.network,
                own_id=oc_identity.identity_hash,
            )
        return self._peer_log

    @property
    def community_reporter_id(self) -> str:
        """SHA256(ipv8_pubkey || network) hex — the ``reporter_id`` used in
        every community-log entry we write. Identical to what
        ``SignedAppendOnlyLog.verify_integrity`` expects for our entries.
        """
        from identity.openclaw_identity import OpenClawIdentity
        return OpenClawIdentity.from_agent_identity(self.identity).identity_hash

    def all_community_entries(self) -> list[dict]:
        """Merge our own community-log entries with every peer's cached entries.

        Returned in source-iteration order; ``replay_community`` will
        re-sort deterministically. Read-only — never re-verifies
        signatures (peer entries were already verified at accept time).
        """
        merged: list[dict] = list(self.community_log.read_entries())
        for source_id in self.peer_log.list_sources():
            merged.extend(self.peer_log.read_entries_for(source_id))
        return merged

    def community_state(self):
        """Compute the current ``CommunityState`` for the loaded network.

        Returns None when no manifest has been injected yet (an agent
        with no network has no community to score).

        Memoised on (own_log_head, sorted peer-log heads): every call
        between appends returns the cached state without re-reading
        any file. Invalidated whenever any head advances — replay then
        re-runs from disk.
        """
        if self._manifest is None:
            return None

        # Build the cheap cache key. ``latest_hash_for`` is O(1) after
        # the first read of each source file.
        own_head = self.community_log.latest_hash()
        peer_heads = tuple(sorted(
            (sid, self.peer_log.latest_hash_for(sid))
            for sid in self.peer_log.list_sources()
        ))
        key = (own_head, peer_heads)

        cached = self._community_state_cache
        if cached is not None and cached[0] == key:
            return cached[1]

        from agent.community_state import replay_community
        state = replay_community(self._manifest, self.all_community_entries())
        self._community_state_cache = (key, state)
        return state

    # ------------------------------------------------------------------
    # Community-join admission (Phase 5 — gatekeeper side)
    # ------------------------------------------------------------------

    def _handle_community_join(self, peer, entry: dict) -> tuple[bool, str]:
        """Validate a foreign signed donation_intent entry from a joiner.

        Pipeline:

          1. No manifest loaded → reject (we don't run a community yet).
          2. Drop the entry into our PeerLog cache; PeerLog runs
             ``SignedAppendOnlyLog.verify_foreign_entry`` (signature +
             identity binding) before persisting.
          3. Re-run community-state replay over our local view (own log
             + every cached peer chain). If the joiner is now in
             ``state.members``, the entry was wire-shape valid AND
             passed the donation-cap / no-double-join rules — accept.
             Otherwise the rules rejected it — reject with a reason.

        Returns ``(accepted, reason)``; the seedbox wire handler turns
        that into a ``CommunityJoinResponsePayload``.
        """
        if self._manifest is None:
            return False, "no_manifest_loaded"

        action = entry.get("action")
        if action != "donation_intent":
            return False, f"unsupported_action:{action}"

        reporter_id = entry.get("reporter_id")
        if not isinstance(reporter_id, str) or not reporter_id:
            return False, "missing_reporter_id"

        # 1. PeerLog rejects on signature / identity-binding / same-id
        # failures (the joiner can't sign as us, and can't ship malformed
        # entries past Ed25519 verify).
        stored, source_id, errors, duplicate = self.peer_log.accept_entry(entry)
        if not stored and not duplicate:
            return False, "; ".join(errors) if errors else "peer_log_rejected"

        # 2. Re-run replay. If the entry's rules-side validation passed,
        # the joiner now appears in members. Otherwise the entry sits in
        # the peer-log cache (rules might pass later — e.g. once
        # additional donations come in) but the joiner stays out for now.
        state = self.community_state()
        if state is None:
            return False, "replay_returned_none"
        if reporter_id in state.members:
            return True, ""
        return False, "rejected_by_community_rules"


