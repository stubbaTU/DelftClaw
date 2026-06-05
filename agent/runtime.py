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
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Optional

from ipv8.configuration import ConfigBuilder
from ipv8.peer import Peer
from ipv8_service import IPv8

from communication.bittorrent import BitTorrentService, build_default_service
from communication.community import CommunityLineageConfig, SeedboxCommunity
from identity.agent_identity import AgentIdentity
from identity.wallet import Wallet
from protocol import OverlayRegistry
from protocol.llm import LLMClient
from protocol.manifest import NetworkManifest, parse_manifest
from admission.donation_verifier import DonationVerifier


JsonDict = dict[str, Any]


@dataclass(frozen=True)
class LineageRuntimeConfig:
    """Opt-in local lineage verification knobs.

    Defaults keep lineage disabled and do not import or exercise verifier
    code. Path fields are local runtime concerns and are resolved relative
    to ``AgentConfig.save_dir`` when not absolute.
    """

    enabled: bool = False
    required: bool = False
    btc_network: str = "mock"
    min_anchor_confirmations: int = 0
    birth_package_path: Optional[Path] = None
    cache_path: Optional[Path] = None
    cache_dir: Optional[Path] = None
    revocation_feed: Optional[Path] = None
    trusted_roots: tuple[dict[str, str], ...] = ()
    accepted_capabilities: tuple[str, ...] = ()


@dataclass
class AgentConfig:
    """Construction-time knobs for one node."""

    port: int = 0
    address: str = "127.0.0.1"
    btc_network: str = "mock"           # synthetic; flip to "testnet" for real bitcoinlib
    save_dir: Path = Path("./downloads")
    seedbox_min_sats: int = 10_000      # gatekeeper-side: minimum donation to admit
    seedbox_min_confirmations: int = 0  # 0 = accept zero-conf for demos
    # Initial synthetic balance for this agent's wallet. 0 = legacy
    # always-zero behaviour. >0 = the wallet exposes a budget the LLM
    # can spend down via wallet_send; over-spending raises a clean
    # "insufficient funds" error. Plumbed from scenario.yaml ->
    # /etc/delftclaw/instances/<instance>.env -> cli.py.
    initial_balance_sats: int = 0
    # Per-agent paths for the community signed log (our own chain) and
    # the peer-log cache (foreign chains pulled by the redteam pull loop).
    # Default to in-process state under save_dir so unit tests don't
    # collide; production sets these via scenario_boot env file to
    # /var/lib/delftclaw/<scenario>/<agent>/{community.log, peer_logs/}.
    community_log_path: Optional[Path] = None
    peer_log_dir: Optional[Path] = None
    # Phase 6: redteam-server (FastAPI) URLs this agent should pull
    # community-log entries from. Each entry is a full base URL like
    # ``http://127.0.0.1:28765``. Empty list disables the pull loop —
    # ``OpenClawAgent`` will not start the background task, the test
    # suite default. ``scenario_boot`` populates this cross-wise.
    peer_log_urls: tuple[str, ...] = ()
    # Pull-loop cadence + batch size. Defaults to the same values the
    # redteam pull-sync demo uses, so behaviour is consistent.
    pull_interval_s: float = 5.0
    pull_batch: int = 100
    # Optional secure deAI lineage status/proof verification. Disabled by
    # default and never affects remote peer admission.
    lineage: LineageRuntimeConfig = field(default_factory=LineageRuntimeConfig)


def uses_mock_regtest_addresses(network: str) -> bool:
    return network.strip().lower() in {
        "mock_regtest",
        "mock-regtest",
        "regtest_mock",
        "regtest-mock",
    }


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

        # Network manifest (None until --manifest, --genesis, network_join,
        # or agent_inject_manifest loads one).
        self._manifest: Optional[NetworkManifest] = None
        self._manifest_md: Optional[str] = None

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

        self._lineage_peer_status: dict[str, JsonDict] = {}
        self._lineage_status: JsonDict = self._disabled_lineage_status(self.config.lineage)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        if self._ipv8 is not None:
            return

        self._refresh_lineage_status(raise_on_required=True)

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
        wallet_address = (
            self.wallet.regtest_address()
            if uses_mock_regtest_addresses(self.config.btc_network)
            else self.wallet.address()
        )
        verifier_network = (
            "mock"
            if uses_mock_regtest_addresses(self.config.btc_network)
            else self.config.btc_network
        )
        verifier = DonationVerifier(
            seedbox_address=wallet_address,
            min_sats=self.config.seedbox_min_sats,
            min_confirmations=self.config.seedbox_min_confirmations,
            network=verifier_network,
        )
        self._seedbox.configure(
            verifier=verifier,
            wallet_address=wallet_address,
            community_join_callback=self._handle_community_join,
            lineage_config=self._seedbox_lineage_config(),
            lineage_proof_provider=self._local_lineage_proof_for_handshake,
            lineage_status_callback=self._record_peer_lineage_status,
        )
        # Persist LLM-generated overlay sources under the agent's save
        # dir so a watchdog restart doesn't re-pay the compiler-LLM
        # round-trip for overlays we've already seen. One file per
        # (canonical_md_sha1, model_id) pair.
        compile_cache = self.config.save_dir / "overlay_compile_cache"
        self._registry = OverlayRegistry(
            self._ipv8, self.llm, cache_dir=compile_cache,
        )

        # Phase 6: start the pull loop iff peer URLs were declared.
        # Empty list (the default) → no background task; pure read-only
        # community state from the local log only.
        if self.config.peer_log_urls:
            await self._start_pull_loop()

    async def _start_pull_loop(self) -> None:
        """Spawn the redteam pull-loop task pointed at ``config.peer_log_urls``.

        Lazy imports keep ``import agent.runtime`` cheap on tests that
        don't exercise the pull layer. Uses the agent's own ``peer_log``
        (which is built from the same directory ``redteam.integration.server``
        uses if the operator runs it for outbound serving — fine to
        share via filesystem, each ``PeerLog`` instance owns its own
        in-process lock and ``accept_entry`` is idempotent on entry_hash).
        """
        import httpx
        from redteam.integration.peer_transport import HttpPeerTransport
        from redteam.integration.pull_loop import run_pull_loop

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
    # Local lineage status (tooling only; no peer admission enforcement)
    # ------------------------------------------------------------------

    @property
    def lineage_status(self) -> JsonDict:
        """Last computed local lineage status.

        This is observability for the local node's own proof only. It is
        never consulted by peer admission or IPv8 handshakes.
        """

        return dict(self._lineage_status)

    def refresh_lineage_status(self) -> JsonDict:
        """Recompute and return local lineage status without changing admission."""

        self._refresh_lineage_status(raise_on_required=False)
        return self.lineage_status

    def _refresh_lineage_status(self, *, raise_on_required: bool) -> None:
        config = self._effective_lineage_config()
        status = self._base_lineage_status(config)
        if not config.enabled:
            self._lineage_status = status
            return

        errors: list[str] = []
        warnings: list[str] = []
        birth_package_path = self._resolve_lineage_path(config.birth_package_path)
        cache_path = self._lineage_cache_path(config)
        revocation_feed_path = self._resolve_lineage_path(config.revocation_feed)

        status["paths"]["birth_package"] = str(birth_package_path) if birth_package_path else ""
        status["paths"]["cache"] = str(cache_path) if cache_path else ""
        status["paths"]["revocation_feed"] = str(revocation_feed_path) if revocation_feed_path else ""

        if config.btc_network != "mock":
            errors.append(
                f"unsupported_lineage_btc_network:{config.btc_network}: only 'mock' is implemented"
            )

        package: JsonDict | None = None
        if birth_package_path is None:
            errors.append("birth_package_path_not_configured")
        elif not birth_package_path.is_file():
            errors.append(f"birth_package_missing:{birth_package_path}")
        else:
            try:
                from identity.lineage.store import read_json

                package = read_json(birth_package_path)
            except Exception as exc:
                errors.append(f"birth_package_load_failed:{type(exc).__name__}: {exc}")

        if package is not None and not errors:
            try:
                from identity.lineage.models import LineageProof, RevocationEventV1
                from identity.lineage.store import read_jsonl
                from identity.lineage.verifier import verify_lineage_proof

                proof = LineageProof.from_dict(dict(package["proof"]))
                if revocation_feed_path is not None:
                    if revocation_feed_path.is_file():
                        revocations = [
                            RevocationEventV1.from_dict(row)
                            for row in read_jsonl(revocation_feed_path)
                        ]
                        proof = replace(proof, revocation_events=revocations)
                    else:
                        warnings.append(f"revocation_feed_missing:{revocation_feed_path}")

                trusted_roots = list(config.trusted_roots)
                if not trusted_roots:
                    raw_roots = package.get("trusted_roots", [])
                    if isinstance(raw_roots, list):
                        trusted_roots = [dict(root) for root in raw_roots if isinstance(root, dict)]

                if not errors:
                    result = verify_lineage_proof(
                        proof,
                        trusted_roots=trusted_roots,  # type: ignore[arg-type]
                        min_confirmations=config.min_anchor_confirmations,
                        cache=cache_path,
                    )
                    result_dict = result.to_dict()
                    status.update({
                        "available": True,
                        "ok": bool(result.ok),
                        "status": result.status,
                        "subject_agent_id": result.subject_agent_id,
                        "certificate_id": result.certificate_id,
                        "verification_result": result_dict,
                    })
                    errors.extend(result.errors)
            except Exception as exc:
                errors.append(f"lineage_verification_failed:{type(exc).__name__}: {exc}")

        if errors:
            status["ok"] = False
            status["errors"] = errors
            if status["status"] in {"disabled", "not_checked"}:
                missing_or_unconfigured = any(
                    error.startswith(("birth_package_path_not_configured", "birth_package_missing"))
                    for error in errors
                )
                status["status"] = "unavailable" if missing_or_unconfigured else "invalid"
        status["warnings"] = warnings
        self._lineage_status = status

        if raise_on_required and config.required and not status.get("ok"):
            detail = "; ".join(errors) if errors else str(status.get("status", "invalid"))
            raise RuntimeError(f"lineage required but local proof is unavailable or invalid: {detail}")

    def _base_lineage_status(self, config: LineageRuntimeConfig) -> JsonDict:
        cache_path = self._lineage_cache_path(config)
        status = {
            "enabled": bool(config.enabled),
            "required": bool(config.required),
            "enforced": False,
            "btc_network": config.btc_network or "mock",
            "default_btc_network": "mock",
            "min_anchor_confirmations": int(config.min_anchor_confirmations),
            "trusted_roots": [dict(root) for root in config.trusted_roots],
            "accepted_capabilities": list(config.accepted_capabilities),
            "available": False,
            "ok": None if not config.enabled else False,
            "status": "disabled" if not config.enabled else "not_checked",
            "subject_agent_id": "",
            "certificate_id": "",
            "errors": [],
            "warnings": [],
            "verification_result": None,
            "paths": {
                "birth_package": str(self._resolve_lineage_path(config.birth_package_path) or ""),
                "cache": str(cache_path or ""),
                "revocation_feed": str(self._resolve_lineage_path(config.revocation_feed) or ""),
            },
        }
        if config.enabled:
            status["peer_status"] = dict(self._lineage_peer_status)
        return status

    def _disabled_lineage_status(self, config: LineageRuntimeConfig) -> JsonDict:
        return self._base_lineage_status(config)

    def _effective_lineage_config(self) -> LineageRuntimeConfig:
        explicit_runtime = self.config.lineage != LineageRuntimeConfig()
        if explicit_runtime:
            return self.config.lineage
        if self._manifest is not None and self._manifest_lineage_is_non_default(self._manifest.lineage):
            return self._lineage_config_from_policy(self._manifest.lineage)
        return self.config.lineage

    def _lineage_config_from_policy(self, policy: Any) -> LineageRuntimeConfig:
        return LineageRuntimeConfig(
            enabled=bool(getattr(policy, "enabled", False)),
            required=bool(getattr(policy, "required", False)),
            btc_network=str(getattr(policy, "btc_network", "mock") or "mock"),
            min_anchor_confirmations=int(getattr(policy, "min_anchor_confirmations", 0)),
            birth_package_path=self._path_or_none(getattr(policy, "birth_package_path", "")),
            cache_path=self._path_or_none(getattr(policy, "cache_path", "")),
            cache_dir=self._path_or_none(getattr(policy, "cache_dir", "")),
            revocation_feed=self._path_or_none(getattr(policy, "revocation_feed", "")),
            trusted_roots=tuple(dict(root) for root in getattr(policy, "trusted_roots", ())),
            accepted_capabilities=tuple(str(item) for item in getattr(policy, "accepted_capabilities", ())),
        )

    def _manifest_lineage_is_non_default(self, policy: Any) -> bool:
        return any((
            bool(getattr(policy, "enabled", False)),
            bool(getattr(policy, "required", False)),
            tuple(getattr(policy, "trusted_roots", ())) != (),
            str(getattr(policy, "btc_network", "mock") or "mock") != "mock",
            int(getattr(policy, "min_anchor_confirmations", 0)) != 0,
            str(getattr(policy, "birth_package_path", "") or "") != "",
            str(getattr(policy, "cache_path", "") or "") != "",
            str(getattr(policy, "cache_dir", "") or "") != "",
            str(getattr(policy, "revocation_feed", "lineage/revocations.jsonl") or "") != "lineage/revocations.jsonl",
            tuple(getattr(policy, "accepted_capabilities", ())) != (),
        ))

    def _path_or_none(self, value: Any) -> Optional[Path]:
        text = str(value or "").strip()
        return Path(text) if text else None

    def _resolve_lineage_path(self, path: Optional[Path]) -> Optional[Path]:
        if path is None:
            return None
        if path.is_absolute():
            return path
        return self.config.save_dir / path

    def _lineage_cache_path(self, config: LineageRuntimeConfig) -> Optional[Path]:
        cache_path = self._resolve_lineage_path(config.cache_path)
        if cache_path is not None:
            return cache_path
        cache_dir = self._resolve_lineage_path(config.cache_dir)
        if cache_dir is None:
            return None
        return cache_dir / "verification_cache.json"

    def _seedbox_lineage_config(self) -> CommunityLineageConfig:
        config = self._effective_lineage_config()
        if not config.enabled:
            return CommunityLineageConfig()
        return CommunityLineageConfig(
            enabled=True,
            required=bool(config.required),
            trusted_roots=tuple(dict(root) for root in config.trusted_roots),
            min_anchor_confirmations=int(config.min_anchor_confirmations),
            accepted_capabilities=tuple(config.accepted_capabilities),
            cache_path=self._lineage_cache_path(config),
        )

    def _local_lineage_proof_for_handshake(self) -> JsonDict | None:
        config = self._effective_lineage_config()
        if not config.enabled:
            return None
        birth_package_path = self._resolve_lineage_path(config.birth_package_path)
        if birth_package_path is None or not birth_package_path.is_file():
            return None
        try:
            from identity.lineage.store import read_json

            package = read_json(birth_package_path)
            proof = package.get("proof")
            return dict(proof) if isinstance(proof, dict) else None
        except Exception:
            return None

    def _record_peer_lineage_status(self, peer: Peer, status: JsonDict) -> None:
        self._lineage_peer_status[peer.mid.hex()] = dict(status)
        if self._lineage_status.get("enabled"):
            self._lineage_status["peer_status"] = dict(self._lineage_peer_status)

    @property
    def lineage_peer_status(self) -> JsonDict:
        return dict(self._lineage_peer_status)

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

        If this agent IS named in the manifest's genesis peer list, the
        manifest is also published into the bootstrap community so future
        joiners can fetch it via ``MANIFEST_REQUEST``. That keeps the
        ``--genesis`` CLI flag and any MCP-driven manifest injection in
        sync — an agent doesn't need to know whether it's "the genesis";
        the manifest tells it.
        """
        manifest = parse_manifest(md_text)
        if self._manifest is not None and self._manifest.network_id == manifest.network_id:
            return self._manifest  # idempotent: same network already loaded

        own_pubkey_hex = self.pubkey_hex.lower()
        self_is_genesis = False
        for gp in manifest.genesis_peers:
            if gp.pubkey_hex.lower() == own_pubkey_hex:
                self_is_genesis = True
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

        self._refresh_lineage_status(raise_on_required=True)
        if self._seedbox is not None:
            self._seedbox.configure(lineage_config=self._seedbox_lineage_config())

        if self_is_genesis and self._seedbox is not None:
            self._seedbox.publish_manifest(md_text)

        return manifest

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

        The tool layer writes community events (donation_intent,
        seedbox_purchase_intent, seedbox_provisioned) here; the redteam
        pull loop (Phase 6) is responsible for shipping them to peers.
        """
        if self._community_log is None:
            from identity.openclaw_identity import OpenClawIdentity
            from redteam.primitives.signed_log import SignedAppendOnlyLog
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
        at ``<dir>/<peer_id>.jsonl``; entries are deposited by the redteam
        pull loop after passing ``SignedAppendOnlyLog.verify_foreign_entry``.

        The PeerLog's network parameter is the **identity network**
        (TESTNET/MAINNET/REGTEST) — not the BTC network — because that's
        what ``identity_hash = SHA256(pubkey || network)`` was bound with.
        """
        if self._peer_log is None:
            from redteam.primitives.peer_log import PeerLog
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


