"""Boot a complete :class:`ServerState` from a :class:`ServerConfig`.

Invocation order matters: this is the single place where IPv8 and
:class:`AgentChannel` are instantiated and started for the MCP server. The
function is async because :meth:`AgentChannel.start` awaits the IPv8
service.

Boot sequence:

1. Load :class:`Seed` via :class:`KeyfileSeedSource` (auto-creates the seed
   file on first run).
2. Build :class:`AgentIdentity` from the seed + network label.
3. Build :class:`IPv8Runtime` bound to the configured IPv8 IP/port.
4. Build :class:`AgentChannel` with a fresh :class:`InMemoryStakeOracle`
   (``mirror_remote=True`` per the M2 demo conventions).
5. Load any pre-issued VCs from disk into the channel's
   :class:`TrustStore`.
6. Apply the optional faucet credit.
7. Read the optional issuer keypair (raw 32 bytes Ed25519).
8. Await :meth:`AgentChannel.start`.
9. Load the :class:`PeerDirectory` from ``peers.yaml``.
"""

from __future__ import annotations

from communication.channel.agent_channel import AgentChannel
from communication.transport.ipv8_runtime import IPv8Runtime, NetworkConfig
from identity.agent_identity import AgentIdentity
from identity.seed import KeyfileSeedSource
from integration.mcp_server.config import ServerConfig
from integration.mcp_server.peer_directory import PeerDirectory
from integration.mcp_server.state import ServerState
from integration.mcp_server.vc_loader import load_credential_from_json
from shared.ids import CredentialId
from shared.logging import get_logger
from stake.in_memory import InMemoryStakeOracle
from trust.store import TrustStore

_log = get_logger("mcp_boot")


async def boot(config: ServerConfig) -> ServerState:
    """Build, start, and return a fully wired :class:`ServerState`.

    The returned state is hot: the IPv8 runtime is listening on its UDP
    port, the AgentChannel is wired into the TrustroomCommunity, and the
    peer directory is loaded. Tools can use the state immediately.

    Use :func:`shutdown` to tear it down at end of life.
    """
    _log.info(
        "boot_starting",
        agent=config.agent.name,
        network=config.agent.network,
        ipv8_port=config.ipv8.bind_port,
        mcp_port=config.mcp.bind_port,
    )

    # 1-2. Identity from seed file (auto-creates if missing).
    seed = KeyfileSeedSource(config.agent.seed_path).load()
    identity = AgentIdentity.from_seed(seed, network=config.agent.network)
    _log.info(
        "identity_loaded",
        agent_id=str(identity.agent_id),
        network=identity.network,
        seed_path=str(config.agent.seed_path),
    )

    # 3. IPv8 runtime.
    runtime = IPv8Runtime(
        identity,
        NetworkConfig(
            port=config.ipv8.bind_port,
            address=config.ipv8.bind_ip,
        ),
    )

    # 4. AgentChannel with an InMemoryStakeOracle in mirror_remote=True mode
    #    (see M2 demo for rationale; we want every receiver to mirror sender
    #    state until the colleague's append-only log lands in M3+).
    trust_store = TrustStore()
    oracle = InMemoryStakeOracle(mirror_remote=True)
    channel = AgentChannel(
        identity=identity,
        runtime=runtime,
        trust_store=trust_store,
        oracle=oracle,
    )

    # 5. Pre-issued VCs.
    for entry in config.vc_store:
        cred = load_credential_from_json(entry.file)
        trust_store.put(CredentialId(entry.vc_id), cred)
        _log.info(
            "vc_loaded",
            vc_id=entry.vc_id,
            file=str(entry.file),
            format_id=cred.format_id,
            issuer_pubkey_prefix=cred.issuer_pubkey[:6].hex(),
        )

    # 6. Optional faucet credit.
    if config.faucet.amount > 0:
        oracle.faucet(identity.agent_id, config.faucet.amount)

    # 7. Optional issuer keypair.
    issuer_priv: bytes | None = None
    if config.issuer_keypair_path is not None:
        issuer_priv = config.issuer_keypair_path.read_bytes()
        if len(issuer_priv) != 32:
            raise ValueError(
                f"issuer_keypair_path={config.issuer_keypair_path} must contain "
                f"exactly 32 raw Ed25519 bytes, got {len(issuer_priv)}"
            )
        _log.info("issuer_keypair_loaded", path=str(config.issuer_keypair_path))

    # 8. Start the channel (boots IPv8, registers TrustroomCommunity, wires it).
    await channel.start()

    # 9. Peer directory.
    peers = PeerDirectory.load(config.peers_file)

    state = ServerState(
        config=config,
        identity=identity,
        runtime=runtime,
        channel=channel,
        peers=peers,
        issuer_priv=issuer_priv,
    )

    _log.info(
        "boot_complete",
        agent=config.agent.name,
        agent_id=str(identity.agent_id),
        ipv8_port=config.ipv8.bind_port,
        peers_known=len(peers.entries),
        vcs_loaded=len(config.vc_store),
        faucet_credited=config.faucet.amount,
    )
    return state


async def shutdown(state: ServerState) -> None:
    """Stop the AgentChannel cleanly. Idempotent."""
    _log.info("shutdown_starting", agent=state.config.agent.name)
    try:
        await state.channel.stop()
    except Exception as exc:  # noqa: BLE001
        _log.warning("shutdown_channel_error", error=str(exc))
    _log.info("shutdown_complete", agent=state.config.agent.name)


__all__ = ["boot", "shutdown"]
