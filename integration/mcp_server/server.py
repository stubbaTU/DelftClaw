"""FastMCP application exposing AgentChannel as 10 LLM-callable tools.

Tools take simple kwargs (strings, ints, an optional :class:`StakeProofDict`)
and return Pydantic models from :mod:`integration.mcp_server.schemas`.
FastMCP introspects the type hints to publish JSON Schema to clients.

Every state-mutating tool acquires ``state.state_lock`` and wraps the body
in ``try/except`` — exceptions become a typed ``error: str`` field on the
result, never a raw protocol-level error. The exception is ``recv_message``
which holds NO lock while waiting (otherwise nothing else could fire while
we're idle).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from fastmcp import FastMCP

from communication.trustroom.policy import (
    CompositePolicy,
    OpenClawAgentPolicy,
)
from communication.trustroom.stake_policy import StakedAdmissionPolicy
from integration.mcp_server.schemas import (
    Inbox,
    Joined,
    MessageRecord,
    MessageSent,
    PeerEntry as PeerEntrySchema,
    Peers,
    Rooms,
    RoomCreated,
    StakeLocked,
    StakeProofDict,
    TransferOk,
    Wallet,
    WhoAmI,
)
from shared.errors import AdmissionDenied
from shared.ids import AgentId, CredentialId, RoomId
from shared.logging import get_logger
from stake.proof import StakeProof

if TYPE_CHECKING:
    from integration.mcp_server.state import ServerState


_log = get_logger("mcp_tools")


_INSTRUCTIONS = (
    "DelftClaw MCP server. Each tool wraps a method on AgentChannel — the "
    "agent's substrate for identity-bound, stake-gated, signed messaging "
    "with synthetic-BTC value transfer over IPv8. Use list_peers to see "
    "available aliases, whoami to identify yourself, and the room/message "
    "tools to discover and converse with peers. Stake operations (lock, "
    "transfer) move synthetic-BTC sats; balances live on a per-agent oracle."
)


def build_app(state: "ServerState") -> FastMCP:
    """Build the FastMCP application bound to a hot :class:`ServerState`.

    The state must already have :meth:`AgentChannel.start` awaited (see
    :func:`integration.mcp_server.boot.boot`). Tool handlers close over
    ``state``.
    """
    cfg = state.config
    mcp = FastMCP(
        name=f"delftclaw-{cfg.agent.name}",
        instructions=_INSTRUCTIONS,
    )

    _log.info(
        "tools_registering",
        agent=cfg.agent.name,
        agent_id=str(state.identity.agent_id),
    )

    # --- 1. delftclaw_whoami ---------------------------------------------

    @mcp.tool(name="delftclaw_whoami")
    async def whoami() -> WhoAmI:
        """Return this agent's identity: agent_id, network, app and wallet pubkeys.

        Use this first in any new conversation to confirm which agent you
        are. ``agent_id`` is the base32 string used in peer-directory
        entries and as ``sender_agent_id`` in incoming messages.
        """
        try:
            async with state.state_lock:
                return WhoAmI(
                    agent_id=str(state.identity.agent_id),
                    network=state.identity.network,
                    app_pubkey_hex=state.identity.app.pubkey.hex(),
                    wallet_pubkey_hex=state.identity.wallet.pubkey.hex(),
                )
        except Exception as exc:  # noqa: BLE001
            return WhoAmI(
                agent_id="",
                network="",
                app_pubkey_hex="",
                wallet_pubkey_hex="",
                error=f"{type(exc).__name__}: {exc}",
            )

    # --- 2. delftclaw_list_peers -----------------------------------------

    @mcp.tool(name="delftclaw_list_peers")
    async def list_peers() -> Peers:
        """Return the static peer directory.

        Use the ``alias`` values for ``host_alias`` / ``target_alias`` /
        ``recipient_alias`` arguments on other tools.
        """
        try:
            async with state.state_lock:
                return Peers(
                    peers=[
                        PeerEntrySchema(
                            alias=e.alias,
                            agent_id=e.agent_id,
                            ip=e.ip,
                            ipv8_port=e.ipv8_port,
                        )
                        for e in state.peers.all()
                    ]
                )
        except Exception as exc:  # noqa: BLE001
            return Peers(error=f"{type(exc).__name__}: {exc}")

    # --- 3. delftclaw_create_room ----------------------------------------

    @mcp.tool(name="delftclaw_create_room")
    async def create_room(
        pinned_issuer_pubkey_hex: str,
        min_stake_sats: int = 0,
    ) -> RoomCreated:
        """Create a Trustroom this agent will host.

        The room admits joiners that present a Verifiable Credential issued
        by ``pinned_issuer_pubkey_hex`` (32-byte Ed25519 verify-key, hex).
        If ``min_stake_sats > 0``, joiners must additionally lock at least
        that many sats under the room's admission purpose before joining.

        Returns ``room_id_hex`` — the room identifier you share with peers
        and pass back to subsequent tool calls.
        """
        try:
            issuer_pubkey = bytes.fromhex(pinned_issuer_pubkey_hex)
            if len(issuer_pubkey) != 32:
                return RoomCreated(
                    error=f"pinned_issuer_pubkey_hex must be 32 bytes, got {len(issuer_pubkey)}"
                )
            async with state.state_lock:
                policies = [OpenClawAgentPolicy(issuer_pubkey)]
                if min_stake_sats > 0:
                    policies.append(
                        StakedAdmissionPolicy(state.channel.oracle, min_sats=min_stake_sats)
                    )
                policy = CompositePolicy(policies) if len(policies) > 1 else policies[0]
                room_id = state.channel.create_room(policy)
            return RoomCreated(
                room_id_hex=room_id.to_bytes().hex(),
                policy_descriptor=type(policy).__name__,
            )
        except Exception as exc:  # noqa: BLE001
            return RoomCreated(error=f"{type(exc).__name__}: {exc}")

    # --- 4. delftclaw_lock_for_admission ---------------------------------

    @mcp.tool(name="delftclaw_lock_for_admission")
    async def lock_for_admission(
        room_id_hex: str,
        amount: int,
        host_alias: str,
    ) -> StakeLocked:
        """Lock ``amount`` sats under a room's admission purpose, broadcast to host.

        Returns the ``stake_proof`` you should pass to
        ``delftclaw_join_room``. The lock is applied to your local oracle
        and broadcast to ``host_alias`` so the host's oracle sees it
        before your join request arrives.
        """
        try:
            room_id = RoomId(bytes.fromhex(room_id_hex))
            async with state.state_lock:
                proof = state.channel.lock_for_admission(room_id, amount)
                host_peer = state.peers.resolve(host_alias, state.channel.community)
                await state.channel.broadcast_last_op(host_peer)
            return StakeLocked(
                stake_proof=StakeProofDict(
                    purpose=proof.purpose,
                    min_sats=proof.min_sats,
                    actor_agent_id_hex=proof.actor.to_bytes().hex(),
                    timestamp_ms=proof.timestamp_ms,
                )
            )
        except Exception as exc:  # noqa: BLE001
            return StakeLocked(error=f"{type(exc).__name__}: {exc}")

    # --- 5. delftclaw_join_room ------------------------------------------

    @mcp.tool(name="delftclaw_join_room")
    async def join_room(
        room_id_hex: str,
        vc_id: str,
        host_alias: str,
        stake_proof: StakeProofDict | None = None,
    ) -> Joined:
        """Join a Trustroom by presenting a VC (and stake proof if required).

        ``vc_id`` must reference a credential pre-loaded in this agent's
        TrustStore. If the room is stake-gated, pass the ``stake_proof``
        returned by a prior ``delftclaw_lock_for_admission`` call.
        """
        try:
            room_id = RoomId(bytes.fromhex(room_id_hex))
            stake_proof_obj: StakeProof | None = None
            if stake_proof is not None:
                actor_bytes = bytes.fromhex(stake_proof.actor_agent_id_hex)
                stake_proof_obj = StakeProof(
                    purpose=stake_proof.purpose,
                    min_sats=stake_proof.min_sats,
                    actor=AgentId(actor_bytes),
                    timestamp_ms=stake_proof.timestamp_ms,
                )
            async with state.state_lock:
                host_peer = state.peers.resolve(host_alias, state.channel.community)
                await state.channel.join_room(
                    room_id=room_id,
                    vc_id=CredentialId(vc_id),
                    host_peer=host_peer,
                    stake_proof=stake_proof_obj,
                )
            return Joined(ok=True, reason="admitted")
        except AdmissionDenied as exc:
            return Joined(ok=False, reason=str(exc))
        except Exception as exc:  # noqa: BLE001
            return Joined(ok=False, reason="error", error=f"{type(exc).__name__}: {exc}")

    # --- 6. delftclaw_send_message ---------------------------------------

    @mcp.tool(name="delftclaw_send_message")
    async def send_message(
        room_id_hex: str,
        text: str,
        target_alias: str,
    ) -> MessageSent:
        """Send a signed application message to ``target_alias`` in ``room_id_hex``.

        The message goes inside a WireFrame signed by your AppSigningKey.
        Replay defence and nonce dedup are applied on the receive side.
        """
        try:
            room_id = RoomId(bytes.fromhex(room_id_hex))
            async with state.state_lock:
                target_peer = state.peers.resolve(target_alias, state.channel.community)
                msg_id = await state.channel.send(room_id, text, target_peer=target_peer)
            return MessageSent(message_id_hex=msg_id.to_bytes().hex())
        except Exception as exc:  # noqa: BLE001
            return MessageSent(error=f"{type(exc).__name__}: {exc}")

    # --- 7. delftclaw_recv_message ---------------------------------------

    @mcp.tool(name="delftclaw_recv_message")
    async def recv_message(timeout_ms: int = 0) -> Inbox:
        """Pop the next inbound message from this agent's inbox, or return null.

        With the default ``timeout_ms=0`` returns immediately: ``message``
        is non-null if a message was queued, ``null`` otherwise. Set
        ``timeout_ms`` to wait briefly for a message to arrive.
        """
        # NOTE: deliberately no state_lock — recv blocks; we don't want to
        # hold a lock while waiting. Reading from the inbox is itself
        # asyncio-safe.
        try:
            timeout_s = max(0.001, timeout_ms / 1000.0) if timeout_ms > 0 else 0.001
            try:
                msg = await state.channel.recv(timeout=timeout_s)
            except asyncio.TimeoutError:
                return Inbox(message=None)
            return Inbox(
                message=MessageRecord(
                    room_id_hex=msg.room_id.to_bytes().hex(),
                    sender_agent_id=str(msg.sender),
                    text=msg.message.text,
                    received_at_iso=msg.received_at.isoformat(),
                )
            )
        except Exception as exc:  # noqa: BLE001
            return Inbox(error=f"{type(exc).__name__}: {exc}")

    # --- 8. delftclaw_transfer -------------------------------------------

    @mcp.tool(name="delftclaw_transfer")
    async def transfer(
        recipient_alias: str,
        amount: int,
    ) -> TransferOk:
        """Transfer synthetic-BTC sats to ``recipient_alias``.

        Signed by this agent's wallet key. Applied locally and broadcast
        to the recipient's MCP server via IPv8. Replay-protected by the
        oracle's nonce dedup set.
        """
        try:
            async with state.state_lock:
                recipient_entry = state.peers.lookup(recipient_alias)
                target_peer = state.peers.resolve(recipient_alias, state.channel.community)
                recipient_agent_id = AgentId.from_pubkey(recipient_entry.raw_verify_key())
                await state.channel.transfer(
                    recipient=recipient_agent_id,
                    amount=amount,
                    target_peer=target_peer,
                )
            return TransferOk(ok=True)
        except Exception as exc:  # noqa: BLE001
            return TransferOk(ok=False, error=f"{type(exc).__name__}: {exc}")

    # --- 9. delftclaw_list_rooms -----------------------------------------

    @mcp.tool(name="delftclaw_list_rooms")
    async def list_rooms() -> Rooms:
        """Return the rooms this agent is currently joined to (as ``room_id_hex``)."""
        try:
            async with state.state_lock:
                rooms = state.channel.list_rooms()
            return Rooms(room_ids_hex=[r.to_bytes().hex() for r in rooms])
        except Exception as exc:  # noqa: BLE001
            return Rooms(error=f"{type(exc).__name__}: {exc}")

    # --- 10. delftclaw_wallet_balance ------------------------------------

    @mcp.tool(name="delftclaw_wallet_balance")
    async def wallet_balance() -> Wallet:
        """Return this agent's spendable sats balance and per-room admission locks."""
        try:
            async with state.state_lock:
                balance = state.channel.oracle.balance(state.identity.agent_id)
                locked: dict[str, int] = {}
                for room_id in state.channel.list_rooms():
                    purpose = f"admission:room={room_id.to_bytes().hex()}"
                    amt = state.channel.oracle.locked(state.identity.agent_id, purpose)
                    if amt > 0:
                        locked[purpose] = amt
            return Wallet(balance=balance, locked=locked)
        except Exception as exc:  # noqa: BLE001
            return Wallet(error=f"{type(exc).__name__}: {exc}")

    return mcp


__all__ = ["build_app"]
