"""AgentChannel: the OpenClaw-facing facade over TrustroomCommunity."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import time

from communication.admission.codec import pack_presentation
from communication.admission.join_protocol import AdmissionGate
from communication.admission.presenter import CredentialPresenter
from communication.admission.verifier import MultiFormatVerifier
from communication.channel.inbox import Inbox, IncomingMessage
from communication.payload.application_message import (
    MessageBuilder,
    PayloadRouter,
    pack_application_message,
)
from communication.trustroom.community import TrustroomCommunity
from communication.trustroom.lifecycle import RoomRegistry, RoomState
from communication.trustroom.stake_policy import admission_purpose
from communication.trustroom.state import TrustroomState
from shared.envelopes import WireFrame
from shared.errors import AdmissionDenied
from shared.ids import AgentId, CredentialId, Epoch, MessageId, Nonce, RoomId
from shared.logging import get_logger
from shared.stake import StakeOp, StakeOpKind
from stake.in_memory import InMemoryStakeOracle
from stake.oracle import StakeOracle
from stake.proof import StakeProof
from trust.formats.toy import ToyEd25519Format
from trust.revocation import NullRevocationChecker, RevocationChecker

_log = get_logger("agent_channel")

if TYPE_CHECKING:
    from communication.transport.ipv8_runtime import IPv8Runtime
    from communication.trustroom.advertisement import RoomAdvertisement
    from communication.trustroom.policy import AdmissionPolicy
    from identity.agent_identity import AgentIdentity
    from trust.formats.base import CredentialFormat
    from trust.store import TrustStore


class AgentChannel:
    """Single class OpenClaw integrates with.

    Wraps `TrustroomCommunity` and exposes ~9 methods the LLM tool layer can call.
    Method bodies compose calls into community, trust_store, inbox.
    """

    def __init__(
        self,
        identity: "AgentIdentity",
        runtime: "IPv8Runtime",
        trust_store: "TrustStore",
        *,
        credential_format: "CredentialFormat | None" = None,
        revocation: RevocationChecker | None = None,
        inbox: Inbox | None = None,
        oracle: StakeOracle | None = None,
    ) -> None:
        self._identity = identity
        self._runtime = runtime
        self._trust_store = trust_store
        self._format = credential_format or ToyEd25519Format()
        self._revocation = revocation or NullRevocationChecker()
        self._inbox = inbox or Inbox()
        self._oracle: StakeOracle = oracle or InMemoryStakeOracle()

        self._community: TrustroomCommunity | None = None
        self._trustroom_state = TrustroomState()
        self._registry = RoomRegistry()
        self._policies: dict[bytes, "AdmissionPolicy"] = {}
        self._presenter = CredentialPresenter(
            store=self._trust_store,
            format=self._format,
            identity=self._identity,
        )

        # Tell the runtime to load TrustroomCommunity at startup.
        self._runtime.register_community(TrustroomCommunity)

    async def start(self) -> None:
        _log.info(
            "channel_start",
            agent_id=str(self._identity.agent_id),
            network=self._identity.network,
            credential_format=self._format.format_id,
            oracle_class=type(self._oracle).__name__,
        )
        await self._runtime.start()
        community: TrustroomCommunity = self._runtime.get_overlay(TrustroomCommunity)
        verifier = MultiFormatVerifier(
            formats={self._format.format_id: self._format},
            revocation=self._revocation,
        )
        gate = AdmissionGate(verifier=verifier, policy=_DispatchingPolicy(self._policies))
        community.wire(
            identity=self._identity,
            admission=gate,
            payload_router=PayloadRouter(self._inbox),
            trustroom_state=self._trustroom_state,
            oracle=self._oracle,
        )
        self._community = community

    @property
    def oracle(self) -> StakeOracle:
        """The StakeOracle this channel reads/writes balances and locks against."""
        return self._oracle

    async def stop(self) -> None:
        _log.info("channel_stop", agent_id=str(self._identity.agent_id))
        await self._runtime.stop()
        self._community = None

    # --- room operations --------------------------------------------------

    def create_room(self, policy: "AdmissionPolicy") -> RoomId:
        community = self._require_community()
        room_id = community.create_room(policy)
        self._policies[room_id.to_bytes()] = policy
        self._registry.add(room_id, RoomState.JOINED)  # host is auto-joined
        _log.info(
            "room_created",
            room_id=str(room_id),
            policy=type(policy).__name__,
            host=str(self._identity.agent_id),
        )
        return room_id

    async def join_room(
        self,
        room_id: RoomId,
        vc_id: CredentialId,
        host_peer: Any,
        *,
        stake_proof: StakeProof | None = None,
    ) -> None:
        community = self._require_community()
        _log.info(
            "join_attempt",
            room_id=str(room_id),
            vc_id=str(vc_id),
            with_stake=stake_proof is not None,
        )
        host_agent_id = AgentId.from_pubkey(host_peer.public_key.veri.vk)
        _log.debug(
            "join_resolving_host",
            room_id=str(room_id),
            host_agent_id=str(host_agent_id),
            host_mid=host_peer.mid.hex() if hasattr(host_peer, "mid") else None,
        )
        presentation = self._presenter.present(
            vc_id=vc_id,
            audience=host_agent_id,
            nonce=Nonce.fresh(),
            stake_proof=stake_proof,
        )
        self._registry.add(room_id, RoomState.PENDING_JOIN)
        _log.debug("room_state_pending", room_id=str(room_id))
        accepted, host_app_pubkey = await community.send_join_request(
            host_peer=host_peer,
            room_id=room_id,
            presentation_bytes=pack_presentation(presentation),
        )
        if not accepted:
            self._registry.add(room_id, RoomState.ERROR)
            _log.info(
                "join_refused",
                room_id=str(room_id),
                reason="host returned accepted=False",
            )
            raise AdmissionDenied(f"host refused join for room {room_id}")
        if len(host_app_pubkey) != 32:
            # Trust boundary: host accepted us but didn't ship a usable pubkey.
            # We refuse to populate state we can't verify against.
            self._registry.add(room_id, RoomState.ERROR)
            _log.info(
                "join_refused",
                room_id=str(room_id),
                reason="host_app_pubkey absent or malformed",
                host_app_pubkey_bytes=len(host_app_pubkey),
            )
            raise AdmissionDenied(
                f"host accepted but returned no app_pubkey for room {room_id}"
            )
        # Pin the host into our own TrustroomState so host-originated WireFrames
        # pass the is_member() check on our receive path.
        self._trustroom_state.create(
            room_id,
            host=host_agent_id,
            host_app_pubkey=host_app_pubkey,
            policy_descriptor="remote-host",
        )
        self._registry.add(room_id, RoomState.JOINED)
        _log.info(
            "join_succeeded",
            room_id=str(room_id),
            host=str(host_agent_id),
            pinned_host_app_pubkey_prefix=host_app_pubkey[:6].hex(),
        )

    def leave_room(self, room_id: RoomId) -> None:
        community = self._require_community()
        community.leave_room(room_id)
        self._trustroom_state.remove(room_id)
        self._registry.remove(room_id)
        self._policies.pop(room_id.to_bytes(), None)
        _log.info("room_left", room_id=str(room_id))

    def list_rooms(self) -> list[RoomId]:
        return self._registry.all_joined()

    def members(self, room_id: RoomId) -> list[AgentId]:
        return self._trustroom_state.members(room_id)

    def advertisements(self) -> list["RoomAdvertisement"]:
        # Advertiser is deferred (M2). Discovery is out-of-band in M1.
        return []

    # --- messaging --------------------------------------------------------

    async def send(
        self,
        room_id: RoomId,
        text: str,
        target_peer: Any,
    ) -> MessageId:
        community = self._require_community()
        _log.info("send_attempt", room_id=str(room_id), text_len=len(text))
        msg = MessageBuilder().with_text(text).build()
        blob = pack_application_message(msg)
        nonce = Nonce.fresh()
        ts_ms = int(time.time() * 1000)
        _log.debug(
            "frame_preparing",
            room_id=str(room_id),
            payload_bytes=len(blob),
            nonce_prefix=nonce.to_bytes()[:6].hex(),
            timestamp_ms=ts_ms,
        )
        frame = WireFrame.unsigned(
            room_id=room_id,
            epoch=Epoch(0),
            sender=self._identity.agent_id,
            msg_type=int(TrustroomCommunity.MsgId.APPLICATION),
            nonce=nonce,
            timestamp_ms=ts_ms,
            payload=blob,
        )
        signed = frame.sign(self._identity.app.key)
        signed_bytes = signed.to_bytes()
        _log.debug(
            "frame_signed",
            room_id=str(room_id),
            frame_bytes=len(signed_bytes),
            sig_prefix=signed.sender_signature[:6].hex(),
        )
        await community.send_application(target_peer, signed_bytes)
        msg_id = MessageId.fresh()
        _log.info(
            "send_complete",
            room_id=str(room_id),
            message_id=str(msg_id),
            frame_bytes=len(signed_bytes),
        )
        return msg_id

    async def recv(self, timeout: float | None = None) -> IncomingMessage:
        _log.debug("recv_waiting", timeout=timeout)
        msg = await self._inbox.get(timeout)
        _log.info(
            "recv_returned",
            room_id=str(msg.room_id),
            sender=str(msg.sender),
            text_len=len(msg.message.text),
        )
        return msg

    # --- staking -----------------------------------------------------------

    def lock_for_admission(
        self,
        room_id: RoomId,
        amount: int,
    ) -> StakeProof:
        """Lock ``amount`` sats locally under the room's admission purpose, return a StakeProof.

        Applies the lock to the local oracle synchronously. The corresponding
        broadcast (so the host can see the lock) happens via ``broadcast_stake_op``
        — callers usually do that immediately after, before calling ``join_room``.
        """
        purpose = f"admission:room={room_id.to_bytes().hex()}"
        _log.info(
            "stake_lock_attempt",
            room_id=str(room_id),
            amount=amount,
            purpose=purpose,
            balance_before=self._oracle.balance(self._identity.agent_id),
        )
        op = self._signed_op(
            kind=StakeOpKind.LOCK,
            target=None,
            amount=amount,
            purpose=purpose,
        )
        self._oracle.apply(op)
        proof = StakeProof(
            purpose=purpose,
            min_sats=amount,
            actor=self._identity.agent_id,
            timestamp_ms=op.timestamp_ms,
        )
        # Stash the op so the caller can broadcast it.
        self._last_op_bytes = op.to_bytes()
        _log.info(
            "stake_locked",
            room_id=str(room_id),
            amount=amount,
            purpose=purpose,
            balance_after=self._oracle.balance(self._identity.agent_id),
            locked_total=self._oracle.locked(self._identity.agent_id, purpose),
        )
        return proof

    async def broadcast_last_op(self, target_peer: Any) -> None:
        """Send the most-recent locally-applied StakeOp to ``target_peer``.

        Convenience: callers do ``lock_for_admission`` or ``transfer`` (apply locally)
        and then ``broadcast_last_op`` to push the same op to the host/recipient.
        """
        community = self._require_community()
        if not getattr(self, "_last_op_bytes", None):
            raise RuntimeError("no stake op pending broadcast")
        _log.info(
            "stake_op_broadcasting",
            op_bytes=len(self._last_op_bytes),
            target_mid=target_peer.mid.hex() if hasattr(target_peer, "mid") else None,
        )
        await community.send_stake_op(target_peer, self._last_op_bytes)

    async def transfer(
        self,
        recipient: AgentId,
        amount: int,
        target_peer: Any,
    ) -> None:
        """Sign + apply locally + broadcast a TRANSFER op."""
        community = self._require_community()
        _log.info(
            "stake_transfer_attempt",
            recipient=str(recipient),
            amount=amount,
            balance_before=self._oracle.balance(self._identity.agent_id),
        )
        op = self._signed_op(
            kind=StakeOpKind.TRANSFER,
            target=recipient,
            amount=amount,
            purpose="",
        )
        self._oracle.apply(op)
        await community.send_stake_op(target_peer, op.to_bytes())
        _log.info(
            "stake_transferred",
            recipient=str(recipient),
            amount=amount,
            balance_after=self._oracle.balance(self._identity.agent_id),
            recipient_balance_after=self._oracle.balance(recipient),
        )

    def _signed_op(
        self,
        *,
        kind: StakeOpKind,
        target: AgentId | None,
        amount: int,
        purpose: str,
    ) -> StakeOp:
        return StakeOp.unsigned(
            kind=kind,
            actor=self._identity.agent_id,
            target=target,
            amount=int(amount),
            purpose=purpose,
            nonce=Nonce.fresh(),
            timestamp_ms=int(time.time() * 1000),
        ).sign(self._identity.wallet.key)

    # --- internals --------------------------------------------------------

    @property
    def community(self) -> TrustroomCommunity:
        return self._require_community()

    def _require_community(self) -> TrustroomCommunity:
        if self._community is None:
            raise RuntimeError("AgentChannel.start() has not been awaited yet")
        return self._community


class _DispatchingPolicy:
    """Policy adapter: dispatches by ``ctx.room_id`` into a per-room ``AdmissionPolicy``."""

    def __init__(self, by_room: dict[bytes, "AdmissionPolicy"]) -> None:
        self._by_room = by_room

    def evaluate(self, vc, ctx):
        from communication.trustroom.policy import AdmissionDecision

        policy = self._by_room.get(ctx.room_id.to_bytes())
        if policy is None:
            return AdmissionDecision(admitted=False, reason="no policy for room")
        return policy.evaluate(vc, ctx)
