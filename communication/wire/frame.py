"""Plaintext header bytes that get signed (but not encrypted) per outgoing frame.

`WireFrame` itself lives in `openclaw_shared.envelopes`; this header is the
sub-structure used to compute the frame signature.
"""

from __future__ import annotations

from dataclasses import dataclass

from shared.ids import AgentId, Epoch, MessageId, RoomId


@dataclass(frozen=True)
class WireFrameHeader:
    """Plaintext routing info bound by the sender_signature on every WireFrame."""

    room_id: RoomId
    epoch: Epoch
    sender: AgentId
    msg_id: MessageId
