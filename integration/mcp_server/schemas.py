"""Pydantic models for MCP tool inputs (nested) and outputs.

Most tool inputs use bare kwargs (string/int parameters) — FastMCP turns
those into JSON Schema directly. Inputs that carry nested structure (only
``stake_proof`` so far) keep a Pydantic model so the schema describes the
shape clearly to LLMs.

Conventions
-----------
* ``*_hex`` — bytes serialised as lowercase hex strings (no ``0x`` prefix).
* ``agent_id`` — base32-lowercase string from :meth:`AgentId.__str__`
  (16 chars; project-wide identifier).
* ``alias`` — short name from ``peers.yaml`` (e.g. ``"alice"``); LLMs use
  these instead of raw bytes.
* Errors — every result model carries an optional ``error: str`` field so
  the LLM never sees a raw Python exception.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


# --- shared shapes ------------------------------------------------------------


class StakeProofDict(BaseModel):
    """A stake-proof claim that travels inside a join request.

    Equivalent to :class:`stake.proof.StakeProof` but expressed in
    LLM-friendly types. Round-trippable via
    ``actor=AgentId(bytes.fromhex(actor_agent_id_hex))``.
    """

    purpose: str = Field(description="Lock purpose, e.g. 'admission:room=<hex>'")
    min_sats: int = Field(description="Minimum sats the stake claim binds")
    actor_agent_id_hex: str = Field(
        description=(
            "32-byte hex of the actor's AgentId (the lock holder). Hex (not "
            "the friendly base32 form) because the display form is lossy."
        )
    )
    timestamp_ms: int = Field(description="Unix ms when the proof was minted")


class MessageRecord(BaseModel):
    """One delivered application message returned by ``recv_message``."""

    room_id_hex: str
    sender_agent_id: str
    text: str
    received_at_iso: str = Field(description="ISO-8601 UTC timestamp")


class PeerEntry(BaseModel):
    alias: str
    agent_id: str
    ip: str
    ipv8_port: int


# --- tool result models -------------------------------------------------------


class WhoAmI(BaseModel):
    """Identity of *this* MCP server's underlying agent."""

    agent_id: str = Field(description="Base32 agent_id")
    network: str = Field(description="Network label (e.g. TESTNET)")
    app_pubkey_hex: str
    wallet_pubkey_hex: str
    error: str | None = None


class Peers(BaseModel):
    peers: list[PeerEntry] = Field(default_factory=list)
    error: str | None = None


class RoomCreated(BaseModel):
    room_id_hex: str = ""
    policy_descriptor: str = ""
    error: str | None = None


class StakeLocked(BaseModel):
    stake_proof: StakeProofDict | None = None
    error: str | None = None


class Joined(BaseModel):
    ok: bool = False
    reason: str = ""
    error: str | None = None


class MessageSent(BaseModel):
    message_id_hex: str | None = None
    error: str | None = None


class Inbox(BaseModel):
    message: MessageRecord | None = None
    error: str | None = None


class TransferOk(BaseModel):
    ok: bool = False
    error: str | None = None


class Rooms(BaseModel):
    room_ids_hex: list[str] = Field(default_factory=list)
    error: str | None = None


class Wallet(BaseModel):
    balance: int = Field(default=0, description="Spendable sats (locked amounts excluded)")
    locked: dict[str, int] = Field(
        default_factory=dict,
        description="Mapping of lock-purpose → locked sats for rooms this agent is in",
    )
    error: str | None = None


__all__ = [
    "StakeProofDict",
    "MessageRecord",
    "PeerEntry",
    "WhoAmI",
    "Peers",
    "RoomCreated",
    "StakeLocked",
    "Joined",
    "MessageSent",
    "Inbox",
    "TransferOk",
    "Rooms",
    "Wallet",
]
