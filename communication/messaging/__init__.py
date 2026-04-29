"""Layer 4: forward-secret group messaging.

`SecureGroupSession` is the contract; both `MLSSession` (Path A, RFC 9420) and
`RatchetSession` (Path B, HKDF + Ed25519 fallback) implement it. ADR 0003
decides which becomes the default by 2026-05-08.
"""

from communication.messaging.group_state import GroupState
from communication.messaging.secure_group_session import (
    SecureGroupSession,
    SecureGroupSessionFactory,
)
from communication.messaging.ratchet_session import RatchetSession
from communication.messaging.mls_session import MLSSession
from communication.messaging.group_manager import GroupManager
from communication.messaging.envelope import PrivateMessage

__all__ = [
    "GroupState",
    "SecureGroupSession",
    "SecureGroupSessionFactory",
    "RatchetSession",
    "MLSSession",
    "GroupManager",
    "PrivateMessage",
]
