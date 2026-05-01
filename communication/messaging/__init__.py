"""Layer 4: forward-secret group messaging.

`SecureGroupSession` is the contract; pick a backend at construction time.
`MockBackend` is the test-only identity-encryption backend. ADR 0003 will
commit to a real backend (likely an `mls-rs-python` wrapper as Path A) by
2026-05-08 — see PROJECT_DESIGN §7.9.
"""

from communication.messaging.envelope import PrivateMessage
from communication.messaging.group_manager import GroupManager
from communication.messaging.group_state import GroupState
from communication.messaging.mock_backend import MockBackend, MockBackendFactory
from communication.messaging.secure_group_session import (
    SecureGroupSession,
    SecureGroupSessionFactory,
)

__all__ = [
    "GroupState",
    "SecureGroupSession",
    "SecureGroupSessionFactory",
    "MockBackend",
    "MockBackendFactory",
    "GroupManager",
    "PrivateMessage",
]
