"""``StakeOracle`` — read+write access to balances and locks.

Backed by either an in-memory state machine (M2) or the colleague's
append-only log (M3+). The Protocol is the integration boundary.
"""

from __future__ import annotations

from typing import Protocol

from shared.ids import AgentId
from shared.stake import StakeOp


class StakeOracle(Protocol):
    """Strategy for reading and mutating synthetic-BTC state."""

    def balance(self, agent: AgentId) -> int: ...

    def locked(self, agent: AgentId, purpose: str) -> int: ...

    def has_lock(self, agent: AgentId, purpose: str, min_sats: int) -> bool: ...

    def apply(self, op: StakeOp) -> None:
        """Apply a verified ``StakeOp`` to local state. Raises ``StakeError`` on invalid op.

        The signature MUST already have been verified by the caller. Validation
        here is purely state-machine semantics: balance suffices, nonce unseen,
        target/purpose semantics correct for this kind.
        """
        ...
