"""In-memory ``StakeOracle`` backend.

The state machine reducer for synthetic-BTC operations. Caller verifies the
``StakeOp`` signature before calling :meth:`apply`; this class only enforces
state-level rules (balance suffices, nonce unseen, semantics by kind).
"""

from __future__ import annotations

from shared.ids import AgentId
from shared.logging import get_logger
from shared.stake import StakeOp, StakeOpKind

_log = get_logger("stake_oracle")


class StakeError(Exception):
    """An invalid ``StakeOp`` reached the oracle's reducer."""


class InMemoryStakeOracle:
    """Local-only stake oracle. State is a balance map plus a per-purpose lock map."""

    def __init__(self, *, mirror_remote: bool = False) -> None:
        """Construct an empty oracle.

        ``mirror_remote=True`` switches semantics for ``LOCK`` and ``TRANSFER``: if
        the actor's local balance is too low, the oracle treats the missing funds
        as if a faucet credited them just before the op. This is the M2 stand-in
        for a replicated ledger — every receiver mirrors every sender's state.
        Real Byzantine resistance comes with M3's append-only log + KeyBundle PKI.
        """
        self._balances: dict[AgentId, int] = {}
        self._locks: dict[tuple[AgentId, str], int] = {}
        self._seen_nonces: set[bytes] = set()
        self._mirror_remote = mirror_remote
        _log.debug("oracle_initialised", mirror_remote=mirror_remote)

    # --- queries -----------------------------------------------------------

    def balance(self, agent: AgentId) -> int:
        return self._balances.get(agent, 0)

    def locked(self, agent: AgentId, purpose: str) -> int:
        return self._locks.get((agent, purpose), 0)

    def has_lock(self, agent: AgentId, purpose: str, min_sats: int) -> bool:
        actual = self.locked(agent, purpose)
        result = actual >= min_sats
        _log.debug(
            "has_lock_query",
            agent=str(agent),
            purpose=purpose,
            min_sats=min_sats,
            actual=actual,
            result=result,
        )
        return result

    # --- mutations ---------------------------------------------------------

    def faucet(self, agent: AgentId, amount: int) -> None:
        """Test-only mint shortcut. Bypasses signature/nonce checks; demo bootstrap."""
        if amount <= 0:
            raise StakeError("faucet amount must be positive")
        prior = self.balance(agent)
        self._balances[agent] = prior + amount
        _log.info(
            "faucet_credit",
            agent=str(agent),
            amount=amount,
            balance_before=prior,
            balance_after=prior + amount,
        )

    def apply(self, op: StakeOp) -> None:
        if op.amount <= 0:
            _log.info("oracle_apply_rejected", reason="non_positive_amount", kind=str(op.kind))
            raise StakeError(f"{op.kind}: amount must be positive")

        nonce_key = op.nonce.to_bytes()
        if nonce_key in self._seen_nonces:
            _log.info(
                "oracle_apply_rejected",
                reason="nonce_replay",
                kind=str(op.kind),
                actor=str(op.actor),
            )
            raise StakeError(f"{op.kind}: nonce already seen")

        if op.kind == StakeOpKind.MINT:
            prior = self.balance(op.actor)
            self._balances[op.actor] = prior + op.amount
            _log.info(
                "oracle_mint",
                actor=str(op.actor),
                amount=op.amount,
                balance_before=prior,
                balance_after=prior + op.amount,
            )

        elif op.kind == StakeOpKind.TRANSFER:
            if op.target is None:
                _log.info("oracle_apply_rejected", reason="transfer_no_target")
                raise StakeError("transfer: target is required")
            if self.balance(op.actor) < op.amount and not self._mirror_remote:
                _log.info(
                    "oracle_apply_rejected",
                    reason="transfer_insufficient_balance",
                    actor=str(op.actor),
                    have=self.balance(op.actor),
                    need=op.amount,
                )
                raise StakeError(
                    f"transfer: insufficient balance "
                    f"(have {self.balance(op.actor)}, need {op.amount})"
                )
            actor_before = self.balance(op.actor)
            target_before = self.balance(op.target)
            self._balances[op.actor] = actor_before - op.amount
            self._balances[op.target] = target_before + op.amount
            _log.info(
                "oracle_transfer",
                actor=str(op.actor),
                target=str(op.target),
                amount=op.amount,
                actor_balance_before=actor_before,
                actor_balance_after=actor_before - op.amount,
                target_balance_before=target_before,
                target_balance_after=target_before + op.amount,
            )

        elif op.kind == StakeOpKind.LOCK:
            if not op.purpose:
                _log.info("oracle_apply_rejected", reason="lock_no_purpose")
                raise StakeError("lock: purpose is required")
            if self.balance(op.actor) < op.amount and not self._mirror_remote:
                _log.info(
                    "oracle_apply_rejected",
                    reason="lock_insufficient_balance",
                    actor=str(op.actor),
                    have=self.balance(op.actor),
                    need=op.amount,
                )
                raise StakeError(
                    f"lock: insufficient balance "
                    f"(have {self.balance(op.actor)}, need {op.amount})"
                )
            balance_before = self.balance(op.actor)
            self._balances[op.actor] = balance_before - op.amount
            key = (op.actor, op.purpose)
            locked_before = self._locks.get(key, 0)
            self._locks[key] = locked_before + op.amount
            _log.info(
                "oracle_lock",
                actor=str(op.actor),
                amount=op.amount,
                purpose=op.purpose,
                balance_before=balance_before,
                balance_after=balance_before - op.amount,
                locked_before=locked_before,
                locked_after=locked_before + op.amount,
            )

        elif op.kind == StakeOpKind.UNLOCK:
            if not op.purpose:
                _log.info("oracle_apply_rejected", reason="unlock_no_purpose")
                raise StakeError("unlock: purpose is required")
            key = (op.actor, op.purpose)
            current = self._locks.get(key, 0)
            if current < op.amount:
                _log.info(
                    "oracle_apply_rejected",
                    reason="unlock_insufficient_lock",
                    actor=str(op.actor),
                    have=current,
                    need=op.amount,
                )
                raise StakeError(
                    f"unlock: insufficient lock "
                    f"(have {current}, need {op.amount})"
                )
            balance_before = self.balance(op.actor)
            self._locks[key] = current - op.amount
            self._balances[op.actor] = balance_before + op.amount
            _log.info(
                "oracle_unlock",
                actor=str(op.actor),
                amount=op.amount,
                purpose=op.purpose,
                locked_before=current,
                locked_after=current - op.amount,
                balance_before=balance_before,
                balance_after=balance_before + op.amount,
            )

        else:
            raise StakeError(f"unknown op kind: {op.kind!r}")

        self._seen_nonces.add(nonce_key)
