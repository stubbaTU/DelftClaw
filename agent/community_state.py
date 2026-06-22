"""Community state replayed from signed-log entries — no treasurer, no key custody.

The treasury balance and membership roster are computed by folding every member's
signed log: ``replay_community(manifest, entries)`` is a pure fold over entry dicts
(no IPv8/HTTP/IO), so tests can build small entry lists and assert state directly.
Two actions are recognised, ``donation_intent`` (admits the donor) and ``payment``
(peer-to-peer fake-BTC transfer); everything else is ignored. Entries are sorted by
``(timestamp, reporter_id, entry_hash)`` so replay is order-independent, and rejected
entries are dropped from the view (the log itself is read-only). Validation lives in
the ``_validate_*`` helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from protocol.manifest import NetworkManifest


COMMUNITY_ACTIONS = frozenset({"donation_intent", "payment"})


@dataclass(frozen=True)
class DonationIntent:
    """An accepted donation that admitted a new member."""

    reporter_id: str        # SHA256(pubkey || network) hex of the donor
    amount_sats: int
    timestamp: str          # ISO 8601 from the underlying signed entry
    entry_hash: str         # signed-log chain hash of the entry
    wallet_address: str = ""  # the donor's wallet address (account id for the ledger)


@dataclass(frozen=True)
class Payment:
    """An accepted peer-to-peer payment, addressed by wallet (the id exchanged
    via PEER_INTRO) so a sender knowing only a peer's wallet can attribute it."""

    from_wallet: str        # wallet of the sender (the signer of the entry)
    to_wallet: str          # wallet of the recipient
    amount_sats: int
    timestamp: str
    entry_hash: str


@dataclass(frozen=True)
class CommunityState:
    """Aggregate view derived by ``replay_community(...)``; frozen/immutable so
    the tool surface can hand it out without mutation worries."""

    members: frozenset[str]
    donations: tuple[DonationIntent, ...]
    balance_sats: int               # treasury: sum of accepted donations
    payments: tuple[Payment, ...] = ()

    @property
    def member_count(self) -> int:
        return len(self.members)

    @property
    def member_wallets(self) -> dict[str, str]:
        """reporter_id → wallet address, from each member's donation."""
        return {d.reporter_id: d.wallet_address for d in self.donations if d.wallet_address}

    @property
    def balances(self) -> dict[str, int]:
        """Per-wallet net transfer position (received − sent): the signed-log
        ledger every peer derives identically, with no custodian. Treasury
        (donations) is separate, in ``balance_sats``."""
        out: dict[str, int] = {w: 0 for w in self.member_wallets.values()}
        for p in self.payments:
            out[p.from_wallet] = out.get(p.from_wallet, 0) - p.amount_sats
            out[p.to_wallet] = out.get(p.to_wallet, 0) + p.amount_sats
        return out


def replay_community(
    manifest: NetworkManifest,
    entries: Iterable[dict],
) -> CommunityState:
    """Fold signed-log entry dicts into a ``CommunityState``: filter to community
    actions, sort for deterministic order, validate each against the state so far
    (valid extends it, invalid is dropped). Signatures are verified upstream (by
    ``PeerLog`` / the local log); this never re-checks them."""
    network_id_hex = manifest.network_id.hex()
    relevant = [e for e in entries if e.get("action") in COMMUNITY_ACTIONS]
    ordered = sorted(
        relevant,
        key=lambda e: (
            e.get("timestamp", ""),
            e.get("reporter_id", ""),
            e.get("entry_hash", ""),
        ),
    )

    members: set[str] = set()
    donations: list[DonationIntent] = []
    payments: list[Payment] = []
    balance = 0
    # reporter_id -> wallet, filled as donations are accepted; lets a payment
    # derive the sender's wallet and check the recipient is a member
    wallet_by_member: dict[str, str] = {}

    for entry in ordered:
        action = entry.get("action")
        details = entry.get("details") or {}
        if details.get("network_id_hex") != network_id_hex:
            continue  # targets a different network

        if action == "donation_intent":
            accepted = _validate_donation_intent(
                entry, details, manifest, members, donations,
            )
            if accepted is not None:
                members.add(accepted.reporter_id)
                donations.append(accepted)
                balance += accepted.amount_sats
                if accepted.wallet_address:
                    wallet_by_member[accepted.reporter_id] = accepted.wallet_address

        elif action == "payment":
            # both parties must already be admitted at this point in time order
            accepted_pay = _validate_payment(entry, details, members, wallet_by_member)
            if accepted_pay is not None:
                payments.append(accepted_pay)

    return CommunityState(
        members=frozenset(members),
        donations=tuple(donations),
        balance_sats=balance,
        payments=tuple(payments),
    )


# Per-entry validators: pure, return None on reject or the record on accept.


def _validate_donation_intent(
    entry: dict,
    details: dict,
    manifest: NetworkManifest,
    members: set[str],
    prior_donations: list[DonationIntent],
) -> Optional[DonationIntent]:
    reporter_id = entry.get("reporter_id")
    if not isinstance(reporter_id, str) or not reporter_id:
        return None
    if reporter_id in members:
        return None  # already admitted; double-join rejected

    amount = details.get("amount_sats")
    if not isinstance(amount, int) or isinstance(amount, bool):
        return None
    if amount < manifest.admission.min_sats:
        return None

    if not prior_donations:
        cap = manifest.admission.effective_bootstrap_cap_sats
    else:
        avg = sum(d.amount_sats for d in prior_donations) // len(prior_donations)
        cap = max(manifest.admission.min_sats, avg)
    if amount > cap:
        return None

    wallet = details.get("wallet_address")
    return DonationIntent(
        reporter_id=reporter_id,
        amount_sats=amount,
        timestamp=entry.get("timestamp", "") or "",
        entry_hash=entry.get("entry_hash", "") or "",
        wallet_address=wallet if isinstance(wallet, str) else "",
    )


def _validate_payment(
    entry: dict,
    details: dict,
    members: set[str],
    wallet_by_member: dict[str, str],
) -> Optional[Payment]:
    """Accept a payment iff both parties are admitted members. The sender's wallet
    is derived from its own donation (not trusted from the entry); ``to_wallet``
    must belong to a member; the amount must be a positive int."""
    from_id = entry.get("reporter_id")
    if not isinstance(from_id, str) or from_id not in members:
        return None
    from_wallet = wallet_by_member.get(from_id)
    if not from_wallet:
        return None  # sender's wallet unknown (no donation on record)

    to_wallet = details.get("to_wallet")
    if not isinstance(to_wallet, str) or not to_wallet:
        return None
    if to_wallet not in wallet_by_member.values():
        return None  # recipient is not a known member wallet
    if to_wallet == from_wallet:
        return None  # no self-payment

    amount = details.get("amount_sats")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        return None

    return Payment(
        from_wallet=from_wallet,
        to_wallet=to_wallet,
        amount_sats=amount,
        timestamp=entry.get("timestamp", "") or "",
        entry_hash=entry.get("entry_hash", "") or "",
    )
