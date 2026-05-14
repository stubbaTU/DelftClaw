"""Community state replay over a stream of signed log entries.

The DelftClaw community has **no treasurer** and **no key custody** —
treasury balance, membership roster, and seedbox count are all computed
by replaying every member's signed log. Each member owns its own
:class:`~redteam.primitives.signed_log.SignedAppendOnlyLog`; peers pull
each other's chains via :mod:`redteam.integration.pull_loop` and cache
them locally via :class:`~redteam.primitives.peer_log.PeerLog`. The
"community log" is the logical union of all these chains.

This module is pure: ``replay_community(manifest, entries)`` is a fold
over an iterable of entry dicts. No IPv8, no HTTP, no file I/O. That
lets unit tests build small entry lists and assert state directly.

# Wire shape

Community events ride the existing v2 signed-log entry envelope. Three
``action`` values are recognised; everything else is ignored on replay
(an agent's log can carry application/accountability entries too).

  ``donation_intent``        — signed by the donor. Admits the donor.
      details = {
        "network_id_hex": "<40-hex>",
        "amount_sats":    int,
      }

  ``seedbox_purchase_intent`` — signed by any admitted member.
      details = {
        "network_id_hex": "<40-hex>",
        "cost_sats":      int,
      }

  ``seedbox_provisioned``     — signed by the member who actually spawned
      details = {                  the VPS. References the matching intent.
        "network_id_hex":       "<40-hex>",
        "purchase_intent_hash": "<entry_hash hex of the accepted intent>",
        "seedbox_url":          "<reachable address>",
        "seedbox_pubkey_hex":   "<the new seedbox's IPv8 pubkey hex>",
      }

# Validation rules

Donation:
  1. ``reporter_id`` not already a member.
  2. ``amount_sats >= manifest.admission.min_sats``.
  3. If ``prior_donations`` empty:  ``amount_sats <= effective_bootstrap_cap_sats``.
     Else:                          ``amount_sats <= max(min_sats, mean(prior.amount_sats))``.

Purchase intent:
  1. ``manifest.admission.seedbox_growth_enabled`` is True.
  2. ``reporter_id`` is an admitted member.
  3. ``cost_sats == manifest.admission.seedbox_cost_sats`` (exact — manifest declares the price).
  4. ``balance_sats >= cost_sats`` at this log position.
  5. ``member_count > max_agents_per_seedbox × seedbox_count`` (threshold tripped).
  6. ``pending_purchases == 0``  (no accepted purchase still awaiting its
     ``seedbox_provisioned`` entry). First-comer wins on race.

Provisioned:
  1. ``reporter_id`` is an admitted member.
  2. ``details.purchase_intent_hash`` references an accepted intent.
  3. That intent has no prior matching provisioned event.

Rejected entries are silently dropped from the state — the entries
remain in the underlying signed log (replay is read-only) but never
affect the community view.

# Determinism

Replay sorts entries by ``(timestamp, reporter_id, entry_hash)``.
Timestamps are ISO 8601 strings written by ``SignedAppendOnlyLog`` and
break ties only deterministically. The order is independent of input
order: replay over any permutation of the same entry set produces the
same ``CommunityState``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from protocol.manifest import NetworkManifest


# Module-level set of recognised community actions; anything else is
# ignored on replay (an agent's signed log carries other action types
# from the security subsystem too).
COMMUNITY_ACTIONS = frozenset({
    "donation_intent",
    "seedbox_purchase_intent",
    "seedbox_provisioned",
})


# ---------------------------------------------------------------------------
# Typed records (frozen so a CommunityState is hashable + safe to share)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DonationIntent:
    """An accepted donation that admitted a new member."""

    reporter_id: str        # SHA256(pubkey || network) hex of the donor
    amount_sats: int
    timestamp: str          # ISO 8601 from the underlying signed entry
    entry_hash: str         # signed-log chain hash of the entry


@dataclass(frozen=True)
class SeedboxPurchaseIntent:
    """An accepted purchase intent (community committed to spending)."""

    reporter_id: str
    cost_sats: int
    timestamp: str
    entry_hash: str


@dataclass(frozen=True)
class SeedboxProvisioned:
    """An accepted provisioning event closing a purchase intent."""

    reporter_id: str
    purchase_intent_hash: str
    seedbox_url: str
    seedbox_pubkey_hex: str
    timestamp: str
    entry_hash: str


@dataclass(frozen=True)
class CommunityState:
    """Aggregate view derived by ``replay_community(...)``.

    A frozen dataclass so the tool surface can hand it to a caller
    without worrying about mutation. All collections are ``frozenset``
    / ``tuple`` — hashable, immutable.
    """

    members: frozenset[str]
    donations: tuple[DonationIntent, ...]
    purchases: tuple[SeedboxPurchaseIntent, ...]
    provisioned: tuple[SeedboxProvisioned, ...]
    balance_sats: int
    seedbox_count: int               # 1 (the genesis seedbox) + len(provisioned)

    @property
    def member_count(self) -> int:
        return len(self.members)

    @property
    def pending_purchases(self) -> int:
        """Accepted purchase_intents not yet closed by a provisioned event."""
        return len(self.purchases) - len(self.provisioned)

    def threshold_active(self, manifest: NetworkManifest) -> bool:
        """Has the network grown past one seedbox's capacity at the current count?

        False when the manifest disables growth (either of the two growth
        fields is zero — see ``AdmissionPolicy.seedbox_growth_enabled``).
        """
        if not manifest.admission.seedbox_growth_enabled:
            return False
        cap = manifest.admission.max_agents_per_seedbox * self.seedbox_count
        return self.member_count > cap


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def replay_community(
    manifest: NetworkManifest,
    entries: Iterable[dict],
) -> CommunityState:
    """Fold a stream of signed-log entry dicts into a ``CommunityState``.

    Entries are pre-filtered to community actions, then sorted by
    ``(timestamp, reporter_id, entry_hash)`` for deterministic order
    independent of input iteration. Each is validated against the state
    accumulated so far; valid ones extend the state, invalid ones are
    silently dropped.

    The caller is responsible for upstream signature verification —
    entries pulled from a ``PeerLog`` have already been verified by
    ``SignedAppendOnlyLog.verify_foreign_entry``; entries read from the
    local signed log are trusted by virtue of being on disk. This
    function never re-checks signatures.
    """
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
    purchases: list[SeedboxPurchaseIntent] = []
    provisioned: list[SeedboxProvisioned] = []
    balance = 0
    seedbox_count = 1   # genesis seedbox is the network-manifest origin

    for entry in ordered:
        action = entry.get("action")
        details = entry.get("details") or {}
        if details.get("network_id_hex") != network_id_hex:
            continue  # entry targets a different network — ignore

        if action == "donation_intent":
            accepted = _validate_donation_intent(
                entry, details, manifest, members, donations,
            )
            if accepted is not None:
                members.add(accepted.reporter_id)
                donations.append(accepted)
                balance += accepted.amount_sats

        elif action == "seedbox_purchase_intent":
            pending = len(purchases) - len(provisioned)
            accepted = _validate_purchase_intent(
                entry, details, manifest, members, balance,
                seedbox_count, pending,
            )
            if accepted is not None:
                purchases.append(accepted)
                balance -= accepted.cost_sats

        elif action == "seedbox_provisioned":
            accepted = _validate_provisioned(
                entry, details, members, purchases, provisioned,
            )
            if accepted is not None:
                provisioned.append(accepted)
                seedbox_count += 1

    return CommunityState(
        members=frozenset(members),
        donations=tuple(donations),
        purchases=tuple(purchases),
        provisioned=tuple(provisioned),
        balance_sats=balance,
        seedbox_count=seedbox_count,
    )


# ---------------------------------------------------------------------------
# Per-entry validators (pure; return None on reject, the record on accept)
# ---------------------------------------------------------------------------


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

    return DonationIntent(
        reporter_id=reporter_id,
        amount_sats=amount,
        timestamp=entry.get("timestamp", "") or "",
        entry_hash=entry.get("entry_hash", "") or "",
    )


def _validate_purchase_intent(
    entry: dict,
    details: dict,
    manifest: NetworkManifest,
    members: set[str],
    balance_sats: int,
    seedbox_count: int,
    pending_purchases: int,
) -> Optional[SeedboxPurchaseIntent]:
    if not manifest.admission.seedbox_growth_enabled:
        return None

    reporter_id = entry.get("reporter_id")
    if not isinstance(reporter_id, str) or reporter_id not in members:
        return None  # signer must be admitted

    cost = details.get("cost_sats")
    if not isinstance(cost, int) or isinstance(cost, bool):
        return None
    if cost != manifest.admission.seedbox_cost_sats:
        return None  # manifest declares the price; exact-match enforced

    if balance_sats < cost:
        return None  # treasury can't cover this spend

    threshold = manifest.admission.max_agents_per_seedbox * seedbox_count
    if len(members) <= threshold:
        return None  # threshold not tripped — no growth authorised

    if pending_purchases != 0:
        return None  # first-comer already won; await provisioned event

    return SeedboxPurchaseIntent(
        reporter_id=reporter_id,
        cost_sats=cost,
        timestamp=entry.get("timestamp", "") or "",
        entry_hash=entry.get("entry_hash", "") or "",
    )


def _validate_provisioned(
    entry: dict,
    details: dict,
    members: set[str],
    purchases: list[SeedboxPurchaseIntent],
    provisioned: list[SeedboxProvisioned],
) -> Optional[SeedboxProvisioned]:
    reporter_id = entry.get("reporter_id")
    if not isinstance(reporter_id, str) or reporter_id not in members:
        return None

    purchase_intent_hash = details.get("purchase_intent_hash")
    if not isinstance(purchase_intent_hash, str) or not purchase_intent_hash:
        return None

    # The referenced intent must exist + not already be closed by a
    # prior provisioned event. Comparing by entry_hash so there's no
    # ambiguity with multiple-purchase scenarios.
    matching = next(
        (p for p in purchases if p.entry_hash == purchase_intent_hash),
        None,
    )
    if matching is None:
        return None
    already_closed = any(
        v.purchase_intent_hash == purchase_intent_hash for v in provisioned
    )
    if already_closed:
        return None

    seedbox_url = details.get("seedbox_url", "")
    seedbox_pubkey_hex = details.get("seedbox_pubkey_hex", "")
    if not isinstance(seedbox_url, str) or not isinstance(seedbox_pubkey_hex, str):
        return None
    if not seedbox_url or not seedbox_pubkey_hex:
        return None

    return SeedboxProvisioned(
        reporter_id=reporter_id,
        purchase_intent_hash=purchase_intent_hash,
        seedbox_url=seedbox_url,
        seedbox_pubkey_hex=seedbox_pubkey_hex,
        timestamp=entry.get("timestamp", "") or "",
        entry_hash=entry.get("entry_hash", "") or "",
    )
