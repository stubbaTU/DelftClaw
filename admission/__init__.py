"""Bitcoin-donation admission gate for SeedboxCommunity.

Exposes ``DonationVerifier`` (gatekeeper-side check that a joiner's
txid paid >= ``min_sats`` to the seedbox address) and the
``DonationVerification`` result dataclass.

This module used to live at ``replication/verification/donation_verifier.py``
in the v5.0 layout; the rename is part of the v5.1 cleanup. The
``replication/`` package retains other (unrelated) subproject work.
"""

from admission.donation_verifier import DonationVerification, DonationVerifier

__all__ = ["DonationVerification", "DonationVerifier"]
