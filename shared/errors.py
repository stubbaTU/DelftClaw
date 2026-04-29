"""Exception hierarchy used across all packages."""

from __future__ import annotations


class OpenClawError(Exception):
    """Base of every package-specific exception."""


class CommunicationError(OpenClawError):
    """Any failure inside the channel."""


class AdmissionDenied(CommunicationError):
    """Layer 3: the presented VC failed the admission policy."""


class CredentialInvalid(CommunicationError):
    """The VC signature, expiry, audience binding, or schema was invalid."""


class EpochMismatch(CommunicationError):
    """Layer 4: the peer is in a different MLS / ratchet epoch."""


class PayloadInvalid(CommunicationError):
    """Layer 5 deserialisation or schema validation failed."""


class WalletError(OpenClawError):
    """Bitcoin signing, UTXO selection, or broadcast failed."""


class IdentityError(OpenClawError):
    """BIP-32 derivation, seed loading, or key construction failed."""
