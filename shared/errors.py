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
    """The peer is in a different room-state epoch (admission state moved)."""


class ReplayDetected(CommunicationError):
    """Layer 2: a frame's nonce was already seen, or its timestamp is outside the skew window."""


class PayloadInvalid(CommunicationError):
    """Layer 5 deserialisation or schema validation failed."""
