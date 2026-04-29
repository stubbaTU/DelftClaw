"""Verifies a Presentation: format-specific check + revocation lookup."""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Mapping, Protocol

from shared.credentials import Presentation, VerifiedCredential
from trust.formats.base import CredentialFormat
from trust.revocation import RevocationChecker


class CredentialVerifier(Protocol):
    """Strategy for turning a Presentation into a VerifiedCredential."""

    def verify(self, presentation: Presentation) -> VerifiedCredential:
        # Verify issuer sig, holder binding, audience, nonce, expiry, revocation; raise CredentialInvalid.
        ...


class MultiFormatVerifier(CredentialVerifier):
    """Dispatches to a CredentialFormat by `presentation.credential.format_id`."""

    def __init__(
        self,
        formats: Mapping[str, CredentialFormat],
        revocation: RevocationChecker,
        clock: Callable[[], datetime] = datetime.utcnow,
    ) -> None:
        # Store the format registry, revocation checker, and clock for expiry checks.
        ...

    def verify(self, presentation: Presentation) -> VerifiedCredential:
        # Look up format by id, call format.verify, then RevocationChecker.is_revoked.
        ...
