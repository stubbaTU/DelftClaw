"""Verifies a Presentation: format-specific check + revocation lookup."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Mapping, Protocol

from shared.credentials import Presentation, VerifiedCredential
from shared.errors import CredentialInvalid
from trust.formats.base import CredentialFormat
from trust.revocation import RevocationChecker


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CredentialVerifier(Protocol):
    """Strategy for turning a Presentation into a VerifiedCredential."""

    def verify(self, presentation: Presentation) -> VerifiedCredential: ...


class MultiFormatVerifier(CredentialVerifier):
    """Dispatches to a ``CredentialFormat`` by ``presentation.credential.format_id``."""

    def __init__(
        self,
        formats: Mapping[str, CredentialFormat],
        revocation: RevocationChecker,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._formats = dict(formats)
        self._revocation = revocation
        self._clock = clock

    def verify(self, presentation: Presentation) -> VerifiedCredential:
        cred = presentation.credential
        format_plugin = self._formats.get(cred.format_id)
        if format_plugin is None:
            raise CredentialInvalid(f"no plugin registered for format {cred.format_id!r}")
        if not format_plugin.verify(cred):
            raise CredentialInvalid(f"format {cred.format_id!r} rejected the credential")
        revoked = self._revocation.is_revoked(cred)
        return VerifiedCredential(
            credential=cred,
            verified_at=self._clock(),
            revocation_status="unknown" if revoked else "fresh",
        )
