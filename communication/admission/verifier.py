"""Verifies a Presentation: format-specific check + revocation lookup."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Mapping, Protocol

from shared.credentials import Presentation, VerifiedCredential
from shared.errors import CredentialInvalid
from shared.logging import get_logger
from trust.formats.base import CredentialFormat
from trust.revocation import RevocationChecker

_log = get_logger("verifier")


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
        _log.debug("verify_dispatching", format_id=cred.format_id)
        format_plugin = self._formats.get(cred.format_id)
        if format_plugin is None:
            _log.info(
                "verify_rejected",
                reason="no_plugin_for_format",
                format_id=cred.format_id,
                registered=list(self._formats.keys()),
            )
            raise CredentialInvalid(f"no plugin registered for format {cred.format_id!r}")
        if not format_plugin.verify(cred):
            _log.info(
                "verify_rejected",
                reason="format_plugin_rejected",
                format_id=cred.format_id,
            )
            raise CredentialInvalid(f"format {cred.format_id!r} rejected the credential")
        revoked = self._revocation.is_revoked(cred)
        _log.debug(
            "verify_revocation_checked",
            checker=type(self._revocation).__name__,
            revoked=revoked,
        )
        verified = VerifiedCredential(
            credential=cred,
            verified_at=self._clock(),
            revocation_status="unknown" if revoked else "fresh",
        )
        _log.info(
            "verify_passed",
            format_id=cred.format_id,
            revocation_status=verified.revocation_status,
        )
        return verified
