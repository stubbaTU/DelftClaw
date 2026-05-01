"""Revocation lookup strategies for Verifiable Credentials."""

from __future__ import annotations

from typing import Protocol

from shared.credentials import Credential


class RevocationChecker(Protocol):
    """Strategy for checking whether a credential has been revoked."""

    def is_revoked(self, credential: Credential) -> bool: ...


class NullRevocationChecker(RevocationChecker):
    """No-op checker — every credential is treated as non-revoked.

    Suitable for tests, local development, and any setting where revocation
    state is delivered out-of-band. Switch to a Status-List-2021 or CRL-backed
    checker before production.
    """

    def is_revoked(self, credential: Credential) -> bool:
        return False
