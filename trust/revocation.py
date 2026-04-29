"""Revocation status checks against issuer-published lists."""

from __future__ import annotations

from typing import Protocol

from shared.credentials import Credential


class RevocationChecker(Protocol):
    """Strategy for asking 'is this credential still valid?'"""

    def is_revoked(self, c: Credential) -> bool:
        # Consult the issuer's status list (or equivalent) and report revocation state.
        ...


class StatusListChecker(RevocationChecker):
    """Concrete checker that fetches a W3C Status List from a fixed URL."""

    def __init__(self, status_list_url: str) -> None:
        # Store the URL and prepare an HTTP client (lazy).
        ...
