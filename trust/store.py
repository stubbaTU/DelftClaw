"""Local cache of VCs an agent holds."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from shared.credentials import Credential
from shared.ids import CredentialId


class TrustStore(Protocol):
    """Strategy for persisting / retrieving VCs the agent has been issued."""

    def add(self, c: Credential) -> CredentialId:
        # Persist a credential and return its local CredentialId.
        ...

    def get(self, id: CredentialId) -> Credential:
        # Retrieve a credential by id; raise KeyError if absent.
        ...

    def list(self) -> list[Credential]:
        # Return every credential currently stored.
        ...

    def remove(self, id: CredentialId) -> None:
        # Delete a credential from the store.
        ...


class LocalFileTrustStore(TrustStore):
    """Concrete TrustStore: one JSON file per credential under a directory."""

    def __init__(self, root: Path) -> None:
        # Store the directory under which credential JSON files live; create on first use.
        ...
