"""Local store of Credentials keyed by CredentialId."""

from __future__ import annotations

from shared.credentials import Credential
from shared.ids import CredentialId


class TrustStore:
    """In-memory mapping from CredentialId to Credential.

    Production deployments will swap this for a disk- or KMS-backed store; the
    interface (``put`` / ``get`` / ``__contains__``) stays the same.
    """

    def __init__(self) -> None:
        self._creds: dict[CredentialId, Credential] = {}

    def put(self, vc_id: CredentialId, credential: Credential) -> None:
        self._creds[vc_id] = credential

    def get(self, vc_id: CredentialId) -> Credential:
        return self._creds[vc_id]

    def __contains__(self, vc_id: CredentialId) -> bool:
        return vc_id in self._creds
