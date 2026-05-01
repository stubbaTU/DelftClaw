"""CredentialFormat Protocol — encode/decode/verify a Credential in a specific wire format."""

from __future__ import annotations

from typing import Mapping, Protocol

from shared.credentials import Credential


class CredentialFormat(Protocol):
    """One implementation per supported VC format (``w3c-jwt``, ``sd-jwt``, ``bbs+``).

    Implementations live in `trust/formats/<name>.py` and are registered with
    ``MultiFormatVerifier`` keyed off ``Credential.format_id``.
    """

    format_id: str

    def issue(
        self,
        issuer_pubkey: bytes,
        subject_pubkey: bytes,
        claims: Mapping[str, object],
        signing_key: bytes,
    ) -> Credential: ...

    def verify(self, credential: Credential) -> bool: ...
