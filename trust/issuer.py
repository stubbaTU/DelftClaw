"""The trusted authority that issues VCs to agents."""

from __future__ import annotations

from typing import Any, Mapping

from shared.credentials import Credential


class Issuer:
    """A trusted authority that issues Verifiable Credentials in some chosen format."""

    def __init__(self, signing_key: bytes, issuer_did: str) -> None:
        # Store the issuer's signing key and decentralised identifier for embedding in VCs.
        ...

    def issue(
        self,
        subject_pubkey: bytes,
        claims: Mapping[str, Any],
        format_id: str,
    ) -> Credential:
        # Build a signed VC binding `subject_pubkey` to `claims`; format dispatch via formats/.
        ...
