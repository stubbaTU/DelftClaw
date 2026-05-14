"""Toy Ed25519 credential format — a development stand-in until W3C-JWT lands (§15.4)."""

from __future__ import annotations

from typing import Mapping

import msgpack
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from shared.credentials import Credential


_FORMAT_ID = "toy-ed25519"


def _canonical_claims(issuer_pubkey: bytes, subject_pubkey: bytes, claims_blob: bytes) -> bytes:
    """Bytes the issuer signs; recomputed at verify time."""
    return msgpack.packb(
        (issuer_pubkey, subject_pubkey, claims_blob),
        use_bin_type=True,
    )


class ToyEd25519Format:
    """Plaintext Ed25519-signed Verifiable Credential, ``format_id = "toy-ed25519"``.

    ``Credential.raw`` is a msgpack 2-tuple ``(claims_blob, issuer_signature)`` where
    ``claims_blob = msgpack(dict(claims))`` and ``issuer_signature`` covers
    ``msgpack((issuer_pubkey, subject_pubkey, claims_blob))``.
    """

    format_id: str = _FORMAT_ID

    def issue(
        self,
        issuer_pubkey: bytes,
        subject_pubkey: bytes,
        claims: Mapping[str, object],
        signing_key: bytes,
    ) -> Credential:
        claims_dict = dict(claims)
        claims_blob = msgpack.packb(claims_dict, use_bin_type=True)
        canonical = _canonical_claims(issuer_pubkey, subject_pubkey, claims_blob)
        signature = Ed25519PrivateKey.from_private_bytes(signing_key).sign(canonical)
        raw = msgpack.packb((claims_blob, signature), use_bin_type=True)
        return Credential(
            format_id=_FORMAT_ID,
            issuer_pubkey=bytes(issuer_pubkey),
            subject_pubkey=bytes(subject_pubkey),
            claims=claims_dict,
            raw=raw,
        )

    def verify(self, credential: Credential) -> bool:
        if credential.format_id != _FORMAT_ID:
            return False
        try:
            unpacked = msgpack.unpackb(credential.raw, raw=False, use_list=False)
        except (msgpack.UnpackException, ValueError):
            return False
        if not isinstance(unpacked, tuple) or len(unpacked) != 2:
            return False
        claims_blob, signature = unpacked
        canonical = _canonical_claims(
            credential.issuer_pubkey,
            credential.subject_pubkey,
            bytes(claims_blob),
        )
        try:
            Ed25519PublicKey.from_public_bytes(credential.issuer_pubkey).verify(
                bytes(signature), canonical
            )
        except (InvalidSignature, ValueError):
            return False
        try:
            roundtripped = msgpack.unpackb(bytes(claims_blob), raw=False)
        except (msgpack.UnpackException, ValueError):
            return False
        return roundtripped == dict(credential.claims)
