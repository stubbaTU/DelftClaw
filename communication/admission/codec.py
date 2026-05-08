"""Wire codec for ``Presentation`` — the only credential artefact that crosses the wire."""

from __future__ import annotations

import msgpack

from shared.credentials import Credential, Presentation
from shared.errors import PayloadInvalid
from shared.ids import AgentId, Nonce
from stake.proof import StakeProof


def pack_presentation(p: Presentation) -> bytes:
    """Serialise a ``Presentation`` for the ``JoinRequestPayload.presentation`` slot."""
    claims_blob = msgpack.packb(dict(p.credential.claims), use_bin_type=True)
    stake_blob = p.stake_proof.to_bytes() if p.stake_proof is not None else b""
    return msgpack.packb(
        (
            p.credential.format_id,
            p.credential.issuer_pubkey,
            p.credential.subject_pubkey,
            claims_blob,
            p.credential.raw,
            p.audience.to_bytes(),
            p.nonce.to_bytes(),
            p.holder_signature,
            stake_blob,
        ),
        use_bin_type=True,
    )


def unpack_presentation(blob: bytes) -> Presentation:
    """Inverse of ``pack_presentation``; raises ``PayloadInvalid`` on a malformed blob."""
    try:
        unpacked = msgpack.unpackb(blob, raw=False, use_list=False)
    except (msgpack.UnpackException, ValueError) as exc:
        raise PayloadInvalid(f"Presentation: msgpack decode failed: {exc}") from exc
    if not isinstance(unpacked, tuple) or len(unpacked) != 9:
        raise PayloadInvalid("Presentation: expected a 9-element tuple")

    (
        format_id,
        issuer_pubkey,
        subject_pubkey,
        claims_blob,
        raw,
        audience_b,
        nonce_b,
        sig,
        stake_blob,
    ) = unpacked

    try:
        claims = msgpack.unpackb(claims_blob, raw=False)
    except (msgpack.UnpackException, ValueError) as exc:
        raise PayloadInvalid(f"Presentation: claims decode failed: {exc}") from exc
    if not isinstance(claims, dict):
        raise PayloadInvalid("Presentation: claims must decode to a dict")

    stake_proof = None
    if stake_blob:
        stake_proof = StakeProof.from_bytes(bytes(stake_blob))

    return Presentation(
        credential=Credential(
            format_id=str(format_id),
            issuer_pubkey=bytes(issuer_pubkey),
            subject_pubkey=bytes(subject_pubkey),
            claims=claims,
            raw=bytes(raw),
        ),
        audience=AgentId(bytes(audience_b)),
        nonce=Nonce(bytes(nonce_b)),
        holder_signature=bytes(sig),
        stake_proof=stake_proof,
    )
