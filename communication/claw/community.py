from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IdentityAnnouncementPayload:
    identity_hash: bytes
    public_key: bytes
    network: str


@dataclass(frozen=True)
class PeerIdentityRecord:
    identity_hash: bytes
    public_key: bytes
    network: str


class ClawPoCCommunity:
    """Minimal IPv8-compatible community facade used by the OpenClaw bridge."""

    def __init__(self, *args, **kwargs):
        self.openclaw_identity = None
        self.peer_identities: dict[bytes, PeerIdentityRecord] = {}
        self.announced = False

    def wire(self, *, openclaw_identity) -> None:
        self.openclaw_identity = openclaw_identity

    def announce_identity(self) -> IdentityAnnouncementPayload:
        if self.openclaw_identity is None:
            raise RuntimeError("OpenClaw identity has not been wired")
        payload = IdentityAnnouncementPayload(
            identity_hash=self.openclaw_identity.identity_hash_bytes,
            public_key=self.openclaw_identity.public_key,
            network=self.openclaw_identity.network,
        )
        self.announced = True
        return payload

    def add_peer_identity(self, record: PeerIdentityRecord) -> None:
        self.peer_identities[record.identity_hash] = record

    def get_peer_identity(self, identity_hash: bytes) -> PeerIdentityRecord | None:
        return self.peer_identities.get(identity_hash)
