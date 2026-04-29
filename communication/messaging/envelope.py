"""The Layer-4 unit handed to the wire layer."""

from __future__ import annotations

from dataclasses import dataclass

from shared.ids import Epoch


@dataclass(frozen=True)
class PrivateMessage:
    """Output of SecureGroupSession.encrypt; framed by the wire layer."""

    epoch: Epoch
    sender_index: int
    ciphertext: bytes
