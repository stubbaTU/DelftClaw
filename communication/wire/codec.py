"""WireFrame ↔ bytes serialisation."""

from __future__ import annotations

from typing import Protocol

from shared.envelopes import WireFrame


class Codec(Protocol):
    """Strategy for encoding/decoding a WireFrame to/from bytes."""

    def encode(self, frame: WireFrame) -> bytes:
        # Serialise the WireFrame to a byte string suitable for IPv8 transport.
        ...

    def decode(self, blob: bytes) -> WireFrame:
        # Parse a byte string into a WireFrame; raise PayloadInvalid on malformed input.
        ...


class MsgpackCodec(Codec):
    """Default codec: msgpack — deterministic, small, schema-aware."""

    def encode(self, frame: WireFrame) -> bytes:
        # msgpack-pack the frame's fields in fixed order so signatures are reproducible.
        ...

    def decode(self, blob: bytes) -> WireFrame:
        # msgpack-unpack and validate field types before constructing the WireFrame.
        ...
