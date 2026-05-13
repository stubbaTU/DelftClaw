"""Public-key bundle a peer publishes so others can authenticate it."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KeyBundle:
    """The public-key triple the agent advertises."""

    ipv8: bytes
    app: bytes
    wallet: bytes
