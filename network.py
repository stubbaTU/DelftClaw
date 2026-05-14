"""Minimal UDPEndpoint stub.

The colleague's root ``agent.py`` (the legacy P2PAgent) imports
``UDPEndpoint`` from a ``network`` module that was never committed to
master. This file is a thin stub so that test collection for
``tests/test_agent_signed_migration.py`` proceeds — the red-step tests
fail at assertion (their intended state until the colleague's Phase C
green step lands), not at import.

The stub does not bind a real UDP socket; ``start()`` / ``stop()`` /
``send()`` are no-ops. The migration tests only construct a
``P2PAgent`` and inspect its log; they never exercise the endpoint.
"""

from __future__ import annotations

from typing import Callable


class UDPEndpoint:
    """No-op UDP endpoint shim — see module docstring."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8090) -> None:
        self.host = host
        self.port = port
        self._callbacks: list[Callable[[bytes, tuple], None]] = []

    def add_message_callback(self, cb: Callable[[bytes, tuple], None]) -> None:
        self._callbacks.append(cb)

    async def start(self) -> None:
        return None

    def stop(self) -> None:
        return None

    def send(self, msg: bytes, addr: tuple) -> None:
        return None
