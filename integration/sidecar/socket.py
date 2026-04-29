"""Unix-domain socket server used by the Sidecar."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable


class UnixSocketServer:
    """Listens on a Unix-domain socket and dispatches each connection to a callback."""

    def __init__(self, path: Path, on_connection: Callable[[Any, Any], Any]) -> None:
        # Store the socket path and the per-connection async handler.
        ...

    async def serve_forever(self) -> None:
        # Bind, listen, and dispatch incoming connections until close() is called.
        ...

    async def close(self) -> None:
        # Stop accepting connections and unlink the socket file.
        ...
