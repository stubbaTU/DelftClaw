from __future__ import annotations

import asyncio
import hashlib
import threading
from pathlib import Path
from typing import Any


def _load_seed(key_path: Path | None):
    """Return a 32-byte ``Seed`` for ``AgentIdentity``, tolerating legacy files.

    Three cases:
      1. ``key_path`` missing or empty → defer to ``KeyfileSeedSource`` default
         path; auto-generates a fresh 32-byte hex seed if the file is missing.
      2. ``key_path`` content is 64 hex chars (the new format) → load it as-is
         via ``KeyfileSeedSource``.
      3. ``key_path`` content is anything else (e.g. a legacy ``LibNaCLSK``
         binary blob written by the old ``OpenClawIdentity``) → SHA-256 the
         raw bytes to derive a deterministic 32-byte seed. The bridge boots
         instead of crashing; the resulting agent_id differs from the old
         value but is stable across restarts of the same key file.
    """
    from identity.seed import KeyfileSeedSource, Seed

    if key_path is None or not key_path.exists():
        return KeyfileSeedSource(str(key_path) if key_path is not None else None).load()

    raw = key_path.read_bytes()
    try:
        return KeyfileSeedSource(str(key_path)).load()
    except ValueError:
        return Seed(hashlib.sha256(raw).digest())


class OpenClawBridge:
    """Bridge the HTTP security gateway to the IPv8-backed OpenClaw PoC layer.

    The bridge always owns a persistent ``AgentIdentity`` (BIP-32 multi-key bundle
    keyed off a seed file). When requested, it also starts ``OpenClawAgent`` in a
    background asyncio loop so the same gateway process can expose both:

    - HTTP tool-call security endpoints for Telegram/OpenClaw
    - IPv8 identity announcements for DelftClaw peers
    """

    def __init__(
        self,
        *,
        network: str = "MAINNET",
        key_path: str | Path | None = None,
        p2p_enabled: bool = False,
        p2p_host: str = "0.0.0.0",
        p2p_port: int = 9000,
        working_dir: str = ".",
    ) -> None:
        from identity.agent_identity import AgentIdentity

        # ``OpenClawIdentity`` was renamed to ``AgentIdentity`` (the BIP-32
        # multi-key bundle); we now derive it from a seed file at ``key_path``.
        # When ``key_path`` is empty/None, falls back to the platform default
        # (~/.openclaw/identity/seed.txt). Legacy key files written by the old
        # ``OpenClawIdentity`` (LibNaCL binary blobs) are tolerated — see
        # ``_load_seed`` for the format-detection fallback.
        self.key_path: Path | None = Path(key_path) if key_path not in {"", None} else None
        seed = _load_seed(self.key_path)
        self.identity = AgentIdentity.from_seed(seed, network=network)
        self.p2p_enabled = p2p_enabled
        self.p2p_host = p2p_host
        self.p2p_port = p2p_port
        self.working_dir = working_dir

        self._agent: Any | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._started = threading.Event()
        self._startup_error: str | None = None

    @property
    def agent_id(self) -> str:
        return str(self.identity.network_hash)

    def start(self) -> None:
        if not self.p2p_enabled or self._thread is not None:
            return

        self._thread = threading.Thread(target=self._run_loop, name="openclaw-p2p-bridge", daemon=True)
        self._thread.start()
        self._started.wait(timeout=10)
        if self._startup_error:
            raise RuntimeError(self._startup_error)

    def stop(self) -> None:
        if self._loop is None:
            return
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=10)
        self._thread = None
        self._loop = None

    def status(self) -> dict[str, Any]:
        community = getattr(self._agent, "community", None)
        peer_identities = {}
        if community is not None:
            try:
                peer_identities = {
                    mid.hex(): {
                        "identity_hash": record.identity_hash.hex(),
                        "public_key": record.public_key.hex(),
                        "network": record.network,
                        "last_seen": record.last_seen,
                    }
                    for mid, record in community.peer_identities.items()
                }
            except Exception:
                peer_identities = {}

        return {
            "enabled": True,
            "identity_hash": self.agent_id,
            "network": self.identity.network,
            "key_path": str(self.key_path) if self.key_path is not None else "",
            "public_key": self.identity.ipv8.raw_pubkey.hex(),
            "serialized_public_key": self.identity.ipv8.pubkey.hex(),
            "p2p_enabled": self.p2p_enabled,
            "p2p_running": self._agent is not None and self._startup_error is None,
            "p2p_host": self.p2p_host,
            "p2p_port": self.p2p_port,
            "peer_count": len(peer_identities),
            "peer_identities": peer_identities,
            "startup_error": self._startup_error,
        }

    def _run_loop(self) -> None:
        from communication.claw.openclaw_agent import OpenClawAgent

        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)

        async def start_agent() -> None:
            self._agent = OpenClawAgent(
                network=self.identity.network,
                identity=self.identity,
                port=self.p2p_port,
                address=self.p2p_host,
                working_dir=self.working_dir,
            )
            await self._agent.start()

        async def stop_agent() -> None:
            if self._agent is not None:
                await self._agent.stop()
                self._agent = None

        try:
            loop.run_until_complete(start_agent())
            self._started.set()
            loop.run_forever()
        except Exception as exc:
            self._startup_error = str(exc)
            self._started.set()
        finally:
            try:
                loop.run_until_complete(stop_agent())
            finally:
                loop.close()
