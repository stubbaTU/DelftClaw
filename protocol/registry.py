"""Register compiled overlay classes with a *running* IPv8 instance.

After ``await ipv8.start()`` the static ``extra_communities`` map is no
longer consulted, but ``ipv8.overlays`` is still mutable and the endpoint
will deliver packets to any community whose 20-byte prefix it sees on
the wire (``Community.__init__`` registers the prefix listener
automatically). This registry compiles a `.md` descriptor via
``protocol.compiler.compile_overlay`` and appends the resulting instance
to ``ipv8.overlays`` under ``ipv8.overlay_lock``.
"""

from __future__ import annotations

from typing import Any, Optional

from ipv8.community import CommunitySettings

from protocol.compiler import CompiledOverlay, compile_overlay
from protocol.llm import LLMClient


class OverlayRegistry:
    """Owns the compiler + cache + IPv8 registration for runtime overlays.

    Idempotent: loading the same ``.md`` twice returns the cached
    instance instead of registering a duplicate community.
    """

    def __init__(self, ipv8: Any, llm: LLMClient) -> None:
        self._ipv8 = ipv8
        self._llm = llm
        self._compiled: dict[bytes, CompiledOverlay] = {}
        self._instances: dict[bytes, Any] = {}

    def load(self, md_text: str) -> Any:
        """Compile + register; return the live community instance.

        On a second call with the same descriptor, returns the existing
        instance without recompiling or re-registering.
        """
        compiled = compile_overlay(md_text, self._llm)
        cid = compiled.community_id
        if cid in self._instances:
            return self._instances[cid]

        settings = self._build_settings()
        instance = compiled.community_class(settings)

        with self._ipv8.overlay_lock:
            self._ipv8.overlays.append(instance)

        # Outside the static IPv8 boot path no one will call started() for us.
        if hasattr(instance, "started"):
            instance.started()

        self._compiled[cid] = compiled
        self._instances[cid] = instance
        return instance

    def get(self, community_id: bytes) -> Optional[Any]:
        """Return the live overlay instance for ``community_id``, or None."""
        return self._instances.get(community_id)

    def list_loaded(self) -> list[bytes]:
        return list(self._instances.keys())

    def _build_settings(self) -> CommunitySettings:
        """Crib peer/endpoint/network from any already-loaded overlay.

        IPv8's ``CommunitySettings`` only needs ``my_peer``, ``endpoint``,
        ``network`` — all three are shared across overlays running on
        the same IPv8 instance, so any bootstrap-loaded community is a
        valid template.
        """
        if not self._ipv8.overlays:
            raise RuntimeError(
                "OverlayRegistry: cannot derive settings — IPv8 has no loaded overlays yet"
            )
        template = self._ipv8.overlays[0]
        return CommunitySettings(
            my_peer=template.my_peer,
            endpoint=template.endpoint,
            network=template.network,
        )
