from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any

from claw_community.ports import LocalCommunicationPlaceholder


class AgentContentCommunicationPort(LocalCommunicationPlaceholder):
    """Bridge the demo community service to the merged OpenClaw agent stack.

    The professor demo has a synchronous community service, while the merged
    communication layer is async and IPv8-backed. This adapter keeps the demo
    service sync-compatible, but when a started ``agent.runtime.OpenClawAgent``
    is supplied it sends file-location requests over the compiled
    ``content_community`` overlay instead of only recording a placeholder.
    """

    def __init__(self, agent: Any, *, timeout_s: float = 2.0) -> None:
        super().__init__()
        self.agent = agent
        self.timeout_s = timeout_s

    def send_message(self, *, sender_id: str, recipient_id: str, message: str) -> dict[str, Any]:
        peers = self._known_peers()
        record = {
            "type": "send_message",
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "message": message,
            "transport": "ipv8-peer-placeholder",
            "peer_count": len(peers),
            "note": "direct text messaging is not a first-class merged overlay yet",
        }
        self.messages.append(record)
        return {"ok": True, **record}

    def broadcast(self, *, sender_id: str, community_id: str, message: str) -> dict[str, Any]:
        peers = self._known_peers()
        record = {
            "type": "broadcast",
            "sender_id": sender_id,
            "community_id": community_id,
            "message": message,
            "transport": "ipv8-peer-placeholder",
            "peer_count": len(peers),
            "note": "broadcast is represented by per-peer overlay messages when a concrete overlay exists",
        }
        self.messages.append(record)
        return {"ok": True, **record}

    def request_file_location(self, *, sender_id: str, community_id: str, query: str) -> dict[str, Any]:
        try:
            result = _run_sync(lambda: self._request_file_location_transport(query=query))
        except Exception as exc:
            fallback = super().request_file_location(
                sender_id=sender_id,
                community_id=community_id,
                query=query,
            )
            fallback["transport"] = "local-placeholder"
            fallback["adapter_error"] = f"{type(exc).__name__}: {exc}"
            return fallback
        record = {
            "type": "request_file_location",
            "sender_id": sender_id,
            "community_id": community_id,
            "query": query,
            **result,
        }
        self.messages.append(record)
        return {"ok": True, **record}

    async def async_request_file_location(self, *, sender_id: str, community_id: str, query: str) -> dict[str, Any]:
        result = await self._request_file_location_transport(query=query)
        record = {
            "type": "request_file_location",
            "sender_id": sender_id,
            "community_id": community_id,
            "query": query,
            **result,
        }
        self.messages.append(record)
        return {"ok": True, **record}

    async def _request_file_location_transport(self, *, query: str) -> dict[str, Any]:
        overlay = self._content_overlay()
        peers = self._known_peers()
        if not peers:
            return {
                "transport": "content-overlay",
                "sent": False,
                "peer_count": 0,
                "remote_results": [],
                "note": "no verified peers are known to this agent",
            }

        before = len(getattr(overlay, "response_cache", []))
        payload_cls = self.agent.registry._compiled[CONTENT_HASH].payload_classes["SEARCH_REQUEST"]
        for peer in peers:
            overlay.ez_send(peer, payload_cls(query.encode("utf-8")))

        deadline = asyncio.get_running_loop().time() + self.timeout_s
        while asyncio.get_running_loop().time() < deadline:
            if len(getattr(overlay, "response_cache", [])) > before:
                break
            await asyncio.sleep(0.05)

        responses = list(getattr(overlay, "response_cache", [])[before:])
        return {
            "transport": "content-overlay",
            "sent": True,
            "peer_count": len(peers),
            "remote_results": responses,
        }

    def _content_overlay(self) -> Any:
        registry = self.agent.registry
        overlay = registry.get(CONTENT_HASH)
        if overlay is None:
            self.agent.publish_overlay(CONTENT_MD)
            overlay = registry.get(CONTENT_HASH)
        if overlay is None:
            raise RuntimeError("content_community overlay is not loaded")
        return overlay

    def _known_peers(self) -> list[Any]:
        return list(self.agent.known_peers())


def _run_sync(coro_factory):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro_factory())
    raise RuntimeError("AgentContentCommunicationPort cannot block inside an active event loop")


def _canonicalize_md(text: str) -> bytes:
    text = text.replace("\r\n", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines).encode("utf-8")


CONTENT_MD = (Path(__file__).resolve().parents[1] / "protocol" / "examples" / "content_community.md").read_text(
    encoding="utf-8"
)
CONTENT_HASH = hashlib.sha1(_canonicalize_md(CONTENT_MD)).digest()[:20]
