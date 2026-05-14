"""Peer-to-peer transport surface for pull-based Layer 3 sync.

Defines a small :class:`typing.Protocol` so the pull-loop algorithm can
treat any peer-fetcher uniformly, plus a concrete HTTP implementation
backed by ``httpx.AsyncClient`` for the dev-mode wire layer.

The protocol is intentionally tiny — just the three GETs the pull
algorithm actually needs against the FastAPI server in
``redteam.integration.server``:

* ``get_head(peer_url)``                       — current chain head hash
* ``get_entries_since(peer_url, since, limit)`` — incremental batch
* ``get_identity(peer_url)``                   — node identity advert

Transport-level errors (connection refused, timeout, malformed status
codes) are NOT swallowed: ``httpx.RequestError`` and friends propagate
to the caller so the pull-loop driver can decide how to handle them
(currently: log + skip-this-peer-this-iteration).

For tests, callers may mount the in-process ASGI app directly via
``httpx.AsyncClient(transport=httpx.ASGITransport(app=app))`` so no
real port is opened. For real deployments, a single AsyncClient is
shared across peers and its lifecycle is owned by the caller.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import httpx


@runtime_checkable
class PeerTransport(Protocol):
    """Read-only fetcher for a remote :mod:`redteam.integration.server`.

    Implementations may use any wire protocol (HTTP today, IPv8 later)
    so long as they expose these three coroutines. The pull-loop in
    :mod:`redteam.integration.pull_loop` only ever talks through this
    protocol — swapping the transport does not require any algorithm
    change.
    """

    async def get_head(self, peer_url: str) -> str:
        """Return the peer's current chain head hash (``"GENESIS"`` if empty)."""
        ...

    async def get_entries_since(
        self, peer_url: str, since: str, limit: int
    ) -> dict:
        """Return ``{"entries": [...], "head_hash": str}`` for entries strictly
        after ``since`` (or from the start of the chain when
        ``since == "GENESIS"``), capped to ``limit`` entries."""
        ...

    async def get_identity(self, peer_url: str) -> dict:
        """Return the peer's identity advert dict (identity_hash, pubkey_hex,
        network)."""
        ...


class HttpPeerTransport:
    """``httpx.AsyncClient``-backed implementation of :class:`PeerTransport`.

    The client is owned by the caller (one shared client across peers is
    the common case). The ``timeout`` value is preserved on
    :attr:`_timeout` so it can be inspected in tests, and is forwarded
    to every outbound request.

    Errors raised by ``httpx`` (connection refused, timeouts, malformed
    status codes via ``raise_for_status``) are NOT caught here: the
    pull-loop driver decides per-peer error policy.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        timeout: float = 5.0,
    ) -> None:
        self._client = client
        self._timeout = timeout

    async def get_head(self, peer_url: str) -> str:
        """``GET <peer_url>/head`` → return the ``head_hash`` field."""
        resp = await self._client.get(
            f"{peer_url}/head", timeout=self._timeout
        )
        resp.raise_for_status()
        return resp.json()["head_hash"]

    async def get_entries_since(
        self, peer_url: str, since: str, limit: int
    ) -> dict:
        """``GET <peer_url>/entries?since=<since>&limit=<limit>``.

        Returns the full response dict (``entries`` list + ``head_hash``)
        unchanged so the caller can route entries straight into
        :meth:`PeerLog.accept_entry`.

        Refuses oversized batches: if the peer ignores ``limit`` and
        returns more than ``limit * 10`` entries, this raises
        :class:`ValueError`. The caller's pull-loop catches this the
        same way it catches transport errors (log + skip-this-cycle),
        which prevents a hostile or buggy peer from streaming an
        unbounded entries list into receiver memory.
        """
        resp = await self._client.get(
            f"{peer_url}/entries",
            params={"since": since, "limit": limit},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        served = data.get("entries", [])
        max_served = max(limit, 1) * 10
        if len(served) > max_served:
            raise ValueError(
                f"peer returned {len(served)} entries for limit={limit} "
                f"(cap {max_served}); refusing oversized batch"
            )
        return data

    async def get_identity(self, peer_url: str) -> dict:
        """``GET <peer_url>/identity`` → identity advert dict."""
        resp = await self._client.get(
            f"{peer_url}/identity", timeout=self._timeout
        )
        resp.raise_for_status()
        return resp.json()
