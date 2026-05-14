"""Pull-based Layer 3 sync — algorithm + driver.

Two coroutines:

* :func:`pull_once` — single-shot algorithm. For one peer, fetch the
  head, decide whether anything changed, fetch a batch of entries, and
  feed them through :meth:`PeerLog.accept_entry`. Returns
  ``(new_last_known_hash, appended_count, rejection_log)`` so the caller
  can persist per-peer state and surface rejections.
* :func:`run_pull_loop` — driver. Holds an in-memory per-peer cursor
  dict, calls :func:`pull_once` for each peer per interval, and exits
  cleanly when ``stop_event.set()`` is signalled.

Algorithm decisions locked in by the test suite:

1. **No-op when peer head unchanged.** When ``peer_head == last_known_hash``
   and ``peer_head != "GENESIS"``, the entries endpoint is NOT called.
2. **First-time pull uses ``since="GENESIS"``.**
3. **Reject-and-stop.** If any entry in a batch fails verification, log
   the rejection and stop processing the rest of the batch. The cursor
   advances only as far as the last successfully-stored entry.
4. **Idempotent re-runs.** Duplicates (already in PeerLog) advance the
   cursor without counting as a new append — they're a successful
   confirmation of "we have this".
5. **Per-peer error isolation.** A transport error against one peer is
   logged and does NOT break the loop for other peers. Errors in
   :func:`pull_once` itself bubble up unchanged so unit tests can pin
   transport behavior.
6. **Clean shutdown.** ``stop_event.set()`` causes the driver to exit
   within ~one ``interval`` (the sleep is wrapped in
   ``asyncio.wait_for(stop_event.wait(), timeout=interval)``).
"""

from __future__ import annotations

import asyncio

from redteam.integration.peer_transport import PeerTransport
from redteam.primitives.peer_log import PeerLog
from shared.logging import get_logger

_logger = get_logger(__name__)


async def pull_once(
    transport: PeerTransport,
    peer_url: str,
    peer_log: PeerLog,
    last_known_hash: str | None,
    batch: int,
) -> tuple[str, int, list[tuple[str, list[str]]]]:
    """Fetch one batch from ``peer_url`` and feed it into ``peer_log``.

    Returns ``(new_last_known_hash, appended_count, rejection_log)``:

    * ``new_last_known_hash`` — the hash to use as ``since`` on the next
      call. Advances to the last successfully-stored entry's hash; on
      a rejection it stops at the prior good entry; on no-op (head
      unchanged) it stays at ``last_known_hash``; on empty fresh peer
      it returns the peer's head (or ``"GENESIS"`` when there's nothing
      to know).
    * ``appended_count`` — number of newly-persisted entries (excludes
      duplicates).
    * ``rejection_log`` — list of ``(entry_hash, errors)`` tuples for
      every entry the verifier refused. After the first rejection the
      loop breaks; this list will therefore have at most one element
      per call.

    Transport errors are NOT caught here. The driver
    (:func:`run_pull_loop`) handles per-peer transport-error policy.
    """
    peer_head = await transport.get_head(peer_url)

    # No-op: peer head is exactly what we already know about. Skip the
    # entries call entirely. ``GENESIS`` is excluded from this check
    # because two empty peers both report GENESIS — we still want to
    # advance the cursor in that case (the empty-peer test pins this).
    if peer_head == last_known_hash and peer_head != "GENESIS":
        return (peer_head, 0, [])

    since = last_known_hash or "GENESIS"
    resp = await transport.get_entries_since(peer_url, since, batch)
    served = resp.get("entries", [])

    appended = 0
    rejections: list[tuple[str, list[str]]] = []
    new_last = last_known_hash

    for entry in served:
        stored, _src, errs, duplicate = peer_log.accept_entry(entry)
        if not stored and errs:
            # Reject-and-stop: record the rejection, do not advance the
            # cursor past this point. Next interval will retry from the
            # last good ``since``.
            rejections.append((entry.get("entry_hash") or "<missing>", errs))
            break
        if stored:
            appended += 1
            new_last = entry["entry_hash"]
        elif duplicate:
            # Duplicate is a successful confirmation that we already had
            # this entry — advance the cursor so we don't keep re-pulling
            # the same prefix every interval.
            new_last = entry["entry_hash"]

    if not served and new_last is None:
        # Empty peer + no prior cursor → adopt the peer's head as the
        # cursor so the next call sees "head unchanged" and short-circuits.
        new_last = peer_head

    return (new_last or "GENESIS", appended, rejections)


async def run_pull_loop(
    transport: PeerTransport,
    peer_urls: list[str],
    peer_log: PeerLog,
    interval: float,
    batch: int,
    stop_event: asyncio.Event,
    initial_state: dict[str, str] | None = None,
) -> None:
    """Per-peer pull driver.

    Iterates over ``peer_urls`` per ``interval``, calling
    :func:`pull_once` for each. Per-peer ``last_known_hash`` is tracked
    in an in-memory dict seeded from ``initial_state`` (callers that
    want to resume across restarts pass the tail hashes from
    :meth:`PeerLog.read_entries_for`).

    Exits within ~one ``interval`` of ``stop_event.set()``. Per-peer
    transport errors are logged at warning level and do NOT break the
    loop for other peers.
    """
    state: dict[str, str] = dict(initial_state or {})

    while not stop_event.is_set():
        for peer_url in peer_urls:
            try:
                new_last, appended, rejs = await pull_once(
                    transport=transport,
                    peer_url=peer_url,
                    peer_log=peer_log,
                    last_known_hash=state.get(peer_url),
                    batch=batch,
                )
            except Exception as exc:
                # Per-peer error policy (deliberate v1 — no backoff):
                # log + skip-this-peer-this-iteration + DO NOT advance
                # the cursor. This catch covers transport errors
                # (connection refused, timeout, malformed JSON) AND the
                # oversized-batch ``ValueError`` from peer_transport. A
                # consistently-failing peer is therefore retried every
                # ``interval`` forever — that's intentional. Add
                # exponential backoff in v2 if it becomes a hot spot.
                _logger.warning(
                    "pull_loop.error",
                    peer_url=peer_url,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                continue

            state[peer_url] = new_last
            if appended > 0:
                _logger.info(
                    "pull_loop.synced",
                    peer_url=peer_url,
                    appended=appended,
                )
            if rejs:
                _logger.warning(
                    "pull_loop.rejected",
                    peer_url=peer_url,
                    count=len(rejs),
                )

        # Interruptible sleep: ``stop_event.set()`` wakes us up
        # immediately; otherwise we wait the full interval. Either way
        # the loop exits within ~one interval of the signal.
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
