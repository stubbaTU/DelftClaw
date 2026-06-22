"""Shared implementation of ``content_search_and_fetch``.

Both ``agent.tools.build_tools`` and ``agent.mcp_server.build_mcp_server`` expose
this tool to the agent. Keeping the body in one module is what stops them from
drifting again — the v1 fix (IPv8 CONTENT_REQUEST/CONTENT_DELIVERY, hash + size
verify, ``record_download``) was landed in ``agent/tools.py`` first and the
duplicate in ``mcp_server.py`` silently kept the broken stub path. The deployed
MCP scenario only failed because of that drift.

Wire trace produced by this helper (identical regardless of call site):

  IPv8 send msg=SEARCH_REQUEST peer=<mid12> overlay=content_community
       via=content_search_and_fetch query=<q>
  IPv8 recv msg=SEARCH_RESPONSE peer=? overlay=content_community
       via=response_cache results=<n> pick=<mode> name=<file> bytes=<n>

The ``peer=?`` on the recv line is by design — the LLM-generated
``content_community.on_search_response`` runs in the overlay sandbox and can't
emit wire logs; the row is appended to ``response_cache`` with no per-row peer
attribution. So this helper emits a single synthetic recv line after the search
completes.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
from pathlib import Path
from typing import Any


_wire_logger = logging.getLogger("delftclaw.communication.wire")


async def content_search_and_fetch_impl(
    agent: Any,
    *,
    query: str = "",
    timeout_s: float = 10.0,
    pick: str | int = "random",
) -> dict[str, Any]:
    """Search the content_community overlay, fetch one matching file over IPv8.

    Steps, in order:

      1. find a loaded overlay whose parsed ``identity.name`` is
         ``"content_community"`` (the LLM-compiled one);
      2. snapshot ``len(overlay.response_cache)``;
      3. send SEARCH_REQUEST to every known peer with the caller's query;
      4. poll ``response_cache`` until new rows arrive or ``timeout_s`` expires;
      5. strict substring filter (``name + tags``) on **only** the new rows —
         past accumulated responses can't re-broaden the result;
      6. pick (``"random"`` / ``"first"`` / int index, falls back to random);
      7. extract the 20-byte ``content_id`` from the chosen row's magnet's btih;
      8. ``await agent.seedbox.fetch_content(peer, content_id)`` for each
         known peer until one resolves;
      9. **verify** ``sha1(bytes) == content_id`` AND
         ``len(bytes) == row["size"]`` (size check is best-effort: skipped if
         the catalogue row omits it);
     10. write the verified bytes to ``agent.bittorrent.save_dir / safe_name``;
     11. ``agent.bittorrent.record_download(magnet, path, total_bytes)`` so
         ``torrent_stats`` / the ``torrent_progress_gte_1`` predicate fire on a
         REAL file (the v0 stub fabricated ``progress=1.0`` for placeholder
         ``stub-<btih>.bin`` content; the watchdog's snapshot view of an empty
         torrents list comes from that mismatch).

    On any failure returns ``{"error": <reason>, ...}``; never silently writes
    a fake completion (no false-green).
    """
    compiled_item = None
    overlay = None
    for community_id in agent.registry.list_loaded():
        compiled = agent.registry._compiled[community_id]
        if compiled.parsed is not None and compiled.parsed.identity.get("name") == "content_community":
            compiled_item = compiled
            overlay = agent.registry.get(community_id)
            break
    if compiled_item is None or overlay is None:
        return {"error": "content_community_not_loaded"}

    def _filter(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Strict substring match against name + tags only.

        Magnet hex is excluded from the haystack (matching a btih by accident
        is never what the user means), and the previous
        ``"creative commons" in haystack`` fallback is dropped — it silently
        re-broadened every targeted query.
        """
        q = query.lower()
        out: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            haystack = " ".join([
                str(row.get("name", "")),
                " ".join(str(t) for t in row.get("tags", []) or []),
            ]).lower()
            if not q or q in haystack:
                out.append(row)
        return out

    peers = list(agent.known_peers())
    if not peers:
        return {"error": "no_known_peers_for_content_search"}
    payload_cls = compiled_item.payload_classes.get("SEARCH_REQUEST")
    if payload_cls is None:
        return {"error": "content_community_missing_SEARCH_REQUEST"}

    before = len(getattr(overlay, "response_cache", []) or [])
    for peer in peers:
        _wire_logger.info(
            "IPv8 send msg=SEARCH_REQUEST peer=%s overlay=content_community via=content_search_and_fetch query=%r",
            peer.mid.hex()[:12], query,
        )
        overlay.ez_send(peer, payload_cls(query.encode("utf-8")))
    sent = True

    deadline = asyncio.get_running_loop().time() + timeout_s
    while asyncio.get_running_loop().time() < deadline:
        if len(getattr(overlay, "response_cache", []) or []) > before:
            break
        await asyncio.sleep(0.1)

    new_rows = list(getattr(overlay, "response_cache", []) or [])[before:]
    rows = _filter(new_rows)

    if not rows:
        return {
            "searched": sent,
            "peer_count": len(peers),
            "response_count": len(new_rows),
            "error": "no_matching_content_response",
        }

    if isinstance(pick, int) and 0 <= pick < len(rows):
        chosen = rows[pick]
        pick_mode = f"index_{pick}"
    elif pick == "first":
        chosen = rows[0]
        pick_mode = "first"
    else:
        chosen = random.choice(rows)
        pick_mode = "random"

    magnet = str(chosen.get("magnet") or "")
    if not magnet:
        return {"error": "matching_content_response_missing_magnet", "result": chosen}

    # The catalogue's magnet btih IS the content_id (sha1 of the file bytes);
    # see ``communication.community.content_id_for_bytes``. That binding gives
    # us a self-verifying fetch: ask any peer for content_id, they reply with
    # bytes, we refuse to accept unless sha1(bytes) matches.
    btih_marker = "urn:btih:"
    idx = magnet.find(btih_marker)
    if idx < 0:
        return {"error": "matching_magnet_missing_btih", "magnet": magnet}
    btih_hex = magnet[idx + len(btih_marker):].split("&", 1)[0].strip().lower()
    try:
        content_id = bytes.fromhex(btih_hex)
    except ValueError:
        return {"error": "matching_magnet_btih_not_hex", "magnet": magnet}
    if len(content_id) != 20:
        return {"error": "matching_magnet_btih_wrong_length", "magnet": magnet}

    candidate_peers = list(agent.known_peers())
    data: bytes | None = None
    last_err = ""
    for peer in candidate_peers:
        try:
            fut = agent.seedbox.fetch_content(peer, content_id)
            data = await asyncio.wait_for(fut, timeout=max(timeout_s, 10.0))
            break
        except asyncio.TimeoutError:
            last_err = f"timeout from {peer.mid.hex()[:12]}"
            continue
        except Exception as exc:  # noqa: BLE001
            last_err = f"{type(exc).__name__}: {exc}"
            continue
    if data is None:
        return {
            "error": "content_fetch_failed",
            "magnet": magnet,
            "result": chosen,
            "detail": last_err or "no peer responded with the bytes",
        }

    # Self-verify: defend against a peer that publishes the right content_id
    # on the SEARCH path but a different file on the CONTENT path.
    # (``on_content_delivery`` also drops mismatches before resolving the
    # future, so this is belt-and-braces — and it surfaces a clean error if
    # the advertised size column lies.)
    if hashlib.sha1(data).digest() != content_id:
        return {"error": "content_hash_mismatch", "magnet": magnet}
    expected_size = chosen.get("size")
    if isinstance(expected_size, int) and expected_size > 0 and len(data) != expected_size:
        return {
            "error": "content_size_mismatch",
            "magnet": magnet,
            "expected_size": expected_size,
            "actual_size": len(data),
        }

    save_dir = Path(agent.bittorrent.save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)
    name = str(chosen.get("name") or f"{content_id.hex()}.bin")
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    out_path = save_dir / safe_name
    out_path.write_bytes(data)
    agent.bittorrent.record_download(magnet, out_path, len(data))

    # Wake peers — file_share's v4 chain depends on fetcher_1 noticing its
    # download is done so it can advance to authoring. Without this, fetcher_1
    # waits up to ``interval_s`` (240s) after the fetch tool returns.
    from agent.wake_signal import signal_peers
    signal_peers(f"content_fetched:{safe_name}")

    _wire_logger.info(
        "IPv8 recv msg=SEARCH_RESPONSE peer=? overlay=content_community via=response_cache results=%d pick=%s name=%s bytes=%d",
        len(rows), pick_mode, name, len(data),
    )
    return {
        "searched": sent,
        "peer_count": len(peers),
        "result": chosen,
        "magnet": magnet,
        "download_path": str(out_path),
        "verified_size_bytes": len(data),
        "content_id_hex": content_id.hex(),
        "pick": pick_mode,
        "result_count": len(rows),
        "torrent_stats": _torrent_stats_snapshot(agent),
    }


def _torrent_stats_snapshot(agent: Any) -> list[dict[str, Any]]:
    """Mirror of ``agent.tools.torrent_stats`` so the helper is self-contained.

    Returns the same dict shape both call sites already expose under the
    ``torrent_stats`` MCP tool, so the response payload from
    ``content_search_and_fetch`` is identical no matter which dispatch path
    delivered it.
    """
    return [
        {
            "magnet": t.magnet,
            "name": t.name,
            "progress": t.progress,
            "seeding": t.seeding,
            "save_path": str(t.save_path) if t.save_path else None,
            "peers": t.peers,
        }
        for t in agent.bittorrent.stats()
    ]


async def content_fetch_via_transfer_impl(
    agent: Any,
    *,
    query: str = "",
    timeout_s: float = 20.0,
    pick: str | int = "random",
) -> dict[str, Any]:
    """Search content_community, then fetch the file over the ``file_transfer``
    overlay (chunked, hash-verified) instead of the single-shot
    ``SeedboxCommunity.fetch_content`` path used by
    ``content_search_and_fetch_impl``.

    The discovery half mirrors ``content_search_and_fetch_impl`` (SEARCH ->
    pick -> 20-byte content_id from the magnet btih). The transfer half drives
    the compiled ``file_transfer`` overlay: send ``FETCH_REQUEST(content_id)``,
    let the overlay's handlers stream the manifest + chunks and reassemble +
    verify them, then read the bytes out of ``overlay.transfers[<cid hex>]``.
    Completion is surfaced to the existing ``torrent_progress_gte_1`` predicate
    via ``record_download`` (the same shim the content_search path uses).

    On any failure returns ``{"error": <reason>, ...}``; never writes a partial
    or unverified file.
    """
    # --- Discovery (mirrors content_search_and_fetch_impl) -------------------
    disc_compiled = None
    disc_overlay = None
    for community_id in agent.registry.list_loaded():
        compiled = agent.registry._compiled[community_id]
        if compiled.parsed is not None and compiled.parsed.identity.get("name") == "content_community":
            disc_compiled = compiled
            disc_overlay = agent.registry.get(community_id)
            break
    if disc_compiled is None or disc_overlay is None:
        return {"error": "content_community_not_loaded"}

    peers = list(agent.known_peers())
    if not peers:
        return {"error": "no_known_peers_for_content_search"}
    search_cls = disc_compiled.payload_classes.get("SEARCH_REQUEST")
    if search_cls is None:
        return {"error": "content_community_missing_SEARCH_REQUEST"}

    before = len(getattr(disc_overlay, "response_cache", []) or [])
    for peer in peers:
        _wire_logger.info(
            "IPv8 send msg=SEARCH_REQUEST peer=%s overlay=content_community via=content_fetch_via_transfer query=%r",
            peer.mid.hex()[:12], query,
        )
        disc_overlay.ez_send(peer, search_cls(query.encode("utf-8")))

    deadline = asyncio.get_running_loop().time() + timeout_s
    while asyncio.get_running_loop().time() < deadline:
        if len(getattr(disc_overlay, "response_cache", []) or []) > before:
            break
        await asyncio.sleep(0.1)
    new_rows = list(getattr(disc_overlay, "response_cache", []) or [])[before:]

    q = query.lower()
    rows = [
        r for r in new_rows
        if isinstance(r, dict) and (
            not q
            or q in (str(r.get("name", "")) + " "
                     + " ".join(str(t) for t in (r.get("tags") or []))).lower()
        )
    ]
    if not rows:
        return {
            "searched": True, "peer_count": len(peers),
            "response_count": len(new_rows), "error": "no_matching_content_response",
        }

    if isinstance(pick, int) and 0 <= pick < len(rows):
        chosen = rows[pick]
        pick_mode = f"index_{pick}"
    elif pick == "first":
        chosen = rows[0]
        pick_mode = "first"
    else:
        chosen = random.choice(rows)
        pick_mode = "random"

    magnet = str(chosen.get("magnet") or "")
    if not magnet:
        return {"error": "matching_content_response_missing_magnet", "result": chosen}
    idx = magnet.find("urn:btih:")
    if idx < 0:
        return {"error": "matching_magnet_missing_btih", "magnet": magnet}
    btih_hex = magnet[idx + len("urn:btih:"):].split("&", 1)[0].strip().lower()
    try:
        content_id = bytes.fromhex(btih_hex)
    except ValueError:
        return {"error": "matching_magnet_btih_not_hex", "magnet": magnet}
    if len(content_id) != 20:
        return {"error": "matching_magnet_btih_wrong_length", "magnet": magnet}

    # --- Transfer over the file_transfer overlay ----------------------------
    ft_compiled = None
    ft_overlay = None
    for community_id in agent.registry.list_loaded():
        compiled = agent.registry._compiled[community_id]
        if compiled.parsed is not None and compiled.parsed.identity.get("name") == "file_transfer":
            ft_compiled = compiled
            ft_overlay = agent.registry.get(community_id)
            break
    if ft_compiled is None or ft_overlay is None:
        return {"error": "file_transfer_overlay_not_loaded"}
    fetch_cls = ft_compiled.payload_classes.get("FETCH_REQUEST")
    if fetch_cls is None:
        return {"error": "file_transfer_missing_FETCH_REQUEST"}

    key = content_id.hex()
    transfers = getattr(ft_overlay, "transfers", None)
    if isinstance(transfers, dict):
        transfers.pop(key, None)  # clear any stale entry for a clean poll

    # content_id is the raw 20 bytes; FETCH_REQUEST's field is hash20 (= "20s"),
    # so the payload is constructed directly (no encoding coercion needed).
    for peer in peers:
        _wire_logger.info(
            "IPv8 send msg=FETCH_REQUEST peer=%s overlay=file_transfer via=content_fetch_via_transfer content_id=%s",
            peer.mid.hex()[:12], key[:16],
        )
        ft_overlay.ez_send(peer, fetch_cls(content_id))

    deadline = asyncio.get_running_loop().time() + timeout_s
    entry: dict[str, Any] | None = None
    while asyncio.get_running_loop().time() < deadline:
        entry = getattr(ft_overlay, "transfers", {}).get(key)
        if isinstance(entry, dict) and entry.get("complete"):
            break
        await asyncio.sleep(0.1)
    if not (isinstance(entry, dict) and entry.get("complete")):
        return {"error": "file_transfer_incomplete", "content_id_hex": key, "magnet": magnet}
    if not entry.get("ok"):
        return {"error": "file_transfer_hash_mismatch", "content_id_hex": key, "magnet": magnet}

    chunks = entry.get("chunks") or {}
    total = int(entry.get("total") or len(chunks))
    try:
        data = b"".join(chunks[s] for s in range(total))
    except KeyError:
        return {"error": "file_transfer_missing_chunk", "content_id_hex": key}

    # Belt-and-braces: the catalogue content_id is sha1(bytes) (the overlay
    # already checked the manifest's sha256 end-to-end).
    if hashlib.sha1(data).digest() != content_id:
        return {"error": "content_hash_mismatch", "magnet": magnet}
    expected_size = chosen.get("size")
    if isinstance(expected_size, int) and expected_size > 0 and len(data) != expected_size:
        return {
            "error": "content_size_mismatch",
            "expected_size": expected_size, "actual_size": len(data),
        }

    save_dir = Path(agent.bittorrent.save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)
    name = str(chosen.get("name") or f"{key}.bin")
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    out_path = save_dir / safe_name
    out_path.write_bytes(data)
    agent.bittorrent.record_download(magnet, out_path, len(data))

    from agent.wake_signal import signal_peers
    signal_peers(f"content_fetched:{safe_name}")

    _wire_logger.info(
        "IPv8 recv msg=CHUNK x%d peer=? overlay=file_transfer via=content_fetch_via_transfer name=%s bytes=%d",
        total, name, len(data),
    )
    return {
        "searched": True,
        "peer_count": len(peers),
        "result": chosen,
        "magnet": magnet,
        "download_path": str(out_path),
        "verified_size_bytes": len(data),
        "content_id_hex": key,
        "chunks": total,
        "pick": pick_mode,
        "transport": "file_transfer_overlay",
        "torrent_stats": _torrent_stats_snapshot(agent),
    }
