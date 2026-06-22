"""Shared impl of the ``overlay_author_and_publish`` tool: an agent introduces a
new or evolved protocol mid-session as JSON, which is synthesized into a
byte-exact ``.md`` (``agent.overlay_authoring``), compiled, installed, and
gossiped to peers. Both ``agent.tools`` and ``agent.mcp_server`` delegate here
so the deployed and in-process paths can't drift."""

from __future__ import annotations

import logging
from typing import Any

from agent.overlay_authoring import OverlayAuthoringError, synthesize_overlay_markdown


_tool_logger = logging.getLogger("delftclaw.agent.tools")


async def overlay_author_and_publish_impl(
    agent: Any,
    *,
    name: str,
    version: str,
    description: str,
    messages: list[dict],
    change_summary: str,
    runtime_state: list[dict] | None = None,
    constants: list[dict] | None = None,
    samples: dict[str, dict[str, Any]] | None = None,
    supersedes_cid_hex: str | None = None,
) -> dict[str, Any]:
    """Author a new overlay spec, publish it locally, and offer it to peers.

    ``messages`` = ``[{name, msg_id, fields:[{name, encoding, description}],
    handler}]``; ``samples`` = optional ``{msg_name: {field: value}}`` for the
    non-zero test vector. Returns what was published, or ``{"error": ...}``."""
    # only a loaded overlay of the SAME name may be superseded (version bump)
    supersedes = (supersedes_cid_hex or "").strip().lower() or None
    if supersedes is not None:
        try:
            pred_cid = bytes.fromhex(supersedes)
        except ValueError:
            return {"error": f"supersedes_not_hex:{supersedes}"}
        if len(pred_cid) != 20:
            return {"error": f"supersedes_wrong_length:{supersedes}"}
        pred = agent.registry._compiled.get(pred_cid)
        if pred is None:
            return {"error": f"supersedes_overlay_not_loaded:{supersedes}"}
        pred_name = pred.parsed.identity.get("name") if pred.parsed else None
        if pred_name != name:
            return {
                "error": "supersedes_name_mismatch",
                "detail": f"predecessor is {pred_name!r}, cannot be superseded by {name!r}",
            }

    # author_id binds this agent's wallet so adopters attribute the spec
    author_id = agent.wallet.address()
    try:
        md_text = synthesize_overlay_markdown(
            name=name,
            version=version,
            description=description,
            messages=messages,
            runtime_state=runtime_state,
            constants=constants,
            supersedes=supersedes,
            author_id=author_id,
            change_summary=change_summary,
            samples=samples,
        )
    except (OverlayAuthoringError, KeyError, TypeError) as exc:
        return {"error": f"overlay_synthesis_failed:{type(exc).__name__}:{exc}"}

    # publish: serve bytes + compile (live LLM) + install + archive. The
    # authored_event is threaded into aload's shielded post-compile section so
    # the version_history row survives an outer cancellation.
    authored_event = {
        "name": name,
        "identity_version": version,
        "supersedes": supersedes,
        "author_id": author_id,
        "change_summary": change_summary,
    }
    try:
        agent.seedbox.publish_overlay(md_text)
        instance = await agent.registry.aload(
            md_text, provenance="published", authored_event=authored_event,
        )
    except Exception as exc:  # noqa: BLE001
        return {"error": f"overlay_publish_failed:{type(exc).__name__}:{exc}"}

    cid_hex = instance.community_id.hex()

    # gossip OVERLAY_OFFER to every known peer so they can fetch + adopt
    offered = agent.seedbox.offer_overlay_to_all_peers()

    # wake peers' watchdogs so they react in seconds, not at the next 240s tick
    from agent.wake_signal import signal_peers
    signal_peers(f"overlay_published:{cid_hex[:12]}")

    _tool_logger.info(
        "OVERLAY authored cid=%s name=%s version=%s supersedes=%s offered_to=%d",
        cid_hex, name, version, supersedes or "-", offered,
    )
    return {
        "community_id_hex": cid_hex,
        "name": name,
        "version": version,
        "supersedes": supersedes,
        "author_id": author_id,
        "change_summary": change_summary,
        "offered_to_peers": offered,
        "archived": getattr(agent.registry, "_archive", None) is not None,
    }
