from __future__ import annotations

import argparse
import json
import re
from typing import Any

from security.integration.client import DelftClawClient


SUPPORTED_EXAMPLES = [
    "what files are stored on our Claw Network?",
    'what files are stored on our Claw Network containing "Creative Commons"?',
    "go to the Claw Network, find Creative Commons Audio Archive 2023, and play a random file",
    "create seedbox seedbox_id=demo-seedbox-1 donation_address=tb1q-demo capacity=100",
    'add file file_id=cc-001 seedbox_id=demo-seedbox-1 name="Creative Commons Audio Archive 2023 - Track 1" url=https://example.invalid/audio.mp3 tags="Creative Commons,audio"',
    "submit proof seedbox_id=demo-seedbox-1 storage_url=https://example.invalid/proof nonce=proof-001",
    "record donation seedbox_id=demo-seedbox-1 amount_sats=1000 txid=tx-demo-001",
    "submit microtask task_id=task-001 seedbox_id=demo-seedbox-1 file_hash=file-sha result_hash=result-sha",
    "verify microtask task_id=task-001 expected_result_hash=result-sha",
    "audit seedboxes",
    "show reputation for agent-a",
    "send message to agent-b: hello from DelftClaw",
]


def handle_agentic_request(text: str, client: DelftClawClient | None = None) -> dict[str, Any]:
    """
    Translate common user-facing Claw Network requests into DelftClaw tool calls.

    This is intentionally small and deterministic. OpenClaw should prefer the
    MCP tool manifest and docs/agent_intents.md, but this adapter gives agents
    a simple bridge when they receive natural language over Telegram.
    """

    client = client or DelftClawClient()
    normalized = " ".join(text.strip().split())
    lowered = normalized.casefold()
    fields = _extract_fields(normalized)

    if _asks_to_spawn_agent(lowered):
        required = ("agent_id", "provider", "region", "flavor", "ssh_key")
        missing = _missing(fields, required)
        return {
            "intent": "spawn_agent",
            "ok": False,
            "requires_confirmation": True,
            "status": "not_gateway_backed_yet",
            "message": "Live agent spawning needs a guarded DelftClaw provisioning tool before it should run from Telegram.",
            "missing_fields": missing,
            "known_fields": fields,
            "next_prompt": (
                "Please provide agent_id, provider, region, flavor, ssh_key, and budget/days. "
                "After that DelftClaw can turn this into a guarded provisioning request."
            ),
        }

    if _asks_for_random_playback(lowered):
        query = _extract_quoted_query(normalized) or _extract_after_find(normalized) or ""
        return {
            "intent": "play_random_file",
            "tool": "delftclaw_pick_random_file",
            "result": client.pick_random_seedbox_file(query=query),
        }

    if _asks_to_register_seedbox(lowered):
        values = {
            "seedbox_id": _value(fields, "seedbox_id", "seedbox", "id"),
            "donation_address": _value(fields, "donation_address", "address", "wallet"),
            "advertised_capacity_gb": _int_value(fields, "advertised_capacity_gb", "capacity", "capacity_gb", "gb"),
        }
        missing = _missing(values, ("seedbox_id", "donation_address", "advertised_capacity_gb"))
        if missing:
            return _needs_details(
                "register_seedbox",
                "delftclaw_register_seedbox",
                missing,
                "Please provide seedbox_id, donation_address, and capacity in GB.",
                values,
            )
        return {
            "intent": "register_seedbox",
            "tool": "delftclaw_register_seedbox",
            "result": client.register_seedbox(
                seedbox_id=str(values["seedbox_id"]),
                donation_address=str(values["donation_address"]),
                advertised_capacity_gb=int(values["advertised_capacity_gb"]),
                fake=_bool_value(fields, "fake"),
            ),
        }

    if _asks_to_index_file(lowered):
        values = {
            "file_id": _value(fields, "file_id", "id"),
            "seedbox_id": _value(fields, "seedbox_id", "seedbox"),
            "name": _value(fields, "name", "title"),
            "content_url": _value(fields, "content_url", "url", "link"),
            "sha256": _value(fields, "sha256", "hash") or "",
            "size_bytes": _int_value(fields, "size_bytes", "bytes", "size") or 0,
            "media_type": _value(fields, "media_type", "type") or "",
            "tags": _tags_value(fields),
        }
        missing = _missing(values, ("file_id", "seedbox_id", "name", "content_url"))
        if missing:
            return _needs_details(
                "index_seedbox_file",
                "delftclaw_index_seedbox_file",
                missing,
                "Please provide file_id, seedbox_id, name, and content_url/url.",
                values,
            )
        return {
            "intent": "index_seedbox_file",
            "tool": "delftclaw_index_seedbox_file",
            "result": client.index_seedbox_file(
                file_id=str(values["file_id"]),
                seedbox_id=str(values["seedbox_id"]),
                name=str(values["name"]),
                content_url=str(values["content_url"]),
                sha256=str(values["sha256"]),
                size_bytes=int(values["size_bytes"]),
                media_type=str(values["media_type"]),
                tags=list(values["tags"]),
            ),
        }

    if _asks_to_submit_proof(lowered):
        values = {
            "seedbox_id": _value(fields, "seedbox_id", "seedbox"),
            "storage_url": _value(fields, "storage_url", "proof_url", "url"),
            "nonce": _value(fields, "nonce"),
            "proof_id": _value(fields, "proof_id") or None,
        }
        missing = _missing(values, ("seedbox_id", "storage_url", "nonce"))
        if missing:
            return _needs_details(
                "submit_seedbox_proof",
                "delftclaw_submit_seedbox_proof",
                missing,
                "Please provide seedbox_id, storage_url/proof_url, and nonce.",
                values,
            )
        return {
            "intent": "submit_seedbox_proof",
            "tool": "delftclaw_submit_seedbox_proof",
            "result": client.submit_seedbox_proof(
                seedbox_id=str(values["seedbox_id"]),
                storage_url=str(values["storage_url"]),
                nonce=str(values["nonce"]),
                proof_id=values["proof_id"],
            ),
        }

    if _asks_to_record_donation(lowered):
        values = {
            "seedbox_id": _value(fields, "seedbox_id", "seedbox"),
            "amount_sats": _int_value(fields, "amount_sats", "sats", "amount"),
            "txid": _value(fields, "txid", "transaction", "transaction_id") or None,
        }
        missing = _missing(values, ("seedbox_id", "amount_sats"))
        if missing:
            return _needs_details(
                "broadcast_seedbox_donation",
                "delftclaw_broadcast_seedbox_donation",
                missing,
                "Please provide seedbox_id and amount_sats. txid is optional for local smoke tests.",
                values,
            )
        return {
            "intent": "broadcast_seedbox_donation",
            "tool": "delftclaw_broadcast_seedbox_donation",
            "result": client.broadcast_seedbox_donation(
                seedbox_id=str(values["seedbox_id"]),
                amount_sats=int(values["amount_sats"]),
                txid=values["txid"],
                stolen_from_honest_agent=_bool_value(fields, "stolen_from_honest_agent", "stolen"),
            ),
        }

    if _asks_to_submit_microtask(lowered):
        values = {
            "task_id": _value(fields, "task_id", "task"),
            "seedbox_id": _value(fields, "seedbox_id", "seedbox"),
            "file_hash": _value(fields, "file_hash"),
            "result_hash": _value(fields, "result_hash"),
            "task_type": _value(fields, "task_type") or "storage_check",
        }
        missing = _missing(values, ("task_id", "seedbox_id", "file_hash", "result_hash"))
        if missing:
            return _needs_details(
                "submit_atomic_microtask",
                "delftclaw_submit_atomic_microtask",
                missing,
                "Please provide task_id, seedbox_id, file_hash, and result_hash.",
                values,
            )
        return {
            "intent": "submit_atomic_microtask",
            "tool": "delftclaw_submit_atomic_microtask",
            "result": client.submit_atomic_microtask(
                task_id=str(values["task_id"]),
                seedbox_id=str(values["seedbox_id"]),
                file_hash=str(values["file_hash"]),
                result_hash=str(values["result_hash"]),
                task_type=str(values["task_type"]),
            ),
        }

    if _asks_to_verify_microtask(lowered):
        values = {
            "task_id": _value(fields, "task_id", "task"),
            "expected_result_hash": _value(fields, "expected_result_hash", "result_hash", "expected"),
        }
        missing = _missing(values, ("task_id", "expected_result_hash"))
        if missing:
            return _needs_details(
                "verify_atomic_microtask",
                "delftclaw_verify_atomic_microtask",
                missing,
                "Please provide task_id and expected_result_hash.",
                values,
            )
        return {
            "intent": "verify_atomic_microtask",
            "tool": "delftclaw_verify_atomic_microtask",
            "result": client.verify_atomic_microtask(
                task_id=str(values["task_id"]),
                expected_result_hash=str(values["expected_result_hash"]),
            ),
        }

    if _asks_to_audit_seedboxes(lowered):
        return {
            "intent": "audit_seedboxes",
            "tool": "delftclaw_audit_seedboxes",
            "result": client.audit_seedboxes(),
        }

    if _asks_for_reputation(lowered):
        agent_id = _value(fields, "agent_id", "agent") or _extract_after_for(normalized)
        return {
            "intent": "get_reputation",
            "tool": "delftclaw_get_reputation",
            "result": client.reputation(agent_id=agent_id),
        }

    if _asks_to_send_message(lowered):
        recipient = _value(fields, "recipient", "to") or _extract_message_recipient(normalized)
        message = _value(fields, "message") or _extract_message_body(normalized)
        missing = []
        if not recipient:
            missing.append("recipient")
        if not message:
            missing.append("message")
        if missing:
            return _needs_details(
                "send_message",
                "delftclaw_send_message",
                missing,
                "Please provide a recipient and message, for example: send message to agent-b: hello.",
                {"recipient": recipient, "message": message},
            )
        return {
            "intent": "send_message",
            "tool": "delftclaw_send_message",
            "result": client.send_message(recipient=recipient, message=message),
        }

    if _asks_for_files(lowered):
        query = _extract_quoted_query(normalized) or _extract_containing_query(normalized)
        if query:
            return {
                "intent": "search_files",
                "tool": "delftclaw_search_files",
                "result": client.search_seedbox_files(query=query),
            }
        return {
            "intent": "list_files",
            "tool": "delftclaw_list_files",
            "result": client.list_seedbox_files(),
        }

    if "status" in lowered or "metrics" in lowered:
        return {
            "intent": "network_status",
            "tool": "delftclaw_get_metrics",
            "result": client.metrics(),
        }

    return {
        "intent": "unknown",
        "ok": False,
        "error": "No DelftClaw command mapping matched this request.",
        "supported_examples": SUPPORTED_EXAMPLES,
    }


def _asks_for_files(lowered: str) -> bool:
    return "files" in lowered and ("claw network" in lowered or "seedbox" in lowered)


def _asks_for_random_playback(lowered: str) -> bool:
    return "play" in lowered and "random" in lowered and ("claw network" in lowered or "seedbox" in lowered)


def _asks_to_spawn_agent(lowered: str) -> bool:
    return any(word in lowered for word in ("spawn", "create", "provision", "launch")) and "agent" in lowered


def _asks_to_register_seedbox(lowered: str) -> bool:
    return any(word in lowered for word in ("create", "register", "add", "spawn")) and "seedbox" in lowered and "file" not in lowered


def _asks_to_index_file(lowered: str) -> bool:
    return any(word in lowered for word in ("add", "index", "register")) and "file" in lowered


def _asks_to_submit_proof(lowered: str) -> bool:
    return "proof" in lowered and any(word in lowered for word in ("submit", "add", "record"))


def _asks_to_record_donation(lowered: str) -> bool:
    return "donation" in lowered or "donate" in lowered


def _asks_to_submit_microtask(lowered: str) -> bool:
    return "microtask" in lowered and any(word in lowered for word in ("submit", "add", "record", "claim"))


def _asks_to_verify_microtask(lowered: str) -> bool:
    return "microtask" in lowered and any(word in lowered for word in ("verify", "confirm", "check"))


def _asks_to_audit_seedboxes(lowered: str) -> bool:
    return "audit" in lowered and "seedbox" in lowered


def _asks_for_reputation(lowered: str) -> bool:
    return "reputation" in lowered or "trust score" in lowered


def _asks_to_send_message(lowered: str) -> bool:
    return "send" in lowered and "message" in lowered


def _extract_quoted_query(text: str) -> str:
    match = re.search(r'"([^"]+)"', text)
    return match.group(1).strip() if match else ""


def _extract_containing_query(text: str) -> str:
    match = re.search(r"\bcontaining\s+(.+?)[?.!]*$", text, flags=re.IGNORECASE)
    return match.group(1).strip().strip("\"'") if match else ""


def _extract_after_find(text: str) -> str:
    match = re.search(r"\bfind\s+(.+?)(?:,\s*and\s*play|\s+and\s+play|$)", text, flags=re.IGNORECASE)
    return match.group(1).strip().strip("\"'") if match else ""


def _extract_after_for(text: str) -> str:
    match = re.search(r"\bfor\s+([A-Za-z0-9_.:-]+)", text, flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _extract_message_recipient(text: str) -> str:
    match = re.search(r"\bto\s+([A-Za-z0-9_.-]+)", text, flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""


def _extract_message_body(text: str) -> str:
    match = re.search(r":\s*(.+)$", text)
    return match.group(1).strip() if match else ""


def _extract_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    pattern = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s]+)")
    for key, raw in pattern.findall(text):
        fields[key.casefold().replace("-", "_")] = raw.strip().strip("\"'")
    return fields


def _value(fields: dict[str, str], *names: str) -> str:
    for name in names:
        value = fields.get(name.casefold().replace("-", "_"))
        if value not in {None, ""}:
            return str(value)
    return ""


def _int_value(fields: dict[str, str], *names: str) -> int | None:
    value = _value(fields, *names)
    if not value:
        return None
    digits = re.sub(r"[^0-9]", "", value)
    return int(digits) if digits else None


def _bool_value(fields: dict[str, str], *names: str) -> bool:
    return _value(fields, *names).casefold() in {"1", "true", "yes", "on"}


def _tags_value(fields: dict[str, str]) -> list[str]:
    raw = _value(fields, "tags", "tag")
    return [tag.strip() for tag in raw.split(",") if tag.strip()] if raw else []


def _missing(values: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    return [name for name in required if values.get(name) in {None, ""}]


def _needs_details(
    intent: str,
    tool: str,
    missing: list[str],
    next_prompt: str,
    known_fields: dict[str, Any],
) -> dict[str, Any]:
    return {
        "intent": intent,
        "tool": tool,
        "ok": False,
        "needs_more_info": True,
        "missing_fields": missing,
        "known_fields": known_fields,
        "next_prompt": next_prompt,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Handle a natural-language DelftClaw request.")
    parser.add_argument("request", help="User request, for example: what files are stored on our Claw Network?")
    args = parser.parse_args()
    print(json.dumps(handle_agentic_request(args.request), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
