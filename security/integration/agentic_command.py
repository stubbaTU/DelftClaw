from __future__ import annotations

import argparse
import json
import re
from typing import Any

from security.integration.client import DelftClawClient


def handle_agentic_request(text: str, client: DelftClawClient | None = None) -> dict[str, Any]:
    """
    Translate common user-facing Claw Network requests into DelftClaw tool calls.

    This is intentionally small and deterministic. OpenClaw should prefer the
    tool manifest and protocol.md, but this adapter gives agents a simple bridge
    when they receive natural language over Telegram.
    """

    client = client or DelftClawClient()
    normalized = " ".join(text.strip().split())
    lowered = normalized.casefold()

    if _asks_for_random_playback(lowered):
        query = _extract_quoted_query(normalized) or _extract_after_find(normalized) or ""
        return {
            "intent": "play_random_file",
            "tool": "delftclaw_pick_random_file",
            "result": client.pick_random_seedbox_file(query=query),
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
        "supported_examples": [
            "what files are stored on our Claw Network?",
            'what files are stored on our Claw Network containing "Creative Commons"?',
            "go to the Claw Network, find Creative Commons Audio Archive 2023, and play a random file",
        ],
    }


def _asks_for_files(lowered: str) -> bool:
    return "files" in lowered and ("claw network" in lowered or "seedbox" in lowered)


def _asks_for_random_playback(lowered: str) -> bool:
    return "play" in lowered and "random" in lowered and ("claw network" in lowered or "seedbox" in lowered)


def _extract_quoted_query(text: str) -> str:
    match = re.search(r'"([^"]+)"', text)
    return match.group(1).strip() if match else ""


def _extract_containing_query(text: str) -> str:
    match = re.search(r"\bcontaining\s+(.+?)[?.!]*$", text, flags=re.IGNORECASE)
    return match.group(1).strip().strip("\"'") if match else ""


def _extract_after_find(text: str) -> str:
    match = re.search(r"\bfind\s+(.+?)(?:,\s*and\s*play|\s+and\s+play|$)", text, flags=re.IGNORECASE)
    return match.group(1).strip().strip("\"'") if match else ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Handle a natural-language DelftClaw request.")
    parser.add_argument("request", help="User request, for example: what files are stored on our Claw Network?")
    args = parser.parse_args()
    print(json.dumps(handle_agentic_request(args.request), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
