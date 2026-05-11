from __future__ import annotations

from typing import Any

from security.integration.agentic_command import handle_agentic_request


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def list_seedbox_files(self) -> dict[str, Any]:
        self.calls.append(("list_seedbox_files", {}))
        return {"ok": True, "files": []}

    def search_seedbox_files(self, query: str) -> dict[str, Any]:
        self.calls.append(("search_seedbox_files", {"query": query}))
        return {"ok": True, "query": query, "files": []}

    def pick_random_seedbox_file(self, query: str = "") -> dict[str, Any]:
        self.calls.append(("pick_random_seedbox_file", {"query": query}))
        return {"ok": True, "playback_intent": {"url": "https://example.invalid/audio.mp3"}}

    def metrics(self) -> dict[str, Any]:
        self.calls.append(("metrics", {}))
        return {"ok": True}


def test_agentic_command_lists_files() -> None:
    client = FakeClient()
    result = handle_agentic_request("what files are stored on our Claw Network?", client)

    assert result["intent"] == "list_files"
    assert client.calls == [("list_seedbox_files", {})]


def test_agentic_command_searches_quoted_files() -> None:
    client = FakeClient()
    result = handle_agentic_request(
        'what files are stored on our Claw Network containing "Creative Commons"?',
        client,
    )

    assert result["intent"] == "search_files"
    assert client.calls == [("search_seedbox_files", {"query": "Creative Commons"})]


def test_agentic_command_picks_random_playback_file() -> None:
    client = FakeClient()
    result = handle_agentic_request(
        "go to the Claw Network, find Creative Commons Audio Archive 2023, and play a random file",
        client,
    )

    assert result["intent"] == "play_random_file"
    assert client.calls == [("pick_random_seedbox_file", {"query": "Creative Commons Audio Archive 2023"})]
