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

    def register_seedbox(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("register_seedbox", kwargs))
        return {"ok": True}

    def index_seedbox_file(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("index_seedbox_file", kwargs))
        return {"ok": True}

    def submit_seedbox_proof(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("submit_seedbox_proof", kwargs))
        return {"ok": True}

    def broadcast_seedbox_donation(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("broadcast_seedbox_donation", kwargs))
        return {"ok": True}

    def submit_atomic_microtask(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("submit_atomic_microtask", kwargs))
        return {"ok": True}

    def verify_atomic_microtask(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("verify_atomic_microtask", kwargs))
        return {"ok": True}

    def audit_seedboxes(self) -> dict[str, Any]:
        self.calls.append(("audit_seedboxes", {}))
        return {"ok": True}

    def reputation(self, agent_id: str | None = None) -> dict[str, Any]:
        self.calls.append(("reputation", {"agent_id": agent_id}))
        return {"ok": True}

    def send_message(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("send_message", kwargs))
        return {"ok": True}

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


def test_agentic_command_registers_seedbox_with_fields() -> None:
    client = FakeClient()
    result = handle_agentic_request(
        "create seedbox seedbox_id=demo-seedbox-1 donation_address=tb1q-demo capacity=100",
        client,
    )

    assert result["intent"] == "register_seedbox"
    assert client.calls == [
        (
            "register_seedbox",
            {
                "seedbox_id": "demo-seedbox-1",
                "donation_address": "tb1q-demo",
                "advertised_capacity_gb": 100,
                "fake": False,
            },
        )
    ]


def test_agentic_command_asks_for_missing_seedbox_details() -> None:
    result = handle_agentic_request("create a seedbox", FakeClient())

    assert result["needs_more_info"] is True
    assert result["missing_fields"] == ["seedbox_id", "donation_address", "advertised_capacity_gb"]


def test_agentic_command_indexes_seedbox_file() -> None:
    client = FakeClient()
    result = handle_agentic_request(
        'add file file_id=cc-001 seedbox_id=demo-seedbox-1 name="Creative Commons Audio" '
        'url=https://example.invalid/audio.mp3 media_type=audio/mpeg tags="Creative Commons,audio"',
        client,
    )

    assert result["intent"] == "index_seedbox_file"
    assert client.calls == [
        (
            "index_seedbox_file",
            {
                "file_id": "cc-001",
                "seedbox_id": "demo-seedbox-1",
                "name": "Creative Commons Audio",
                "content_url": "https://example.invalid/audio.mp3",
                "sha256": "",
                "size_bytes": 0,
                "media_type": "audio/mpeg",
                "tags": ["Creative Commons", "audio"],
            },
        )
    ]


def test_agentic_command_submits_proof_and_donation() -> None:
    client = FakeClient()
    handle_agentic_request(
        "submit proof seedbox_id=demo-seedbox-1 storage_url=https://example.invalid/proof nonce=nonce-001",
        client,
    )
    handle_agentic_request(
        "record donation seedbox_id=demo-seedbox-1 amount_sats=1000 txid=tx-demo",
        client,
    )

    assert client.calls == [
        (
            "submit_seedbox_proof",
            {
                "seedbox_id": "demo-seedbox-1",
                "storage_url": "https://example.invalid/proof",
                "nonce": "nonce-001",
                "proof_id": None,
            },
        ),
        (
            "broadcast_seedbox_donation",
            {
                "seedbox_id": "demo-seedbox-1",
                "amount_sats": 1000,
                "txid": "tx-demo",
                "stolen_from_honest_agent": False,
            },
        ),
    ]


def test_agentic_command_submits_and_verifies_microtask() -> None:
    client = FakeClient()
    handle_agentic_request(
        "submit microtask task_id=task-001 seedbox_id=demo-seedbox-1 file_hash=file-sha result_hash=result-sha",
        client,
    )
    handle_agentic_request("verify microtask task_id=task-001 expected_result_hash=result-sha", client)

    assert client.calls == [
        (
            "submit_atomic_microtask",
            {
                "task_id": "task-001",
                "seedbox_id": "demo-seedbox-1",
                "file_hash": "file-sha",
                "result_hash": "result-sha",
                "task_type": "storage_check",
            },
        ),
        (
            "verify_atomic_microtask",
            {
                "task_id": "task-001",
                "expected_result_hash": "result-sha",
            },
        ),
    ]


def test_agentic_command_audits_reputation_and_messages() -> None:
    client = FakeClient()
    handle_agentic_request("audit seedboxes", client)
    handle_agentic_request("show reputation for agent-a", client)
    handle_agentic_request("send message to agent-b: hello from DelftClaw", client)

    assert client.calls == [
        ("audit_seedboxes", {}),
        ("reputation", {"agent_id": "agent-a"}),
        ("send_message", {"recipient": "agent-b", "message": "hello from DelftClaw"}),
    ]


def test_agentic_command_spawn_agent_returns_guarded_plan() -> None:
    result = handle_agentic_request("spawn agent agent_id=child-a provider=sporestack", FakeClient())

    assert result["intent"] == "spawn_agent"
    assert result["requires_confirmation"] is True
    assert result["status"] == "not_gateway_backed_yet"
    assert result["missing_fields"] == ["region", "flavor", "ssh_key"]
