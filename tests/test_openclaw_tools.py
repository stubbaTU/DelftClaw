from __future__ import annotations

from typing import Any

from security.integration import openclaw_tools


class FakeDelftClawClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def send_message(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("send_message", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def register_seedbox(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("register_seedbox", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def broadcast_seedbox_donation(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("broadcast_seedbox_donation", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def submit_seedbox_proof(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("submit_seedbox_proof", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def submit_atomic_microtask(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("submit_atomic_microtask", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def verify_atomic_microtask(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("verify_atomic_microtask", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def report_security_event(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("report_security_event", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def index_seedbox_file(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("index_seedbox_file", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def list_seedbox_files(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list_seedbox_files", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def search_seedbox_files(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("search_seedbox_files", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def pick_random_seedbox_file(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("pick_random_seedbox_file", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def audit_seedboxes(self) -> dict[str, Any]:
        self.calls.append(("audit_seedboxes", {}))
        return {"ok": True, "call": self.calls[-1]}

    def metrics(self) -> dict[str, Any]:
        self.calls.append(("metrics", {}))
        return {"ok": True, "call": self.calls[-1]}

    def reputation(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("reputation", kwargs))
        return {"ok": True, "call": self.calls[-1]}

    def openclaw_status(self) -> dict[str, Any]:
        self.calls.append(("openclaw_status", {}))
        return {"ok": True, "call": self.calls[-1]}

    def tool_call(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("tool_call", {"args": args, **kwargs}))
        return {"ok": False, "blocked": True, "call": self.calls[-1]}


def test_normal_tool_registry_matches_manifest() -> None:
    manifest_names = {spec["name"] for spec in openclaw_tools.tool_manifest()}

    assert set(openclaw_tools.TOOL_REGISTRY) == manifest_names
    assert "delftclaw_run_blocking_probe" not in manifest_names


def test_experiment_only_manifest_is_opt_in() -> None:
    manifest_names = {spec["name"] for spec in openclaw_tools.tool_manifest(include_experiment_only=True)}

    assert "delftclaw_run_blocking_probe" in manifest_names


def test_openclaw_tool_wrappers_call_client(monkeypatch) -> None:
    fake_client = FakeDelftClawClient()
    monkeypatch.setattr(openclaw_tools, "_client", lambda: fake_client)

    assert openclaw_tools.delftclaw_send_message("peer", "hello")["ok"] is True
    assert openclaw_tools.delftclaw_register_seedbox("seedbox-1", "addr", 100)["ok"] is True
    assert openclaw_tools.delftclaw_broadcast_seedbox_donation("seedbox-1", 1000)["ok"] is True
    assert openclaw_tools.delftclaw_submit_seedbox_proof("seedbox-1", "https://proof", "nonce")["ok"] is True
    assert openclaw_tools.delftclaw_submit_atomic_microtask("task-1", "seedbox-1", "file", "result")["ok"] is True
    assert openclaw_tools.delftclaw_verify_atomic_microtask("task-1", "result")["ok"] is True
    assert openclaw_tools.delftclaw_report_security_event("agent", "unauthorized_tool_request")["ok"] is True
    assert openclaw_tools.delftclaw_index_seedbox_file("file-1", "seedbox-1", "Creative Commons", "https://example")["ok"] is True
    assert openclaw_tools.delftclaw_list_files()["ok"] is True
    assert openclaw_tools.delftclaw_search_files("Creative Commons")["ok"] is True
    assert openclaw_tools.delftclaw_pick_random_file("Creative Commons")["ok"] is True
    assert openclaw_tools.delftclaw_audit_seedboxes()["ok"] is True
    assert openclaw_tools.delftclaw_get_metrics()["ok"] is True
    assert openclaw_tools.delftclaw_get_reputation("agent")["ok"] is True
    assert openclaw_tools.delftclaw_get_openclaw_status()["ok"] is True
    assert openclaw_tools.delftclaw_run_blocking_probe()["blocked"] is True

    assert [name for name, _ in fake_client.calls] == [
        "send_message",
        "register_seedbox",
        "broadcast_seedbox_donation",
        "submit_seedbox_proof",
        "submit_atomic_microtask",
        "verify_atomic_microtask",
        "report_security_event",
        "index_seedbox_file",
        "list_seedbox_files",
        "search_seedbox_files",
        "pick_random_seedbox_file",
        "audit_seedboxes",
        "metrics",
        "reputation",
        "openclaw_status",
        "tool_call",
    ]
