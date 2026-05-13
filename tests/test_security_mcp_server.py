from __future__ import annotations

from fastapi.testclient import TestClient

from security.integration import mcp_server


def test_security_mcp_manifest_lists_gateway_tools() -> None:
    client = TestClient(mcp_server.app())

    response = client.get("/mcp")

    assert response.status_code == 200
    body = response.json()
    assert body["server"] == "delftclaw-security"
    assert "delftclaw_register_seedbox" in body["tools"]
    assert "delftclaw_run_blocking_probe" not in body["tools"]


def test_security_mcp_can_call_registered_tool(monkeypatch) -> None:
    def fake_metrics() -> dict:
        return {"ok": True, "metric": "value"}

    monkeypatch.setitem(mcp_server.TOOL_REGISTRY, "delftclaw_get_metrics", fake_metrics)
    client = TestClient(mcp_server.app())

    response = client.post("/mcp/tool/delftclaw_get_metrics", json={"args": {}})

    assert response.status_code == 200
    assert response.json() == {"ok": True, "metric": "value"}


def test_security_mcp_experiment_tools_are_opt_in() -> None:
    client = TestClient(mcp_server.app(include_experiment_only=True))

    response = client.get("/mcp")

    assert response.status_code == 200
    assert "delftclaw_run_blocking_probe" in response.json()["tools"]
