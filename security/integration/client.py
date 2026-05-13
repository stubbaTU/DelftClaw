from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class DelftClawClient:
    """Small HTTP client for OpenClaw tool adapters."""

    def __init__(self, base_url: str | None = None, agent_id: str | None = None, timeout: float = 10.0):
        self.base_url = (base_url or os.getenv("DELFTCLAW_GATEWAY_URL") or "http://127.0.0.1:8765").rstrip("/")
        self.agent_id = agent_id or os.getenv("DELFTCLAW_AGENT_ID") or "local-openclaw-agent"
        self.timeout = timeout

    def tool_call(
        self,
        tool_name: str,
        tool_kwargs: dict[str, Any] | None = None,
        *,
        payload_id: str | None = None,
        source: str = "openclaw",
    ) -> dict[str, Any]:
        return self._post(
            "/tool-call",
            {
                "agent_id": self.agent_id,
                "tool_name": tool_name,
                "tool_kwargs": tool_kwargs or {},
                "payload_id": payload_id,
                "source": source,
            },
        )

    def send_message(self, recipient: str, message: str, *, payload_id: str | None = None) -> dict[str, Any]:
        return self.tool_call(
            "send_message",
            {"recipient": recipient, "message": message},
            payload_id=payload_id,
        )

    def register_seedbox(
        self,
        seedbox_id: str,
        donation_address: str,
        advertised_capacity_gb: int,
        *,
        fake: bool = False,
        payload_id: str | None = None,
    ) -> dict[str, Any]:
        return self.tool_call(
            "register_seedbox",
            {
                "seedbox_id": seedbox_id,
                "donation_address": donation_address,
                "advertised_capacity_gb": advertised_capacity_gb,
                "fake": fake,
            },
            payload_id=payload_id,
        )

    def broadcast_seedbox_donation(
        self,
        seedbox_id: str,
        amount_sats: int,
        *,
        txid: str | None = None,
        stolen_from_honest_agent: bool = False,
        confirmations: int = 0,
        output_index: int | None = None,
        payload_id: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "seedbox_id": seedbox_id,
            "amount_sats": amount_sats,
            "stolen_from_honest_agent": stolen_from_honest_agent,
            "confirmations": confirmations,
        }
        if txid:
            payload["txid"] = txid
        if output_index is not None:
            payload["output_index"] = output_index
        return self.tool_call("broadcast_seedbox_donation", payload, payload_id=payload_id)

    def submit_seedbox_proof(
        self,
        seedbox_id: str,
        storage_url: str,
        nonce: str,
        *,
        proof_id: str | None = None,
        payload_id: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "seedbox_id": seedbox_id,
            "storage_url": storage_url,
            "nonce": nonce,
        }
        if proof_id:
            payload["proof_id"] = proof_id
        return self.tool_call("submit_seedbox_proof", payload, payload_id=payload_id)

    def submit_atomic_microtask(
        self,
        task_id: str,
        seedbox_id: str,
        file_hash: str,
        result_hash: str,
        *,
        task_type: str = "storage_check",
        payload_id: str | None = None,
    ) -> dict[str, Any]:
        return self.tool_call(
            "submit_atomic_microtask",
            {
                "task_id": task_id,
                "seedbox_id": seedbox_id,
                "file_hash": file_hash,
                "result_hash": result_hash,
                "task_type": task_type,
            },
            payload_id=payload_id,
        )

    def verify_atomic_microtask(
        self,
        task_id: str,
        expected_result_hash: str,
        *,
        payload_id: str | None = None,
    ) -> dict[str, Any]:
        return self.tool_call(
            "verify_atomic_microtask",
            {
                "task_id": task_id,
                "expected_result_hash": expected_result_hash,
            },
            payload_id=payload_id,
        )

    def index_seedbox_file(
        self,
        file_id: str,
        seedbox_id: str,
        name: str,
        content_url: str,
        *,
        sha256: str = "",
        size_bytes: int = 0,
        media_type: str = "",
        tags: list[str] | None = None,
        payload_id: str | None = None,
    ) -> dict[str, Any]:
        return self.tool_call(
            "index_seedbox_file",
            {
                "file_id": file_id,
                "seedbox_id": seedbox_id,
                "name": name,
                "content_url": content_url,
                "sha256": sha256,
                "size_bytes": size_bytes,
                "media_type": media_type,
                "tags": tags or [],
            },
            payload_id=payload_id,
        )

    def list_seedbox_files(self, *, payload_id: str | None = None) -> dict[str, Any]:
        return self.tool_call("list_seedbox_files", {}, payload_id=payload_id)

    def search_seedbox_files(self, query: str, *, payload_id: str | None = None) -> dict[str, Any]:
        return self.tool_call("search_seedbox_files", {"query": query}, payload_id=payload_id)

    def pick_random_seedbox_file(self, query: str = "", *, payload_id: str | None = None) -> dict[str, Any]:
        return self.tool_call("pick_random_seedbox_file", {"query": query}, payload_id=payload_id)

    def report_security_event(
        self,
        subject_id: str,
        action: str,
        details: dict[str, Any] | None = None,
        *,
        severity: int = 10,
    ) -> dict[str, Any]:
        return self._post(
            "/security-report",
            {
                "agent_id": self.agent_id,
                "subject_id": subject_id,
                "action": action,
                "details": details or {},
                "severity": severity,
            },
        )

    def audit_seedboxes(self) -> dict[str, Any]:
        return self._post("/audit/seedboxes", {"agent_id": self.agent_id})

    def metrics(self) -> dict[str, Any]:
        return self._get("/metrics")

    def reputation(self, agent_id: str | None = None) -> dict[str, Any]:
        return self._get(f"/reputation/{agent_id or self.agent_id}")

    def openclaw_status(self) -> dict[str, Any]:
        return self._get("/openclaw/status")

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self._open(request)

    def _get(self, path: str) -> dict[str, Any]:
        request = Request(f"{self.base_url}{path}", method="GET")
        return self._open(request)

    def _open(self, request: Request) -> dict[str, Any]:
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            error_body = exc.read().decode("utf-8")
            try:
                parsed = json.loads(error_body)
            except json.JSONDecodeError:
                parsed = {"error": error_body}
            parsed.setdefault("status", exc.code)
            return parsed
        except (OSError, URLError) as exc:
            return {"ok": False, "error": str(exc)}
