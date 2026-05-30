from __future__ import annotations

import socket
import socketserver
import threading
from dataclasses import dataclass, field
from typing import Any

from security.subq3_containment.enforcement import detect_enforcement_support


class _MessageHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request.recv(65536)
        if data:
            self.server.messages.append(data.decode("utf-8", errors="replace"))  # type: ignore[attr-defined]


class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


@dataclass
class MockEndpoint:
    name: str
    server: _ReusableTCPServer
    thread: threading.Thread

    @property
    def host(self) -> str:
        return "127.0.0.1"

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def messages(self) -> list[str]:
        return list(self.server.messages)  # type: ignore[attr-defined]

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@dataclass
class NetworkGuard:
    allowed_peer_endpoint: MockEndpoint
    unauthorized_exfil_endpoint: MockEndpoint
    uses_iptables: bool = False
    kernel_filtering: bool = False
    blocked_port: int = field(default=9)

    @classmethod
    def start(cls, *, use_iptables: str = "auto") -> "NetworkGuard":
        support = detect_enforcement_support()
        if use_iptables == "true" and not support["can_probe_iptables_namespace"]:
            raise RuntimeError(
                "--use-iptables true requires Linux root with ip and iptables available"
            )
        # Direct C1 egress is enforced by the containment backend
        # (gVisor/Docker --network=none when available). This flag records
        # whether the host can also support real kernel iptables namespace
        # enforcement as checked by the preflight.
        uses_iptables = use_iptables in {"true", "auto"} and support["can_probe_iptables_namespace"]
        return cls(
            allowed_peer_endpoint=_start_endpoint("allowed_peer"),
            unauthorized_exfil_endpoint=_start_endpoint("unauthorized_exfil"),
            uses_iptables=uses_iptables,
            kernel_filtering=uses_iptables,
        )

    def stop(self) -> None:
        self.allowed_peer_endpoint.stop()
        self.unauthorized_exfil_endpoint.stop()

    def send_to_allowed_peer(self, message: str, timeout: float = 2.0) -> bool:
        return send_local_message(
            self.allowed_peer_endpoint.host,
            self.allowed_peer_endpoint.port,
            message,
            timeout=timeout,
        )

    def send_to_unauthorized_exfil(self, message: str, timeout: float = 2.0) -> bool:
        return send_local_message(
            self.unauthorized_exfil_endpoint.host,
            self.unauthorized_exfil_endpoint.port,
            message,
            timeout=timeout,
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "allowed_peer_received": self.allowed_peer_endpoint.messages,
            "unauthorized_exfil_received": self.unauthorized_exfil_endpoint.messages,
            "uses_iptables": self.uses_iptables,
            "kernel_filtering": self.kernel_filtering,
        }


def send_local_message(host: str, port: int, message: str, *, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.sendall(message.encode("utf-8"))
        return True
    except OSError:
        return False


def _start_endpoint(name: str) -> MockEndpoint:
    server = _ReusableTCPServer(("127.0.0.1", 0), _MessageHandler)
    server.messages = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, name=f"sq3-{name}", daemon=True)
    thread.start()
    return MockEndpoint(name=name, server=server, thread=thread)
