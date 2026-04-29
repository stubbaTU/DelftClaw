"""Sidecar daemon that exposes AgentChannel over a Unix-domain JSON-RPC socket."""

from integration.sidecar.server import Sidecar
from integration.sidecar.socket import UnixSocketServer
from integration.sidecar.lifecycle import run

__all__ = ["Sidecar", "UnixSocketServer", "run"]
