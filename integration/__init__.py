"""JSON-RPC sidecar that bridges the Claude Code skill to AgentChannel."""

__version__ = "0.1.0"

from integration.sidecar.server import Sidecar
from integration.rpc.methods import RpcMethod, RpcMethodRegistry

__all__ = ["Sidecar", "RpcMethod", "RpcMethodRegistry"]
