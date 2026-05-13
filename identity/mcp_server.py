"""Identity MCP server for OpenClaw autonomous tool calls."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import os

from fastapi import FastAPI
from pydantic import BaseModel

from identity.agent_identity import AgentIdentity
from identity.verification import VerificationChallenge, is_verified, simulate_regtest_payment
from shared.credentials import issue_credential as issue_credential_impl
from shared.credentials import verify_credential as verify_credential_impl


DEFAULT_IDENTITY_PATH = Path(__file__).resolve().parent / "agent_identity.json"


class ToolCall(BaseModel):
    """Generic JSON payload for HTTP tool calls."""

    args: dict = {}


class IdentityToolServer:
    """Server state that owns one loaded AgentIdentity for all tool requests."""

    def __init__(self, identity: AgentIdentity) -> None:
        self.identity = identity
        self._last_challenge: VerificationChallenge | None = None

    def get_identity(self) -> dict:
        """Return public identity details: agent id, pubkeys, wallet address/xpub, and network."""
        return self.identity.public_bundle()

    def get_wallet_balance(self) -> dict:
        """Return current wallet balance values."""
        sats = self.identity.wallet.get_balance()
        return {
            "address": self.identity.wallet.address(),
            "balance_satoshis": sats,
            "balance_btc": sats / 100_000_000,
            "network": self.identity.network,
        }

    def sign_message(self, message: str) -> dict:
        """Sign a message with this agent's IPv8 key for identity proof."""
        sig = self.identity.ipv8.sign(message.encode("utf-8"))
        return {"message": message, "signature_hex": sig.hex(), "agent_id": self.identity.get_identity_hash()}

    def verify_message(self, message: str, signature_hex: str, agent_id: str) -> dict:
        """Verify a signed message against an expected agent id."""
        if agent_id != self.identity.get_identity_hash():
            return {"valid": False, "agent_id": agent_id, "message": message}
        valid = self.identity.ipv8.verify(message.encode("utf-8"), bytes.fromhex(signature_hex))
        return {"valid": bool(valid), "agent_id": agent_id, "message": message}

    def issue_credential(self, claims: dict) -> dict:
        """Issue a Verifiable Credential signed by this agent."""
        return issue_credential_impl(self.identity, dict(claims))

    def verify_credential(self, vc: dict, expected_issuer_id: str) -> dict:
        """Verify a Verifiable Credential from a peer."""
        valid = verify_credential_impl(vc, expected_issuer_id)
        return {"valid": valid, "issuer_id": vc.get("issuer_id"), "claims": vc.get("claims", {})}

    def create_verification_challenge(self) -> dict:
        """Create a 1000-satoshi identity verification challenge."""
        self._last_challenge = VerificationChallenge.create(self.identity, self.identity.network)
        return {
            "challenge_address": self._last_challenge.challenge_address,
            "nonce": self._last_challenge.nonce,
            "amount_satoshis": self._last_challenge.amount_satoshis,
            "network": self._last_challenge.network,
        }

    def submit_verification(self, txid: str) -> dict:
        """Verify txid against latest challenge and return VerificationResult."""
        if self._last_challenge is None:
            return {"error": "no active challenge"}
        result = self._last_challenge.verify(txid, self.identity, self.identity.network)
        return {
            "verified": result.verified,
            "txid": result.txid,
            "agent_id": result.agent_id,
            "timestamp": result.timestamp,
            "confirmations": result.confirmations,
            "error": result.error,
        }

    def check_verification_status(self, agent_id: str) -> dict:
        """Check whether a given agent has a successful verification record."""
        return {"verified": is_verified(agent_id), "agent_id": agent_id}


try:
    from mcp.server.fastmcp import FastMCP
except Exception:  # pragma: no cover - optional dependency path
    FastMCP = None  # type: ignore[assignment]


class IdentityMCPServer:
    """HTTP server wrapper exposing identity tools with MCP-style semantics."""

    def __init__(self, tool_server: IdentityToolServer) -> None:
        self.tools = tool_server
        self.fastmcp = self._build_fastmcp()

    def _build_fastmcp(self):
        """Build native FastMCP tool registry when the mcp package is available."""
        if FastMCP is None:
            return None
        app = FastMCP("agent-identity")

        @app.tool()
        def get_identity() -> dict:
            """Return this agent's public identity bundle."""
            return self.tools.get_identity()

        @app.tool()
        def get_wallet_balance() -> dict:
            """Return this agent wallet balance details."""
            return self.tools.get_wallet_balance()

        @app.tool()
        def sign_message(message: str) -> dict:
            """Sign a message using the agent IPv8 key."""
            return self.tools.sign_message(message)

        @app.tool()
        def verify_message(message: str, signature_hex: str, agent_id: str) -> dict:
            """Verify a signed message against expected agent id."""
            return self.tools.verify_message(message, signature_hex, agent_id)

        @app.tool()
        def issue_credential(claims: dict) -> dict:
            """Issue a credential signed by this identity."""
            return self.tools.issue_credential(claims)

        @app.tool()
        def verify_credential(vc: dict, expected_issuer_id: str) -> dict:
            """Verify a credential from another agent."""
            return self.tools.verify_credential(vc, expected_issuer_id)

        @app.tool()
        def create_verification_challenge() -> dict:
            """Create a 1000-satoshi verification challenge."""
            return self.tools.create_verification_challenge()

        @app.tool()
        def submit_verification(txid: str) -> dict:
            """Submit a txid for challenge verification."""
            return self.tools.submit_verification(txid)

        @app.tool()
        def check_verification_status(agent_id: str) -> dict:
            """Check verification status for an agent id."""
            return self.tools.check_verification_status(agent_id)

        return app

    @classmethod
    def boot(cls, identity_path: str | Path = DEFAULT_IDENTITY_PATH, network: str = "REGTEST") -> "IdentityMCPServer":
        """Load existing identity JSON or create and persist a new one."""
        path = Path(identity_path)
        if path.exists():
            identity = AgentIdentity.load(path)
        else:
            identity = AgentIdentity(network=network, agent_index=0)
            identity.save(path)
        return cls(IdentityToolServer(identity))

    def create_app(self) -> FastAPI:
        """Create an HTTP app exposing MCP-compatible tool call endpoints."""
        app = FastAPI(title="OpenClaw Identity MCP", version="1.0")

        @app.get("/health")
        def health() -> dict:
            """Basic readiness probe used by the integration fixture."""
            return {"ok": True}

        @app.get("/mcp")
        def manifest() -> dict:
            """Return server and tool manifest."""
            return {
                "server": "agent-identity",
                "tools": [
                    "get_identity",
                    "get_wallet_balance",
                    "sign_message",
                    "verify_message",
                    "issue_credential",
                    "verify_credential",
                    "create_verification_challenge",
                    "submit_verification",
                    "check_verification_status",
                ],
            }

        @app.post("/mcp/tool/{tool_name}")
        def call_tool(tool_name: str, req: ToolCall) -> dict:
            """Execute one named tool and return JSON output."""
            try:
                args = req.args or {}
                if tool_name == "get_identity":
                    return self.tools.get_identity()
                if tool_name == "get_wallet_balance":
                    return self.tools.get_wallet_balance()
                if tool_name == "sign_message":
                    return self.tools.sign_message(str(args.get("message", "")))
                if tool_name == "verify_message":
                    return self.tools.verify_message(
                        str(args.get("message", "")),
                        str(args.get("signature_hex", "")),
                        str(args.get("agent_id", "")),
                    )
                if tool_name == "issue_credential":
                    return self.tools.issue_credential(dict(args.get("claims", {})))
                if tool_name == "verify_credential":
                    return self.tools.verify_credential(
                        dict(args.get("vc", {})),
                        str(args.get("expected_issuer_id", "")),
                    )
                if tool_name == "create_verification_challenge":
                    return self.tools.create_verification_challenge()
                if tool_name == "submit_verification":
                    return self.tools.submit_verification(str(args.get("txid", "")))
                if tool_name == "check_verification_status":
                    return self.tools.check_verification_status(str(args.get("agent_id", "")))
                if tool_name == "simulate_regtest_payment":
                    if self.tools._last_challenge is None:
                        return {"error": "no active challenge"}
                    txid = simulate_regtest_payment(self.tools.identity, self.tools._last_challenge)
                    return {"txid": txid}
                return {"error": f"unknown tool: {tool_name}"}
            except Exception as exc:
                return {"error": str(exc)}

        return app


def default_port() -> int:
    """Return configured port from IDENTITY_MCP_PORT or default 7701."""
    return int(os.environ.get("IDENTITY_MCP_PORT", "7701"))
