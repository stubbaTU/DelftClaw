"""SporeStack VPS provisioning.

Wraps `sporestack.api_client.APIClient` so the rest of the codebase only sees
domain types (`Server`, `ServerSpec`). Every call hits the live SporeStack
API; tests must inject a fake `APIClient` or set `OPENCLAW_REPLICATION_LIVE=0`
to skip them.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Optional

from sporestack.api_client import APIClient
from sporestack.constants import Currency, Provider


@dataclass(frozen=True)
class ServerSpec:
    """Minimum input the caller must provide to launch a server."""

    flavor: str
    operating_system: str
    ssh_key: str
    days: int = 7
    provider: str = Provider.DIGITALOCEAN.value
    region: Optional[str] = None
    hostname: str = ""


@dataclass(frozen=True)
class Server:
    """The handle returned to callers after a successful launch."""

    machine_id: str
    token: str
    ipv4: Optional[str]
    ipv6: Optional[str]


def _live_only() -> None:
    if os.environ.get("OPENCLAW_REPLICATION_LIVE") != "1":
        raise RuntimeError(
            "live SporeStack call attempted without OPENCLAW_REPLICATION_LIVE=1"
        )


class SporeStackProvisioner:
    """Domain-level wrapper around the SporeStack API client."""

    def __init__(self, client: APIClient | None = None) -> None:
        self._client = client or APIClient()

    @staticmethod
    def fresh_token() -> str:
        # SporeStack tokens are arbitrary client-chosen strings; 32 bytes hex is plenty.
        return secrets.token_hex(32)

    def fund_token(self, token: str, dollars: int, currency: Currency = Currency.btc):
        """Top up `token` with `dollars` worth of BTC. Returns an Invoice the caller pays."""
        _live_only()
        return self._client.token_add(token=token, dollars=dollars, currency=currency)

    def balance(self, token: str) -> int:
        """USD-cent balance of `token`."""
        _live_only()
        return self._client.token_balance(token=token).cents

    def launch(self, token: str, spec: ServerSpec) -> Server:
        _live_only()
        resp = self._client.server_launch(
            token=token,
            flavor=spec.flavor,
            operating_system=spec.operating_system,
            ssh_key=spec.ssh_key,
            provider=Provider(spec.provider),
            region=spec.region,
            hostname=spec.hostname,
            days=spec.days,
        )
        return Server(
            machine_id=resp.machine_id,
            token=token,
            ipv4=getattr(resp, "ipv4", None),
            ipv6=getattr(resp, "ipv6", None),
        )

    def info(self, server: Server):
        _live_only()
        return self._client.server_info(token=server.token, machine_id=server.machine_id)

    def destroy(self, server: Server) -> None:
        _live_only()
        self._client.server_delete(token=server.token, machine_id=server.machine_id)
