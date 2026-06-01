from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SporeStackRequestPlan:
    endpoint: str
    method: str
    payload: dict[str, Any]
    dry_run: bool = True


class SporeStackSeedboxProvider:
    """Adapter for SporeStack seedbox provisioning.

    Dry-run is the default so demos can use the real SporeStack request shape
    without funding an account or launching a paid server.
    """

    def __init__(self, *, token: str = "", dry_run: bool = True) -> None:
        self.token = token
        self.dry_run = dry_run

    def quote_seedbox(
        self,
        *,
        flavor: str = "vps-1vcpu-1gb",
        provider: str = "digitalocean",
        days: int = 30,
    ) -> dict[str, Any]:
        plan = SporeStackRequestPlan(
            endpoint="/server/quote",
            method="GET",
            payload={"flavor": flavor, "provider": provider, "days": days},
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return {"ok": True, "operation": "quote_seedbox", "plan": asdict(plan)}

        from sporestack.client import Client

        quote = Client().server_quote(days=days, flavor=flavor, provider=provider)
        return {"ok": True, "operation": "quote_seedbox", "quote": _model_to_dict(quote), "plan": asdict(plan)}

    def create_funding_invoice(self, *, dollars: int, currency: str = "btc") -> dict[str, Any]:
        self._require_token()
        plan = SporeStackRequestPlan(
            endpoint=f"/token/{self.token}/add",
            method="POST",
            payload={"dollars": dollars, "currency": currency},
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return {"ok": True, "operation": "create_funding_invoice", "plan": asdict(plan)}

        from sporestack.client import Client

        invoice = Client(client_token=self.token).token().add(dollars=dollars, currency=currency)
        return {
            "ok": True,
            "operation": "create_funding_invoice",
            "invoice": _model_to_dict(invoice),
            "plan": asdict(plan),
        }

    def launch_seedbox(
        self,
        *,
        ssh_key: str,
        flavor: str = "vps-1vcpu-1gb",
        operating_system: str = "ubuntu-24-04",
        provider: str = "digitalocean",
        days: int = 30,
        region: str | None = None,
        hostname: str = "delftclaw-seedbox",
        user_data: str | None = None,
    ) -> dict[str, Any]:
        self._require_token()
        payload = {
            "flavor": flavor,
            "operating_system": operating_system,
            "provider": provider,
            "days": days,
            "region": region,
            "hostname": hostname,
            "ssh_key": ssh_key,
            "user_data": user_data,
        }
        plan = SporeStackRequestPlan(
            endpoint=f"/token/{self.token}/servers",
            method="POST",
            payload=payload,
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return {"ok": True, "operation": "launch_seedbox", "plan": asdict(plan)}

        from sporestack.client import Client

        server = Client(client_token=self.token, ssh_key=ssh_key).token().launch_server(
            flavor=flavor,
            operating_system=operating_system,
            provider=provider,
            days=days,
            region=region,
            hostname=hostname,
            user_data=user_data,
        )
        return {
            "ok": True,
            "operation": "launch_seedbox",
            "server": {"machine_id": server.machine_id},
            "plan": asdict(plan),
        }

    def list_seedboxes(self) -> dict[str, Any]:
        self._require_token()
        plan = SporeStackRequestPlan(
            endpoint=f"/token/{self.token}/servers",
            method="GET",
            payload={"include_deleted": True, "include_forgotten": True},
            dry_run=self.dry_run,
        )
        if self.dry_run:
            return {"ok": True, "operation": "list_seedboxes", "plan": asdict(plan), "servers": []}

        from sporestack.client import Client

        servers = Client(client_token=self.token).token().servers(show_forgotten=True)
        return {
            "ok": True,
            "operation": "list_seedboxes",
            "servers": [{"machine_id": server.machine_id} for server in servers],
            "plan": asdict(plan),
        }

    def _require_token(self) -> None:
        if not self.token:
            raise ValueError("SporeStack token is required; use a placeholder token for dry-run demos")


def _model_to_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    if isinstance(value, dict):
        return value
    return {"value": str(value)}
