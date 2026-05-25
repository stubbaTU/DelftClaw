from __future__ import annotations

from security.subq2_accountability.sporestack_provider import SporeStackSeedboxProvider


def test_sporestack_provider_dry_run_uses_real_endpoint_shape() -> None:
    provider = SporeStackSeedboxProvider(token="demo-token", dry_run=True)

    quote = provider.quote_seedbox(days=1)
    invoice = provider.create_funding_invoice(dollars=1)
    launch = provider.launch_seedbox(ssh_key="ssh-ed25519 DEMO")
    servers = provider.list_seedboxes()

    assert quote["plan"]["endpoint"] == "/server/quote"
    assert quote["plan"]["method"] == "GET"
    assert invoice["plan"]["endpoint"] == "/token/demo-token/add"
    assert invoice["plan"]["method"] == "POST"
    assert launch["plan"]["endpoint"] == "/token/demo-token/servers"
    assert launch["plan"]["method"] == "POST"
    assert servers["plan"]["endpoint"] == "/token/demo-token/servers"
    assert servers["servers"] == []
