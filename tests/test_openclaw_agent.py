from __future__ import annotations

import pytest

from communication.claw import openclaw_agent as oc_mod


class _FakeIdentity:
    def __init__(self, *args, **kwargs) -> None:
        self._hash = "deadbeef"
        self.ipv8 = object()

    def get_identity_hash(self) -> str:
        return self._hash


class _FakeCommunity:
    def __init__(self) -> None:
        self.wired = None
        self.announced = False

    def wire(self, *, openclaw_identity) -> None:
        self.wired = openclaw_identity

    def announce_identity(self) -> None:
        self.announced = True


class _FakeRuntime:
    def __init__(self, identity, network_config) -> None:
        self.identity = identity
        self.network_config = network_config
        self.started = False
        self.stopped = False
        self.registered = []
        self.overlay = _FakeCommunity()

    def register_community(self, community_cls) -> None:
        self.registered.append(community_cls)

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    def get_overlay(self, community_cls):
        return self.overlay

    @property
    def my_peer(self):
        return object()


@pytest.mark.asyncio
async def test_openclaw_agent_wires_identity_into_runtime(monkeypatch) -> None:
    monkeypatch.setattr(oc_mod, "OpenClawIdentity", _FakeIdentity)
    monkeypatch.setattr(oc_mod, "IPv8Runtime", _FakeRuntime)

    agent = oc_mod.OpenClawAgent(network="MAINNET", port=9010)
    await agent.start()

    assert agent.identity_hash == "deadbeef"
    assert agent.community is not None
    community = agent.community
    assert getattr(community, "wired") is agent.identity
    assert getattr(community, "announced") is True
    assert agent.runtime.started is True
    assert agent.runtime.registered == [oc_mod.ClawPoCCommunity]

    await agent.stop()
    assert agent.runtime.stopped is True


