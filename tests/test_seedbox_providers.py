from __future__ import annotations

from pathlib import Path

import pytest

from security.seedbox_providers import LocalSeedboxProvider, MockSeedboxProvider, RealSporeStackProvider, provider_for


def test_mock_seedbox_launch_returns_demo_metadata(tmp_path: Path) -> None:
    content = tmp_path / "content"
    content.mkdir()
    (content / "demo.txt").write_text("hello", encoding="utf-8")

    metadata = MockSeedboxProvider(root=tmp_path / "out").launch(
        hostname="demo-seedbox",
        content_dir=content,
        capacity_gb=100,
    )

    assert metadata.provider == "mock"
    assert metadata.health_status == "healthy"
    assert metadata.ip == "127.0.0.1"
    assert metadata.torrent_metadata[0]["magnet_uri"].startswith("magnet:?xt=urn:btih:")
    assert (tmp_path / "out" / "demo-seedbox" / "seedbox_metadata.json").exists()


def test_local_seedbox_launch_writes_catalog_and_log(tmp_path: Path) -> None:
    content = tmp_path / "content"
    content.mkdir()
    (content / "paper.pdf").write_text("paper", encoding="utf-8")

    metadata = LocalSeedboxProvider(root=tmp_path / "out").launch(
        hostname="local-seedbox",
        content_dir=content,
        capacity_gb=100,
    )

    assert metadata.provider == "local"
    assert Path(metadata.logs_path).exists()
    assert (tmp_path / "out" / "local-seedbox" / "content_catalog.csv").exists()


def test_sporestack_provider_is_plan_only_for_now(tmp_path: Path) -> None:
    provider = RealSporeStackProvider()

    plan = provider.plan(hostname="future", content_dir=tmp_path, capacity_gb=100)

    assert plan.provider == "sporestack"
    assert plan.dry_run is True
    with pytest.raises(RuntimeError):
        provider.launch(hostname="future", content_dir=tmp_path, capacity_gb=100)


def test_provider_factory_rejects_unknown_provider(tmp_path: Path) -> None:
    assert provider_for("mock", root=tmp_path).provider_name == "mock"
    assert provider_for("local", root=tmp_path).provider_name == "local"
    with pytest.raises(ValueError):
        provider_for("unknown", root=tmp_path)
