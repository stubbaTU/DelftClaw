from __future__ import annotations

from pathlib import Path

from security.containment_layer.firewall import FirewallBackend, NFT_TABLE, egress_filter


def test_native_nftables_filter_uses_dedicated_table_and_cleans_up(monkeypatch, tmp_path: Path) -> None:
    commands: list[tuple[list[str], str]] = []

    class Result:
        stdout = "table inet vukzero_sq3 {}\n"
        stderr = ""
        returncode = 0

    def fake_run(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
        commands.append((list(cmd), kwargs.get("input", "")))
        return Result()

    monkeypatch.setattr("security.containment_layer.firewall.subprocess.run", fake_run)
    backend = FirewallBackend("native_nftables", "iptables", "", "nft 1.0", "")

    with egress_filter(
        backend,
        container_ip="172.31.77.15",
        gateway_ip="172.31.77.1",
        allowed_peer_port=12345,
        out_dir=tmp_path,
        artifact_label="C1_vukzero_gvisor",
    ):
        pass

    scripts = [stdin for cmd, stdin in commands if cmd == ["nft", "-f", "-"]]
    assert len(scripts) == 1
    assert f"table inet {NFT_TABLE}" in scripts[0]
    assert "tcp dport 12345 accept" in scripts[0]
    assert "ip saddr 172.31.77.15 reject" in scripts[0]
    deletes = [cmd for cmd, _ in commands if cmd[:4] == ["nft", "delete", "table", "inet"]]
    assert len(deletes) == 2
    assert (tmp_path / "sq3_nft_ruleset_C1_vukzero_gvisor.txt").exists()
