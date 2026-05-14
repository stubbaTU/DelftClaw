from __future__ import annotations

import csv
import hashlib
import json
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


DEFAULT_ROOT = Path("seedbox_artifacts")


@dataclass(frozen=True)
class SeedboxLaunchPlan:
    provider: str
    hostname: str
    content_dir: str
    capacity_gb: int
    dry_run: bool
    estimated_cost_cents: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SeedboxMetadata:
    provider: str
    machine_id: str
    hostname: str
    ip: str
    ssh_host: str | None
    ssh_port: int | None
    ssh_user: str | None
    content_dir: str
    health_status: str
    torrent_metadata: list[dict[str, str]]
    logs_path: str
    created_at: str


class SeedboxProvider(Protocol):
    provider_name: str

    def plan(self, *, hostname: str, content_dir: Path, capacity_gb: int) -> SeedboxLaunchPlan:
        ...

    def launch(self, *, hostname: str, content_dir: Path, capacity_gb: int) -> SeedboxMetadata:
        ...


class MockSeedboxProvider:
    provider_name = "mock"

    def __init__(self, *, root: Path = DEFAULT_ROOT) -> None:
        self.root = root

    def plan(self, *, hostname: str, content_dir: Path, capacity_gb: int) -> SeedboxLaunchPlan:
        return SeedboxLaunchPlan(
            provider=self.provider_name,
            hostname=hostname,
            content_dir=str(content_dir),
            capacity_gb=capacity_gb,
            dry_run=True,
            estimated_cost_cents=0,
            notes=[
                "Mock provider does not start a process or container.",
                "It creates deterministic seedbox metadata for professor demos.",
            ],
        )

    def launch(self, *, hostname: str, content_dir: Path, capacity_gb: int) -> SeedboxMetadata:
        metadata = _build_metadata(
            provider=self.provider_name,
            hostname=hostname,
            ip="127.0.0.1",
            ssh_host=None,
            ssh_port=None,
            ssh_user=None,
            content_dir=content_dir,
            logs_path=self.root / hostname / "mock_seedbox.log",
        )
        _persist_metadata(self.root, metadata)
        return metadata


class LocalSeedboxProvider:
    provider_name = "local"

    def __init__(self, *, root: Path = DEFAULT_ROOT) -> None:
        self.root = root

    def plan(self, *, hostname: str, content_dir: Path, capacity_gb: int) -> SeedboxLaunchPlan:
        return SeedboxLaunchPlan(
            provider=self.provider_name,
            hostname=hostname,
            content_dir=str(content_dir),
            capacity_gb=capacity_gb,
            dry_run=False,
            estimated_cost_cents=0,
            notes=[
                "Local provider creates a localhost seedbox record and file catalog.",
                "It does not require Docker, LXC, SporeStack, or payment.",
            ],
        )

    def launch(self, *, hostname: str, content_dir: Path, capacity_gb: int) -> SeedboxMetadata:
        content_dir.mkdir(parents=True, exist_ok=True)
        log_path = self.root / hostname / "local_seedbox.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            f"{_now()} local seedbox available at {content_dir}\n",
            encoding="utf-8",
        )
        metadata = _build_metadata(
            provider=self.provider_name,
            hostname=hostname,
            ip=_localhost_ip(),
            ssh_host="localhost",
            ssh_port=None,
            ssh_user=None,
            content_dir=content_dir,
            logs_path=log_path,
        )
        _persist_metadata(self.root, metadata)
        _write_catalog(self.root, metadata)
        return metadata


class RealSporeStackProvider:
    provider_name = "sporestack"

    def plan(self, *, hostname: str, content_dir: Path, capacity_gb: int) -> SeedboxLaunchPlan:
        return SeedboxLaunchPlan(
            provider=self.provider_name,
            hostname=hostname,
            content_dir=str(content_dir),
            capacity_gb=capacity_gb,
            dry_run=True,
            estimated_cost_cents=0,
            notes=[
                "Real SporeStack is intentionally disabled by default.",
                "Wire this later after token, balance, SSH key, invoice payment, and deployment checks exist.",
            ],
        )

    def launch(self, *, hostname: str, content_dir: Path, capacity_gb: int) -> SeedboxMetadata:
        raise RuntimeError("real SporeStack launch is disabled; use --provider mock or --provider local")


def provider_for(name: str, *, root: Path = DEFAULT_ROOT) -> SeedboxProvider:
    normalized = name.strip().lower()
    if normalized == "mock":
        return MockSeedboxProvider(root=root)
    if normalized == "local":
        return LocalSeedboxProvider(root=root)
    if normalized == "sporestack":
        return RealSporeStackProvider()
    raise ValueError("provider must be one of: mock, local, sporestack")


def _build_metadata(
    *,
    provider: str,
    hostname: str,
    ip: str,
    ssh_host: str | None,
    ssh_port: int | None,
    ssh_user: str | None,
    content_dir: Path,
    logs_path: Path,
) -> SeedboxMetadata:
    torrents = _torrent_metadata(content_dir)
    return SeedboxMetadata(
        provider=provider,
        machine_id=_machine_id(provider, hostname, content_dir),
        hostname=hostname,
        ip=ip,
        ssh_host=ssh_host,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        content_dir=str(content_dir),
        health_status="healthy",
        torrent_metadata=torrents,
        logs_path=str(logs_path),
        created_at=_now(),
    )


def _torrent_metadata(content_dir: Path) -> list[dict[str, str]]:
    if not content_dir.exists():
        return []
    rows = []
    for path in sorted(item for item in content_dir.rglob("*") if item.is_file()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        info_hash = digest[:40]
        rows.append(
            {
                "name": path.name,
                "sha256": digest,
                "info_hash": info_hash,
                "magnet_uri": f"magnet:?xt=urn:btih:{info_hash}&dn={path.name}",
            }
        )
    return rows


def _persist_metadata(root: Path, metadata: SeedboxMetadata) -> None:
    target = root / metadata.hostname / "seedbox_metadata.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(asdict(metadata), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_catalog(root: Path, metadata: SeedboxMetadata) -> None:
    target = root / metadata.hostname / "content_catalog.csv"
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["name", "sha256", "info_hash", "magnet_uri"])
        writer.writeheader()
        writer.writerows(metadata.torrent_metadata)


def _machine_id(provider: str, hostname: str, content_dir: Path) -> str:
    digest = hashlib.sha256(f"{provider}:{hostname}:{content_dir}".encode("utf-8")).hexdigest()[:16]
    return f"{provider}-{digest}"


def _localhost_ip() -> str:
    try:
        return socket.gethostbyname("localhost")
    except OSError:
        return "127.0.0.1"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
