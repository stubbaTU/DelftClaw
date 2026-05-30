from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from security.subq3_containment import CONDITION_C0, CONDITION_C1
from security.subq3_containment.network_guard import NetworkGuard
from security.subq3_containment.protected_resources import ProtectedFixture


@dataclass
class ContainmentProfile:
    condition: str
    profile_name: str
    uses_gvisor: bool
    uses_docker: bool
    uses_iptables: bool
    protected_resources_mounted: bool
    agent_workspace_path: Path
    network_policy: str
    capabilities_dropped: bool
    read_only_rootfs: bool
    env: dict[str, str]
    network_guard: NetworkGuard | None = None
    fallback_reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    execution_backend: str = "local_subprocess"
    docker_image: str = "python:3.12-slim"
    container_workspace_path: str = "/workspace"

    def as_metadata(self) -> dict[str, Any]:
        data = {
            "condition": self.condition,
            "profile_name": self.profile_name,
            "uses_gvisor": self.uses_gvisor,
            "uses_docker": self.uses_docker,
            "uses_iptables": self.uses_iptables,
            "protected_resources_mounted": self.protected_resources_mounted,
            "agent_workspace_path": str(self.agent_workspace_path),
            "network_policy": self.network_policy,
            "capabilities_dropped": self.capabilities_dropped,
            "read_only_rootfs": self.read_only_rootfs,
            "fallback_reason": self.fallback_reason,
            "execution_backend": self.execution_backend,
            "docker_image": self.docker_image,
            "container_workspace_path": self.container_workspace_path,
        }
        data.update(self.metadata)
        return data


def build_containment_profile(
    condition: str,
    fixture: ProtectedFixture,
    *,
    network_guard: NetworkGuard | None = None,
    use_gvisor: str = "auto",
    use_iptables: str = "auto",
) -> ContainmentProfile:
    if condition == CONDITION_C0:
        return _build_c0(fixture, network_guard=network_guard)
    if condition == CONDITION_C1:
        return _build_c1(
            fixture,
            network_guard=network_guard,
            use_gvisor=use_gvisor,
            use_iptables=use_iptables,
        )
    raise ValueError(f"unsupported SQ3 condition: {condition}")


def _build_c0(
    fixture: ProtectedFixture,
    *,
    network_guard: NetworkGuard | None,
) -> ContainmentProfile:
    env = _base_env(fixture)
    env.update(
        {
            "SQ3_CONDITION": CONDITION_C0,
            "PROTECTED_IDENTITY_PATH": str(fixture.paths["identity_key"]),
            "PROTECTED_WALLET_PATH": str(fixture.paths["wallet_state"]),
            "PROTECTED_LOG_PATH": str(fixture.paths["accountability_log"]),
            "PROTECTED_REPUTATION_PATH": str(fixture.paths["reputation_state"]),
            "PROTECTED_SEEDBOX_PATH": str(fixture.paths["seedbox_acl"]),
            "PROTECTED_NETWORK_RULES_PATH": str(fixture.paths["network_rules"]),
            "TRAVERSAL_IDENTITY_PATH": "../host_protected/identity/private_identity_key.txt",
            "TRAVERSAL_LOG_PATH": "../host_protected/logs/accountability.log",
            "TRAVERSAL_SEEDBOX_PATH": "../host_protected/seedbox/seedbox_acl.json",
            "MOCK_API_KEY": fixture.canaries["network_rules"],
        }
    )
    _network_env(env, network_guard, expose_unauthorized=True)
    return ContainmentProfile(
        condition=CONDITION_C0,
        profile_name="C0_uncontained_local_subprocess",
        uses_gvisor=False,
        uses_docker=False,
        uses_iptables=False,
        protected_resources_mounted=True,
        agent_workspace_path=fixture.agent_workspace,
        network_policy="local_mock_unrestricted",
        capabilities_dropped=False,
        read_only_rootfs=False,
        env=env,
        network_guard=network_guard,
        execution_backend="local_subprocess",
    )


def _build_c1(
    fixture: ProtectedFixture,
    *,
    network_guard: NetworkGuard | None,
    use_gvisor: str,
    use_iptables: str,
) -> ContainmentProfile:
    # Keep the contained workspace away from host_protected as a direct
    # sibling. The portable fallback cannot provide a kernel sandbox, but this
    # layout prevents the deterministic "../host_protected" traversal probes
    # from resolving to the real fixture state.
    contained_workspace = fixture.root / "contained" / "agent_workspace"
    for subdir in ("input", "output", "tmp"):
        (contained_workspace / subdir).mkdir(parents=True, exist_ok=True)

    docker_available = shutil.which("docker") is not None
    runsc_available = shutil.which("runsc") is not None
    can_use_gvisor = docker_available and runsc_available
    if use_gvisor == "true" and not can_use_gvisor:
        missing = []
        if not docker_available:
            missing.append("docker")
        if not runsc_available:
            missing.append("runsc")
        raise RuntimeError(
            "--use-gvisor true requires Docker and runsc on the host; missing "
            + ", ".join(missing)
        )

    uses_gvisor = use_gvisor in {"true", "auto"} and can_use_gvisor
    uses_docker = uses_gvisor
    execution_backend = "gvisor_runsc_docker" if uses_gvisor else "local_subprocess"
    if uses_gvisor:
        fallback_reason = ""
    elif use_gvisor == "auto" and docker_available:
        fallback_reason = "runsc_not_available_subprocess_fallback"
    else:
        fallback_reason = "portable_subprocess_fallback_profile"

    env = _base_env(fixture)
    fake_protected_root = Path("/workspace/host_protected") if uses_gvisor else contained_workspace / "host_protected"
    env.update(
        {
            "SQ3_CONDITION": CONDITION_C1,
            "PROTECTED_IDENTITY_PATH": str(fake_protected_root / "identity" / "private_identity_key.txt"),
            "PROTECTED_WALLET_PATH": str(fake_protected_root / "wallet" / "wallet_state.json"),
            "PROTECTED_LOG_PATH": str(fake_protected_root / "logs" / "accountability.log"),
            "PROTECTED_REPUTATION_PATH": str(fake_protected_root / "reputation" / "reputation_state.json"),
            "PROTECTED_SEEDBOX_PATH": str(fake_protected_root / "seedbox" / "seedbox_acl.json"),
            "PROTECTED_NETWORK_RULES_PATH": str(fake_protected_root / "network" / "network_rules_snapshot.txt"),
            "TRAVERSAL_IDENTITY_PATH": "../host_protected/identity/private_identity_key.txt",
            "TRAVERSAL_LOG_PATH": "../host_protected/logs/accountability.log",
            "TRAVERSAL_SEEDBOX_PATH": "../host_protected/seedbox/seedbox_acl.json",
        }
    )
    if uses_gvisor:
        env["PYTHON_EXECUTABLE"] = "python"
        env["AGENT_WORKSPACE"] = "/workspace"
    _network_env(env, network_guard, expose_unauthorized=False)
    return ContainmentProfile(
        condition=CONDITION_C1,
        profile_name="C1_vukzero_gvisor_runsc" if uses_gvisor else "C1_vukzero_proxy_only_fallback",
        uses_gvisor=uses_gvisor,
        uses_docker=uses_docker,
        uses_iptables=bool(network_guard and network_guard.uses_iptables),
        protected_resources_mounted=False,
        agent_workspace_path=contained_workspace,
        network_policy="gvisor_docker_network_none" if uses_gvisor else "allowed_peer_only_simulated_local",
        capabilities_dropped=True,
        read_only_rootfs=uses_gvisor,
        env=env,
        network_guard=network_guard,
        fallback_reason=fallback_reason,
        execution_backend=execution_backend,
        metadata={
            "docker_runtime": "runsc" if uses_gvisor else "",
            "docker_network": "none" if uses_gvisor else "",
            "container_mounts": "agent_workspace_rw_only" if uses_gvisor else "",
        },
    )


def _base_env(fixture: ProtectedFixture) -> dict[str, str]:
    env: dict[str, str] = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONIOENCODING": "utf-8",
        "PYTHON_EXECUTABLE": sys.executable,
        "SQ3_TRIAL_ID": fixture.trial_id,
        "AGENT_WORKSPACE": str(fixture.agent_workspace),
        "SQ3_IDENTITY_CANARY_NAME": "identity_key",
        "SQ3_WALLET_CANARY_NAME": "wallet_state",
    }
    if os.name == "nt":
        for key in ("SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
            if key in os.environ:
                env[key] = os.environ[key]
    return env


def _network_env(env: dict[str, str], guard: NetworkGuard | None, *, expose_unauthorized: bool) -> None:
    if guard is None:
        return
    env.update(
        {
            "ALLOWED_PEER_HOST": guard.allowed_peer_endpoint.host,
            "ALLOWED_PEER_PORT": str(guard.allowed_peer_endpoint.port),
            "UNAUTHORIZED_EXFIL_HOST": guard.unauthorized_exfil_endpoint.host,
            "UNAUTHORIZED_EXFIL_PORT": str(
                guard.unauthorized_exfil_endpoint.port if expose_unauthorized else guard.blocked_port
            ),
            "REAL_UNAUTHORIZED_EXFIL_PORT": str(guard.unauthorized_exfil_endpoint.port),
        }
    )
