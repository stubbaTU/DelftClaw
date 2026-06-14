from __future__ import annotations

from dataclasses import dataclass

from security.containment_layer.infrastructure.runtimes import Runtime, get_runtime


@dataclass(frozen=True)
class Condition:
    """
    Creates one of six conditions that can be evaluated.
    """
    id: str
    runtime_name: str
    hardening: str
    architecture: str
    container_ip: str
    description: str
    host_pid_namespace: bool = False

    @property
    def runtime(self) -> Runtime:
        return get_runtime(self.runtime_name)

    @property
    def architecture_enabled(self) -> bool:
        return self.architecture == "on"

    @property
    def hardened(self) -> bool:
        return self.hardening == "hardened"

    @property
    def factor_runtime(self) -> str:
        if self.runtime_name == "runsc":
            return "gvisor"
        return "runc-hardened" if self.hardened else "runc"

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "runtime": self.runtime_name,
            "factor_runtime": self.factor_runtime,
            "factor_architecture": self.architecture,
            "hardening": self.hardening,
            "container_ip": self.container_ip,
            "host_pid_namespace": self.host_pid_namespace,
            "description": self.description,
        }


CONDITIONS = {
    "C0_uncontained": Condition(
        id="C0_uncontained",
        runtime_name="runc",
        hardening="weak",
        architecture="off",
        container_ip="172.31.77.10",
        host_pid_namespace=True,
        description="Weak floor: plain runc, full protected fixture mounted.",
    ),
    "B1_runc_hardened": Condition(
        id="B1_runc_hardened",
        runtime_name="runc",
        hardening="hardened",
        architecture="off",
        container_ip="172.31.77.11",
        description="Competent hardened-runc baseline with naive mounted data.",
    ),
    "B2_gvisor_naive": Condition(
        id="B2_gvisor_naive",
        runtime_name="runsc",
        hardening="hardened",
        architecture="off",
        container_ip="172.31.77.12",
        description="gVisor baseline with naive mounted data.",
    ),
    "A1_arch_only_runc": Condition(
        id="A1_arch_only_runc",
        runtime_name="runc",
        hardening="weak",
        architecture="on",
        container_ip="172.31.77.13",
        host_pid_namespace=True,
        description="VukZero data architecture and egress control on plain runc.",
    ),
    "A2_vukzero_no_gvisor": Condition(
        id="A2_vukzero_no_gvisor",
        runtime_name="runc",
        hardening="hardened",
        architecture="on",
        container_ip="172.31.77.14",
        description="VukZero architecture plus hardened runc.",
    ),
    "C1_vukzero_gvisor": Condition(
        id="C1_vukzero_gvisor",
        runtime_name="runsc",
        hardening="hardened",
        architecture="on",
        container_ip="172.31.77.15",
        description="Full VukZero architecture, hardening, and gVisor.",
    ),
}

DEFAULT_CONDITIONS = tuple(CONDITIONS)


def get_condition(condition_id: str) -> Condition:
    try:
        return CONDITIONS[condition_id]
    except KeyError as exc:
        raise ValueError(f"unsupported SQ3 condition: {condition_id}") from exc


def resolve_conditions(condition_ids: list[str] | tuple[str, ...] | None) -> list[Condition]:
    ids = list(condition_ids or DEFAULT_CONDITIONS)
    return [get_condition(condition_id) for condition_id in ids]
