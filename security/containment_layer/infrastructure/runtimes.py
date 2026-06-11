from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Runtime:
    name: str
    docker_runtime_flag: str
    notes: str
    gvisor_platform: str = ""

    @property
    def uses_gvisor(self) -> bool:
        return self.name == "runsc"

    def docker_args(self) -> list[str]:
        if not self.docker_runtime_flag:
            return []
        return [f"--runtime={self.docker_runtime_flag}"]


RUNTIMES = {
    "runc": Runtime(
        name="runc",
        docker_runtime_flag="",
        notes="Docker's standard OCI runtime.",
    ),
    "runsc": Runtime(
        name="runsc",
        docker_runtime_flag="runsc",
        notes="gVisor userspace-kernel runtime.",
        gvisor_platform="systrap",
    ),
}


def get_runtime(name: str) -> Runtime:
    try:
        return RUNTIMES[name]
    except KeyError as exc:
        raise ValueError(f"unsupported SQ3 runtime: {name}") from exc

