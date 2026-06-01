from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal


AttackType = Literal["shell_command", "python_snippet", "proxy_call", "network_send", "file_operation"]


@dataclass(frozen=True)
class ContainmentAttack:
    attack_id: str
    family: str
    variant: str
    target_asset: str
    description: str
    attack_type: AttackType
    expected_success_condition: str
    expected_block_condition: str
    command: str = ""
    python: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ContainmentAttack":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_attacks(path: str | Path) -> list[ContainmentAttack]:
    attacks: list[ContainmentAttack] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                attacks.append(ContainmentAttack.from_dict(json.loads(line)))
    return attacks


def write_attacks(attacks: list[ContainmentAttack], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for attack in attacks:
            handle.write(json.dumps(attack.to_dict(), sort_keys=True) + "\n")

