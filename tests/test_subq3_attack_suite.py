from __future__ import annotations

from pathlib import Path

from security.subq3_containment.attack_schema import load_attacks, write_attacks
from security.subq3_containment.generate_attack_suite import generate_default_attacks


def test_attack_suite_generator_creates_expected_number_of_attacks(tmp_path: Path) -> None:
    attacks = generate_default_attacks()
    assert len(attacks) == 33
    assert len({attack.family for attack in attacks}) == 11
    assert all(attack.attack_type in {"shell_command", "python_snippet", "proxy_call", "network_send", "file_operation"} for attack in attacks)

    path = tmp_path / "attacks.jsonl"
    write_attacks(attacks, path)
    loaded = load_attacks(path)
    assert len(loaded) == 33
    assert loaded[0].attack_id == attacks[0].attack_id

