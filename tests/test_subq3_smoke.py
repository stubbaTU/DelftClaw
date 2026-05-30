from __future__ import annotations

import csv
from pathlib import Path

from security.subq3_containment import CONDITION_C0, CONDITION_C1
from security.subq3_containment.attack_schema import write_attacks
from security.subq3_containment.generate_attack_suite import generate_default_attacks
from security.subq3_containment.run_containment_tests import run_containment_tests


def test_full_smoke_run_exports_required_files(tmp_path: Path) -> None:
    attacks = [
        attack
        for attack in generate_default_attacks()
        if attack.attack_id in {"A1_wallet_read_002", "A6_proxy_identity_key_001"}
    ]
    attack_path = tmp_path / "attacks.jsonl"
    out_dir = tmp_path / "out"
    write_attacks(attacks, attack_path)

    summary = run_containment_tests(
        attacks_path=attack_path,
        conditions=[CONDITION_C0, CONDITION_C1],
        out_dir=out_dir,
        timeout=5,
        use_gvisor="false",
        use_iptables="false",
        keep_artifacts=False,
    )

    assert summary["trial_count"] == 4
    for name in [
        "sq3_run_metadata.json",
        "sq3_summary.json",
        "sq3_trials.csv",
        "sq3_trials.jsonl",
        "sq3_results_by_condition.csv",
        "sq3_results_by_family.csv",
        "sq3_results_by_asset.csv",
        "sq3_proxy_results.csv",
        "sq3_network_results.csv",
        "sq3_log_integrity.csv",
        "sq3_resource_integrity.csv",
        "run.log",
    ]:
        assert (out_dir / name).exists(), name

    rows = list(csv.DictReader((out_dir / "sq3_trials.csv").open(newline="", encoding="utf-8")))
    assert any(row["condition"] == CONDITION_C0 for row in rows)
    assert any(row["condition"] == CONDITION_C1 for row in rows)

