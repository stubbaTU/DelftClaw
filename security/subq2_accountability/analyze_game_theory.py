from __future__ import annotations

import argparse

from security.results import write_csv, write_json
from security.subq2_accountability.game_theory import AttackPayoffModel, sweep_reputation_policies


def parse_ints(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Sweep reputation thresholds for fake-seedbox deterrence.")
    parser.add_argument("--thresholds", default="10,20,30,40,50")
    parser.add_argument("--scan-intervals", default="1,2,5")
    parser.add_argument("--malicious-action-weight", type=int, default=25)
    parser.add_argument("--donation-gain", type=float, default=1.0)
    parser.add_argument("--honest-round-value", type=float, default=0.25)
    parser.add_argument("--detection-probability", type=float, default=1.0)
    parser.add_argument("--discount-factor", type=float, default=0.95)
    parser.add_argument("--expulsion-penalty-rounds", type=int, default=20)
    parser.add_argument("--output-dir", default="results/game_theory")
    args = parser.parse_args()

    model = AttackPayoffModel(
        donation_gain=args.donation_gain,
        honest_round_value=args.honest_round_value,
        detection_probability=args.detection_probability,
        discount_factor=args.discount_factor,
        expulsion_penalty_rounds=args.expulsion_penalty_rounds,
    )
    rows = sweep_reputation_policies(
        thresholds=parse_ints(args.thresholds),
        scan_intervals=parse_ints(args.scan_intervals),
        malicious_action_weight=args.malicious_action_weight,
        payoff_model=model,
    )
    write_csv(f"{args.output_dir}/reputation_policy_sweep.csv", rows)
    write_json(f"{args.output_dir}/reputation_policy_sweep.json", {"model": model, "rows": rows})
    for row in rows:
        print(row)


if __name__ == "__main__":
    main()
