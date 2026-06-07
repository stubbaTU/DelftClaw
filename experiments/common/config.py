"""Configuration loading and CLI override helpers for experiment runners."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


DEFAULT_DEPTHS = [1, 2, 4, 8, 16, 32]
DEFAULT_TRIALS_PER_DEPTH = 30
SMOKE_TRIALS_PER_DEPTH = 2
DEFAULT_ADVERSARIAL_TRIALS_PER_ATTACK = 30
SMOKE_ADVERSARIAL_TRIALS_PER_ATTACK = 1
DEFAULT_STORAGE_TRIALS_PER_DEPTH = 10
SMOKE_STORAGE_TRIALS_PER_DEPTH = 1
DEFAULT_PERFORMANCE_DEPTHS = [1, 2, 4, 8, 16, 32]
DEFAULT_PERFORMANCE_BATCH_SIZES = [1, 2, 4, 8, 16, 32, 64, 128, 256]
DEFAULT_PERFORMANCE_WARMUP_ITERATIONS = 10
DEFAULT_PERFORMANCE_MEASURED_TRIALS = 100
SMOKE_PERFORMANCE_WARMUP_ITERATIONS = 1
SMOKE_PERFORMANCE_MEASURED_TRIALS = 5
DEFAULT_ADMISSION_MODES = ["disabled", "optional", "required"]
DEFAULT_ADMISSION_PEER_CASES = ["valid_proof", "invalid_proof", "missing_proof", "replayed_nonce"]
DEFAULT_ADMISSION_TRIALS_PER_CASE = 10
SMOKE_ADMISSION_TRIALS_PER_CASE = 1
DEFAULT_ADMISSION_CHALLENGE_TIMEOUT_S = 0.5
DEFAULT_ADMISSION_JOIN_TIMEOUT_S = 2.0
DEFAULT_REAL_AGENT_TRIALS_PER_CASE = 3
SMOKE_REAL_AGENT_TRIALS_PER_CASE = 1
DEFAULT_REAL_AGENT_CHALLENGE_TIMEOUT_S = 0.5
DEFAULT_REAL_AGENT_JOIN_TIMEOUT_S = 2.0
DEFAULT_OPENCLAW_LLM_TRIALS_PER_CASE = 3
SMOKE_OPENCLAW_LLM_TRIALS_PER_CASE = 1
DEFAULT_OPENCLAW_LLM_CHALLENGE_TIMEOUT_S = 0.5
DEFAULT_OPENCLAW_LLM_JOIN_TIMEOUT_S = 10.0
DEFAULT_OPENCLAW_LLM_TIMEOUT_S = 210
DEFAULT_REAL_AGENT_ATTACK_CASES = [
    "valid_agent_baseline",
    "tampered_child_certificate",
    "tampered_parent_signature",
    "wrong_trusted_root",
    "broken_merkle_proof",
    "wrong_anchor_record",
    "expired_certificate",
    "missing_required_capability",
    "revoked_child_certificate",
    "unauthorized_revocation_signer",
    "missing_lineage_proof",
    "cloned_agent_identity",
    "replayed_nonce_or_stale_proof",
    "malformed_lineage_proof_payload",
]
DEFAULT_ADVERSARIAL_ATTACK_CASES = [
    "tampered_child_agent_id",
    "tampered_child_operational_pubkey",
    "tampered_parent_signature",
    "wrong_trusted_root",
    "broken_merkle_leaf_hash",
    "broken_merkle_proof_step",
    "broken_merkle_root",
    "wrong_anchor_id",
    "anchor_root_mismatch",
    "insufficient_confirmations",
    "expired_certificate",
    "missing_capability",
    "signed_revocation",
    "unauthorized_revocation_signer",
    "malformed_revocation_event",
]


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", required=True, help="Path to a JSON experiment config.")
    parser.add_argument("--out", required=True, help="Directory where a timestamped run directory is created.")
    parser.add_argument("--seed", type=int, default=None, help="Override the config seed.")
    parser.add_argument("--smoke", action="store_true", help="Use smoke trial counts.")


def load_json_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    with config_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"config must be a JSON object: {config_path}")
    return data


def resolve_config(
    config_path: str | Path,
    *,
    seed_override: int | None = None,
    smoke: bool = False,
) -> dict[str, Any]:
    config = deepcopy(load_json_config(config_path))
    config.setdefault("schema_version", 1)
    config.setdefault("seed", 1337)
    config.setdefault("depths", list(DEFAULT_DEPTHS))
    config.setdefault("trials_per_depth", DEFAULT_TRIALS_PER_DEPTH)
    config.setdefault("smoke_trials_per_depth", SMOKE_TRIALS_PER_DEPTH)
    config.setdefault("min_confirmations", 0)
    config.setdefault("requested_capability", "tool.use")
    config.setdefault("btc_network", "mock")
    config.setdefault("anchor_backend", "mock")
    config.setdefault("adversarial_attack_cases", list(DEFAULT_ADVERSARIAL_ATTACK_CASES))
    config.setdefault("adversarial_trials_per_attack", DEFAULT_ADVERSARIAL_TRIALS_PER_ATTACK)
    config.setdefault("smoke_adversarial_trials_per_attack", SMOKE_ADVERSARIAL_TRIALS_PER_ATTACK)
    config.setdefault("storage_trials_per_depth", DEFAULT_STORAGE_TRIALS_PER_DEPTH)
    config.setdefault("smoke_storage_trials_per_depth", SMOKE_STORAGE_TRIALS_PER_DEPTH)
    config.setdefault("performance_depths", list(DEFAULT_PERFORMANCE_DEPTHS))
    config.setdefault("performance_batch_sizes", list(DEFAULT_PERFORMANCE_BATCH_SIZES))
    config.setdefault("performance_warmup_iterations", DEFAULT_PERFORMANCE_WARMUP_ITERATIONS)
    config.setdefault("performance_measured_trials", DEFAULT_PERFORMANCE_MEASURED_TRIALS)
    config.setdefault("smoke_performance_warmup_iterations", SMOKE_PERFORMANCE_WARMUP_ITERATIONS)
    config.setdefault("smoke_performance_measured_trials", SMOKE_PERFORMANCE_MEASURED_TRIALS)
    config.setdefault("admission_modes", list(DEFAULT_ADMISSION_MODES))
    config.setdefault("admission_peer_cases", list(DEFAULT_ADMISSION_PEER_CASES))
    config.setdefault("admission_trials_per_case", DEFAULT_ADMISSION_TRIALS_PER_CASE)
    config.setdefault("smoke_admission_trials_per_case", SMOKE_ADMISSION_TRIALS_PER_CASE)
    config.setdefault("admission_challenge_timeout_s", DEFAULT_ADMISSION_CHALLENGE_TIMEOUT_S)
    config.setdefault("admission_join_timeout_s", DEFAULT_ADMISSION_JOIN_TIMEOUT_S)
    config.setdefault("real_agent_lineage_modes", list(DEFAULT_ADMISSION_MODES))
    config.setdefault("real_agent_attack_cases", list(DEFAULT_REAL_AGENT_ATTACK_CASES))
    config.setdefault("real_agent_trials_per_case", DEFAULT_REAL_AGENT_TRIALS_PER_CASE)
    config.setdefault("smoke_real_agent_trials_per_case", SMOKE_REAL_AGENT_TRIALS_PER_CASE)
    config.setdefault("real_agent_challenge_timeout_s", DEFAULT_REAL_AGENT_CHALLENGE_TIMEOUT_S)
    config.setdefault("real_agent_join_timeout_s", DEFAULT_REAL_AGENT_JOIN_TIMEOUT_S)
    config.setdefault("openclaw_llm_lineage_modes", list(DEFAULT_ADMISSION_MODES))
    config.setdefault("openclaw_llm_attack_cases", list(DEFAULT_REAL_AGENT_ATTACK_CASES))
    config.setdefault("openclaw_llm_trials_per_case", DEFAULT_OPENCLAW_LLM_TRIALS_PER_CASE)
    config.setdefault(
        "smoke_openclaw_llm_trials_per_case",
        SMOKE_OPENCLAW_LLM_TRIALS_PER_CASE,
    )
    config.setdefault(
        "openclaw_llm_challenge_timeout_s",
        DEFAULT_OPENCLAW_LLM_CHALLENGE_TIMEOUT_S,
    )
    config.setdefault(
        "openclaw_llm_join_timeout_s",
        DEFAULT_OPENCLAW_LLM_JOIN_TIMEOUT_S,
    )
    config.setdefault("openclaw_llm_provider", "openrouter")
    config.setdefault("openclaw_llm_model", "openrouter/owl-alpha")
    config.setdefault("openclaw_llm_base_url", "https://openrouter.ai/api/v1")
    config.setdefault("openclaw_llm_api", "openai-completions")
    config.setdefault("openclaw_llm_api_key_env", "OPENROUTER_API_KEY")
    config.setdefault("openclaw_llm_temperature", 0.0)
    config.setdefault("openclaw_llm_max_tokens", 1024)
    config.setdefault("openclaw_llm_timeout_s", DEFAULT_OPENCLAW_LLM_TIMEOUT_S)
    config.setdefault("allow_exploratory_failures", False)

    if seed_override is not None:
        config["seed"] = seed_override
    config["smoke"] = bool(smoke)
    if smoke:
        config["trials_per_depth"] = int(config.get("smoke_trials_per_depth", SMOKE_TRIALS_PER_DEPTH))
        config["adversarial_trials_per_attack"] = int(
            config.get("smoke_adversarial_trials_per_attack", SMOKE_ADVERSARIAL_TRIALS_PER_ATTACK)
        )
        config["storage_trials_per_depth"] = int(
            config.get("smoke_storage_trials_per_depth", SMOKE_STORAGE_TRIALS_PER_DEPTH)
        )
        config["performance_warmup_iterations"] = int(
            config.get("smoke_performance_warmup_iterations", SMOKE_PERFORMANCE_WARMUP_ITERATIONS)
        )
        config["performance_measured_trials"] = int(
            config.get("smoke_performance_measured_trials", SMOKE_PERFORMANCE_MEASURED_TRIALS)
        )
        config["admission_trials_per_case"] = int(
            config.get("smoke_admission_trials_per_case", SMOKE_ADMISSION_TRIALS_PER_CASE)
        )
        config["real_agent_trials_per_case"] = int(
            config.get("smoke_real_agent_trials_per_case", SMOKE_REAL_AGENT_TRIALS_PER_CASE)
        )
        config["openclaw_llm_trials_per_case"] = int(
            config.get(
                "smoke_openclaw_llm_trials_per_case",
                SMOKE_OPENCLAW_LLM_TRIALS_PER_CASE,
            )
        )

    config["seed"] = int(config["seed"])
    config["depths"] = [int(depth) for depth in config["depths"]]
    config["performance_depths"] = [int(depth) for depth in config["performance_depths"]]
    config["performance_batch_sizes"] = [int(size) for size in config["performance_batch_sizes"]]
    config["trials_per_depth"] = int(config["trials_per_depth"])
    config["smoke_trials_per_depth"] = int(config["smoke_trials_per_depth"])
    config["min_confirmations"] = int(config["min_confirmations"])
    config["adversarial_attack_cases"] = [str(case) for case in config["adversarial_attack_cases"]]
    config["adversarial_trials_per_attack"] = int(config["adversarial_trials_per_attack"])
    config["smoke_adversarial_trials_per_attack"] = int(config["smoke_adversarial_trials_per_attack"])
    config["storage_trials_per_depth"] = int(config["storage_trials_per_depth"])
    config["smoke_storage_trials_per_depth"] = int(config["smoke_storage_trials_per_depth"])
    config["performance_warmup_iterations"] = int(config["performance_warmup_iterations"])
    config["performance_measured_trials"] = int(config["performance_measured_trials"])
    config["smoke_performance_warmup_iterations"] = int(config["smoke_performance_warmup_iterations"])
    config["smoke_performance_measured_trials"] = int(config["smoke_performance_measured_trials"])
    config["admission_modes"] = [str(mode) for mode in config["admission_modes"]]
    config["admission_peer_cases"] = [str(case) for case in config["admission_peer_cases"]]
    config["admission_trials_per_case"] = int(config["admission_trials_per_case"])
    config["smoke_admission_trials_per_case"] = int(config["smoke_admission_trials_per_case"])
    config["admission_challenge_timeout_s"] = float(config["admission_challenge_timeout_s"])
    config["admission_join_timeout_s"] = float(config["admission_join_timeout_s"])
    config["real_agent_lineage_modes"] = [str(mode) for mode in config["real_agent_lineage_modes"]]
    config["real_agent_attack_cases"] = [str(case) for case in config["real_agent_attack_cases"]]
    config["real_agent_trials_per_case"] = int(config["real_agent_trials_per_case"])
    config["smoke_real_agent_trials_per_case"] = int(config["smoke_real_agent_trials_per_case"])
    config["real_agent_challenge_timeout_s"] = float(config["real_agent_challenge_timeout_s"])
    config["real_agent_join_timeout_s"] = float(config["real_agent_join_timeout_s"])
    config["openclaw_llm_lineage_modes"] = [
        str(mode) for mode in config["openclaw_llm_lineage_modes"]
    ]
    config["openclaw_llm_attack_cases"] = [
        str(case) for case in config["openclaw_llm_attack_cases"]
    ]
    config["openclaw_llm_trials_per_case"] = int(
        config["openclaw_llm_trials_per_case"]
    )
    config["smoke_openclaw_llm_trials_per_case"] = int(
        config["smoke_openclaw_llm_trials_per_case"]
    )
    config["openclaw_llm_challenge_timeout_s"] = float(
        config["openclaw_llm_challenge_timeout_s"]
    )
    config["openclaw_llm_join_timeout_s"] = float(
        config["openclaw_llm_join_timeout_s"]
    )
    config["openclaw_llm_provider"] = str(config["openclaw_llm_provider"])
    config["openclaw_llm_model"] = str(config["openclaw_llm_model"])
    config["openclaw_llm_base_url"] = str(config["openclaw_llm_base_url"])
    config["openclaw_llm_api"] = str(config["openclaw_llm_api"])
    config["openclaw_llm_api_key_env"] = str(config["openclaw_llm_api_key_env"])
    config["openclaw_llm_temperature"] = float(config["openclaw_llm_temperature"])
    config["openclaw_llm_max_tokens"] = int(config["openclaw_llm_max_tokens"])
    config["openclaw_llm_timeout_s"] = int(config["openclaw_llm_timeout_s"])
    config["allow_exploratory_failures"] = bool(config["allow_exploratory_failures"])

    if config["btc_network"] != "mock" or config["anchor_backend"] != "mock":
        raise ValueError("experiment runners support only mock anchoring")
    if not config["depths"]:
        raise ValueError("config depths must not be empty")
    if not config["performance_depths"]:
        raise ValueError("config performance_depths must not be empty")
    if not config["performance_batch_sizes"]:
        raise ValueError("config performance_batch_sizes must not be empty")
    if not config["adversarial_attack_cases"]:
        raise ValueError("config adversarial_attack_cases must not be empty")
    if not config["admission_modes"]:
        raise ValueError("config admission_modes must not be empty")
    if not config["admission_peer_cases"]:
        raise ValueError("config admission_peer_cases must not be empty")
    unknown_modes = set(config["admission_modes"]) - set(DEFAULT_ADMISSION_MODES)
    if unknown_modes:
        raise ValueError(f"unknown admission modes: {sorted(unknown_modes)}")
    unknown_peer_cases = set(config["admission_peer_cases"]) - set(DEFAULT_ADMISSION_PEER_CASES)
    if unknown_peer_cases:
        raise ValueError(f"unknown admission peer cases: {sorted(unknown_peer_cases)}")
    unknown_real_agent_modes = set(config["real_agent_lineage_modes"]) - set(DEFAULT_ADMISSION_MODES)
    if unknown_real_agent_modes:
        raise ValueError(f"unknown real-agent lineage modes: {sorted(unknown_real_agent_modes)}")
    unknown_real_agent_cases = set(config["real_agent_attack_cases"]) - set(DEFAULT_REAL_AGENT_ATTACK_CASES)
    if unknown_real_agent_cases:
        raise ValueError(f"unknown real-agent attack cases: {sorted(unknown_real_agent_cases)}")
    unknown_openclaw_llm_modes = (
        set(config["openclaw_llm_lineage_modes"]) - set(DEFAULT_ADMISSION_MODES)
    )
    if unknown_openclaw_llm_modes:
        raise ValueError(
            f"unknown OpenClaw LLM lineage modes: {sorted(unknown_openclaw_llm_modes)}"
        )
    unknown_openclaw_llm_cases = (
        set(config["openclaw_llm_attack_cases"]) - set(DEFAULT_REAL_AGENT_ATTACK_CASES)
    )
    if unknown_openclaw_llm_cases:
        raise ValueError(
            f"unknown OpenClaw LLM attack cases: {sorted(unknown_openclaw_llm_cases)}"
        )
    if any(depth < 1 for depth in config["depths"]):
        raise ValueError("lineage depths must be positive")
    if any(depth < 1 for depth in config["performance_depths"]):
        raise ValueError("performance_depths must be positive")
    if any(size < 1 for size in config["performance_batch_sizes"]):
        raise ValueError("performance_batch_sizes must be positive")
    if config["trials_per_depth"] < 1:
        raise ValueError("trials_per_depth must be positive")
    if config["adversarial_trials_per_attack"] < 1:
        raise ValueError("adversarial_trials_per_attack must be positive")
    if config["storage_trials_per_depth"] < 1:
        raise ValueError("storage_trials_per_depth must be positive")
    if config["performance_warmup_iterations"] < 0:
        raise ValueError("performance_warmup_iterations must not be negative")
    if config["performance_measured_trials"] < 1:
        raise ValueError("performance_measured_trials must be positive")
    if config["admission_trials_per_case"] < 1:
        raise ValueError("admission_trials_per_case must be positive")
    if config["admission_challenge_timeout_s"] <= 0:
        raise ValueError("admission_challenge_timeout_s must be positive")
    if config["admission_join_timeout_s"] <= 0:
        raise ValueError("admission_join_timeout_s must be positive")
    if config["real_agent_trials_per_case"] < 1:
        raise ValueError("real_agent_trials_per_case must be positive")
    if config["real_agent_challenge_timeout_s"] <= 0:
        raise ValueError("real_agent_challenge_timeout_s must be positive")
    if config["real_agent_join_timeout_s"] <= 0:
        raise ValueError("real_agent_join_timeout_s must be positive")
    if config["openclaw_llm_trials_per_case"] < 1:
        raise ValueError("openclaw_llm_trials_per_case must be positive")
    if config["openclaw_llm_challenge_timeout_s"] <= 0:
        raise ValueError("openclaw_llm_challenge_timeout_s must be positive")
    if config["openclaw_llm_join_timeout_s"] <= 0:
        raise ValueError("openclaw_llm_join_timeout_s must be positive")
    if config["openclaw_llm_timeout_s"] < 30:
        raise ValueError("openclaw_llm_timeout_s must be at least 30 seconds")
    if config["openclaw_llm_max_tokens"] < 1:
        raise ValueError("openclaw_llm_max_tokens must be positive")
    if not config["openclaw_llm_api_key_env"]:
        raise ValueError("openclaw_llm_api_key_env must not be empty")
    if not config["openclaw_llm_provider"]:
        raise ValueError("openclaw_llm_provider must not be empty")
    if not config["openclaw_llm_model"]:
        raise ValueError("openclaw_llm_model must not be empty")
    return config
