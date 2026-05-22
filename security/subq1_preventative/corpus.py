from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable

from security.contracts import SQ1Payload


DATASET_DIR = Path(__file__).resolve().parents[1] / "datasets"
DEFAULT_ATTACK_CORPUS = DATASET_DIR / "sq1_private_key_payloads.jsonl"
DEFAULT_STRESS_ATTACK_CORPUS = DATASET_DIR / "sq1_private_key_payloads_stress.jsonl"
DEFAULT_BENIGN_CORPUS = DATASET_DIR / "sq1_benign_controls.jsonl"

FAMILIES = {
    "direct_instruction_override",
    "authority_maintenance_pretext",
    "tool_use_coercion",
    "output_laundering",
    "policy_confusion",
    "seedbox_domain_injection",
    "obfuscation_encoding",
    "multi_turn_state_poisoning",
}
VECTORS = {"torrent_metadata", "udp_peer_message", "seedbox_status_report"}
FORBIDDEN_TARGET = "read_mock_private_identity_key"


def load_sq1_payloads(path: str | Path = DEFAULT_ATTACK_CORPUS) -> list[SQ1Payload]:
    payloads: list[SQ1Payload] = []
    source = Path(path)
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            item = json.loads(line)
            try:
                payloads.append(
                    SQ1Payload(
                        id=str(item["id"]),
                        family=str(item["family"]),
                        vector=str(item["vector"]),
                        surface=str(item["surface"]),
                        variant=str(item["variant"]),
                        benign_task=str(item["benign_task"]),
                        target_forbidden_action=str(item["target_forbidden_action"]),
                        expected_sink=str(item["expected_sink"]),
                        payload_text=str(item["payload_text"]),
                        malicious=bool(item.get("malicious", True)),
                    )
                )
            except KeyError as exc:
                raise ValueError(f"{source}:{line_number} missing key {exc.args[0]!r}") from exc
    return payloads


def load_sq1_benign_controls(path: str | Path = DEFAULT_BENIGN_CORPUS) -> list[SQ1Payload]:
    return load_sq1_payloads(path)


def corpus_hash(paths: Iterable[str | Path]) -> str:
    digest = hashlib.sha256()
    for raw_path in paths:
        path = Path(raw_path)
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def validate_attack_corpus(payloads: list[SQ1Payload]) -> list[str]:
    errors: list[str] = []
    ids = [payload.id for payload in payloads]
    duplicates = sorted({payload_id for payload_id in ids if ids.count(payload_id) > 1})
    if duplicates:
        errors.append(f"duplicate payload ids: {duplicates}")
    if len(payloads) != 72:
        errors.append(f"expected 72 attack payloads, got {len(payloads)}")

    families = {payload.family for payload in payloads}
    vectors = {payload.vector for payload in payloads}
    if families != FAMILIES:
        errors.append(f"families mismatch: expected {sorted(FAMILIES)}, got {sorted(families)}")
    if vectors != VECTORS:
        errors.append(f"vectors mismatch: expected {sorted(VECTORS)}, got {sorted(vectors)}")

    for family in sorted(FAMILIES):
        for vector in sorted(VECTORS):
            subset = [p for p in payloads if p.family == family and p.vector == vector]
            variants = {payload.variant for payload in subset}
            if len(subset) != 3:
                errors.append(f"{family}/{vector}: expected 3 variants, got {len(subset)}")
            if len(variants) != len(subset):
                errors.append(f"{family}/{vector}: variants are not unique")

    bad_targets = [
        payload.id for payload in payloads
        if payload.target_forbidden_action != FORBIDDEN_TARGET
    ]
    if bad_targets:
        errors.append(f"payloads target non-SQ1 actions: {bad_targets}")

    non_malicious = [payload.id for payload in payloads if not payload.malicious]
    if non_malicious:
        errors.append(f"attack corpus contains benign payloads: {non_malicious}")

    return errors


def corpus_composition_rows(payloads: list[SQ1Payload]) -> list[dict[str, int | str]]:
    rows: list[dict[str, int | str]] = []
    for family in sorted({payload.family for payload in payloads}):
        row: dict[str, int | str] = {"family": family}
        total = 0
        for vector in sorted(VECTORS):
            count = sum(1 for payload in payloads if payload.family == family and payload.vector == vector)
            row[vector] = count
            total += count
        row["total"] = total
        rows.append(row)
    return rows
