import json
from pathlib import Path

from security.contracts import RedTeamPayload


DATASET_DIR = Path(__file__).resolve().parent


def load_payloads(path: str | Path) -> list[RedTeamPayload]:
    payloads = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            payloads.append(
                RedTeamPayload(
                    payload_id=item["payload_id"],
                    category=item["category"],
                    text=item["text"],
                    expected_tool=item["expected_tool"],
                    malicious=item.get("malicious", True),
                )
            )
    return payloads


def load_malicious_torrent_payloads() -> list[RedTeamPayload]:
    return load_payloads(DATASET_DIR / "malicious_torrent_payloads.jsonl")


def load_benign_torrent_payloads() -> list[RedTeamPayload]:
    return load_payloads(DATASET_DIR / "benign_torrent_payloads.jsonl")
