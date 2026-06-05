"""JSON/JSONL persistence helpers for lineage data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from identity.lineage.models import AnchorRecord, CertificateBatch, ChildCertificateV1, JsonDict, to_json_dict


def write_json(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = to_json_dict(value) if not isinstance(value, (dict, list)) else value
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: str | Path) -> JsonDict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def append_jsonl(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = to_json_dict(value) if not isinstance(value, dict) else value
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, sort_keys=True) + "\n")


def read_jsonl(path: str | Path) -> list[JsonDict]:
    source = Path(path)
    if not source.exists():
        return []
    rows: list[JsonDict] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


class LineageStore:
    """Small file layout helper rooted at ``<save_dir>/lineage``."""

    def __init__(self, save_dir: str | Path) -> None:
        self.root = Path(save_dir) / "lineage"
        self.batches_dir = self.root / "batches"

    @property
    def birth_package_path(self) -> Path:
        return self.root / "birth_package.json"

    @property
    def certificates_path(self) -> Path:
        return self.root / "certificates.jsonl"

    @property
    def anchors_path(self) -> Path:
        return self.root / "anchors.jsonl"

    @property
    def revocations_path(self) -> Path:
        return self.root / "revocations.jsonl"

    @property
    def cache_path(self) -> Path:
        return self.root / "cache.json"

    def save_birth_package(self, package: JsonDict) -> None:
        write_json(self.birth_package_path, package)

    def append_certificate(self, certificate: ChildCertificateV1) -> None:
        append_jsonl(self.certificates_path, certificate)

    def append_anchor(self, anchor: AnchorRecord) -> None:
        append_jsonl(self.anchors_path, anchor)

    def append_revocation(self, event: JsonDict) -> None:
        append_jsonl(self.revocations_path, event)

    def save_batch(self, batch: CertificateBatch) -> Path:
        path = self.batches_dir / f"{batch.batch_id}.json"
        write_json(path, batch)
        return path

    def load_batch(self, batch_id: str) -> CertificateBatch:
        return CertificateBatch.from_dict(read_json(self.batches_dir / f"{batch_id}.json"))
