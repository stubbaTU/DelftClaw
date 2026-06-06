"""I/O helpers for experiment run directories and outputs."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiments.common.validation import validate_non_empty_csv, validate_rows_schema


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamp_for_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


def make_run_id(git_commit: str) -> str:
    suffix = git_commit[:8] if git_commit and git_commit != "unavailable" else "nogit"
    return f"{timestamp_for_run_id()}-{suffix}"


def create_run_directory(out_dir: str | Path, *, git_commit: str) -> Path:
    base = Path(out_dir)
    run_dir = base / make_run_id(git_commit)
    counter = 1
    while run_dir.exists():
        run_dir = base / f"{make_run_id(git_commit)}-{counter}"
        counter += 1
    for subdir in ("raw", "tables", "figures"):
        (run_dir / subdir).mkdir(parents=True, exist_ok=False)
    return run_dir


def file_size_bytes(path: str | Path) -> int:
    file_path = Path(path)
    if not file_path.exists():
        return 0
    if not file_path.is_file():
        raise ValueError(f"not a file: {file_path}")
    return file_path.stat().st_size


def directory_total_bytes(path: str | Path) -> int:
    root = Path(path)
    if not root.exists():
        return 0
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    total = 0
    for item in root.rglob("*"):
        if item.is_file():
            total += item.stat().st_size
    return total


def write_json(path: str | Path, data: Any) -> None:
    json_path = Path(path)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def read_json(path: str | Path) -> Any:
    json_path = Path(path)
    with json_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_csv(path: str | Path) -> list[dict[str, str]]:
    csv_path = Path(path)
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: str | Path, rows: list[dict[str, object]], columns: list[str]) -> None:
    validate_rows_schema(rows, columns)
    csv_path = Path(path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    validate_non_empty_csv(csv_path)
