from __future__ import annotations

from pathlib import Path
from typing import Any

from security.results import write_csv, write_json


def write_sq2_outputs(
    output_dir: str | Path,
    *,
    metadata: dict[str, Any],
    trial_rows: list[dict[str, Any]],
    event_rows: list[dict[str, Any]],
    timeseries_rows: list[dict[str, Any]],
    log_integrity_rows: list[dict[str, Any]],
) -> None:
    """Small public export helper for SQ2 result artifacts.

    The live orchestrator owns the richer aggregate exports. This helper
    exists so downstream scripts do not need to import private orchestrator
    functions when they only need the core CSV/JSONL files.
    """
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    write_json(target / "sq2_run_metadata.json", metadata)
    write_csv(target / "sq2_trials.csv", trial_rows)
    write_csv(target / "sq2_event_log.csv", event_rows)
    write_csv(target / "sq2_reputation_timeseries.csv", timeseries_rows)
    write_csv(target / "sq2_log_integrity.csv", log_integrity_rows)

