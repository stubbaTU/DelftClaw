from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any, Iterable


DISCOVERY_TERMS = {
    "find",
    "identify",
    "look up",
    "lookup",
    "search",
    "who",
    "which",
}
EFFECT_TERMS = {
    "book",
    "create",
    "email",
    "invite",
    "message",
    "pay",
    "post",
    "schedule",
    "send",
    "share",
    "transfer",
}
BROADCAST_TERMS = {
    "channel",
    "post",
    "public",
    "publish",
    "slack",
}
READ_TERMS = {
    "find",
    "look up",
    "lookup",
    "read",
    "search",
    "summarize",
}


def classify_task_shape(task_text: str) -> dict[str, Any]:
    normalized = " ".join(task_text.lower().split())
    discoveries = sorted(term for term in DISCOVERY_TERMS if _contains_term(normalized, term))
    effects = sorted(term for term in EFFECT_TERMS if _contains_term(normalized, term))
    broadcasts = sorted(term for term in BROADCAST_TERMS if _contains_term(normalized, term))
    reads = sorted(term for term in READ_TERMS if _contains_term(normalized, term))
    return {
        "multi_hop_into_effect": bool(discoveries and effects),
        "read_then_broadcast": bool(reads and broadcasts),
        "discovery_terms": discoveries,
        "effect_terms": effects,
        "broadcast_terms": broadcasts,
        "read_terms": reads,
    }


def audit_suite_tasks(tasks: Iterable[tuple[str, str]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for task_id, task_text in tasks:
        rows.append({"task_id": task_id, "task_text": task_text, **classify_task_shape(task_text)})
    return {
        "task_count": len(rows),
        "multi_hop_into_effect_count": sum(bool(row["multi_hop_into_effect"]) for row in rows),
        "read_then_broadcast_count": sum(bool(row["read_then_broadcast"]) for row in rows),
        "rows": rows,
        "note": "Heuristic upper-bound audit; manually review flagged tasks before interpreting utility loss.",
    }


def load_agentdojo_tasks(benchmark_version: str, suite_name: str) -> list[tuple[str, str]]:
    try:
        from agentdojo.task_suite.load_suites import get_suite
    except ModuleNotFoundError as exc:
        raise RuntimeError("AgentDojo is not installed in this environment") from exc
    suite = get_suite(benchmark_version, suite_name)
    user_tasks = getattr(suite, "user_tasks", None)
    if user_tasks is None:
        raise RuntimeError("AgentDojo suite does not expose user_tasks")
    items = user_tasks.items() if isinstance(user_tasks, dict) else enumerate(user_tasks)
    return [(str(task_id), _task_text(task)) for task_id, task in items]


def write_audit(audit: dict[str, Any], output_dir: Path, suite_name: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{suite_name}_task_shape_audit.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    columns = [
        "task_id",
        "multi_hop_into_effect",
        "read_then_broadcast",
        "discovery_terms",
        "effect_terms",
        "broadcast_terms",
        "read_terms",
        "task_text",
    ]
    with (output_dir / f"{suite_name}_task_shape_audit.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in audit["rows"]:
            writer.writerow({
                **row,
                "discovery_terms": ",".join(row["discovery_terms"]),
                "effect_terms": ",".join(row["effect_terms"]),
                "broadcast_terms": ",".join(row["broadcast_terms"]),
                "read_terms": ",".join(row["read_terms"]),
            })


def _task_text(task: Any) -> str:
    if isinstance(task, str):
        return task
    for attribute in ("PROMPT", "prompt", "user_task", "task"):
        value = getattr(task, attribute, None)
        if isinstance(value, str):
            return value
    if hasattr(task, "model_dump"):
        payload = task.model_dump()
        for key in ("prompt", "user_task", "task"):
            if isinstance(payload.get(key), str):
                return payload[key]
    return str(task)


def _contains_term(text: str, term: str) -> bool:
    return bool(re.search(rf"\b{re.escape(term)}\b", text))


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit AgentDojo benign tasks for SQ1 utility-ceiling shapes.")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--suites", nargs="+", default=["workspace", "slack", "banking", "travel"])
    parser.add_argument("--out", type=Path, default=Path("results/sq1_task_shape_audit"))
    args = parser.parse_args()
    summaries: dict[str, Any] = {}
    for suite_name in args.suites:
        audit = audit_suite_tasks(load_agentdojo_tasks(args.benchmark_version, suite_name))
        write_audit(audit, args.out, suite_name)
        summaries[suite_name] = {key: value for key, value in audit.items() if key != "rows"}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "sq1_task_shape_audit_summary.json").write_text(
        json.dumps(summaries, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(json.dumps(summaries, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
