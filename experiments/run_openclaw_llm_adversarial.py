"""Run real OpenClaw/OpenRouter agents against controlled lineage cases."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path
from time import perf_counter_ns
from typing import Any

from fastmcp import Client

from deploy.openclaw_output import parse_openclaw_json_stdout
from deploy.openclaw_workspace import (
    OpenClawWorkspaceSpec,
    invoke_openclaw_agent,
    openclaw_preflight,
    provision_openclaw_workspace,
)
from experiments.common.config import add_common_args, resolve_config
from experiments.common.environment import capture_environment
from experiments.common.io import create_run_directory, utc_timestamp, write_csv, write_json
from experiments.common.validation import (
    OPENCLAW_LLM_ADVERSARIAL_SCHEMA,
    OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA,
    validate_csv_exact_schema,
    validate_non_empty_csv,
)
from experiments.openclaw_llm_controller import (
    LineageExperimentController,
    build_experiment_mcp_server,
)


RUNNER_NAME = "openclaw_llm_adversarial"
MILESTONE_CASES = ("valid_agent_baseline", "tampered_parent_signature")
SECRET_PATTERN = re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]+\b")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def redact_text(text: str, *, secrets: tuple[str, ...] = ()) -> str:
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return SECRET_PATTERN.sub("[REDACTED]", redacted)


def assert_no_secrets(root: Path, *, secrets: tuple[str, ...] = ()) -> None:
    secret_bytes = [secret.encode("utf-8") for secret in secrets if secret]
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        if any(secret in data for secret in secret_bytes):
            raise RuntimeError(f"secret value leaked into artifact: {path.name}")
        text = data.decode("utf-8", errors="ignore")
        if SECRET_PATTERN.search(text):
            raise RuntimeError(f"OpenRouter-looking secret leaked into artifact: {path.name}")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _relative(path: Path, run_dir: Path) -> str:
    return path.relative_to(run_dir).as_posix()


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _capture_command(args: list[str], *, cwd: Path | None = None) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "").strip(),
        "stderr": (proc.stderr or "").strip(),
    }


def qualify_openrouter_model(model_id: str, *, timeout_s: int = 30) -> dict[str, Any]:
    """Confirm the configured model still advertises required parameters."""

    request = urllib.request.Request(
        "https://openrouter.ai/api/v1/models",
        headers={"User-Agent": "delftclaw-lineage-experiment/1"},
    )
    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        payload = json.loads(response.read().decode("utf-8"))
    rows = payload.get("data", []) if isinstance(payload, dict) else []
    model = next(
        (row for row in rows if isinstance(row, dict) and row.get("id") == model_id),
        None,
    )
    if model is None:
        raise RuntimeError(f"OpenRouter model is unavailable: {model_id}")
    supported = {str(value) for value in model.get("supported_parameters", [])}
    required = {"tools", "temperature", "seed"}
    missing = sorted(required - supported)
    if missing:
        raise RuntimeError(
            f"OpenRouter model {model_id} lacks required parameters: {missing}"
        )
    return {
        "model_id": model_id,
        "canonical_slug": model.get("canonical_slug", ""),
        "context_length": model.get("context_length", ""),
        "supported_parameters": sorted(supported),
        "pricing": model.get("pricing", {}),
        "expiration_date": model.get("expiration_date"),
        "qualified": True,
    }


def run_preflight(
    *,
    repo_root: Path,
    config: dict[str, Any],
    qualify_model: bool,
) -> dict[str, Any]:
    key_env = str(config["openclaw_llm_api_key_env"])
    result = {
        "timestamp_utc": utc_timestamp(),
        "git_revision": _capture_command(["git", "rev-parse", "HEAD"], cwd=repo_root),
        "git_status": _capture_command(["git", "status", "--short"], cwd=repo_root),
        "python_version": platform.python_version(),
        "node_version": _capture_command(["node", "--version"]),
        "openclaw": openclaw_preflight(),
        "openclaw_agents": _capture_command(["openclaw", "agents", "list", "--json"]),
        "openclaw_mcp": _capture_command(["openclaw", "mcp", "list"]),
        "api_key_env": key_env,
        "api_key_present": bool(os.environ.get(key_env)),
    }
    if not result["api_key_present"]:
        raise RuntimeError(f"required API key environment variable is unset: {key_env}")
    if qualify_model:
        result["model_qualification"] = qualify_openrouter_model(
            str(config["openclaw_llm_model"])
        )
    else:
        result["model_qualification"] = {"qualified": False, "skipped": True}
    return result


def build_prompt(*, trial_id: str, mode: str, attack_case: str) -> str:
    return (
        "Synthetic lineage admission experiment. Do not use shell, filesystem, "
        "browser, messaging, or network tools. Inspect the available experiment "
        "tools and complete exactly this workflow: call "
        "lineage_experiment_prepare_case with attack_case "
        f"{json.dumps(attack_case)}, then call lineage_experiment_request_join "
        "exactly once, then call lineage_experiment_peer_status exactly once. "
        "Report only a short completion status after the tools finish. "
        f"Trial id: {trial_id}. Lineage mode: {mode}."
    )


async def _await_mcp(url: str, *, timeout_s: float = 15.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_s
    last_error = ""
    while asyncio.get_running_loop().time() < deadline:
        try:
            async with Client(url) as client:
                tools = await client.list_tools()
            names = {tool.name for tool in tools}
            expected = {
                "lineage_experiment_prepare_case",
                "lineage_experiment_request_join",
                "lineage_experiment_peer_status",
            }
            if names == expected:
                return
            last_error = f"unexpected MCP tool set: {sorted(names)}"
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        await asyncio.sleep(0.1)
    raise RuntimeError(f"experiment MCP server did not become ready: {last_error}")


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _tool_success(rows: list[dict[str, Any]], name: str) -> bool:
    return any(row.get("tool") == name and row.get("ok") is True for row in rows)


async def _run_trial(
    *,
    config: dict[str, Any],
    environment: dict[str, Any],
    preflight: dict[str, Any],
    run_dir: Path,
    mode: str,
    attack_case: str,
    trial_index: int,
) -> dict[str, object]:
    trial_id = f"openclaw-llm-{mode}-{attack_case}-trial-{trial_index:04d}"
    artifact_dir = run_dir / "raw" / RUNNER_NAME / trial_id
    artifact_dir.mkdir(parents=True, exist_ok=False)
    ledger_path = artifact_dir / "tool_calls.jsonl"
    protocol_path = artifact_dir / "protocol_result.json"
    stdout_path = artifact_dir / "openclaw_stdout.json"
    stderr_path = artifact_dir / "openclaw_stderr.txt"
    prompt_path = artifact_dir / "prompt.txt"
    metadata_path = artifact_dir / "metadata.json"
    manifest_path = artifact_dir / "artifact_manifest.json"
    prompt = build_prompt(trial_id=trial_id, mode=mode, attack_case=attack_case)
    _write_text(prompt_path, prompt)
    _write_text(ledger_path, "")

    controller = LineageExperimentController(
        config=config,
        experiment_name=RUNNER_NAME,
        mode=mode,
        target_attack_case=attack_case,
        trial_index=trial_index,
        trial_id=trial_id,
        trial_root=artifact_dir / "runtime",
        ledger_path=ledger_path,
    )
    mcp = build_experiment_mcp_server(controller)
    port = _free_tcp_port()
    mcp_url = f"http://127.0.0.1:{port}/mcp"
    agent_id = f"lineage-{hashlib.sha256(trial_id.encode()).hexdigest()[:12]}"
    model_seed = int.from_bytes(
        hashlib.sha256(
            f"{config['seed']}|{trial_id}".encode("utf-8")
        ).digest()[:4],
        "big",
    )
    spec = OpenClawWorkspaceSpec(
        home=artifact_dir / "openclaw-home",
        agent_id=agent_id,
        mcp_name=f"lineage-{trial_id}",
        mcp_url=mcp_url,
        provider=str(config["openclaw_llm_provider"]),
        model_id=str(config["openclaw_llm_model"]),
        base_url=str(config["openclaw_llm_base_url"]),
        api=str(config["openclaw_llm_api"]),
        api_key_env=str(config["openclaw_llm_api_key_env"]),
        timeout_s=int(config["openclaw_llm_timeout_s"]),
        temperature=float(config["openclaw_llm_temperature"]),
        seed=model_seed,
        max_tokens=int(config["openclaw_llm_max_tokens"]),
    )
    api_key = os.environ.get(spec.api_key_env, "")
    secrets = (api_key,)
    proc_returncode = -1
    stdout = ""
    stderr = ""
    runner_error = ""
    started_ns = perf_counter_ns()
    server_task = asyncio.create_task(
        mcp.run_async(transport="streamable-http", host="127.0.0.1", port=port)
    )
    try:
        await _await_mcp(mcp_url)
        await asyncio.to_thread(provision_openclaw_workspace, spec)
        proc = await asyncio.to_thread(invoke_openclaw_agent, spec, prompt)
        proc_returncode = proc.returncode
        stdout = redact_text(proc.stdout or "", secrets=secrets)
        stderr = redact_text(proc.stderr or "", secrets=secrets)
    except subprocess.TimeoutExpired as exc:
        runner_error = f"openclaw_timeout:{exc.timeout}"
        stdout = redact_text(str(exc.stdout or ""), secrets=secrets)
        stderr = redact_text(str(exc.stderr or ""), secrets=secrets)
    except Exception as exc:
        runner_error = f"{type(exc).__name__}: {exc}"
    finally:
        await controller.stop()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            if not runner_error:
                runner_error = f"mcp_server_error:{type(exc).__name__}: {exc}"
        shutil.rmtree(artifact_dir / "runtime", ignore_errors=True)
        shutil.rmtree(artifact_dir / "openclaw-home", ignore_errors=True)
    duration_ms = (perf_counter_ns() - started_ns) / 1_000_000

    _write_text(stdout_path, stdout)
    _write_text(stderr_path, stderr)
    protocol = controller.protocol_result()
    write_json(protocol_path, protocol)
    ledger_rows = _read_ledger(ledger_path)
    prepare_called = _tool_success(ledger_rows, "lineage_experiment_prepare_case")
    request_called = _tool_success(ledger_rows, "lineage_experiment_request_join")
    status_called = _tool_success(ledger_rows, "lineage_experiment_peer_status")
    expected_tools_called = prepare_called and request_called and status_called
    llm_task_success = bool(expected_tools_called and protocol["join_attempted"])
    summary = parse_openclaw_json_stdout(stdout)
    semantic_error = summary.semantic_error or summary.parse_error or ""
    if proc_returncode != 0 and not runner_error:
        runner_error = f"openclaw_exit_code:{proc_returncode}"
    if semantic_error and not runner_error:
        runner_error = semantic_error

    metadata = {
        "trial_id": trial_id,
        "provider": spec.provider,
        "model": spec.model_id,
        "model_ref": spec.model_ref,
        "agent_id": agent_id,
        "mcp_url": mcp_url,
        "temperature": spec.temperature,
        "model_seed": model_seed,
        "max_tokens": spec.max_tokens,
        "timeout_s": spec.timeout_s,
        "openclaw_version": preflight["openclaw"]["openclaw_version"],
        "api_key_env": spec.api_key_env,
        "api_key_present": bool(api_key),
    }
    write_json(metadata_path, metadata)
    artifacts = {}
    for name, path in {
        "prompt": prompt_path,
        "openclaw_stdout": stdout_path,
        "openclaw_stderr": stderr_path,
        "tool_ledger": ledger_path,
        "protocol_result": protocol_path,
        "metadata": metadata_path,
    }.items():
        if path.exists():
            artifacts[name] = {
                "path": _relative(path, run_dir),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
    write_json(manifest_path, {"trial_id": trial_id, "artifacts": artifacts})
    assert_no_secrets(artifact_dir, secrets=secrets)

    lineage_errors = protocol["lineage_errors"]
    protocol_assessed_ok = bool(
        not protocol["join_attempted"] or protocol["protocol_expectation_met"]
    )
    row_ok = bool(not runner_error and protocol_assessed_ok)
    if runner_error:
        result_name = "runner_error"
    elif not llm_task_success:
        result_name = "llm_task_failure"
    elif not protocol["protocol_expectation_met"]:
        result_name = "protocol_mismatch"
    else:
        result_name = "measured"
    error_message = runner_error
    if not error_message and protocol["join_attempted"] and not protocol["protocol_expectation_met"]:
        error_message = "protocol_expectation_mismatch"
    return {
        "schema_version": config["schema_version"],
        "run_id": run_dir.name,
        "runner": RUNNER_NAME,
        "seed": config["seed"],
        "trial_id": trial_id,
        "timestamp_utc": utc_timestamp(),
        "git_commit": environment["git_commit"],
        "python_version": environment["python_version"],
        "platform": environment["platform"],
        "attack_case": attack_case,
        "selected_attack_case": protocol["selected_attack_case"],
        "lineage_mode": mode,
        "provider": spec.provider,
        "model": spec.model_id,
        "model_ref": spec.model_ref,
        "openclaw_version": preflight["openclaw"]["openclaw_version"],
        "openclaw_agent_id": agent_id,
        "prompt_hash": sha256_file(prompt_path),
        "trial_attempt": trial_index,
        "temperature": spec.temperature,
        "model_seed": model_seed,
        "max_tokens": spec.max_tokens,
        "tool_loop_started": bool(ledger_rows),
        "tool_calls_count": len(ledger_rows),
        "prepare_called": prepare_called,
        "expected_tool_called": expected_tools_called,
        "join_attempted": protocol["join_attempted"],
        "status_called": status_called,
        "proof_supplied": protocol["proof_supplied"],
        "expected_accept": protocol["expected_accept"],
        "join_accepted": (
            protocol["join_accepted"]
            if protocol["join_accepted"] is not None
            else ""
        ),
        "lineage_status": protocol["lineage_status"],
        "rejected": protocol["rejected"],
        "false_accept": protocol["false_accept"],
        "llm_task_success": llm_task_success,
        "protocol_expectation_met": protocol["protocol_expectation_met"],
        "duration_ms": duration_ms,
        "openclaw_exit_code": proc_returncode,
        "openclaw_semantic_error": semantic_error,
        "lineage_error_count": len(lineage_errors),
        "first_lineage_error": str(lineage_errors[0]) if lineage_errors else "",
        "stdout_artifact": _relative(stdout_path, run_dir),
        "stdout_sha256": sha256_file(stdout_path),
        "stderr_artifact": _relative(stderr_path, run_dir),
        "stderr_sha256": sha256_file(stderr_path),
        "tool_ledger_artifact": _relative(ledger_path, run_dir) if ledger_path.exists() else "",
        "tool_ledger_sha256": sha256_file(ledger_path) if ledger_path.exists() else "",
        "protocol_artifact": _relative(protocol_path, run_dir),
        "protocol_sha256": sha256_file(protocol_path),
        "artifact_manifest": _relative(manifest_path, run_dir),
        "artifact_manifest_sha256": sha256_file(manifest_path),
        "ok": row_ok,
        "result": result_name,
        "error_message": error_message,
    }


def _summary_rows(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str], list[dict[str, object]]] = {}
    for row in rows:
        grouped.setdefault(
            (str(row["lineage_mode"]), str(row["attack_case"])),
            [],
        ).append(row)
    output: list[dict[str, object]] = []
    for (mode, attack_case), group in sorted(grouped.items()):
        trials = len(group)
        llm_successes = sum(row["llm_task_success"] is True for row in group)
        join_rows = [row for row in group if row["join_attempted"] is True]
        protocol_successes = sum(
            row["protocol_expectation_met"] is True for row in join_rows
        )
        output.append({
            "lineage_mode": mode,
            "attack_case": attack_case,
            "trials": trials,
            "llm_task_successes": llm_successes,
            "llm_task_success_rate": llm_successes / trials if trials else 0.0,
            "join_attempts": len(join_rows),
            "protocol_expectation_met_count": protocol_successes,
            "protocol_correct_rate": (
                protocol_successes / len(join_rows) if join_rows else ""
            ),
            "false_accepts": sum(row["false_accept"] is True for row in join_rows),
        })
    return output


async def _build_rows(
    *,
    config: dict[str, Any],
    environment: dict[str, Any],
    preflight: dict[str, Any],
    run_dir: Path,
    milestone: bool,
) -> list[dict[str, object]]:
    modes = ["required"] if milestone else list(config["openclaw_llm_lineage_modes"])
    cases = list(MILESTONE_CASES) if milestone else list(config["openclaw_llm_attack_cases"])
    trials = 1 if milestone else int(config["openclaw_llm_trials_per_case"])
    rows = []
    for mode in modes:
        for attack_case in cases:
            for trial_index in range(trials):
                rows.append(await _run_trial(
                    config=config,
                    environment=environment,
                    preflight=preflight,
                    run_dir=run_dir,
                    mode=mode,
                    attack_case=attack_case,
                    trial_index=trial_index,
                ))
    return rows


def run(args: argparse.Namespace) -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    config = resolve_config(args.config, seed_override=args.seed, smoke=args.smoke)
    environment = capture_environment(repo_root)
    run_dir = create_run_directory(args.out, git_commit=str(environment["git_commit"]))
    config["config_path"] = str(Path(args.config).resolve())
    config["run_id"] = run_dir.name
    config["milestone"] = bool(args.milestone)
    config["claim_boundary"] = (
        "real OpenClaw/OpenRouter tool calls and real OpenClawAgent/IPv8 admission; "
        "mock lineage anchors only"
    )
    write_json(run_dir / "config.json", config)
    write_json(run_dir / "environment.json", environment)
    preflight = run_preflight(
        repo_root=repo_root,
        config=config,
        qualify_model=not args.skip_model_qualification,
    )
    write_json(run_dir / "preflight.json", preflight)
    if args.preflight_only:
        return run_dir

    rows = asyncio.run(_build_rows(
        config=config,
        environment=environment,
        preflight=preflight,
        run_dir=run_dir,
        milestone=bool(args.milestone),
    ))
    raw_path = run_dir / "raw" / "openclaw_llm_adversarial.csv"
    write_csv(raw_path, rows, OPENCLAW_LLM_ADVERSARIAL_SCHEMA)
    validate_csv_exact_schema(raw_path, OPENCLAW_LLM_ADVERSARIAL_SCHEMA)
    validate_non_empty_csv(raw_path)
    summary_path = run_dir / "tables" / "openclaw_llm_adversarial_summary.csv"
    write_csv(
        summary_path,
        _summary_rows(rows),
        OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA,
    )
    validate_csv_exact_schema(
        summary_path,
        OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA,
    )
    if not config["allow_exploratory_failures"]:
        failed = [str(row["trial_id"]) for row in rows if row["ok"] is False]
        if failed:
            raise RuntimeError(
                "OpenClaw LLM adversarial trial failures: " + "; ".join(failed[:5])
            )
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_common_args(parser)
    parser.add_argument(
        "--milestone",
        action="store_true",
        help="Run required-mode valid baseline and tampered-parent-signature only.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Record compatibility and model qualification without running trials.",
    )
    parser.add_argument(
        "--skip-model-qualification",
        action="store_true",
        help="Skip the live OpenRouter catalog check.",
    )
    args = parser.parse_args(argv)
    try:
        run_dir = run(args)
    except Exception as exc:
        print(f"OpenClaw LLM adversarial runner failed: {exc}", file=sys.stderr)
        return 1
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
