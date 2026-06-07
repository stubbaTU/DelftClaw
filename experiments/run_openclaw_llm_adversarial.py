"""Run real OpenClaw/OpenRouter agents against controlled lineage cases."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from time import perf_counter, perf_counter_ns
from typing import Any, Iterator

from fastmcp import Client
import uvicorn

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
LOGGER = logging.getLogger(RUNNER_NAME)


def _format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    seconds = max(0.0, seconds)
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{remainder:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


@dataclass
class TimingCollector:
    stages: dict[str, list[float]] = field(default_factory=dict)
    trials: list[dict[str, Any]] = field(default_factory=list)

    def add(self, stage: str, elapsed_s: float) -> None:
        self.stages.setdefault(stage, []).append(elapsed_s)

    @contextmanager
    def measure(self, stage: str) -> Iterator[None]:
        started = perf_counter()
        try:
            yield
        finally:
            self.add(stage, perf_counter() - started)

    def stage_summary(self) -> list[dict[str, object]]:
        rows = []
        for stage, samples in self.stages.items():
            total_s = sum(samples)
            rows.append({
                "stage": stage,
                "count": len(samples),
                "total_s": total_s,
                "average_s": total_s / len(samples),
                "max_s": max(samples),
            })
        return sorted(rows, key=lambda row: float(row["total_s"]), reverse=True)

    def as_dict(self, *, total_elapsed_s: float) -> dict[str, object]:
        return {
            "runner": RUNNER_NAME,
            "total_elapsed_s": total_elapsed_s,
            "stages": self.stage_summary(),
            "trials": self.trials,
        }


@dataclass
class ProgressReporter:
    total_trials: int
    progress_interval_s: float
    started_at: float = field(default_factory=perf_counter)
    completed_durations_s: list[float] = field(default_factory=list)

    def log(self, stage: str, message: str, *args: object) -> None:
        LOGGER.info("stage=%s " + message, stage, *args)

    @property
    def completed_trials(self) -> int:
        return len(self.completed_durations_s)

    def overall_eta_s(self) -> float | None:
        if not self.completed_durations_s:
            return None
        average_s = sum(self.completed_durations_s) / len(self.completed_durations_s)
        return average_s * (self.total_trials - self.completed_trials)

    def trial_started(
        self,
        *,
        trial_number: int,
        trial_id: str,
        mode: str,
        attack_case: str,
    ) -> None:
        self.log(
            "trial",
            "event=start progress=%d/%d mode=%s attack=%s trial=%s "
            "elapsed=%s eta=%s",
            trial_number,
            self.total_trials,
            mode,
            attack_case,
            trial_id,
            _format_duration(perf_counter() - self.started_at),
            _format_duration(self.overall_eta_s()),
        )

    def trial_finished(self, *, trial_id: str, elapsed_s: float, result: str) -> None:
        self.completed_durations_s.append(elapsed_s)
        self.log(
            "trial",
            "event=complete progress=%d/%d trial=%s result=%s duration=%s "
            "elapsed=%s eta=%s",
            self.completed_trials,
            self.total_trials,
            trial_id,
            result,
            _format_duration(elapsed_s),
            _format_duration(perf_counter() - self.started_at),
            _format_duration(self.overall_eta_s()),
        )


def _configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), None)
    if not isinstance(level, int):
        raise ValueError(f"invalid log level: {level_name}")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    ))
    LOGGER.handlers.clear()
    LOGGER.addHandler(handler)
    LOGGER.setLevel(level)
    LOGGER.propagate = False


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


def _subprocess_error_detail(
    exc: subprocess.CalledProcessError,
    *,
    secrets: tuple[str, ...] = (),
    limit: int = 1200,
) -> str:
    stdout = " ".join(str(exc.stdout or "").strip().split())
    stderr = " ".join(str(exc.stderr or "").strip().split())
    detail = stderr or stdout or "no stdout/stderr"
    detail = redact_text(detail, secrets=secrets)
    return (
        f"openclaw_command_failed:exit={exc.returncode} "
        f"command={exc.cmd!r} detail={detail[:limit]}"
    )


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
    timings: TimingCollector | None = None,
) -> dict[str, Any]:
    key_env = str(config["openclaw_llm_api_key_env"])
    result = {
        "timestamp_utc": utc_timestamp(),
        "git_revision": _capture_command(["git", "rev-parse", "HEAD"], cwd=repo_root),
        "git_status": _capture_command(["git", "status", "--short"], cwd=repo_root),
        "python_version": platform.python_version(),
        "mcp_stack": {
            package: importlib.metadata.version(package)
            for package in ("fastmcp", "mcp", "uvicorn")
        },
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
        started_at = perf_counter()
        try:
            result["model_qualification"] = qualify_openrouter_model(
                str(config["openclaw_llm_model"])
            )
        finally:
            if timings is not None:
                timings.add(
                    "preflight.model_catalog_api",
                    perf_counter() - started_at,
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


def _start_mcp_http_server(
    mcp,
    *,
    host: str,
    port: int,
) -> tuple[uvicorn.Server, asyncio.Task[None]]:
    """Start FastMCP with a retained Uvicorn handle for graceful shutdown."""

    # Each experiment tool stores state in the controller, not in an MCP
    # session. Stateless JSON responses avoid leaving an SSE response open
    # when OpenClaw disconnects or the per-trial server shuts down.
    app = mcp.http_app(
        transport="streamable-http",
        stateless_http=True,
        json_response=True,
    )
    server = uvicorn.Server(uvicorn.Config(
        app,
        host=host,
        port=port,
        lifespan="on",
        log_level="warning",
        timeout_graceful_shutdown=2,
        ws="websockets-sansio",
    ))

    async def serve() -> None:
        async with mcp._lifespan_manager():  # FastMCP's run_http_async contract.
            await server.serve()

    return server, asyncio.create_task(serve())


async def _stop_mcp_http_server(
    server: uvicorn.Server,
    task: asyncio.Task[None],
) -> None:
    server.should_exit = True
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=5)
    except asyncio.TimeoutError:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


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
    progress: ProgressReporter | None = None,
    timings: TimingCollector | None = None,
    trial_number: int = 1,
) -> dict[str, object]:
    timings = timings or TimingCollector()
    trial_id = f"openclaw-llm-{mode}-{attack_case}-trial-{trial_index:04d}"
    trial_started_at = perf_counter()
    if progress is not None:
        progress.trial_started(
            trial_number=trial_number,
            trial_id=trial_id,
            mode=mode,
            attack_case=attack_case,
        )
    trial_timings: dict[str, float] = {}

    @contextmanager
    def measure_trial(stage: str) -> Iterator[None]:
        started = perf_counter()
        try:
            yield
        finally:
            elapsed_s = perf_counter() - started
            trial_timings[stage] = trial_timings.get(stage, 0.0) + elapsed_s
            timings.add(f"trial.{stage}", elapsed_s)

    artifact_dir = run_dir / "raw" / RUNNER_NAME / trial_id
    with measure_trial("prepare"):
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
    llm_elapsed_s = 0.0
    started_ns = perf_counter_ns()
    with measure_trial("mcp_startup"):
        mcp_server, server_task = _start_mcp_http_server(
            mcp,
            host="127.0.0.1",
            port=port,
        )
    try:
        with measure_trial("mcp_ready_wait"):
            await _await_mcp(mcp_url)
        if progress is not None:
            progress.log("mcp", "trial=%s event=ready url=%s", trial_id, mcp_url)
        if progress is not None:
            progress.log("workspace", "trial=%s event=provision_start", trial_id)
        with measure_trial("workspace_provision"):
            await asyncio.to_thread(provision_openclaw_workspace, spec)
        if progress is not None:
            progress.log(
                "workspace",
                "trial=%s event=provision_complete duration=%s",
                trial_id,
                _format_duration(trial_timings["workspace_provision"]),
            )
        if progress is not None:
            progress.log(
                "openclaw_loop",
                "trial=%s event=start model=%s timeout=%s",
                trial_id,
                spec.model_ref,
                _format_duration(float(spec.timeout_s)),
            )
        llm_started_at = perf_counter()
        invoke_task = asyncio.create_task(
            asyncio.to_thread(invoke_openclaw_agent, spec, prompt)
        )
        last_tool_count = 0
        try:
            while True:
                interval_s = (
                    progress.progress_interval_s
                    if progress is not None and progress.progress_interval_s > 0
                    else None
                )
                try:
                    if interval_s is None:
                        proc = await invoke_task
                    else:
                        proc = await asyncio.wait_for(
                            asyncio.shield(invoke_task),
                            timeout=interval_s,
                        )
                    break
                except asyncio.TimeoutError:
                    if invoke_task.done():
                        proc = invoke_task.result()
                        break
                    elapsed_s = perf_counter() - llm_started_at
                    ledger_rows = _read_ledger(ledger_path)
                    latest_tool = (
                        str(ledger_rows[-1].get("tool", "none"))
                        if ledger_rows
                        else "none"
                    )
                    new_tools = max(0, len(ledger_rows) - last_tool_count)
                    last_tool_count = len(ledger_rows)
                    progress.log(
                        "openclaw_loop",
                        "trial=%s event=heartbeat elapsed=%s timeout_remaining=%s "
                        "tool_calls=%d new_tool_calls=%d latest_tool=%s",
                        trial_id,
                        _format_duration(elapsed_s),
                        _format_duration(
                            max(0.0, float(spec.timeout_s) - elapsed_s)
                        ),
                        len(ledger_rows),
                        new_tools,
                        latest_tool,
                    )
        finally:
            llm_elapsed_s = perf_counter() - llm_started_at
            trial_timings["openclaw_model_tool_loop"] = llm_elapsed_s
        if progress is not None:
            progress.log(
                "openclaw_loop",
                "trial=%s event=complete duration=%s exit_code=%d",
                trial_id,
                _format_duration(llm_elapsed_s),
                proc.returncode,
            )
        proc_returncode = proc.returncode
        stdout = redact_text(proc.stdout or "", secrets=secrets)
        stderr = redact_text(proc.stderr or "", secrets=secrets)
    except subprocess.TimeoutExpired as exc:
        runner_error = f"openclaw_timeout:{exc.timeout}"
        stdout = redact_text(str(exc.stdout or ""), secrets=secrets)
        stderr = redact_text(str(exc.stderr or ""), secrets=secrets)
    except subprocess.CalledProcessError as exc:
        stdout = redact_text(str(exc.stdout or ""), secrets=secrets)
        stderr = redact_text(str(exc.stderr or ""), secrets=secrets)
        runner_error = _subprocess_error_detail(exc, secrets=secrets)
    except Exception as exc:
        runner_error = f"{type(exc).__name__}: {exc}"
    finally:
        with measure_trial("cleanup"):
            await controller.stop()
            try:
                await _stop_mcp_http_server(mcp_server, server_task)
            except Exception as exc:
                if not runner_error:
                    runner_error = f"mcp_server_error:{type(exc).__name__}: {exc}"
            shutil.rmtree(artifact_dir / "runtime", ignore_errors=True)
            shutil.rmtree(artifact_dir / "openclaw-home", ignore_errors=True)
    duration_ms = (perf_counter_ns() - started_ns) / 1_000_000

    if progress is not None:
        progress.log("evaluation", "trial=%s event=start", trial_id)
    with measure_trial("evaluation"):
        _write_text(stdout_path, stdout)
        _write_text(stderr_path, stderr)
        protocol = controller.protocol_result()
        write_json(protocol_path, protocol)
        ledger_rows = _read_ledger(ledger_path)
        tool_timings_s: dict[str, float] = {}
        for ledger_row in ledger_rows:
            tool_name = str(ledger_row.get("tool", "unknown"))
            tool_elapsed_s = float(ledger_row.get("duration_ms", 0.0)) / 1000
            tool_timings_s[tool_name] = (
                tool_timings_s.get(tool_name, 0.0) + tool_elapsed_s
            )
            timings.add(f"tool.{tool_name}", tool_elapsed_s)
        local_tool_s = sum(
            float(row.get("duration_ms", 0.0)) / 1000
            for row in ledger_rows
        )
        llm_api_estimate_s = max(0.0, llm_elapsed_s - local_tool_s)
        trial_timings["local_tool_execution"] = local_tool_s
        trial_timings["llm_api_wait_estimate"] = llm_api_estimate_s
        timings.add("trial.local_tool_execution", local_tool_s)
        timings.add("trial.llm_api_wait_estimate", llm_api_estimate_s)
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
        "timing_seconds": trial_timings,
    }
    if progress is not None:
        progress.log("artifacts", "trial=%s event=save_start", trial_id)
    with measure_trial("artifact_save"):
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
    if (
        not error_message
        and protocol["join_attempted"]
        and not protocol["protocol_expectation_met"]
    ):
        error_message = "protocol_expectation_mismatch"
    row = {
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
    trial_elapsed_s = perf_counter() - trial_started_at
    timings.trials.append({
        "trial_id": trial_id,
        "mode": mode,
        "attack_case": attack_case,
        "result": result_name,
        "elapsed_s": trial_elapsed_s,
        "stages": trial_timings,
        "tool_calls": tool_timings_s,
    })
    if progress is not None:
        progress.trial_finished(
            trial_id=trial_id,
            elapsed_s=trial_elapsed_s,
            result=result_name,
        )
    return row


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
    progress: ProgressReporter | None = None,
    timings: TimingCollector | None = None,
) -> list[dict[str, object]]:
    modes = ["required"] if milestone else list(config["openclaw_llm_lineage_modes"])
    cases = list(MILESTONE_CASES) if milestone else list(config["openclaw_llm_attack_cases"])
    trials = 1 if milestone else int(config["openclaw_llm_trials_per_case"])
    rows = []
    trial_number = 0
    for mode in modes:
        for attack_case in cases:
            for trial_index in range(trials):
                trial_number += 1
                rows.append(await _run_trial(
                    config=config,
                    environment=environment,
                    preflight=preflight,
                    run_dir=run_dir,
                    mode=mode,
                    attack_case=attack_case,
                    trial_index=trial_index,
                    progress=progress,
                    timings=timings,
                    trial_number=trial_number,
                ))
    return rows


def run(args: argparse.Namespace) -> Path:
    total_started_at = perf_counter()
    timings = TimingCollector()
    repo_root = Path(__file__).resolve().parents[1]
    LOGGER.info("stage=config event=start path=%s", args.config)
    with timings.measure("run.load_config"):
        config = resolve_config(args.config, seed_override=args.seed, smoke=args.smoke)
    with timings.measure("run.capture_environment"):
        environment = capture_environment(repo_root)
    with timings.measure("run.create_directory"):
        run_dir = create_run_directory(
            args.out,
            git_commit=str(environment["git_commit"]),
        )
    config["config_path"] = str(Path(args.config).resolve())
    config["run_id"] = run_dir.name
    config["milestone"] = bool(args.milestone)
    config["claim_boundary"] = (
        "real OpenClaw/OpenRouter tool calls and real OpenClawAgent/IPv8 admission; "
        "mock lineage anchors only"
    )
    with timings.measure("run.save_initial_metadata"):
        write_json(run_dir / "config.json", config)
        write_json(run_dir / "environment.json", environment)
    LOGGER.info("stage=preflight event=start")
    with timings.measure("run.preflight"):
        preflight = run_preflight(
            repo_root=repo_root,
            config=config,
            qualify_model=not args.skip_model_qualification,
            timings=timings,
        )
    write_json(run_dir / "preflight.json", preflight)
    LOGGER.info(
        "stage=preflight event=complete model=%s openclaw=%s",
        config["openclaw_llm_model"],
        preflight["openclaw"]["openclaw_version"],
    )
    if args.preflight_only:
        total_elapsed_s = perf_counter() - total_started_at
        write_json(
            run_dir / "timing.json",
            timings.as_dict(total_elapsed_s=total_elapsed_s),
        )
        _log_timing_summary(timings, total_elapsed_s=total_elapsed_s, trial_count=0)
        return run_dir

    modes = ["required"] if args.milestone else config["openclaw_llm_lineage_modes"]
    cases = MILESTONE_CASES if args.milestone else config["openclaw_llm_attack_cases"]
    trials_per_case = 1 if args.milestone else config["openclaw_llm_trials_per_case"]
    total_trials = len(modes) * len(cases) * int(trials_per_case)
    progress = ProgressReporter(
        total_trials=total_trials,
        progress_interval_s=float(args.progress_interval),
    )
    LOGGER.info(
        "stage=trials event=start total=%d modes=%d attacks=%d trials_per_case=%d",
        total_trials,
        len(modes),
        len(cases),
        int(trials_per_case),
    )
    with timings.measure("run.execute_trials"):
        rows = asyncio.run(_build_rows(
            config=config,
            environment=environment,
            preflight=preflight,
            run_dir=run_dir,
            milestone=bool(args.milestone),
            progress=progress,
            timings=timings,
        ))
    raw_path = run_dir / "raw" / "openclaw_llm_adversarial.csv"
    summary_path = run_dir / "tables" / "openclaw_llm_adversarial_summary.csv"
    LOGGER.info("stage=results event=start rows=%d", len(rows))
    with timings.measure("run.save_results"):
        write_csv(raw_path, rows, OPENCLAW_LLM_ADVERSARIAL_SCHEMA)
        write_csv(
            summary_path,
            _summary_rows(rows),
            OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA,
        )
    with timings.measure("run.validate_results"):
        validate_csv_exact_schema(raw_path, OPENCLAW_LLM_ADVERSARIAL_SCHEMA)
        validate_non_empty_csv(raw_path)
        validate_csv_exact_schema(
            summary_path,
            OPENCLAW_LLM_ADVERSARIAL_SUMMARY_SCHEMA,
        )
    total_elapsed_s = perf_counter() - total_started_at
    write_json(
        run_dir / "timing.json",
        timings.as_dict(total_elapsed_s=total_elapsed_s),
    )
    LOGGER.info(
        "stage=results event=complete raw=%s summary=%s timing=%s",
        raw_path,
        summary_path,
        run_dir / "timing.json",
    )
    _log_timing_summary(
        timings,
        total_elapsed_s=total_elapsed_s,
        trial_count=len(rows),
    )
    if not config["allow_exploratory_failures"]:
        failed = [row for row in rows if row["ok"] is False]
        if failed:
            details = []
            for row in failed[:5]:
                details.append(
                    f"{row['trial_id']} "
                    f"result={row['result']} "
                    f"exit={row['openclaw_exit_code']} "
                    f"tools={row['tool_calls_count']} "
                    f"semantic={row['openclaw_semantic_error'] or '<none>'} "
                    f"error={row['error_message'] or '<none>'}"
                )
            raise RuntimeError(
                f"OpenClaw LLM adversarial trial failures in {run_dir}: "
                + "; ".join(details)
            )
    return run_dir


def _log_timing_summary(
    timings: TimingCollector,
    *,
    total_elapsed_s: float,
    trial_count: int,
) -> None:
    trial_stages = [
        row for row in timings.stage_summary()
        if str(row["stage"]).startswith("trial.")
    ]
    average_trial_s = (
        sum(float(trial["elapsed_s"]) for trial in timings.trials)
        / len(timings.trials)
        if timings.trials
        else None
    )
    LOGGER.info(
        "stage=timing_summary total=%s trials=%d average_per_trial=%s",
        _format_duration(total_elapsed_s),
        trial_count,
        _format_duration(average_trial_s),
    )
    for rank, row in enumerate(trial_stages[:3], start=1):
        share = (
            float(row["total_s"]) / total_elapsed_s * 100
            if total_elapsed_s > 0
            else 0.0
        )
        LOGGER.info(
            "stage=timing_summary rank=%d bottleneck=%s total=%s average=%s "
            "count=%d share=%.1f%%",
            rank,
            str(row["stage"]).removeprefix("trial."),
            _format_duration(float(row["total_s"])),
            _format_duration(float(row["average_s"])),
            int(row["count"]),
            share,
        )


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
    parser.add_argument(
        "--log-level",
        type=str.upper,
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Logging verbosity (default: INFO).",
    )
    parser.add_argument(
        "--progress-interval",
        type=float,
        default=15.0,
        help="Seconds between LLM/API wait heartbeats; 0 disables heartbeats.",
    )
    args = parser.parse_args(argv)
    try:
        if args.progress_interval < 0:
            raise ValueError("--progress-interval must be non-negative")
        _configure_logging(args.log_level)
        run_dir = run(args)
    except Exception as exc:
        print(f"OpenClaw LLM adversarial runner failed: {exc}", file=sys.stderr)
        return 1
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
