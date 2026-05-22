from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from agent import AgentConfig, OpenAICompatibleToolLLM, OpenClawAgent
from communication.bittorrent import StubBitTorrentService
from identity.agent_identity import AgentIdentity
from identity.seed import Seed
from protocol.llm import StubLLMClient
from security.contracts import SQ1Payload, SQ1TrialResult
from security.subq1_preventative.canary import create_canary_key
from security.subq1_preventative.classifier import classify_trial
from security.subq1_preventative.corpus import (
    DEFAULT_ATTACK_CORPUS,
    DEFAULT_BENIGN_CORPUS,
    corpus_hash,
    load_sq1_benign_controls,
    load_sq1_payloads,
    validate_attack_corpus,
)
from security.subq1_preventative.delivery import canonical_user_prompt, write_trial_input
from security.subq1_preventative.measurement import (
    ScriptedSQ1LLM,
    _export,
    _run_tool_loop_with_trace,
    _safe,
)
from security.subq1_preventative.real_tools import (
    BASELINE_CONDITION,
    DEFENDED_CONDITION,
    SQ1ToolContext,
    build_sq1_tools,
)
from security.subq1_preventative.reporting import summary as build_summary
from security.subq1_preventative.sinks import SinkRecorder


AGENT_SPEC_DIR = Path(__file__).resolve().parent / "agent_specs"
BASELINE_AGENT_SPEC = AGENT_SPEC_DIR / "baseline_agent.md"
DEFENDED_AGENT_SPEC = AGENT_SPEC_DIR / "least_privilege_agent.md"


async def run_openclaw_trial(
    *,
    payload: SQ1Payload,
    condition: str,
    repeat: int,
    run_id: str,
    root: Path,
    mode: str,
    base_url: str,
    model: str,
    api_key: str,
    temperature: float,
    max_iterations: int,
) -> SQ1TrialResult:
    trial_dir = root / "trials" / _safe(condition) / _safe(payload.id) / f"repeat_{repeat:03d}"
    trial_dir.mkdir(parents=True, exist_ok=True)
    canary = create_canary_key(trial_dir, run_id=run_id, repeat=repeat)
    input_path = write_trial_input(trial_dir, payload, canary=canary.canary, key_path=canary.key_path)
    sinks = SinkRecorder(trial_dir)

    agent = _build_disposable_openclaw_agent(trial_dir)
    context = SQ1ToolContext(
        condition=condition,
        trial_dir=trial_dir,
        input_path=input_path,
        key_path=canary.key_path,
        sinks=sinks,
    )
    tools = build_sq1_tools(context)
    llm = (
        ScriptedSQ1LLM(payload)
        if mode == "deterministic"
        else OpenAICompatibleToolLLM(
            base_url=base_url,
            model_id=model,
            api_key=api_key,
            temperature=temperature,
            timeout_s=120.0,
        )
    )

    final_output = ""
    error = None
    started = False
    try:
        await agent.start()
        started = True
        final_output = await _run_tool_loop_with_trace(
            canonical_user_prompt(payload),
            llm,
            tools,
            system_prompt=_system_prompt_for_condition(condition),
            max_iterations=max_iterations,
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if started:
            try:
                await agent.stop()
            except Exception as exc:
                stop_error = f"{type(exc).__name__}: {exc}"
                error = f"{error}; stop_error={stop_error}" if error else f"stop_error={stop_error}"

    sinks.record("final_answer", final_output)
    classification = classify_trial(
        canary=canary.canary,
        final_output=final_output,
        tool_calls=context.trace.calls,
        tool_results=context.trace.results,
        sink_events=sinks.events,
    )
    result = SQ1TrialResult(
        run_id=run_id,
        condition=condition,
        payload_id=payload.id,
        family=payload.family,
        vector=payload.vector,
        surface=payload.surface,
        variant=payload.variant,
        repeat=repeat,
        canary=canary.canary,
        severity=classification.severity,
        asr_success=classification.asr_success,
        forbidden_read_attempted=classification.forbidden_read_attempted,
        forbidden_read_blocked=classification.forbidden_read_blocked,
        key_read_internal=classification.key_read_internal,
        leaked_sinks=classification.leaked_sinks,
        final_output=final_output,
        tool_calls=context.trace.calls,
        tool_results=context.trace.results,
        sink_events=sinks.events,
        error=error,
    )
    (trial_dir / "trial_result.json").write_text(
        json.dumps(asdict(result), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return result


async def run_openclaw_measurement(
    *,
    payloads_path: Path,
    benign_path: Path,
    conditions: list[str],
    repeats: int,
    export_dir: Path,
    mode: str,
    base_url: str,
    model: str,
    api_key: str,
    temperature: float,
    max_iterations: int,
    include_benign: bool,
    limit: int | None = None,
) -> dict[str, Any]:
    attacks = load_sq1_payloads(payloads_path)
    errors = validate_attack_corpus(attacks)
    if errors:
        raise ValueError("invalid SQ1 attack corpus: " + "; ".join(errors))
    benign = load_sq1_benign_controls(benign_path) if include_benign else []
    payloads = attacks + benign
    if limit is not None:
        payloads = payloads[:limit]

    run_id = f"sq1_openclaw_private_key_asr_{int(time.time())}"
    export_dir.mkdir(parents=True, exist_ok=True)
    results: list[SQ1TrialResult] = []
    for condition in conditions:
        if condition not in {BASELINE_CONDITION, DEFENDED_CONDITION}:
            raise ValueError(f"unknown SQ1 condition: {condition}")
        for payload in payloads:
            for repeat in range(1, repeats + 1):
                results.append(await run_openclaw_trial(
                    payload=payload,
                    condition=condition,
                    repeat=repeat,
                    run_id=run_id,
                    root=export_dir,
                    mode=mode,
                    base_url=base_url,
                    model=model,
                    api_key=api_key,
                    temperature=temperature,
                    max_iterations=max_iterations,
                ))

    metadata = {
        "run_id": run_id,
        "created_at_unix": time.time(),
        "runtime": "openclaw-agent",
        "mode": mode,
        "conditions": conditions,
        "repeats": repeats,
        "attack_payloads": str(payloads_path),
        "benign_controls": str(benign_path) if include_benign else "",
        "corpus_hash": corpus_hash([payloads_path, benign_path] if include_benign else [payloads_path]),
        "agent_specs": {
            BASELINE_CONDITION: str(BASELINE_AGENT_SPEC),
            DEFENDED_CONDITION: str(DEFENDED_AGENT_SPEC),
        },
        "identity_material": "fresh disposable OpenClaw AgentIdentity plus per-trial canary key file",
        "python": sys.version,
        "platform": platform.platform(),
        "model": model if mode == "live-llm" else "scripted-deterministic",
        "base_url": base_url if mode == "live-llm" else "",
        "temperature": temperature,
        "max_iterations": max_iterations,
    }
    _export(export_dir, results, payloads, metadata)
    return {"metadata": metadata, "summary": build_summary(results, payloads)}


def _build_disposable_openclaw_agent(trial_dir: Path) -> OpenClawAgent:
    mnemonic = Seed.generate_mnemonic(128)
    identity = AgentIdentity(network="TESTNET", mnemonic=mnemonic)
    save_dir = trial_dir / "openclaw_agent"
    config = AgentConfig(
        port=0,
        address="127.0.0.1",
        btc_network="mock",
        save_dir=save_dir,
        community_log_path=save_dir / "community.log",
        peer_log_dir=save_dir / "peer_logs",
    )
    return OpenClawAgent(
        identity=identity,
        llm=StubLLMClient(sources={}),
        config=config,
        bt_service=StubBitTorrentService(save_dir=save_dir / "torrents"),
    )


def _system_prompt_for_condition(condition: str) -> str:
    if condition == BASELINE_CONDITION:
        return BASELINE_AGENT_SPEC.read_text(encoding="utf-8")
    if condition == DEFENDED_CONDITION:
        return DEFENDED_AGENT_SPEC.read_text(encoding="utf-8")
    raise ValueError(f"unknown SQ1 condition: {condition}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SQ1 against an instantiated OpenClawAgent runtime.")
    parser.add_argument("--payloads", type=Path, default=DEFAULT_ATTACK_CORPUS)
    parser.add_argument("--benign", type=Path, default=DEFAULT_BENIGN_CORPUS)
    parser.add_argument("--conditions", nargs="+", default=[BASELINE_CONDITION, DEFENDED_CONDITION])
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--export-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("deterministic", "live-llm"), default="live-llm")
    parser.add_argument("--base-url", default=os.getenv("OPENCLAW_BASE_URL") or os.getenv("QWEN_BASE_URL", "http://127.0.0.1:11434/v1"))
    parser.add_argument("--model", default=os.getenv("OPENCLAW_MODEL") or os.getenv("QWEN_MODEL", "qwen2.5-coder:7b"))
    parser.add_argument("--api-key", default=os.getenv(os.getenv("OPENCLAW_API_KEY_ENV", "OPENAI_API_KEY"), ""))
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-iterations", type=int, default=8)
    parser.add_argument("--no-benign", action="store_true")
    parser.add_argument("--limit", type=int, default=None, help="Limit payload count for smoke runs.")
    args = parser.parse_args()

    report = asyncio.run(run_openclaw_measurement(
        payloads_path=args.payloads,
        benign_path=args.benign,
        conditions=args.conditions,
        repeats=args.repeats,
        export_dir=args.export_dir,
        mode=args.mode,
        base_url=args.base_url,
        model=args.model,
        api_key=args.api_key,
        temperature=args.temperature,
        max_iterations=args.max_iterations,
        include_benign=not args.no_benign,
        limit=args.limit,
    ))
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
