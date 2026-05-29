from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import platform
import shutil
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from redteam.primitives.signed_log import SignedAppendOnlyLog
from security.results import write_csv, write_json
from security.subq2_accountability.event_gateway import normalize_reputation_tool_call
from security.subq2_accountability.generate_live_scenarios import generate_scenarios
from security.subq2_accountability.live_agent_tools import (
    SQ2ToolContext,
    build_sq2_live_tools,
    event_tool_for_type,
    scripted_tool_message,
    tool_args_for_event,
)
from security.subq2_accountability.live_scenario_schema import (
    ALL_AGENTS,
    CONDITION_C0,
    CONDITION_C1,
    DEFAULT_LIVE_SCENARIOS,
    HONEST_AGENTS,
    PRIMARY_ATTACKER,
    SQ2LiveEvent,
    SQ2LiveScenario,
    load_scenarios,
    normalize_condition,
    sanitized_event_for_agent,
    write_scenarios,
)
from security.subq2_accountability.naive_reputation import NaiveReputationState
from security.subq2_accountability.trustworthy_estimator import (
    EXPULSION_SUSPICION_THRESHOLD,
    TrustworthyEstimator,
)


AGENT_SPEC_DIR = Path(__file__).resolve().parent / "agent_specs"
AGENT_SPECS = {
    "honest": AGENT_SPEC_DIR / "honest_agent.md",
    "primary_attacker": AGENT_SPEC_DIR / "primary_attacker.md",
    "sybil": AGENT_SPEC_DIR / "sybil_agent.md",
    "auditor": AGENT_SPEC_DIR / "auditor_agent.md",
}

TRIAL_COLUMNS = [
    "scenario_id",
    "family",
    "intensity",
    "seed",
    "condition",
    "mode",
    "model",
    "num_events",
    "first_malicious_event_index",
    "first_malicious_round",
    "first_flag_event_index",
    "first_flag_round",
    "expelled",
    "expulsion_event_index",
    "expulsion_round",
    "reputation_lag_events",
    "reputation_lag_rounds",
    "censored",
    "fallout_broadcasts",
    "fraudulent_microtasks_accepted",
    "wash_trades_accepted",
    "collusive_endorsements_accepted",
    "fraudulent_reputation_gain",
    "false_positive_count",
    "false_positive_rate",
    "final_attacker_reputation",
    "final_attacker_suspicion",
    "detection_reasons",
    "log_chain_valid",
    "error",
]

TIMESERIES_COLUMNS = [
    "scenario_id",
    "condition",
    "round",
    "event_index",
    "agent_id",
    "reputation_score",
    "suspicion_score",
    "is_expelled",
]

LAG_COLUMNS = [
    "condition",
    "family",
    "runs",
    "expelled_runs",
    "expulsion_rate",
    "mean_reputation_lag_events",
    "median_reputation_lag_events",
    "mean_reputation_lag_rounds",
    "median_reputation_lag_rounds",
    "censored_runs",
]

FALLOUT_COLUMNS = [
    "condition",
    "family",
    "runs",
    "mean_fallout_broadcasts",
    "median_fallout_broadcasts",
    "mean_fraudulent_microtasks_accepted",
    "mean_wash_trades_accepted",
    "mean_collusive_endorsements_accepted",
    "mean_fraudulent_reputation_gain",
]


@dataclass
class SQ2EventRecord:
    scenario_id: str
    condition: str
    event_index: int
    round: int
    actor_id: str
    event_type: str
    accepted: bool
    blocked: bool
    expelled_after_event: bool
    reason: str
    tool_name: str
    tool_args: dict[str, Any]


@dataclass
class SQ2TrialRun:
    scenario_id: str
    family: str
    intensity: str
    seed: int
    condition: str
    mode: str
    model: str
    num_events: int
    first_malicious_event_index: int
    first_malicious_round: int
    first_flag_event_index: int | None
    first_flag_round: int | None
    expelled: bool
    expulsion_event_index: int | None
    expulsion_round: int | None
    reputation_lag_events: int
    reputation_lag_rounds: int
    censored: bool
    fallout_broadcasts: int
    fraudulent_microtasks_accepted: int
    wash_trades_accepted: int
    collusive_endorsements_accepted: int
    fraudulent_reputation_gain: float
    false_positive_count: int
    false_positive_rate: float
    final_attacker_reputation: float
    final_attacker_suspicion: int
    detection_reasons: str
    log_chain_valid: bool | None
    error: str | None = None


@dataclass
class SQ2RunContext:
    scenario: SQ2LiveScenario
    condition: str
    trial_dir: Path
    threshold: int
    mode: str
    model: str
    naive: NaiveReputationState | None = None
    signed_log: SignedAppendOnlyLog | None = None
    estimator: TrustworthyEstimator | None = None
    reporter_id: str = ""
    event_records: list[SQ2EventRecord] = field(default_factory=list)
    timeseries_rows: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    final_outputs: list[dict[str, Any]] = field(default_factory=list)
    first_flag_event_index: int | None = None
    first_flag_round: int | None = None
    expulsion_event_index: int | None = None
    expulsion_round: int | None = None
    fraudulent_microtasks_accepted: int = 0
    wash_trades_accepted: int = 0
    collusive_endorsements_accepted: int = 0
    fallout_broadcasts: int = 0
    fraudulent_reputation_gain: float = 0.0

    @property
    def c1(self) -> bool:
        return self.condition == CONDITION_C1

    def is_expelled(self, agent_id: str) -> bool:
        if self.c1 and self.estimator is not None:
            return self.estimator.is_expelled(agent_id)
        if self.naive is not None:
            return self.naive.is_expelled(agent_id)
        return False

    def reputation(self, agent_id: str) -> float:
        if self.c1 and self.estimator is not None:
            return self.estimator.get_reputation(agent_id)
        if self.naive is not None:
            return self.naive.get_reputation(agent_id)
        return 0.0

    def suspicion(self, agent_id: str) -> int:
        if self.estimator is not None:
            return self.estimator.get_suspicion(agent_id)
        return 0


class ScriptedSQ2LLM:
    """Deterministic tool-calling model for smoke tests."""

    def __init__(self, event: SQ2LiveEvent) -> None:
        self.event = event
        self.cursor = 0

    def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        if self.cursor == 0:
            self.cursor += 1
            return {"message": scripted_tool_message("call-load", "load_scenario_step", {})}
        if self.cursor == 1:
            self.cursor += 1
            return {"message": scripted_tool_message(
                "call-action",
                event_tool_for_type(self.event.event_type),
                tool_args_for_event(self.event),
            )}
        return {"message": {"role": "assistant", "content": f"executed {self.event.event_type}"}}


async def run_live_measurement(
    *,
    scenarios_path: Path,
    export_dir: Path,
    conditions: list[str],
    mode: str,
    base_url: str,
    model: str,
    api_key: str,
    temperature: float,
    max_iterations: int,
    estimator_interval: int,
    expulsion_threshold: int,
    limit: int | None = None,
    start_openclaw_runtime: bool = False,
) -> dict[str, Any]:
    if not scenarios_path.exists():
        scenarios = generate_scenarios()
        write_scenarios(scenarios_path, scenarios)
    scenarios = load_scenarios(scenarios_path)
    conditions = [normalize_condition(condition) for condition in conditions]
    if limit is not None:
        scenarios = scenarios[:limit]

    export_dir.mkdir(parents=True, exist_ok=True)
    run_id = f"sq2_openclaw_accountability_{int(time.time())}"
    all_trials: list[SQ2TrialRun] = []
    all_event_records: list[SQ2EventRecord] = []
    all_timeseries: list[dict[str, Any]] = []
    log_integrity_rows: list[dict[str, Any]] = []

    for scenario in scenarios:
        for condition in conditions:
            trial = await run_scenario_condition(
                scenario=scenario,
                condition=condition,
                root=export_dir,
                mode=mode,
                base_url=base_url,
                model=model,
                api_key=api_key,
                temperature=temperature,
                max_iterations=max_iterations,
                estimator_interval=estimator_interval,
                expulsion_threshold=expulsion_threshold,
                start_openclaw_runtime=start_openclaw_runtime,
            )
            all_trials.append(trial["trial"])
            all_event_records.extend(trial["events"])
            all_timeseries.extend(trial["timeseries"])
            log_integrity_rows.append(trial["log_integrity"])

    metadata = {
        "run_id": run_id,
        "created_at_unix": time.time(),
        "runtime": "openclaw-agent",
        "mode": mode,
        "conditions": conditions,
        "scenarios": str(scenarios_path),
        "scenario_count": len(scenarios),
        "trial_count": len(all_trials),
        "agent_specs": {key: str(path) for key, path in AGENT_SPECS.items()},
        "start_openclaw_runtime": start_openclaw_runtime,
        "estimator_interval": estimator_interval,
        "expulsion_threshold": expulsion_threshold,
        "python": sys.version,
        "platform": platform.platform(),
        "model": model if mode == "live-llm" else "scripted-deterministic",
        "base_url": base_url if mode == "live-llm" else "",
        "temperature": temperature,
        "max_iterations": max_iterations,
    }
    _export(export_dir, scenarios_path, scenarios, all_trials, all_event_records, all_timeseries, log_integrity_rows, metadata)
    return {"metadata": metadata, "summary": _summary(all_trials)}


async def run_scenario_condition(
    *,
    scenario: SQ2LiveScenario,
    condition: str,
    root: Path,
    mode: str,
    base_url: str,
    model: str,
    api_key: str,
    temperature: float,
    max_iterations: int,
    estimator_interval: int,
    expulsion_threshold: int,
    start_openclaw_runtime: bool,
) -> dict[str, Any]:
    trial_dir = root / "trials" / _safe(condition) / _safe(scenario.scenario_id)
    trial_dir.mkdir(parents=True, exist_ok=True)
    ctx = _build_run_context(scenario, condition, trial_dir, expulsion_threshold, mode=mode, model=model)
    agents: dict[str, Any] = {}
    started: list[Any] = []
    error: str | None = None

    try:
        async def agent_for(actor_id: str) -> Any:
            if actor_id not in agents:
                agent = _build_disposable_openclaw_agent(trial_dir, actor_id) if mode == "live-llm" or start_openclaw_runtime else None
                agents[actor_id] = agent
                if start_openclaw_runtime and agent is not None:
                    await agent.start()
                    started.append(agent)
            return agents[actor_id]

        if start_openclaw_runtime:
            # Start is still per participating actor; this branch exists so the
            # metadata truthfully records runtime startup while keeping agent
            # creation lazy.
            pass

        for event in scenario.events:
            if ctx.is_expelled(event.actor_id):
                ctx.event_records.append(SQ2EventRecord(
                    scenario_id=scenario.scenario_id,
                    condition=condition,
                    event_index=event.index,
                    round=event.round,
                    actor_id=event.actor_id,
                    event_type=event.event_type,
                    accepted=False,
                    blocked=True,
                    expelled_after_event=ctx.is_expelled(event.actor_id),
                    reason="actor already expelled",
                    tool_name="blocked_before_agent_turn",
                    tool_args={},
                ))
                _record_timeseries(ctx, event)
                continue

            agent = await agent_for(event.actor_id)
            llm = (
                ScriptedSQ2LLM(event)
                if mode == "deterministic"
                else _build_live_tool_llm(base_url=base_url, model=model, api_key=api_key, temperature=temperature)
            )

            submit_called = False

            async def submit_event(tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
                nonlocal submit_called
                submit_called = True
                return await _submit_event(ctx, event, tool_name, tool_args)

            tool_context = SQ2ToolContext(
                scenario_id=scenario.scenario_id,
                condition=condition,
                actor_id=event.actor_id,
                event=event,
                trial_dir=trial_dir,
                submit_event=submit_event,
            )
            tools = build_sq2_live_tools(tool_context)
            final_output = await _run_tool_loop_with_trace(
                _event_prompt(scenario, event),
                llm,
                tools,
                system_prompt=_system_prompt_for_actor(event.actor_id, condition),
                max_iterations=max_iterations,
            )
            ctx.tool_calls.extend(tool_context.trace.calls)
            ctx.tool_results.extend(tool_context.trace.results)
            ctx.final_outputs.append({
                "event_index": event.index,
                "actor_id": event.actor_id,
                "final_output": final_output,
                "openclaw_agent_save_dir": str(agent.config.save_dir) if agent is not None else str(trial_dir / "scripted_agents" / event.actor_id),
            })
            if not submit_called:
                ctx.event_records.append(SQ2EventRecord(
                    scenario_id=scenario.scenario_id,
                    condition=condition,
                    event_index=event.index,
                    round=event.round,
                    actor_id=event.actor_id,
                    event_type=event.event_type,
                    accepted=False,
                    blocked=False,
                    expelled_after_event=ctx.is_expelled(event.actor_id),
                    reason="agent returned final text without executing scenario event",
                    tool_name="none",
                    tool_args={},
                ))
                _record_timeseries(ctx, event)

            if condition == CONDITION_C1 and event.index % estimator_interval == 0 and ctx.estimator is not None:
                ctx.estimator.scan()
                _sync_c1_flags(ctx)

    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        for agent in reversed(started):
            try:
                await agent.stop()
            except Exception as exc:
                stop_error = f"{type(exc).__name__}: {exc}"
                error = f"{error}; stop_error={stop_error}" if error else f"stop_error={stop_error}"

    if condition == CONDITION_C1 and ctx.estimator is not None:
        ctx.estimator.scan()
        _sync_c1_flags(ctx)

    trial = _trial_from_context(ctx, error=error)
    (trial_dir / "trial_result.json").write_text(
        json.dumps(asdict(trial), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (trial_dir / "tool_trace.json").write_text(
        json.dumps({
            "tool_calls": ctx.tool_calls,
            "tool_results": ctx.tool_results,
            "final_outputs": ctx.final_outputs,
        }, indent=2, default=str, sort_keys=True),
        encoding="utf-8",
    )
    log_valid: bool | None = None
    log_errors: list[str] = []
    num_log_entries = 0
    if ctx.signed_log is not None:
        log_valid, log_errors = ctx.signed_log.verify_integrity()
        num_log_entries = len(ctx.signed_log.read_entries())
    return {
        "trial": trial,
        "events": ctx.event_records,
        "timeseries": ctx.timeseries_rows,
        "log_integrity": {
            "scenario_id": scenario.scenario_id,
            "condition": condition,
            "log_chain_valid": log_valid,
            "num_log_entries": num_log_entries,
            "tampering_detected": bool(log_errors),
            "errors": ";".join(log_errors),
            "log_path": str(ctx.signed_log.log_path) if ctx.signed_log is not None else "",
        },
    }


async def _submit_event(
    ctx: SQ2RunContext,
    event: SQ2LiveEvent,
    tool_name: str,
    tool_args: dict[str, Any],
) -> dict[str, Any]:
    gateway = normalize_reputation_tool_call(
        scenario=ctx.scenario,
        condition=ctx.condition,
        event=event,
        tool_name=tool_name,
        tool_args=tool_args,
    )
    if not gateway.ok:
        record = SQ2EventRecord(
            scenario_id=ctx.scenario.scenario_id,
            condition=ctx.condition,
            event_index=event.index,
            round=event.round,
            actor_id=event.actor_id,
            event_type=event.event_type,
            accepted=False,
            blocked=True,
            expelled_after_event=ctx.is_expelled(event.actor_id),
            reason=gateway.reason,
            tool_name=tool_name,
            tool_args=tool_args,
        )
        ctx.event_records.append(record)
        _record_timeseries(ctx, event)
        return {"ok": False, "accepted": False, "blocked": True, "reason": gateway.reason}

    if ctx.is_expelled(event.actor_id):
        record = SQ2EventRecord(
            scenario_id=ctx.scenario.scenario_id,
            condition=ctx.condition,
            event_index=event.index,
            round=event.round,
            actor_id=event.actor_id,
            event_type=event.event_type,
            accepted=False,
            blocked=True,
            expelled_after_event=True,
            reason="actor already expelled",
            tool_name=tool_name,
            tool_args=tool_args,
        )
        ctx.event_records.append(record)
        _record_timeseries(ctx, event)
        return {"ok": False, "blocked": True, "reason": record.reason}

    before_reputation = ctx.reputation(PRIMARY_ATTACKER)
    if ctx.condition == CONDITION_C0:
        assert ctx.naive is not None
        decision = ctx.naive.process_event(event)
        reason = decision.reason
    elif ctx.condition == CONDITION_C1:
        assert ctx.signed_log is not None
        assert ctx.estimator is not None
        if ctx.estimator.is_expelled(event.actor_id):
            decision = _SimpleDecision(False, True, False, "actor already expelled")
            reason = decision.reason
        else:
            ctx.signed_log.append_event(
                reporter_id=ctx.reporter_id,
                subject_id=event.actor_id,
                action=event.event_type,
                severity=0,
                details={
                    "scenario_id": ctx.scenario.scenario_id,
                    "event": sanitized_event_for_agent(event),
                    "canonical_event": gateway.canonical_event,
                    "agent_tool": tool_name,
                    "agent_tool_args": tool_args,
                },
                evidence={"condition": ctx.condition},
            )
            ctx.estimator.scan()
            _sync_c1_flags(ctx)
            decision = _SimpleDecision(True, False, ctx.is_expelled(event.actor_id), "accepted into signed accountability log")
            reason = decision.reason
    else:
        raise ValueError(f"unknown SQ2 condition: {ctx.condition}")

    after_reputation = ctx.reputation(PRIMARY_ATTACKER)
    accepted = bool(decision.accepted)
    primary_already_expelled = ctx.is_expelled(PRIMARY_ATTACKER) and (
        ctx.expulsion_event_index is not None and ctx.expulsion_event_index < event.index
    )
    if accepted and event.malicious and not primary_already_expelled:
        ctx.fallout_broadcasts += 1
    if accepted and event.malicious and event.actor_id == PRIMARY_ATTACKER:
        ctx.fraudulent_reputation_gain += max(0.0, after_reputation - before_reputation)
    if accepted and event.malicious and event.event_type == "microtask_reported":
        ctx.fraudulent_microtasks_accepted += 1
    if accepted and event.malicious and event.event_type == "donation_broadcast":
        ctx.wash_trades_accepted += 1
    if accepted and event.malicious and event.event_type == "peer_endorsement":
        ctx.collusive_endorsements_accepted += 1

    record = SQ2EventRecord(
        scenario_id=ctx.scenario.scenario_id,
        condition=ctx.condition,
        event_index=event.index,
        round=event.round,
        actor_id=event.actor_id,
        event_type=event.event_type,
        accepted=accepted,
        blocked=bool(decision.blocked),
        expelled_after_event=ctx.is_expelled(event.actor_id),
        reason=reason,
        tool_name=tool_name,
        tool_args=tool_args,
    )
    ctx.event_records.append(record)
    _record_timeseries(ctx, event)
    return {
        "ok": accepted,
        "accepted": accepted,
        "blocked": bool(decision.blocked),
        "expelled_after_event": record.expelled_after_event,
        "reason": reason,
        "condition": ctx.condition,
    }


@dataclass
class _SimpleDecision:
    accepted: bool
    blocked: bool
    expelled_now: bool
    reason: str


def _build_run_context(
    scenario: SQ2LiveScenario,
    condition: str,
    trial_dir: Path,
    threshold: int,
    *,
    mode: str,
    model: str,
) -> SQ2RunContext:
    if condition == CONDITION_C0:
        return SQ2RunContext(
            scenario=scenario,
            condition=condition,
            trial_dir=trial_dir,
            threshold=threshold,
            mode=mode,
            model=model if mode == "live-llm" else "scripted-deterministic",
            naive=NaiveReputationState(primary_attacker=scenario.primary_attacker),
        )
    if condition == CONDITION_C1:
        identity = _SQ2SigningIdentity(network="TESTNET", key_path=trial_dir / "accountability_identity.json")
        signed_log = SignedAppendOnlyLog(identity, log_path=str(trial_dir / "accountability.log"))
        estimator = TrustworthyEstimator(
            log=signed_log,
            reporter_id=identity.identity_hash,
            primary_attacker=scenario.primary_attacker,
            expulsion_threshold=threshold,
        )
        return SQ2RunContext(
            scenario=scenario,
            condition=condition,
            trial_dir=trial_dir,
            threshold=threshold,
            mode=mode,
            model=model if mode == "live-llm" else "scripted-deterministic",
            signed_log=signed_log,
            estimator=estimator,
            reporter_id=identity.identity_hash,
        )
    raise ValueError(f"unknown SQ2 condition: {condition}")


def _sync_c1_flags(ctx: SQ2RunContext) -> None:
    if ctx.estimator is None:
        return
    primary = ctx.scenario.primary_attacker
    ctx.first_flag_event_index = ctx.estimator.first_flag_event_index.get(primary)
    ctx.first_flag_round = ctx.estimator.first_flag_round.get(primary)
    ctx.expulsion_event_index = ctx.estimator.expulsion_event_index.get(primary)
    ctx.expulsion_round = ctx.estimator.expulsion_round.get(primary)


def _record_timeseries(ctx: SQ2RunContext, event: SQ2LiveEvent) -> None:
    for agent_id in ALL_AGENTS:
        ctx.timeseries_rows.append({
            "scenario_id": ctx.scenario.scenario_id,
            "condition": ctx.condition,
            "round": event.round,
            "event_index": event.index,
            "agent_id": agent_id,
            "reputation_score": ctx.reputation(agent_id),
            "suspicion_score": ctx.suspicion(agent_id),
            "is_expelled": ctx.is_expelled(agent_id),
        })


def _trial_from_context(ctx: SQ2RunContext, error: str | None) -> SQ2TrialRun:
    scenario = ctx.scenario
    primary = scenario.primary_attacker
    if ctx.condition == CONDITION_C0 and ctx.naive is not None:
        first_flag_event_index = ctx.naive.expulsion_event_index.get(primary)
        first_flag_round = ctx.naive.expulsion_round.get(primary)
        expulsion_event_index = ctx.naive.expulsion_event_index.get(primary)
        expulsion_round = ctx.naive.expulsion_round.get(primary)
        false_positive_count = ctx.naive.false_positive_count
        final_rep = ctx.naive.get_reputation(primary)
        final_suspicion = 0
        reasons = ""
        log_valid = None
    else:
        estimator = ctx.estimator
        first_flag_event_index = estimator.first_flag_event_index.get(primary) if estimator else None
        first_flag_round = estimator.first_flag_round.get(primary) if estimator else None
        expulsion_event_index = estimator.expulsion_event_index.get(primary) if estimator else None
        expulsion_round = estimator.expulsion_round.get(primary) if estimator else None
        false_positive_count = estimator.false_positive_count if estimator else 0
        final_rep = estimator.get_reputation(primary) if estimator else 0.0
        final_suspicion = estimator.get_suspicion(primary) if estimator else 0
        reasons = ",".join(estimator.detection_reasons.get(primary, [])) if estimator else ""
        log_valid = ctx.signed_log.verify_integrity()[0] if ctx.signed_log is not None else None

    expelled = expulsion_event_index is not None
    max_event_index = scenario.events[-1].index
    max_round = scenario.events[-1].round
    if expelled:
        lag_events = max(0, int(expulsion_event_index) - scenario.first_malicious_event_index)
        lag_rounds = max(0, int(expulsion_round or 0) - scenario.first_malicious_round)
    else:
        lag_events = max_event_index - scenario.first_malicious_event_index
        lag_rounds = max_round - scenario.first_malicious_round
    false_positive_rate = false_positive_count / len(HONEST_AGENTS)
    return SQ2TrialRun(
        scenario_id=scenario.scenario_id,
        family=scenario.family,
        intensity=scenario.intensity,
        seed=scenario.seed,
        condition=ctx.condition,
        mode=ctx.mode,
        model=ctx.model,
        num_events=len(scenario.events),
        first_malicious_event_index=scenario.first_malicious_event_index,
        first_malicious_round=scenario.first_malicious_round,
        first_flag_event_index=first_flag_event_index,
        first_flag_round=first_flag_round,
        expelled=expelled,
        expulsion_event_index=expulsion_event_index,
        expulsion_round=expulsion_round,
        reputation_lag_events=lag_events,
        reputation_lag_rounds=lag_rounds,
        censored=not expelled,
        fallout_broadcasts=ctx.fallout_broadcasts,
        fraudulent_microtasks_accepted=ctx.fraudulent_microtasks_accepted,
        wash_trades_accepted=ctx.wash_trades_accepted,
        collusive_endorsements_accepted=ctx.collusive_endorsements_accepted,
        fraudulent_reputation_gain=ctx.fraudulent_reputation_gain,
        false_positive_count=false_positive_count,
        false_positive_rate=false_positive_rate,
        final_attacker_reputation=final_rep,
        final_attacker_suspicion=final_suspicion,
        detection_reasons=reasons,
        log_chain_valid=log_valid,
        error=error,
    )


class _SQ2SigningIdentity:
    def __init__(self, *, network: str, key_path: Path) -> None:
        self.network = network.upper()
        self.key_path = key_path
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        if self.key_path.exists():
            private_bytes = bytes.fromhex(json.loads(self.key_path.read_text(encoding="utf-8"))["private_key"])
            self._private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        else:
            self._private_key = Ed25519PrivateKey.generate()
            private_bytes = self._private_key.private_bytes(
                encoding=Encoding.Raw,
                format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            )
            self.key_path.write_text(json.dumps({"network": self.network, "private_key": private_bytes.hex()}), encoding="utf-8")
        self.public_key = self._private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        self.identity_hash = _stable_identity_hash(self.public_key, self.network)

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)


def _stable_identity_hash(public_key: bytes, network: str) -> str:
    import hashlib

    return hashlib.sha256(public_key + network.encode("utf-8")).hexdigest()


def _build_live_tool_llm(*, base_url: str, model: str, api_key: str, temperature: float) -> Any:
    return _HTTPToolLLM(
        base_url=base_url,
        model_id=model,
        api_key=api_key,
        temperature=temperature,
        timeout_s=120.0,
    )


@dataclass
class _HTTPToolLLM:
    base_url: str
    model_id: str
    api_key: str = ""
    temperature: float = 0.0
    timeout_s: float = 120.0

    def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        payload = {
            "model": self.model_id,
            "messages": messages,
            "tools": tools,
            "temperature": self.temperature,
            "max_tokens": max_tokens,
        }
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base_url.rstrip("/") + "/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "DelftClaw-SQ2/1.0",
                **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as response:
                response_payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} from OpenAI-compatible endpoint: {error_body[:1000]}") from exc

        choices = response_payload.get("choices") or []
        if not choices or not choices[0].get("message"):
            raise RuntimeError(f"OpenAI-compatible endpoint returned no assistant message: {response_payload}")
        return {"message": choices[0]["message"]}


def _build_disposable_openclaw_agent(trial_dir: Path, agent_id: str) -> Any:
    from agent import AgentConfig, OpenClawAgent
    from communication.bittorrent import StubBitTorrentService
    from identity.agent_identity import AgentIdentity
    from identity.seed import Seed
    from protocol.llm import StubLLMClient

    mnemonic = Seed.generate_mnemonic(128)
    identity = AgentIdentity(network="TESTNET", mnemonic=mnemonic)
    save_dir = trial_dir / "openclaw_agents" / agent_id
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


async def _run_tool_loop_with_trace(
    user_query: str,
    llm: Any,
    tools: ToolRegistry,
    *,
    system_prompt: str,
    max_iterations: int,
) -> str:
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_query},
    ]
    for _ in range(max_iterations):
        result = llm.complete_with_tools(messages, tools.specs())
        msg = result["message"]
        messages.append(msg)
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            return msg.get("content") or ""
        for call in tool_calls:
            fn = call["function"]
            name = fn["name"]
            args = _parse_tool_args(fn.get("arguments", "{}"))
            tool_result = await tools.dispatch(name, args)
            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "name": name,
                "content": json.dumps(tool_result, default=str, sort_keys=True),
            })
    return "(tool loop hit max_iterations without final text)"


def _parse_tool_args(args_raw: Any) -> dict[str, Any]:
    if isinstance(args_raw, dict):
        return dict(args_raw)
    if not isinstance(args_raw, str) or not args_raw.strip():
        return {}
    try:
        parsed = json.loads(args_raw)
    except json.JSONDecodeError:
        return {"payload": args_raw}
    if isinstance(parsed, dict):
        return parsed
    return {"payload": parsed}


def _event_prompt(scenario: SQ2LiveScenario, event: SQ2LiveEvent) -> str:
    return (
        "Execute the next SQ2 reputation-trap scenario step through the available tool surface. "
        "First call load_scenario_step, then call the one tool that corresponds to the step. "
        "Do not invent extra events.\n\n"
        f"Scenario: {scenario.scenario_id}\n"
        f"Step: {json.dumps(sanitized_event_for_agent(event), sort_keys=True)}"
    )


def _system_prompt_for_actor(actor_id: str, condition: str) -> str:
    if actor_id == PRIMARY_ATTACKER:
        base = AGENT_SPECS["primary_attacker"].read_text(encoding="utf-8")
    elif actor_id.startswith("S"):
        base = AGENT_SPECS["sybil"].read_text(encoding="utf-8")
    elif actor_id == "AUDITOR":
        base = AGENT_SPECS["auditor"].read_text(encoding="utf-8")
    else:
        base = AGENT_SPECS["honest"].read_text(encoding="utf-8")
    return base + f"\n\nCurrent SQ2 condition: {condition}."


def _export(
    export_dir: Path,
    scenarios_path: Path,
    scenarios: list[SQ2LiveScenario],
    trials: list[SQ2TrialRun],
    event_records: list[SQ2EventRecord],
    timeseries_rows: list[dict[str, Any]],
    log_integrity_rows: list[dict[str, Any]],
    metadata: dict[str, Any],
) -> None:
    trial_rows = [asdict(trial) for trial in trials]
    event_rows = [asdict(record) for record in event_records]
    write_json(export_dir / "sq2_run_metadata.json", metadata)
    write_json(export_dir / "sq2_summary.json", _summary(trials))
    shutil.copyfile(scenarios_path, export_dir / "sq2_scenarios.jsonl")
    _write_csv_ordered(export_dir / "sq2_trials.csv", trial_rows, TRIAL_COLUMNS)
    with (export_dir / "sq2_trials.jsonl").open("w", encoding="utf-8") as handle:
        for trial in trials:
            handle.write(json.dumps(asdict(trial), sort_keys=True) + "\n")
    with (export_dir / "sq2_event_log.jsonl").open("w", encoding="utf-8") as handle:
        for row in event_rows:
            handle.write(json.dumps(row, default=str, sort_keys=True) + "\n")
    _write_csv_ordered(export_dir / "sq2_reputation_timeseries.csv", timeseries_rows, TIMESERIES_COLUMNS)
    write_csv(export_dir / "sq2_expulsions.csv", _expulsion_rows(trials))
    _write_csv_ordered(export_dir / "sq2_lag_by_condition.csv", _lag_rows(trials, "condition"), [c for c in LAG_COLUMNS if c != "family"])
    _write_csv_ordered(export_dir / "sq2_lag_by_family.csv", _lag_rows(trials, "family"), [c for c in LAG_COLUMNS if c != "condition"])
    _write_csv_ordered(export_dir / "sq2_fallout_by_condition.csv", _fallout_rows(trials, "condition"), [c for c in FALLOUT_COLUMNS if c != "family"])
    _write_csv_ordered(export_dir / "sq2_fallout_by_family.csv", _fallout_rows(trials, "family"), [c for c in FALLOUT_COLUMNS if c != "condition"])
    write_csv(export_dir / "sq2_detection_reasons.csv", _detection_reason_rows(trials))
    write_csv(export_dir / "sq2_false_positives.csv", _false_positive_rows(trials))
    write_csv(export_dir / "sq2_log_integrity.csv", log_integrity_rows)
    run_log = export_dir / "run.log"
    if not run_log.exists():
        run_log.write_text(
            "SQ2 live OpenClaw accountability run completed.\n"
            f"trials={len(trials)} scenarios={len(scenarios)}\n",
            encoding="utf-8",
        )


def _write_csv_ordered(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    extras = sorted({key for row in rows for key in row if key not in columns})
    fieldnames = [*columns, *extras]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _summary(trials: list[SQ2TrialRun]) -> dict[str, Any]:
    return {
        "trial_count": len(trials),
        "by_condition": _lag_rows(trials, "condition"),
        "fallout_by_condition": _fallout_rows(trials, "condition"),
    }


def _expulsion_rows(trials: list[SQ2TrialRun]) -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": trial.scenario_id,
            "condition": trial.condition,
            "family": trial.family,
            "intensity": trial.intensity,
            "expelled": trial.expelled,
            "expulsion_event_index": trial.expulsion_event_index,
            "expulsion_round": trial.expulsion_round,
            "detection_reasons": trial.detection_reasons,
        }
        for trial in trials
    ]


def _lag_rows(trials: list[SQ2TrialRun], group_key: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in sorted({getattr(trial, group_key) for trial in trials}):
        group = [trial for trial in trials if getattr(trial, group_key) == key]
        lag_events = sorted(trial.reputation_lag_events for trial in group)
        lag_rounds = sorted(trial.reputation_lag_rounds for trial in group)
        rows.append({
            group_key: key,
            "runs": len(group),
            "expelled_runs": sum(1 for trial in group if trial.expelled),
            "expulsion_rate": _rate(sum(1 for trial in group if trial.expelled), len(group)),
            "mean_reputation_lag_events": _mean(lag_events),
            "median_reputation_lag_events": _median(lag_events),
            "mean_reputation_lag_rounds": _mean(lag_rounds),
            "median_reputation_lag_rounds": _median(lag_rounds),
            "censored_runs": sum(1 for trial in group if trial.censored),
        })
    return rows


def _fallout_rows(trials: list[SQ2TrialRun], group_key: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in sorted({getattr(trial, group_key) for trial in trials}):
        group = [trial for trial in trials if getattr(trial, group_key) == key]
        rows.append({
            group_key: key,
            "runs": len(group),
            "mean_fallout_broadcasts": _mean([trial.fallout_broadcasts for trial in group]),
            "median_fallout_broadcasts": _median([trial.fallout_broadcasts for trial in group]),
            "mean_fraudulent_microtasks_accepted": _mean([trial.fraudulent_microtasks_accepted for trial in group]),
            "mean_wash_trades_accepted": _mean([trial.wash_trades_accepted for trial in group]),
            "mean_collusive_endorsements_accepted": _mean([trial.collusive_endorsements_accepted for trial in group]),
            "mean_fraudulent_reputation_gain": _mean([trial.fraudulent_reputation_gain for trial in group]),
        })
    return rows


def _detection_reason_rows(trials: list[SQ2TrialRun]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str, str], int] = {}
    for trial in trials:
        for reason in [item for item in trial.detection_reasons.split(",") if item]:
            key = (trial.condition, trial.family, reason)
            counts[key] = counts.get(key, 0) + 1
    return [
        {"condition": condition, "family": family, "detection_reason": reason, "count": count}
        for (condition, family, reason), count in sorted(counts.items())
    ]


def _false_positive_rows(trials: list[SQ2TrialRun]) -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": trial.scenario_id,
            "condition": trial.condition,
            "family": trial.family,
            "false_positive_count": trial.false_positive_count,
            "false_positive_rate": trial.false_positive_rate,
        }
        for trial in trials
    ]


def _mean(values: list[float | int]) -> float:
    return float(sum(values) / len(values)) if values else 0.0


def _median(values: list[float | int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return float((ordered[middle - 1] + ordered[middle]) / 2)


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _safe(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SQ2 live OpenClaw accountability measurement.")
    parser.add_argument("--scenarios", type=Path, default=DEFAULT_LIVE_SCENARIOS)
    parser.add_argument("--out", "--export-dir", dest="export_dir", type=Path, required=True)
    parser.add_argument("--conditions", nargs="+", default=[CONDITION_C0, CONDITION_C1])
    parser.add_argument("--mode", choices=("deterministic", "live-llm"), default="live-llm")
    parser.add_argument("--base-url", default=os.getenv("OPENCLAW_BASE_URL") or os.getenv("QWEN_BASE_URL", "http://127.0.0.1:11434/v1"))
    parser.add_argument("--model", default=os.getenv("OPENCLAW_MODEL") or os.getenv("QWEN_MODEL", "qwen2.5-coder:7b"))
    parser.add_argument("--api-key", default=os.getenv(os.getenv("OPENCLAW_API_KEY_ENV", "OPENAI_API_KEY"), ""))
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-iterations", type=int, default=5)
    parser.add_argument("--estimator-interval", type=int, default=1)
    parser.add_argument("--expulsion-threshold", type=int, default=EXPULSION_SUSPICION_THRESHOLD)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--start-openclaw-runtime",
        action="store_true",
        help="Start each disposable OpenClawAgent IPv8 runtime. Use for paper runs; deterministic tests can omit it.",
    )
    args = parser.parse_args()

    report = asyncio.run(run_live_measurement(
        scenarios_path=args.scenarios,
        export_dir=args.export_dir,
        conditions=args.conditions,
        mode=args.mode,
        base_url=args.base_url,
        model=args.model,
        api_key=args.api_key,
        temperature=args.temperature,
        max_iterations=args.max_iterations,
        estimator_interval=args.estimator_interval,
        expulsion_threshold=args.expulsion_threshold,
        limit=args.limit,
        start_openclaw_runtime=args.start_openclaw_runtime,
    ))
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
