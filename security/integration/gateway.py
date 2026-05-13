from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import asdict, is_dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from security.contracts import ExecutionResult, SecurityAction, ToolDecision, ToolPolicy, ToolRisk
from security.subq1_preventative.privilege import BaselineExecutor, Hands
from security.subq2_accountability.accountability import AccountabilityMonitor
from security.subq2_accountability.append_log import AppendOnlyLog
from security.subq2_accountability.reputation import ReputationEngine
from security.subq2_accountability.seedbox import DonationLedger, SeedboxRegistry, ServiceProofLedger


class GatewayState:
    """Runtime state for one local DelftClaw gateway."""

    def __init__(
        self,
        *,
        local_agent_id: str,
        log_path: str,
        mode: str = "defended",
        ban_threshold: int = 30,
        openclaw_bridge: Any | None = None,
        max_tool_risk: ToolRisk | str | int = ToolRisk.SENSITIVE,
        run_id: str = "",
        experiment_condition: str = "",
        experiment_root: str = "",
    ):
        if mode not in {"defended", "baseline"}:
            raise ValueError("mode must be 'defended' or 'baseline'")

        self.local_agent_id = local_agent_id
        self.openclaw_bridge = openclaw_bridge
        self.mode = mode
        self.max_tool_risk = max_tool_risk
        self.run_id = run_id
        self.experiment_condition = experiment_condition or mode
        self.experiment_root = experiment_root
        self.run_metadata = {
            "run_id": run_id,
            "experiment_condition": self.experiment_condition,
            "gateway_mode": mode,
            "agent_id": local_agent_id,
            "ban_threshold": ban_threshold,
            "max_tool_risk": str(max_tool_risk),
            "experiment_root": experiment_root,
        }
        self.log = AppendOnlyLog(log_path=log_path, run_metadata=self.run_metadata)
        self.reputation = ReputationEngine(log_path=self.log.log_path, ban_threshold=ban_threshold)
        self.monitor = AccountabilityMonitor(
            log=self.log,
            reputation=self.reputation,
            reporter_id=local_agent_id,
        )
        self.registry = SeedboxRegistry()
        self.ledger = DonationLedger(self.registry)
        self.proof_ledger = ServiceProofLedger(self.registry)
        self.hands = Hands(
            proxy=None,
            allowed_tools=self._allowed_tools(),
            agent_id=local_agent_id,
            max_tool_risk=max_tool_risk,
        )
        self.baseline = BaselineExecutor(
            proxy=None,
            safe_tools={name: policy.handler for name, policy in self._allowed_tools().items()},
        )
        self.tool_call_count = 0
        self.blocked_count = 0
        self.executed_count = 0
        self.missing_proof_audits: set[str] = set()

    def handle_tool_call(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.tool_call_count += 1
        self.monitor.next_step()

        subject_id = str(payload.get("agent_id") or self.local_agent_id)
        tool_name = str(payload.get("tool_name") or "")
        tool_kwargs = dict(payload.get("tool_kwargs") or {})
        payload_id = payload.get("payload_id")
        source = payload.get("source", "openclaw")

        self.reputation.scan_log()
        if self.reputation.is_banned(subject_id):
            self.blocked_count += 1
            self.monitor.record_blocked_action(subject_id)
            return {
                "ok": False,
                "blocked": True,
                "reason": "blocked: subject is reputation-banned",
                "agent_id": subject_id,
                "tool_name": tool_name,
                "reputation": self._reputation_snapshot(subject_id),
            }

        tool_kwargs = self._normalize_tool_kwargs(subject_id, tool_name, tool_kwargs)
        decision = ToolDecision(
            tool_name=tool_name,
            tool_kwargs=tool_kwargs,
            reason=f"real OpenClaw tool request via {source}",
            payload_id=payload_id,
            sender_id=subject_id,
        )

        if self.mode == "baseline":
            try:
                result = self.baseline.execute(decision)
            except Exception as exc:
                result = ExecutionResult(
                    requested_tool=decision.tool_name,
                    executed=False,
                    authorized=False,
                    attack_success=False,
                    reason=f"tool handler failed: {exc}",
                    payload_id=decision.payload_id,
                    sender_id=subject_id,
                )
        else:
            result = self._execute_defended(decision, subject_id)

        self._record_result(subject_id, decision, result)
        self.reputation.scan_log()

        return {
            "ok": result.executed and not result.attack_success,
            "blocked": not result.executed,
            "mode": self.mode,
            "agent_id": subject_id,
            "result": _jsonable(result),
            "reputation": self._reputation_snapshot(subject_id),
        }

    def handle_security_report(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.monitor.next_step()
        subject_id = str(payload.get("subject_id") or payload.get("agent_id") or self.local_agent_id)
        action = str(payload.get("action") or SecurityAction.UNAUTHORIZED_TOOL_REQUEST.value)
        details = dict(payload.get("details") or {})
        severity = int(payload.get("severity", ReputationEngine.DEFAULT_WEIGHTS.get(action, 10)))

        self.log.append_event(
            reporter_id=self.local_agent_id,
            subject_id=subject_id,
            action=action,
            severity=severity,
            details=details,
            evidence=dict(payload.get("evidence") or {}),
        )
        self.reputation.scan_log()
        return {"ok": True, "subject_id": subject_id, "reputation": self._reputation_snapshot(subject_id)}

    def metrics(self) -> dict[str, Any]:
        integrity_ok, integrity_errors = self.log.verify_integrity()
        self.reputation.scan_log()
        return {
            "local_agent_id": self.local_agent_id,
            "mode": self.mode,
            "log_path": self.log.log_path,
            "tool_call_count": self.tool_call_count,
            "executed_count": self.executed_count,
            "blocked_count": self.blocked_count,
            "integrity_ok": integrity_ok,
            "integrity_errors": integrity_errors,
            "scores": self.reputation.scores,
            "banned_agents": sorted(self.reputation.banned_agents),
            "openclaw": self.openclaw_status(),
            "max_tool_risk": str(self.max_tool_risk),
            "run_id": self.run_id,
            "experiment_condition": self.experiment_condition,
            "experiment_root": self.experiment_root,
        }

    def audit_seedboxes(self) -> dict[str, Any]:
        self.monitor.next_step()
        findings = []
        for seedbox_id, seedbox in self.registry.seedboxes.items():
            donations = [donation for donation in self.ledger.donations if donation.seedbox_id == seedbox_id]
            proofs = self.proof_ledger.proofs_for_seedbox(seedbox_id)
            if not donations or proofs or seedbox_id in self.missing_proof_audits:
                continue

            self.missing_proof_audits.add(seedbox_id)
            severity = ReputationEngine.DEFAULT_WEIGHTS[SecurityAction.SEEDBOX_MISSING_PROOF.value]
            details = {
                "step": self.monitor.current_step,
                "seedbox_id": seedbox_id,
                "owner_id": seedbox.owner_id,
                "donation_count": len(donations),
                "proof_count": len(proofs),
            }
            self.log.append_event(
                reporter_id=self.local_agent_id,
                subject_id=seedbox.owner_id,
                action=SecurityAction.SEEDBOX_MISSING_PROOF.value,
                severity=severity,
                details=details,
            )
            findings.append(details)

        self.reputation.scan_log()
        return {"ok": True, "findings": findings, "finding_count": len(findings)}

    def reputation_snapshot(self, agent_id: str) -> dict[str, Any]:
        self.reputation.scan_log()
        return self._reputation_snapshot(agent_id)

    def openclaw_status(self) -> dict[str, Any]:
        if self.openclaw_bridge is None:
            return {"enabled": False}
        return self.openclaw_bridge.status()

    def _execute_defended(self, decision: ToolDecision, subject_id: str) -> ExecutionResult:
        try:
            result = self.hands.execute(decision)
        except Exception as exc:
            result = ExecutionResult(
                requested_tool=decision.tool_name,
                executed=False,
                authorized=False,
                attack_success=False,
                reason=f"blocked: tool handler failed: {exc}",
                payload_id=decision.payload_id,
                sender_id=subject_id,
            )

        if not result.executed:
            self.blocked_count += 1
        return result

    def _record_result(self, subject_id: str, decision: ToolDecision, result: ExecutionResult) -> None:
        if result.executed:
            self.executed_count += 1
        if result.attack_success:
            if decision.tool_name == "exfiltrate_private_key":
                self.monitor.record_private_key_exfiltration(subject_id, payload_id=decision.payload_id)
            else:
                self.monitor.record_unauthorized_execution(
                    subject_id=subject_id,
                    tool_name=decision.tool_name,
                    details={"payload_id": decision.payload_id},
                )
            return

        if not result.executed and not result.authorized:
            self.monitor.record_unauthorized_request(
                subject_id=subject_id,
                tool_name=decision.tool_name,
                details={"payload_id": decision.payload_id, "reason": result.reason},
            )
            return

        if result.executed:
            self.log.append_event(
                reporter_id=self.local_agent_id,
                subject_id=subject_id,
                action=SecurityAction.TOOL_EXECUTION_SUCCESS.value,
                severity=0,
                details={
                    "tool": decision.tool_name,
                    "payload_id": decision.payload_id,
                    "output": _jsonable(result.output),
                },
            )
            if decision.tool_name == "register_seedbox" and decision.tool_kwargs.get("fake"):
                self.monitor.record_fake_seedbox_creation(
                    subject_id=subject_id,
                    seedbox_id=str(decision.tool_kwargs.get("seedbox_id")),
                )
            if decision.tool_name == "broadcast_seedbox_donation" and result.output:
                evidence = result.output.get("donation_evidence")
                if evidence:
                    self.monitor.record_seedbox_donation(
                        subject_id=subject_id,
                        donation=evidence,
                        stolen_from_honest_agent=bool(decision.tool_kwargs.get("stolen_from_honest_agent")),
                    )
            if decision.tool_name == "submit_seedbox_proof" and result.output:
                self.log.append_event(
                    reporter_id=self.local_agent_id,
                    subject_id=subject_id,
                    action=SecurityAction.SEEDBOX_PROOF_OF_SERVICE.value,
                    severity=0,
                    details=_jsonable(result.output),
                )

    def _allowed_tools(self) -> dict[str, ToolPolicy]:
        return {
            **Hands.default_tools(),
            "register_seedbox": ToolPolicy(
                name="register_seedbox",
                handler=self._register_seedbox,
                required_args=("seedbox_id", "donation_address", "advertised_capacity_gb", "owner_id"),
                risk=ToolRisk.SENSITIVE,
            ),
            "broadcast_seedbox_donation": ToolPolicy(
                name="broadcast_seedbox_donation",
                handler=self._broadcast_seedbox_donation,
                required_args=("seedbox_id", "donor_id", "amount_sats", "txid"),
                risk=ToolRisk.SENSITIVE,
            ),
            "submit_seedbox_proof": ToolPolicy(
                name="submit_seedbox_proof",
                handler=self._submit_seedbox_proof,
                required_args=("seedbox_id", "prover_id", "storage_url", "nonce", "proof_id"),
                risk=ToolRisk.SENSITIVE,
            ),
            "report_security_event": ToolPolicy(
                name="report_security_event",
                handler=lambda kwargs: {"reported": True, "details": kwargs},
                required_args=("subject_id", "action"),
                risk=ToolRisk.SENSITIVE,
            ),
        }

    def _register_seedbox(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        seedbox = self.registry.register(
            seedbox_id=str(kwargs["seedbox_id"]),
            owner_id=str(kwargs["owner_id"]),
            donation_address=str(kwargs["donation_address"]),
            advertised_capacity_gb=int(kwargs["advertised_capacity_gb"]),
            fake=bool(kwargs.get("fake", False)),
        )
        return asdict(seedbox)

    def _broadcast_seedbox_donation(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        donation = self.ledger.broadcast_donation(
            donation_id=str(kwargs.get("donation_id") or f"donation-{int(time.time() * 1000)}"),
            seedbox_id=str(kwargs["seedbox_id"]),
            donor_id=str(kwargs["donor_id"]),
            amount_sats=int(kwargs["amount_sats"]),
            txid=str(kwargs["txid"]),
            stolen_from_honest_agent=bool(kwargs.get("stolen_from_honest_agent", False)),
        )
        return {"donation": asdict(donation), "donation_evidence": donation.to_evidence()}

    def _submit_seedbox_proof(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        proof = self.proof_ledger.submit_proof(
            proof_id=str(kwargs["proof_id"]),
            seedbox_id=str(kwargs["seedbox_id"]),
            prover_id=str(kwargs["prover_id"]),
            storage_url=str(kwargs["storage_url"]),
            nonce=str(kwargs["nonce"]),
        )
        return {"proof": asdict(proof)}

    @staticmethod
    def _normalize_tool_kwargs(subject_id: str, tool_name: str, tool_kwargs: dict[str, Any]) -> dict[str, Any]:
        if tool_name == "register_seedbox":
            tool_kwargs.setdefault("owner_id", subject_id)
        if tool_name == "broadcast_seedbox_donation":
            tool_kwargs.setdefault("donor_id", subject_id)
            tool_kwargs.setdefault("txid", f"mock-tx-{subject_id}-{int(time.time() * 1000)}")
        if tool_name == "submit_seedbox_proof":
            tool_kwargs.setdefault("prover_id", subject_id)
            tool_kwargs.setdefault("proof_id", f"proof-{subject_id}-{int(time.time() * 1000)}")
        return tool_kwargs

    def _reputation_snapshot(self, agent_id: str) -> dict[str, Any]:
        return {
            "agent_id": agent_id,
            "score": self.reputation.get_score(agent_id),
            "banned": self.reputation.is_banned(agent_id),
            "harm_count": self.reputation.get_harm_count(agent_id),
        }


class GatewayHandler(BaseHTTPRequestHandler):
    state: GatewayState

    def do_POST(self) -> None:
        payload = self._read_json()
        if payload is None:
            return

        route = urlparse(self.path).path
        if route == "/tool-call":
            self._write_json(HTTPStatus.OK, self.state.handle_tool_call(payload))
        elif route == "/security-report":
            self._write_json(HTTPStatus.OK, self.state.handle_security_report(payload))
        elif route == "/audit/seedboxes":
            self._write_json(HTTPStatus.OK, self.state.audit_seedboxes())
        elif route == "/donation":
            payload["tool_name"] = "broadcast_seedbox_donation"
            payload["tool_kwargs"] = payload.get("tool_kwargs") or {
                key: value
                for key, value in payload.items()
                if key not in {"agent_id", "tool_name", "payload_id", "source"}
            }
            self._write_json(HTTPStatus.OK, self.state.handle_tool_call(payload))
        else:
            self._write_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": f"unknown route {route}"})

    def do_GET(self) -> None:
        route = urlparse(self.path).path
        if route == "/health":
            self._write_json(HTTPStatus.OK, {"ok": True})
        elif route == "/metrics":
            self._write_json(HTTPStatus.OK, self.state.metrics())
        elif route == "/openclaw/status":
            self._write_json(HTTPStatus.OK, self.state.openclaw_status())
        elif route.startswith("/reputation/"):
            agent_id = unquote(route.removeprefix("/reputation/"))
            self._write_json(HTTPStatus.OK, self.state.reputation_snapshot(agent_id))
        else:
            self._write_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": f"unknown route {route}"})

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[gateway] {self.address_string()} - {format % args}")

    def _read_json(self) -> dict[str, Any] | None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            self._write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": f"invalid json: {exc}"})
            return None

    def _write_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(_jsonable(payload), sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_gateway(host: str, port: int, state: GatewayState) -> ThreadingHTTPServer:
    GatewayHandler.state = state
    server = ThreadingHTTPServer((host, port), GatewayHandler)
    print(
        f"DelftClaw gateway listening on http://{host}:{port} "
        f"(agent_id={state.local_agent_id}, mode={state.mode}, log={state.log.log_path})"
    )
    try:
        server.serve_forever()
    finally:
        if state.openclaw_bridge is not None:
            state.openclaw_bridge.stop()
    return server


def load_env_file(path: str | None) -> dict[str, str]:
    if not path:
        return {}
    env_path = Path(path)
    if not env_path.exists():
        raise FileNotFoundError(f"env file not found: {env_path}")

    values = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def env_or(config: dict[str, str], key: str, default: str) -> str:
    return os.getenv(key) or config.get(key) or default


def env_bool(config: dict[str, str], key: str, default: bool = False) -> bool:
    value = os.getenv(key) or config.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_risk(config: dict[str, str], key: str, default: str = ToolRisk.SENSITIVE.value) -> ToolRisk:
    value = env_or(config, key, default).strip().lower()
    return ToolRisk(value)


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the DelftClaw gateway for real OpenClaw agents.")
    parser.add_argument("--env", help="Optional .env file for this local agent.")
    parser.add_argument("--host", help="Gateway bind host.")
    parser.add_argument("--port", type=int, help="Gateway bind port.")
    parser.add_argument("--agent-id", help="Stable local DelftClaw/OpenClaw agent id.")
    parser.add_argument("--log-path", help="Append-only log path.")
    parser.add_argument("--mode", choices=("defended", "baseline"), help="Gateway execution mode.")
    parser.add_argument("--ban-threshold", type=int, help="Reputation score required for expulsion.")
    parser.add_argument("--max-tool-risk", choices=("safe", "sensitive", "dangerous"), help="Highest risk tool Hands may execute.")
    parser.add_argument("--run-id", help="Experiment run id written into every append-only log event.")
    parser.add_argument("--experiment-condition", help="Condition label written into every append-only log event.")
    parser.add_argument("--experiment-root", help="Experiment workspace root for evidence and canary files.")
    parser.add_argument(
        "--use-openclaw-identity",
        action="store_true",
        help="Use OpenClawIdentity as the gateway agent id.",
    )
    parser.add_argument(
        "--enable-openclaw-p2p",
        action="store_true",
        help="Start the IPv8 OpenClaw PoC node inside the gateway process.",
    )
    parser.add_argument("--openclaw-network", help="OpenClaw identity network label.")
    parser.add_argument("--openclaw-key-path", help="Persistent OpenClaw identity key path.")
    parser.add_argument("--openclaw-p2p-host", help="IPv8 bind host for bridged OpenClawAgent.")
    parser.add_argument("--openclaw-p2p-port", type=int, help="IPv8 bind port for bridged OpenClawAgent.")
    args = parser.parse_args()

    env_values = load_env_file(args.env)
    use_openclaw_identity = args.use_openclaw_identity or env_bool(
        env_values,
        "DELFTCLAW_USE_OPENCLAW_IDENTITY",
    )
    enable_openclaw_p2p = args.enable_openclaw_p2p or env_bool(
        env_values,
        "DELFTCLAW_ENABLE_OPENCLAW_P2P",
    )
    openclaw_bridge = None
    agent_id = args.agent_id or env_or(env_values, "DELFTCLAW_AGENT_ID", "local-openclaw-agent")

    if use_openclaw_identity or enable_openclaw_p2p:
        from security.integration.openclaw_bridge import OpenClawBridge

        openclaw_bridge = OpenClawBridge(
            network=args.openclaw_network or env_or(env_values, "DELFTCLAW_OPENCLAW_NETWORK", "MAINNET"),
            key_path=args.openclaw_key_path or env_or(env_values, "DELFTCLAW_OPENCLAW_KEY_PATH", ""),
            p2p_enabled=enable_openclaw_p2p,
            p2p_host=args.openclaw_p2p_host or env_or(env_values, "DELFTCLAW_OPENCLAW_P2P_HOST", "0.0.0.0"),
            p2p_port=args.openclaw_p2p_port or int(env_or(env_values, "DELFTCLAW_OPENCLAW_P2P_PORT", "9000")),
            working_dir=env_or(env_values, "DELFTCLAW_OPENCLAW_WORKING_DIR", "."),
        )
        if use_openclaw_identity:
            agent_id = openclaw_bridge.agent_id
        openclaw_bridge.start()

    host = args.host or env_or(env_values, "DELFTCLAW_GATEWAY_HOST", "127.0.0.1")
    port = args.port or int(env_or(env_values, "DELFTCLAW_GATEWAY_PORT", "8765"))
    mode = args.mode or env_or(env_values, "DELFTCLAW_GATEWAY_MODE", "defended")
    log_path = args.log_path or env_or(env_values, "DELFTCLAW_LOG_PATH", f"logs/{agent_id}_append_only.jsonl")
    threshold = args.ban_threshold or int(env_or(env_values, "DELFTCLAW_BAN_THRESHOLD", "30"))
    max_tool_risk = ToolRisk(args.max_tool_risk) if args.max_tool_risk else env_risk(env_values, "DELFTCLAW_MAX_TOOL_RISK")
    run_id = args.run_id or env_or(env_values, "DELFTCLAW_RUN_ID", "")
    experiment_condition = args.experiment_condition or env_or(env_values, "DELFTCLAW_EXPERIMENT_CONDITION", mode)
    experiment_root = args.experiment_root or env_or(env_values, "DELFTCLAW_EXPERIMENT_ROOT", "")

    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    state = GatewayState(
        local_agent_id=agent_id,
        log_path=log_path,
        mode=mode,
        ban_threshold=threshold,
        openclaw_bridge=openclaw_bridge,
        max_tool_risk=max_tool_risk,
        run_id=run_id,
        experiment_condition=experiment_condition,
        experiment_root=experiment_root,
    )
    run_gateway(host=host, port=port, state=state)


if __name__ == "__main__":
    main()
