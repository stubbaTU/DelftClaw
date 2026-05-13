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
from security.subq2_accountability.bitcoin_anchor import BitcoinAnchor, BitcoinAnchorVerifier
from security.subq2_accountability.reputation import ReputationEngine
from security.subq2_accountability.seedbox import (
    AtomicMicrotask,
    AtomicMicrotaskLedger,
    Donation,
    DonationLedger,
    IndexedFile,
    SeedboxContentIndex,
    Seedbox,
    SeedboxRegistry,
    ServiceProof,
    ServiceProofLedger,
)


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
        bitcoin_network: str = "mock",
        bitcoin_min_confirmations: int = 0,
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
        self.bitcoin_network = bitcoin_network
        self.bitcoin_anchor_verifier = BitcoinAnchorVerifier(
            network=bitcoin_network,
            min_confirmations=bitcoin_min_confirmations,
        )
        self.run_metadata = {
            "run_id": run_id,
            "experiment_condition": self.experiment_condition,
            "gateway_mode": mode,
            "agent_id": local_agent_id,
            "ban_threshold": ban_threshold,
            "max_tool_risk": str(max_tool_risk),
            "experiment_root": experiment_root,
            "bitcoin_network": bitcoin_network,
            "bitcoin_min_confirmations": bitcoin_min_confirmations,
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
        self.microtask_ledger = AtomicMicrotaskLedger(self.registry)
        self.content_index = SeedboxContentIndex(self.registry)
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
        self.state_reload_errors: list[str] = []
        self._reload_runtime_state_from_log()

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
            "bitcoin_network": self.bitcoin_network,
            "loaded_seedbox_count": len(self.registry.seedboxes),
            "loaded_seedbox_file_count": len(self.content_index.files),
            "state_reload_ok": not self.state_reload_errors,
            "state_reload_errors": list(self.state_reload_errors),
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
            "submit_atomic_microtask": ToolPolicy(
                name="submit_atomic_microtask",
                handler=self._submit_atomic_microtask,
                required_args=("task_id", "seedbox_id", "prover_id", "task_type", "file_hash", "result_hash"),
                risk=ToolRisk.SENSITIVE,
            ),
            "verify_atomic_microtask": ToolPolicy(
                name="verify_atomic_microtask",
                handler=self._verify_atomic_microtask,
                required_args=("task_id", "expected_result_hash"),
                risk=ToolRisk.SENSITIVE,
            ),
            "report_security_event": ToolPolicy(
                name="report_security_event",
                handler=lambda kwargs: {"reported": True, "details": kwargs},
                required_args=("subject_id", "action"),
                risk=ToolRisk.SENSITIVE,
            ),
            "index_seedbox_file": ToolPolicy(
                name="index_seedbox_file",
                handler=self._index_seedbox_file,
                required_args=("file_id", "seedbox_id", "name", "content_url"),
                risk=ToolRisk.SENSITIVE,
            ),
            "list_seedbox_files": ToolPolicy(
                name="list_seedbox_files",
                handler=self._list_seedbox_files,
                required_args=(),
                risk=ToolRisk.SAFE,
            ),
            "search_seedbox_files": ToolPolicy(
                name="search_seedbox_files",
                handler=self._search_seedbox_files,
                required_args=("query",),
                risk=ToolRisk.SAFE,
            ),
            "pick_random_seedbox_file": ToolPolicy(
                name="pick_random_seedbox_file",
                handler=self._pick_random_seedbox_file,
                required_args=(),
                risk=ToolRisk.SAFE,
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
        seedbox = self.registry.get(str(kwargs["seedbox_id"]))
        confirmations = int(kwargs.get("confirmations", 0))
        output_index = kwargs.get("output_index")
        anchor = self.bitcoin_anchor_verifier.build_anchor(
            txid=str(kwargs["txid"]),
            donation_address=seedbox.donation_address,
            amount_sats=int(kwargs["amount_sats"]),
            seedbox_id=seedbox.seedbox_id,
            confirmations=confirmations,
            output_index=int(output_index) if output_index is not None else None,
        )
        donation = self.ledger.broadcast_donation(
            donation_id=str(kwargs.get("donation_id") or f"donation-{int(time.time() * 1000)}"),
            seedbox_id=seedbox.seedbox_id,
            donor_id=str(kwargs["donor_id"]),
            amount_sats=int(kwargs["amount_sats"]),
            txid=str(kwargs["txid"]),
            stolen_from_honest_agent=bool(kwargs.get("stolen_from_honest_agent", False)),
            bitcoin_anchor=anchor,
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

    def _submit_atomic_microtask(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        microtask = self.microtask_ledger.submit_result(
            task_id=str(kwargs["task_id"]),
            seedbox_id=str(kwargs["seedbox_id"]),
            prover_id=str(kwargs["prover_id"]),
            task_type=str(kwargs["task_type"]),
            file_hash=str(kwargs["file_hash"]),
            result_hash=str(kwargs["result_hash"]),
        )
        self.monitor.record_atomic_microtask(subject_id=str(kwargs["prover_id"]), microtask=microtask.to_evidence())
        return {"microtask": asdict(microtask), "microtask_evidence": microtask.to_evidence()}

    def _verify_atomic_microtask(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        task_id = str(kwargs["task_id"])
        expected_result_hash = str(kwargs["expected_result_hash"])
        current = self.microtask_ledger.get(task_id)
        try:
            microtask = self.microtask_ledger.verify_result(
                task_id=task_id,
                expected_result_hash=expected_result_hash,
            )
        except ValueError:
            self.monitor.record_rejected_atomic_microtask(
                subject_id=current.prover_id,
                task_id=task_id,
                expected_result_hash=expected_result_hash,
                actual_result_hash=current.result_hash,
            )
            raise
        self.monitor.record_atomic_microtask(subject_id=microtask.prover_id, microtask=microtask.to_evidence())
        return {"verified": True, "microtask": asdict(microtask), "microtask_evidence": microtask.to_evidence()}

    def _index_seedbox_file(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        tags = kwargs.get("tags", ())
        if isinstance(tags, str):
            tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
        indexed_file = self.content_index.index_file(
            file_id=str(kwargs["file_id"]),
            seedbox_id=str(kwargs["seedbox_id"]),
            name=str(kwargs["name"]),
            content_url=str(kwargs["content_url"]),
            sha256=str(kwargs.get("sha256", "")),
            size_bytes=int(kwargs.get("size_bytes", 0)),
            media_type=str(kwargs.get("media_type", "")),
            tags=tuple(str(tag) for tag in tags),
        )
        return {"indexed": True, "file": asdict(indexed_file)}

    def _list_seedbox_files(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        files = [asdict(item) for item in self.content_index.list_files()]
        return {"count": len(files), "files": files}

    def _search_seedbox_files(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        query = str(kwargs.get("query", ""))
        files = [asdict(item) for item in self.content_index.search(query)]
        return {"query": query, "count": len(files), "files": files}

    def _pick_random_seedbox_file(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        query = str(kwargs.get("query", ""))
        indexed_file = self.content_index.random_match(query)
        file_payload = asdict(indexed_file)
        return {
            "query": query,
            "file": file_payload,
            "playback_intent": {
                "action": "play",
                "url": indexed_file.content_url,
                "title": indexed_file.name,
                "media_type": indexed_file.media_type,
            },
        }

    def _reload_runtime_state_from_log(self) -> None:
        integrity_ok, integrity_errors = self.log.verify_integrity()
        if not integrity_ok:
            self.state_reload_errors.extend(integrity_errors)
            return

        for entry in self.log.read_entries():
            details = entry.get("details")
            if isinstance(details, dict):
                step = details.get("step")
                if isinstance(step, int) and not isinstance(step, bool):
                    self.monitor.current_step = max(self.monitor.current_step, step)
            try:
                self._replay_log_entry(entry)
            except Exception as exc:
                action = entry.get("action", "<unknown>")
                entry_hash = str(entry.get("entry_hash", ""))[:12]
                self.state_reload_errors.append(f"could not replay {action} entry {entry_hash}: {exc}")

    def _replay_log_entry(self, entry: dict[str, Any]) -> None:
        action = entry.get("action")
        details = entry.get("details")
        if not isinstance(details, dict):
            return

        if action == SecurityAction.SEEDBOX_MISSING_PROOF.value:
            seedbox_id = details.get("seedbox_id")
            if seedbox_id:
                self.missing_proof_audits.add(str(seedbox_id))
            return

        if action != SecurityAction.TOOL_EXECUTION_SUCCESS.value:
            return

        tool = details.get("tool")
        output = details.get("output")
        if not isinstance(output, dict):
            return

        if tool == "register_seedbox":
            self._restore_seedbox(output)
        elif tool == "broadcast_seedbox_donation":
            self._restore_donation(output.get("donation"))
        elif tool == "submit_seedbox_proof":
            self._restore_service_proof(output.get("proof"))
        elif tool in {"submit_atomic_microtask", "verify_atomic_microtask"}:
            self._restore_atomic_microtask(output.get("microtask"))
        elif tool == "index_seedbox_file":
            self._restore_indexed_file(output.get("file"))

    def _restore_seedbox(self, value: Any) -> None:
        if not isinstance(value, dict):
            return
        seedbox = Seedbox(
            seedbox_id=str(value["seedbox_id"]),
            owner_id=str(value["owner_id"]),
            donation_address=str(value["donation_address"]),
            advertised_capacity_gb=int(value["advertised_capacity_gb"]),
            created_at=str(value.get("created_at", "")),
            fake=bool(value.get("fake", False)),
        )
        self.registry.seedboxes[seedbox.seedbox_id] = seedbox

    def _restore_donation(self, value: Any) -> None:
        if not isinstance(value, dict):
            return
        seedbox_id = str(value["seedbox_id"])
        if seedbox_id not in self.registry.seedboxes:
            raise KeyError(f"unknown seedbox {seedbox_id}")
        donation = Donation(
            donation_id=str(value["donation_id"]),
            seedbox_id=seedbox_id,
            donor_id=str(value["donor_id"]),
            recipient_id=str(value["recipient_id"]),
            amount_sats=int(value["amount_sats"]),
            txid=str(value["txid"]),
            timestamp=str(value.get("timestamp", "")),
            self_donation=bool(value.get("self_donation", False)),
            fake_seedbox=bool(value.get("fake_seedbox", False)),
            stolen_from_honest_agent=bool(value.get("stolen_from_honest_agent", False)),
            bitcoin_anchor=self._restore_bitcoin_anchor(value.get("bitcoin_anchor")),
        )
        self.ledger.donations = [
            item for item in self.ledger.donations if item.donation_id != donation.donation_id
        ]
        self.ledger.donations.append(donation)

    @staticmethod
    def _restore_bitcoin_anchor(value: Any) -> BitcoinAnchor | None:
        if not isinstance(value, dict) or not value:
            return None
        return BitcoinAnchor(
            txid=str(value["txid"]),
            donation_address=str(value["donation_address"]),
            amount_sats=int(value["amount_sats"]),
            seedbox_id=str(value["seedbox_id"]),
            network=str(value.get("network", "mock")),
            confirmations=int(value.get("confirmations", 0)),
            output_index=(
                int(value["output_index"])
                if value.get("output_index") is not None
                else None
            ),
            verified=bool(value.get("verified", False)),
            verification_reason=str(value.get("verification_reason", "")),
            anchor_id=str(value.get("anchor_id", "")),
        )

    def _restore_service_proof(self, value: Any) -> None:
        if not isinstance(value, dict):
            return
        seedbox_id = str(value["seedbox_id"])
        if seedbox_id not in self.registry.seedboxes:
            raise KeyError(f"unknown seedbox {seedbox_id}")
        proof = ServiceProof(
            proof_id=str(value["proof_id"]),
            seedbox_id=seedbox_id,
            prover_id=str(value["prover_id"]),
            storage_url=str(value["storage_url"]),
            nonce=str(value["nonce"]),
            timestamp=str(value.get("timestamp", "")),
        )
        self.proof_ledger.proofs = [
            item for item in self.proof_ledger.proofs if item.proof_id != proof.proof_id
        ]
        self.proof_ledger.proofs.append(proof)

    def _restore_atomic_microtask(self, value: Any) -> None:
        if not isinstance(value, dict):
            return
        seedbox_id = str(value["seedbox_id"])
        if seedbox_id not in self.registry.seedboxes:
            raise KeyError(f"unknown seedbox {seedbox_id}")
        microtask = AtomicMicrotask(
            task_id=str(value["task_id"]),
            seedbox_id=seedbox_id,
            prover_id=str(value["prover_id"]),
            task_type=str(value["task_type"]),
            file_hash=str(value["file_hash"]),
            result_hash=str(value["result_hash"]),
            timestamp=str(value.get("timestamp", "")),
            verified=bool(value.get("verified", False)),
        )
        self.microtask_ledger.microtasks.append(microtask)

    def _restore_indexed_file(self, value: Any) -> None:
        if not isinstance(value, dict):
            return
        seedbox_id = str(value["seedbox_id"])
        if seedbox_id not in self.registry.seedboxes:
            raise KeyError(f"unknown seedbox {seedbox_id}")
        tags = value.get("tags", ())
        if isinstance(tags, str):
            tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
        indexed_file = IndexedFile(
            file_id=str(value["file_id"]),
            seedbox_id=seedbox_id,
            name=str(value["name"]),
            content_url=str(value["content_url"]),
            sha256=str(value.get("sha256", "")),
            size_bytes=int(value.get("size_bytes", 0)),
            media_type=str(value.get("media_type", "")),
            tags=tuple(str(tag) for tag in tags),
            indexed_at=str(value.get("indexed_at", "")),
        )
        self.content_index.files = [
            item for item in self.content_index.files if item.file_id != indexed_file.file_id
        ]
        self.content_index.files.append(indexed_file)

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
        if tool_name == "submit_atomic_microtask":
            tool_kwargs.setdefault("prover_id", subject_id)
            tool_kwargs.setdefault("task_type", "storage_check")
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
    parser.add_argument("--bitcoin-network", help="Bitcoin network label for donation anchors.")
    parser.add_argument("--bitcoin-min-confirmations", type=int, help="Minimum confirmations required for verified anchors.")
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
    bitcoin_network = args.bitcoin_network or env_or(env_values, "DELFTCLAW_BITCOIN_NETWORK", "mock")
    bitcoin_min_confirmations = (
        args.bitcoin_min_confirmations
        if args.bitcoin_min_confirmations is not None
        else int(env_or(env_values, "DELFTCLAW_BITCOIN_MIN_CONFIRMATIONS", "0"))
    )

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
        bitcoin_network=bitcoin_network,
        bitcoin_min_confirmations=bitcoin_min_confirmations,
    )
    run_gateway(host=host, port=port, state=state)


if __name__ == "__main__":
    main()
