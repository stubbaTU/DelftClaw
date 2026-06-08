"""Stateful MCP controller for one OpenClaw LLM lineage trial."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from time import perf_counter
from typing import Any

from fastmcp import FastMCP
from fastmcp.tools import Tool as FastMCPTool
from ipv8.peer import Peer

from agent import LineageRuntimeConfig, OpenClawAgent
from communication.community import CommunityLineageConfig, LineageProofPayload
from experiments.common.io import utc_timestamp
from experiments.common.real_agent_lineage import (
    ATTACK_CASES,
    AlwaysAcceptVerifier,
    EXPECTED_STATUS,
    AttackSetup,
    authority_pubkey,
    build_attack_setup,
    build_proof,
    build_runtime_agent,
    deterministic_identity,
    expected_join_accept,
    mode_flags,
    wait_for_status,
)
from identity.lineage.store import write_json as write_lineage_json


class LineageExperimentController:
    """Own and constrain one deterministic real-runtime admission trial."""

    def __init__(
        self,
        *,
        config: dict[str, Any],
        experiment_name: str,
        mode: str,
        target_attack_case: str,
        trial_index: int,
        trial_id: str,
        trial_root: Path,
        ledger_path: Path,
    ) -> None:
        if target_attack_case not in ATTACK_CASES:
            raise ValueError(f"unsupported attack case: {target_attack_case}")
        mode_flags(mode)
        self.config = config
        self.experiment_name = experiment_name
        self.mode = mode
        self.target_attack_case = target_attack_case
        self.trial_index = trial_index
        self.trial_id = trial_id
        self.trial_root = trial_root.resolve()
        self.ledger_path = ledger_path
        self.prepared = False
        self.join_attempted = False
        self.status_called = False
        self.selected_attack_case = ""
        self.setup: AttackSetup | None = None
        self.gatekeeper: OpenClawAgent | None = None
        self.child: OpenClawAgent | None = None
        self.gatekeeper_peer: Peer | None = None
        self.child_peer: Peer | None = None
        self.join_accepted: bool | None = None
        self.status: dict[str, Any] | None = None
        self.captured_payloads: list[LineageProofPayload] = []

    def _append_ledger(
        self,
        *,
        tool: str,
        arguments: dict[str, Any],
        ok: bool,
        result: Any = None,
        error: str = "",
        duration_ms: float = 0.0,
    ) -> None:
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp_utc": utc_timestamp(),
            "trial_id": self.trial_id,
            "tool": tool,
            "arguments": arguments,
            "ok": ok,
            "result": result,
            "error": error,
            "duration_ms": duration_ms,
        }
        with self.ledger_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    async def _recorded_call(
        self,
        tool: str,
        arguments: dict[str, Any],
        operation,
    ) -> dict[str, Any]:
        started_at = perf_counter()
        try:
            result = await operation()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            self._append_ledger(
                tool=tool,
                arguments=arguments,
                ok=False,
                error=error,
                duration_ms=(perf_counter() - started_at) * 1000,
            )
            return {"ok": False, "error": error}
        self._append_ledger(
            tool=tool,
            arguments=arguments,
            ok=True,
            result=result,
            duration_ms=(perf_counter() - started_at) * 1000,
        )
        return result

    async def prepare_case(self, attack_case: str) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            if self.prepared:
                raise RuntimeError("case_already_prepared")
            if attack_case != self.target_attack_case:
                raise ValueError(
                    f"wrong_attack_case: expected {self.target_attack_case}, got {attack_case}"
                )
            self.selected_attack_case = attack_case
            await self._start_runtimes()
            self.prepared = True
            assert self.setup is not None
            return {
                "ok": True,
                "prepared": True,
                "attack_case": attack_case,
                "lineage_mode": self.mode,
                "proof_supplied": self.setup.proof_supplied,
            }

        return await self._recorded_call(
            "lineage_experiment_prepare_case",
            {"attack_case": attack_case},
            operation,
        )

    async def request_join(self) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            if not self.prepared:
                raise RuntimeError("case_not_prepared")
            if self.join_attempted:
                raise RuntimeError("join_already_attempted")
            if self.child is None or self.gatekeeper is None:
                raise RuntimeError("runtime_not_started")
            if self.gatekeeper_peer is None or self.child_peer is None:
                raise RuntimeError("peers_not_connected")
            self.join_attempted = True
            timeout_s = float(self.config["openclaw_llm_join_timeout_s"])
            self.join_accepted = await asyncio.wait_for(
                self.child.seedbox.request_join(
                    self.gatekeeper_peer,
                    donation_txid=self.trial_id.encode("utf-8"),
                ),
                timeout=timeout_s,
            )
            enabled, _required = mode_flags(self.mode)
            if enabled:
                expected_wire_status = (
                    "valid"
                    if self.target_attack_case == "replayed_nonce_or_stale_proof"
                    else EXPECTED_STATUS[self.target_attack_case]
                )
                self.status = await wait_for_status(
                    self.gatekeeper,
                    self.child_peer.mid.hex(),
                    timeout_s=timeout_s,
                    expected_status=expected_wire_status,
                )
                if self.target_attack_case == "replayed_nonce_or_stale_proof":
                    if not self.captured_payloads:
                        raise RuntimeError("replay_payload_not_captured")
                    self.child.seedbox.ez_send(
                        self.gatekeeper_peer,
                        self.captured_payloads[-1],
                    )
                    self.status = await wait_for_status(
                        self.gatekeeper,
                        self.child_peer.mid.hex(),
                        timeout_s=timeout_s,
                        expected_status="replay",
                    )
            return {
                "ok": True,
                "join_attempted": True,
                "join_accepted": self.join_accepted,
            }

        return await self._recorded_call(
            "lineage_experiment_request_join",
            {},
            operation,
        )

    async def peer_status(self) -> dict[str, Any]:
        async def operation() -> dict[str, Any]:
            if not self.prepared:
                raise RuntimeError("case_not_prepared")
            if not self.join_attempted:
                raise RuntimeError("join_not_attempted")
            self.status_called = True
            status = self.status or {}
            return {
                "ok": True,
                "attack_case": self.target_attack_case,
                "lineage_mode": self.mode,
                "join_accepted": self.join_accepted,
                "lineage_status": str(status.get("status", "")),
                "lineage_ok": status.get("ok", ""),
                "errors": list(status.get("errors", [])),
            }

        return await self._recorded_call(
            "lineage_experiment_peer_status",
            {},
            operation,
        )

    async def _start_runtimes(self) -> None:
        enabled, required = mode_flags(self.mode)
        seed = int(self.config["seed"])
        capability = str(self.config["requested_capability"])
        root = deterministic_identity(
            seed,
            self.experiment_name,
            self.target_attack_case,
            self.trial_index,
            "root",
        )
        gatekeeper_identity = deterministic_identity(
            seed,
            self.experiment_name,
            self.target_attack_case,
            self.trial_index,
            "gatekeeper",
        )
        child_identity = deterministic_identity(
            seed,
            self.experiment_name,
            self.target_attack_case,
            self.trial_index,
            "child",
        )
        gatekeeper_package_path = (
            self.trial_root / "gatekeeper" / "lineage" / "birth_package.json"
        )
        child_package_path = (
            self.trial_root / "child" / "lineage" / "birth_package.json"
        )
        gatekeeper_proof = build_proof(
            root=root,
            subject=gatekeeper_identity,
            family_id=f"gatekeeper-{self.trial_id}",
            capability=capability,
            experiment_name=self.experiment_name,
        )
        trusted_roots = ({
            "agent_id": root.identity_hash,
            "authority_pubkey": authority_pubkey(root),
        },)
        write_lineage_json(gatekeeper_package_path, {
            "version": 1,
            "package_type": "lineage_birth_package_v1",
            "proof": gatekeeper_proof,
            "trusted_roots": list(trusted_roots),
        })
        self.setup = build_attack_setup(
            config=self.config,
            experiment_name=self.experiment_name,
            attack_case=self.target_attack_case,
            trial_index=self.trial_index,
            root=root,
            child=child_identity,
        )
        if self.setup.proof is not None:
            write_lineage_json(child_package_path, {
                "version": 1,
                "package_type": "lineage_birth_package_v1",
                "proof": self.setup.proof,
                "trusted_roots": list(self.setup.trusted_roots),
            })

        gatekeeper_lineage = LineageRuntimeConfig(
            enabled=enabled,
            required=required,
            btc_network="mock",
            min_anchor_confirmations=int(self.config["min_confirmations"]),
            birth_package_path=gatekeeper_package_path if enabled else None,
            cache_path=self.trial_root / "gatekeeper" / "lineage" / "cache.json",
            trusted_roots=trusted_roots if enabled else (),
            accepted_capabilities=self.setup.accepted_capabilities if enabled else (),
        )
        child_lineage = LineageRuntimeConfig(
            enabled=True,
            required=False,
            btc_network="mock",
            birth_package_path=child_package_path,
            cache_path=self.trial_root / "child" / "lineage" / "cache.json",
            trusted_roots=self.setup.trusted_roots,
        )
        self.gatekeeper = build_runtime_agent(
            gatekeeper_identity,
            self.trial_root / "gatekeeper",
            gatekeeper_lineage,
        )
        self.child = build_runtime_agent(
            self.setup.runtime_identity,
            self.trial_root / "child",
            child_lineage,
        )
        await self.gatekeeper.start()
        await self.child.start()
        self.gatekeeper.seedbox.configure(verifier=AlwaysAcceptVerifier())
        if enabled:
            self.gatekeeper.seedbox.configure(lineage_config=CommunityLineageConfig(
                enabled=True,
                required=required,
                trusted_roots=self.setup.trusted_roots,
                min_anchor_confirmations=int(self.config["min_confirmations"]),
                accepted_capabilities=self.setup.accepted_capabilities,
                cache_path=self.trial_root / "gatekeeper" / "lineage" / "peer-cache.json",
                challenge_timeout_s=float(
                    self.config["openclaw_llm_challenge_timeout_s"]
                ),
            ))
            self.child.seedbox.configure(
                lineage_proof_provider=lambda: self.setup.proof
            )

        self.gatekeeper_peer = self.child.add_peer(
            self.gatekeeper.address[0],
            self.gatekeeper.address[1],
            self.gatekeeper.pubkey_hex,
        )
        self.child_peer = self.gatekeeper.add_peer(
            self.child.address[0],
            self.child.address[1],
            self.child.pubkey_hex,
        )
        if enabled and self.target_attack_case == "replayed_nonce_or_stale_proof":
            original_ez_send = self.child.seedbox.ez_send

            def capture(peer: Peer, payload: Any) -> Any:
                if isinstance(payload, LineageProofPayload):
                    self.captured_payloads.append(payload)
                return original_ez_send(peer, payload)

            self.child.seedbox.ez_send = capture  # type: ignore[method-assign]

    async def stop(self) -> None:
        if self.child is not None:
            await self.child.stop()
            self.child = None
        if self.gatekeeper is not None:
            await self.gatekeeper.stop()
            self.gatekeeper = None

    def protocol_result(self) -> dict[str, Any]:
        enabled, _required = mode_flags(self.mode)
        actual_status = str((self.status or {}).get("status", ""))
        expected_status = EXPECTED_STATUS[self.target_attack_case] if enabled else ""
        expected_accept = expected_join_accept(self.mode, self.target_attack_case)
        protocol_met = bool(
            self.join_attempted
            and self.join_accepted == expected_accept
            and ((not enabled and self.status is None) or actual_status == expected_status)
        )
        invalid_case = self.target_attack_case not in {
            "valid_agent_baseline",
            "replayed_nonce_or_stale_proof",
        }
        return {
            "attack_case": self.target_attack_case,
            "selected_attack_case": self.selected_attack_case,
            "lineage_mode": self.mode,
            "proof_supplied": (
                self.setup.proof_supplied if self.setup is not None and enabled else False
            ),
            "expected_accept": expected_accept,
            "join_attempted": self.join_attempted,
            "join_accepted": self.join_accepted,
            "expected_status": expected_status,
            "lineage_status": actual_status,
            "lineage_ok": (self.status or {}).get("ok", ""),
            "lineage_errors": list((self.status or {}).get("errors", [])),
            "rejected": bool(self.status is not None and self.status.get("ok") is False),
            "false_accept": bool(
                self.mode == "required"
                and invalid_case
                and self.join_accepted is True
            ),
            "protocol_expectation_met": protocol_met,
        }


def build_experiment_mcp_server(controller: LineageExperimentController) -> FastMCP:
    """Expose exactly the three experiment tools to OpenClaw."""

    mcp = FastMCP(
        name="delftclaw-lineage-experiment",
        instructions=(
            "Use only these controlled tools. Calls must be sequential, never "
            "parallel or batched: prepare the requested case and wait for success, "
            "request one join and wait for success, then inspect peer status."
        ),
    )
    mcp.add_tool(FastMCPTool.from_function(
        controller.prepare_case,
        name="lineage_experiment_prepare_case",
        description=(
            "Step 1 of 3. Prepare the exact predeclared lineage attack case. Call "
            "this first and wait for a successful result before requesting a join."
        ),
    ))
    mcp.add_tool(FastMCPTool.from_function(
        controller.request_join,
        name="lineage_experiment_request_join",
        description=(
            "Step 2 of 3. Requires prepare_case to have succeeded. Attempt exactly "
            "one normal IPv8 admission join, then wait for its result before status."
        ),
    ))
    mcp.add_tool(FastMCPTool.from_function(
        controller.peer_status,
        name="lineage_experiment_peer_status",
        description=(
            "Step 3 of 3. Requires request_join to have succeeded. Read the "
            "deterministic gatekeeper admission and lineage status."
        ),
    ))
    return mcp
