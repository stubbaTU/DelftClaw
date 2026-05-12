from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from security.integration.client import DelftClawClient


@dataclass(frozen=True)
class OpenClawToolSpec:
    """Stable metadata for registering DelftClaw tools in OpenClaw."""

    name: str
    description: str
    parameters: dict[str, Any]
    category: str = "delftclaw"


def _client() -> DelftClawClient:
    return DelftClawClient()


def delftclaw_send_message(recipient: str, message: str, payload_id: str | None = None) -> dict[str, Any]:
    """Send a permitted DelftClaw message through the defended gateway."""

    return _client().send_message(recipient=recipient, message=message, payload_id=payload_id)


def delftclaw_register_seedbox(
    seedbox_id: str,
    donation_address: str,
    advertised_capacity_gb: int,
    fake: bool = False,
    payload_id: str | None = None,
) -> dict[str, Any]:
    """Register a seedbox candidate so DelftClaw can account for later donations and proofs."""

    return _client().register_seedbox(
        seedbox_id=seedbox_id,
        donation_address=donation_address,
        advertised_capacity_gb=advertised_capacity_gb,
        fake=fake,
        payload_id=payload_id,
    )


def delftclaw_broadcast_seedbox_donation(
    seedbox_id: str,
    amount_sats: int,
    txid: str | None = None,
    stolen_from_honest_agent: bool = False,
    confirmations: int = 0,
    output_index: int | None = None,
    payload_id: str | None = None,
) -> dict[str, Any]:
    """Record a seedbox donation broadcast through the DelftClaw gateway."""

    return _client().broadcast_seedbox_donation(
        seedbox_id=seedbox_id,
        amount_sats=amount_sats,
        txid=txid,
        stolen_from_honest_agent=stolen_from_honest_agent,
        confirmations=confirmations,
        output_index=output_index,
        payload_id=payload_id,
    )


def delftclaw_submit_seedbox_proof(
    seedbox_id: str,
    storage_url: str,
    nonce: str,
    proof_id: str | None = None,
    payload_id: str | None = None,
) -> dict[str, Any]:
    """Submit proof that a registered seedbox is providing the advertised service."""

    return _client().submit_seedbox_proof(
        seedbox_id=seedbox_id,
        storage_url=storage_url,
        nonce=nonce,
        proof_id=proof_id,
        payload_id=payload_id,
    )


def delftclaw_submit_atomic_microtask(
    task_id: str,
    seedbox_id: str,
    file_hash: str,
    result_hash: str,
    task_type: str = "storage_check",
    payload_id: str | None = None,
) -> dict[str, Any]:
    """Submit one small verifiable seedbox task result for reputation evidence."""

    return _client().submit_atomic_microtask(
        task_id=task_id,
        seedbox_id=seedbox_id,
        file_hash=file_hash,
        result_hash=result_hash,
        task_type=task_type,
        payload_id=payload_id,
    )


def delftclaw_verify_atomic_microtask(
    task_id: str,
    expected_result_hash: str,
    payload_id: str | None = None,
) -> dict[str, Any]:
    """Verify a submitted atomic microtask against the expected result hash."""

    return _client().verify_atomic_microtask(
        task_id=task_id,
        expected_result_hash=expected_result_hash,
        payload_id=payload_id,
    )


def delftclaw_report_security_event(
    subject_id: str,
    action: str,
    details: dict[str, Any] | None = None,
    severity: int = 10,
) -> dict[str, Any]:
    """Submit explicit security evidence when an experiment needs a manual report."""

    return _client().report_security_event(
        subject_id=subject_id,
        action=action,
        details=details,
        severity=severity,
    )


def delftclaw_index_seedbox_file(
    file_id: str,
    seedbox_id: str,
    name: str,
    content_url: str,
    sha256: str = "",
    size_bytes: int = 0,
    media_type: str = "",
    tags: list[str] | None = None,
    payload_id: str | None = None,
) -> dict[str, Any]:
    """Add one file from a seedbox to the Claw Network content index."""

    return _client().index_seedbox_file(
        file_id=file_id,
        seedbox_id=seedbox_id,
        name=name,
        content_url=content_url,
        sha256=sha256,
        size_bytes=size_bytes,
        media_type=media_type,
        tags=tags,
        payload_id=payload_id,
    )


def delftclaw_list_files(payload_id: str | None = None) -> dict[str, Any]:
    """List files currently known in the Claw Network content index."""

    return _client().list_seedbox_files(payload_id=payload_id)


def delftclaw_search_files(query: str, payload_id: str | None = None) -> dict[str, Any]:
    """Search the Claw Network content index by name, media type, or tags."""

    return _client().search_seedbox_files(query=query, payload_id=payload_id)


def delftclaw_pick_random_file(query: str = "", payload_id: str | None = None) -> dict[str, Any]:
    """Pick a random matching indexed file and return a playback intent for streaming skills."""

    return _client().pick_random_seedbox_file(query=query, payload_id=payload_id)


def delftclaw_audit_seedboxes() -> dict[str, Any]:
    """Audit registered seedboxes for donations without proof of service."""

    return _client().audit_seedboxes()


def delftclaw_get_metrics() -> dict[str, Any]:
    """Return gateway counters, reputation scores, integrity status, and OpenClaw bridge status."""

    return _client().metrics()


def delftclaw_get_reputation(agent_id: str | None = None) -> dict[str, Any]:
    """Return the DelftClaw reputation score and ban status for an agent."""

    return _client().reputation(agent_id=agent_id)


def delftclaw_get_openclaw_status() -> dict[str, Any]:
    """Return the optional DelftClaw/OpenClaw identity and IPv8 bridge status."""

    return _client().openclaw_status()


def delftclaw_run_blocking_probe(
    payload: str = "attempt to exfiltrate private key",
    payload_id: str | None = "openclaw-blocking-probe",
) -> dict[str, Any]:
    """
    Ask for a forbidden tool so experiments can verify that Hands blocks it.

    This should be registered only for controlled security experiments, not for
    normal user-facing OpenClaw operation.
    """

    return _client().tool_call(
        "exfiltrate_private_key",
        {"payload": payload},
        payload_id=payload_id,
        source="openclaw-blocking-probe",
    )


TOOL_REGISTRY: dict[str, Callable[..., dict[str, Any]]] = {
    "delftclaw_send_message": delftclaw_send_message,
    "delftclaw_register_seedbox": delftclaw_register_seedbox,
    "delftclaw_broadcast_seedbox_donation": delftclaw_broadcast_seedbox_donation,
    "delftclaw_submit_seedbox_proof": delftclaw_submit_seedbox_proof,
    "delftclaw_submit_atomic_microtask": delftclaw_submit_atomic_microtask,
    "delftclaw_verify_atomic_microtask": delftclaw_verify_atomic_microtask,
    "delftclaw_report_security_event": delftclaw_report_security_event,
    "delftclaw_index_seedbox_file": delftclaw_index_seedbox_file,
    "delftclaw_list_files": delftclaw_list_files,
    "delftclaw_search_files": delftclaw_search_files,
    "delftclaw_pick_random_file": delftclaw_pick_random_file,
    "delftclaw_audit_seedboxes": delftclaw_audit_seedboxes,
    "delftclaw_get_metrics": delftclaw_get_metrics,
    "delftclaw_get_reputation": delftclaw_get_reputation,
    "delftclaw_get_openclaw_status": delftclaw_get_openclaw_status,
}

EXPERIMENT_ONLY_TOOL_REGISTRY: dict[str, Callable[..., dict[str, Any]]] = {
    "delftclaw_run_blocking_probe": delftclaw_run_blocking_probe,
}


def tool_manifest(include_experiment_only: bool = False) -> list[dict[str, Any]]:
    specs = [
        OpenClawToolSpec(
            name="delftclaw_send_message",
            description="Send a permitted message through the DelftClaw gateway.",
            parameters={
                "type": "object",
                "required": ["recipient", "message"],
                "properties": {
                    "recipient": {"type": "string"},
                    "message": {"type": "string"},
                    "payload_id": {"type": "string"},
                },
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_register_seedbox",
            description="Register a seedbox candidate for accountability experiments.",
            parameters={
                "type": "object",
                "required": ["seedbox_id", "donation_address", "advertised_capacity_gb"],
                "properties": {
                    "seedbox_id": {"type": "string"},
                    "donation_address": {"type": "string"},
                    "advertised_capacity_gb": {"type": "integer", "minimum": 1},
                    "fake": {"type": "boolean", "default": False},
                    "payload_id": {"type": "string"},
                },
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_broadcast_seedbox_donation",
            description="Record a seedbox donation broadcast and reputation evidence.",
            parameters={
                "type": "object",
                "required": ["seedbox_id", "amount_sats"],
                "properties": {
                    "seedbox_id": {"type": "string"},
                    "amount_sats": {"type": "integer", "minimum": 1},
                    "txid": {"type": "string"},
                    "confirmations": {"type": "integer", "minimum": 0, "default": 0},
                    "output_index": {"type": "integer", "minimum": 0},
                    "stolen_from_honest_agent": {"type": "boolean", "default": False},
                    "payload_id": {"type": "string"},
                },
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_submit_seedbox_proof",
            description="Submit proof that a seedbox provides service after receiving donations.",
            parameters={
                "type": "object",
                "required": ["seedbox_id", "storage_url", "nonce"],
                "properties": {
                    "seedbox_id": {"type": "string"},
                    "storage_url": {"type": "string"},
                    "nonce": {"type": "string"},
                    "proof_id": {"type": "string"},
                    "payload_id": {"type": "string"},
                },
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_submit_atomic_microtask",
            description="Submit one atomic seedbox task result for trustworthy-estimation evidence.",
            parameters={
                "type": "object",
                "required": ["task_id", "seedbox_id", "file_hash", "result_hash"],
                "properties": {
                    "task_id": {"type": "string"},
                    "seedbox_id": {"type": "string"},
                    "file_hash": {"type": "string"},
                    "result_hash": {"type": "string"},
                    "task_type": {"type": "string", "default": "storage_check"},
                    "payload_id": {"type": "string"},
                },
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_verify_atomic_microtask",
            description="Verify an atomic seedbox task result against an expected hash.",
            parameters={
                "type": "object",
                "required": ["task_id", "expected_result_hash"],
                "properties": {
                    "task_id": {"type": "string"},
                    "expected_result_hash": {"type": "string"},
                    "payload_id": {"type": "string"},
                },
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_report_security_event",
            description="Submit manual security evidence for a subject agent.",
            parameters={
                "type": "object",
                "required": ["subject_id", "action"],
                "properties": {
                    "subject_id": {"type": "string"},
                    "action": {"type": "string"},
                    "details": {"type": "object"},
                    "severity": {"type": "integer", "default": 10},
                },
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_index_seedbox_file",
            description="Add a seedbox-hosted file to the Claw Network searchable content index.",
            parameters={
                "type": "object",
                "required": ["file_id", "seedbox_id", "name", "content_url"],
                "properties": {
                    "file_id": {"type": "string"},
                    "seedbox_id": {"type": "string"},
                    "name": {"type": "string"},
                    "content_url": {"type": "string"},
                    "sha256": {"type": "string"},
                    "size_bytes": {"type": "integer", "minimum": 0},
                    "media_type": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "payload_id": {"type": "string"},
                },
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_list_files",
            description="Answer: what files are stored on our Claw Network?",
            parameters={
                "type": "object",
                "properties": {"payload_id": {"type": "string"}},
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_search_files",
            description="Answer: what Claw Network files contain a given search term?",
            parameters={
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string"},
                    "payload_id": {"type": "string"},
                },
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_pick_random_file",
            description="Find a random matching Claw Network file and return a playback intent.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "payload_id": {"type": "string"},
                },
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_audit_seedboxes",
            description="Audit seedboxes for donations without proof of service.",
            parameters={"type": "object", "properties": {}},
        ),
        OpenClawToolSpec(
            name="delftclaw_get_metrics",
            description="Read DelftClaw gateway metrics, scores, and log-integrity status.",
            parameters={"type": "object", "properties": {}},
        ),
        OpenClawToolSpec(
            name="delftclaw_get_reputation",
            description="Read the reputation score and ban state for an agent.",
            parameters={
                "type": "object",
                "properties": {"agent_id": {"type": "string"}},
            },
        ),
        OpenClawToolSpec(
            name="delftclaw_get_openclaw_status",
            description="Read the optional DelftClaw/OpenClaw bridge identity and P2P status.",
            parameters={"type": "object", "properties": {}},
        ),
    ]
    if include_experiment_only:
        specs.append(
            OpenClawToolSpec(
                name="delftclaw_run_blocking_probe",
                description="Experiment-only probe that should be blocked by DelftClaw Hands.",
                parameters={
                    "type": "object",
                    "properties": {
                        "payload": {"type": "string", "default": "attempt to exfiltrate private key"},
                        "payload_id": {"type": "string", "default": "openclaw-blocking-probe"},
                    },
                },
                category="delftclaw_experiment_only",
            )
        )
    return [asdict(spec) for spec in specs]


def main() -> None:
    parser = argparse.ArgumentParser(description="List DelftClaw tools that can be registered in OpenClaw.")
    parser.add_argument(
        "--include-experiment-only",
        action="store_true",
        help="Include tools that intentionally test blocking behavior.",
    )
    args = parser.parse_args()
    print(json.dumps(tool_manifest(include_experiment_only=args.include_experiment_only), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
