from __future__ import annotations

import sys
from pathlib import Path

import pytest

from agent import AgentConfig, LineageRuntimeConfig, OpenClawAgent, build_tools
from communication.bittorrent import StubBitTorrentService
from identity.agent_identity import AgentIdentity
from identity.seed import MnemonicSeedSource
from protocol import StubLLMClient


PARENT_MNEMONIC = "army van defense carry jealous true garbage claim echo media make crunch"
CHILD_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _identity(mnemonic: str) -> AgentIdentity:
    return AgentIdentity.from_seed(MnemonicSeedSource(mnemonic).load(), network="TESTNET")


def _agent(
    identity: AgentIdentity,
    save_dir: Path,
    *,
    lineage: LineageRuntimeConfig | None = None,
) -> OpenClawAgent:
    return OpenClawAgent(
        identity=identity,
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=save_dir,
            lineage=lineage or LineageRuntimeConfig(),
        ),
        bt_service=StubBitTorrentService(save_dir=save_dir),
    )


def _write_birth_package(path: Path, *, parent: AgentIdentity, child: AgentIdentity) -> dict:
    from identity.lineage.canonical import canonical_hash, certificate_hash
    from identity.lineage.certificates import issue_child_certificate, utc_now_iso
    from identity.lineage.merkle import merkle_proof, merkle_root
    from identity.lineage.mock_anchor import MockAnchorBackend
    from identity.lineage.models import CertificateBatch, LineageProof
    from identity.lineage.store import write_json

    certificate = issue_child_certificate(
        parent_signing_key=parent.app,
        family_id="runtime-family",
        parent_agent_id=parent.identity_hash,
        parent_authority_pubkey=parent.app.pubkey.hex(),
        child_agent_id=child.identity_hash,
        child_authority_pubkey=child.app.pubkey.hex(),
        child_operational_pubkey=child.ipv8.raw_pubkey.hex(),
        capabilities=["search"],
        anchor_policy={"required": True, "min_confirmations": 0},
    )
    leaf_hashes = [certificate_hash(certificate)]
    root = merkle_root(leaf_hashes)
    batch = CertificateBatch(
        batch_id=canonical_hash({
            "certificate_id": certificate.certificate_id,
            "issued_at": certificate.issued_at,
            "kind": "lineage_certificate_batch_v1",
        }),
        merkle_root=root,
        leaf_hashes=leaf_hashes,
        certificate_ids=[certificate.certificate_id],
        created_at=utc_now_iso(),
    )
    anchor = MockAnchorBackend().create_anchor(batch)
    proof = LineageProof(
        leaf_certificate=certificate,
        chain=[],
        merkle_leaf_hash=leaf_hashes[0],
        merkle_proof=merkle_proof(leaf_hashes, 0),
        merkle_root=root,
        anchor_id=anchor.anchor_id,
        anchor_record=anchor,
    )
    trusted_roots = [{
        "agent_id": parent.identity_hash,
        "authority_pubkey": parent.app.pubkey.hex(),
    }]
    package = {
        "version": 1,
        "package_type": "lineage_birth_package_v1",
        "proof": proof.to_dict(),
        "certificate_id": certificate.certificate_id,
        "trusted_roots": trusted_roots,
    }
    write_json(path, package)
    return package


@pytest.mark.asyncio
async def test_lineage_default_runtime_status_is_disabled(tmp_path: Path):
    agent = _agent(_identity(CHILD_MNEMONIC), tmp_path / "agent")
    await agent.start()
    try:
        status = agent.lineage_status
        assert status["enabled"] is False
        assert status["required"] is False
        assert status["enforced"] is False
        assert status["btc_network"] == "mock"
        assert status["status"] == "disabled"
    finally:
        await agent.stop()


@pytest.mark.asyncio
async def test_lineage_disabled_does_not_import_or_enforce_verifier(tmp_path: Path):
    sys.modules.pop("identity.lineage.verifier", None)
    lineage = LineageRuntimeConfig(
        enabled=False,
        required=True,
        birth_package_path=tmp_path / "missing_birth_package.json",
    )
    agent = _agent(_identity(CHILD_MNEMONIC), tmp_path / "agent", lineage=lineage)
    await agent.start()
    try:
        assert agent.lineage_status["status"] == "disabled"
        assert "identity.lineage.verifier" not in sys.modules
    finally:
        await agent.stop()


@pytest.mark.asyncio
async def test_lineage_enabled_missing_birth_package_is_status_only_when_not_required(tmp_path: Path):
    lineage = LineageRuntimeConfig(
        enabled=True,
        required=False,
        birth_package_path=tmp_path / "missing_birth_package.json",
    )
    agent = _agent(_identity(CHILD_MNEMONIC), tmp_path / "agent", lineage=lineage)
    await agent.start()
    try:
        status = agent.lineage_status
        assert status["enabled"] is True
        assert status["required"] is False
        assert status["ok"] is False
        assert status["status"] == "unavailable"
        assert any(error.startswith("birth_package_missing:") for error in status["errors"])
    finally:
        await agent.stop()


@pytest.mark.asyncio
async def test_lineage_required_missing_birth_package_fails_startup_cleanly(tmp_path: Path):
    lineage = LineageRuntimeConfig(
        enabled=True,
        required=True,
        birth_package_path=tmp_path / "missing_birth_package.json",
    )
    agent = _agent(_identity(CHILD_MNEMONIC), tmp_path / "agent", lineage=lineage)
    with pytest.raises(RuntimeError, match="lineage required"):
        await agent.start()
    await agent.stop()


@pytest.mark.asyncio
async def test_lineage_status_tool_exposes_runtime_verification(tmp_path: Path):
    parent = _identity(PARENT_MNEMONIC)
    child = _identity(CHILD_MNEMONIC)
    birth_package_path = tmp_path / "birth_package.json"
    package = _write_birth_package(birth_package_path, parent=parent, child=child)
    lineage = LineageRuntimeConfig(
        enabled=True,
        required=True,
        birth_package_path=birth_package_path,
        cache_path=tmp_path / "lineage_cache.json",
        trusted_roots=(
            {"agent_id": parent.identity_hash, "authority_pubkey": parent.app.pubkey.hex()},
        ),
    )
    agent = _agent(child, tmp_path / "agent", lineage=lineage)
    await agent.start()
    try:
        status = agent.lineage_status
        assert status["ok"] is True
        assert status["status"] == "valid"
        assert status["subject_agent_id"] == child.identity_hash
        assert status["certificate_id"] == package["certificate_id"]

        tool_status = await build_tools(agent).dispatch("lineage_status", {})
        assert tool_status["ok"] is True
        assert tool_status["status"] == "valid"
        assert tool_status["certificate_id"] == package["certificate_id"]
        assert tool_status["paths"]["birth_package"] == str(birth_package_path)
    finally:
        await agent.stop()
