"""1-cent Bitcoin identity verification flow for OpenClaw agents."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import hashlib
import json
import time
import uuid

from identity.agent_identity import AgentIdentity
from identity.derivation import verification_challenge_path
from identity.seed import Seed
from identity.wallet import Wallet


_LOG_PATH = Path(__file__).resolve().parent / "verification_log.json"
_TX_LEDGER_PATH = Path(__file__).resolve().parent / "verification_txs.json"


@dataclass(frozen=True)
class VerificationResult:
    """Result of on-chain identity verification."""

    verified: bool
    txid: str
    agent_id: str
    timestamp: float
    confirmations: int
    error: str | None = None


@dataclass(frozen=True)
class VerificationRecord:
    """Append-only audit record for a verification attempt."""

    agent_id: str
    txid: str
    network: str
    timestamp: float
    verified: bool


@dataclass(frozen=True)
class VerificationChallenge:
    """Challenge details shared with prover agent."""

    challenge_address: str
    nonce: str
    amount_satoshis: int
    network: str

    @classmethod
    def create(cls, identity: AgentIdentity, network: str) -> "VerificationChallenge":
        """Create challenge address at m/44'/0'/agent_index'/1/0 and random nonce."""
        normalized_network = network.strip().upper()
        seed = Seed.from_mnemonic(identity.mnemonic)
        challenge_wallet = Wallet.from_seed(
            seed,
            network=normalized_network,
            agent_index=identity.agent_index,
            path=verification_challenge_path(identity.agent_index),
        )
        return cls(
            challenge_address=challenge_wallet.address(),
            nonce=uuid.uuid4().hex,
            amount_satoshis=1000,
            network=normalized_network,
        )

    def expected_op_return(self, identity: AgentIdentity, network: str) -> str:
        """Return expected OP_RETURN digest hex for challenge verification."""
        network_tag = network.strip().upper().encode("ascii")
        payload = identity.get_identity_hash().encode("ascii") + self.nonce.encode("ascii") + network_tag
        return hashlib.sha256(payload).hexdigest()

    def verify(self, txid: str, identity: AgentIdentity, network: str) -> VerificationResult:
        """Verify tx details against challenge requirements and append audit log."""
        normalized_network = network.strip().upper()
        tx = _get_tx(txid)
        now = time.time()
        if tx is None:
            result = VerificationResult(False, txid, identity.get_identity_hash(), now, 0, "transaction not found")
            _append_record(result, normalized_network)
            return result

        confirmations = int(tx.get("confirmations", 0))
        min_confirmations = 0 if normalized_network == "REGTEST" else 1
        if confirmations < min_confirmations:
            result = VerificationResult(False, txid, identity.get_identity_hash(), now, confirmations, "insufficient confirmations")
            _append_record(result, normalized_network)
            return result

        if str(tx.get("to_address")) != self.challenge_address:
            result = VerificationResult(False, txid, identity.get_identity_hash(), now, confirmations, "challenge address mismatch")
            _append_record(result, normalized_network)
            return result

        if int(tx.get("amount_satoshis", -1)) != self.amount_satoshis:
            result = VerificationResult(False, txid, identity.get_identity_hash(), now, confirmations, "amount mismatch")
            _append_record(result, normalized_network)
            return result

        expected_op_return = self.expected_op_return(identity, normalized_network)
        if str(tx.get("op_return")) != expected_op_return:
            result = VerificationResult(False, txid, identity.get_identity_hash(), now, confirmations, "op_return mismatch")
            _append_record(result, normalized_network)
            return result

        if str(tx.get("from_address")) != identity.wallet.address():
            result = VerificationResult(False, txid, identity.get_identity_hash(), now, confirmations, "wallet ownership proof failed")
            _append_record(result, normalized_network)
            return result

        result = VerificationResult(True, txid, identity.get_identity_hash(), now, confirmations, None)
        _append_record(result, normalized_network)
        return result


def simulate_regtest_payment(identity: AgentIdentity, challenge: VerificationChallenge) -> str:
    """Create a local ledger entry emulating a valid REGTEST verification tx."""
    txid = uuid.uuid4().hex
    tx = {
        "txid": txid,
        "from_address": identity.wallet.address(),
        "to_address": challenge.challenge_address,
        "amount_satoshis": challenge.amount_satoshis,
        "op_return": challenge.expected_op_return(identity, "REGTEST"),
        "confirmations": 1,
        "network": "REGTEST",
        "timestamp": time.time(),
    }
    ledger = _load_json(_TX_LEDGER_PATH)
    ledger[txid] = tx
    _TX_LEDGER_PATH.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    return txid


def is_verified(agent_id: str) -> bool:
    """Return True if verification log contains at least one successful record."""
    if not _LOG_PATH.exists():
        return False
    for line in _LOG_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        if record.get("agent_id") == agent_id and record.get("verified") is True:
            return True
    return False


def _append_record(result: VerificationResult, network: str) -> None:
    record = VerificationRecord(
        agent_id=result.agent_id,
        txid=result.txid,
        network=network,
        timestamp=result.timestamp,
        verified=result.verified,
    )
    _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(record), sort_keys=True) + "\n")


def _get_tx(txid: str) -> dict[str, object] | None:
    ledger = _load_json(_TX_LEDGER_PATH)
    return ledger.get(txid)


def _load_json(path: Path) -> dict[str, dict[str, object]]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))

