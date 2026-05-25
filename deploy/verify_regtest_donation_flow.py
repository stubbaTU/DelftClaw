#!/usr/bin/env python3
"""Live verification for regtest donation-backed community admission.

This script starts an isolated Bitcoin Core regtest datadir, runs the repo's
wallet setup script, and proves that Bob can donate 10,000 sats to Alice using
the same on-chain path the agent tools use.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DONATION_SATS = 10_000
BOB_TARGET_SATS = 20_000
RPC_USER = "admin"
RPC_PASSWORD = "admin"


class VerificationError(RuntimeError):
    """Raised when a verification step fails."""


@dataclass
class CommandResult:
    stdout: str
    stderr: str


def _run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout_s: float = 60.0,
    check: bool = True,
) -> CommandResult:
    proc = subprocess.run(
        args,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout_s,
    )
    if check and proc.returncode != 0:
        rendered = " ".join(args)
        raise VerificationError(
            f"command failed ({proc.returncode}): {rendered}\n"
            f"stdout:\n{proc.stdout.strip()}\n"
            f"stderr:\n{proc.stderr.strip()}"
        )
    return CommandResult(proc.stdout, proc.stderr)


def _btc_to_sats(value: str | int | float | Decimal) -> int:
    return int((Decimal(str(value)) * Decimal(100_000_000)).to_integral_value())


def _sats_to_btc(sats: int) -> str:
    whole, frac = divmod(int(sats), 100_000_000)
    return f"{whole}.{frac:08d}"


def _json_cli(result: CommandResult) -> Any:
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"bitcoin-cli returned invalid JSON: {result.stdout}") from exc


def _which(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise VerificationError(f"required executable not found on PATH: {name}")
    return found


def _default_bitcoind_for_cli(bitcoin_cli: str) -> str:
    env_value = os.environ.get("BITCOIND")
    if env_value:
        return env_value
    cli_path = Path(bitcoin_cli)
    sibling = cli_path.with_name("bitcoind.exe" if os.name == "nt" else "bitcoind")
    if sibling.exists():
        return str(sibling)
    return _which("bitcoind")


def _choose_rpc_port(preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _bash_path_style(bash_path: str) -> str:
    if os.name == "nt" and "windowsapps" in bash_path.lower():
        return "wsl"
    return "git-bash"


def _to_bash_path(path: Path | str, *, style: str = "git-bash") -> str:
    raw = str(path)
    if os.name != "nt":
        return raw
    p = Path(raw)
    drive = p.drive.rstrip(":").lower()
    rest = str(p)[len(p.drive):].replace("\\", "/").lstrip("/")
    if drive:
        if style == "wsl":
            return f"/mnt/{drive}/{rest}"
        return f"/{drive}/{rest}"
    return raw.replace("\\", "/")


def _stable_labeled_address(cli: "BitcoinCli", wallet: str) -> str:
    label = f"delftclaw:{wallet}:primary"
    result = cli.json([f"-rpcwallet={wallet}", "getaddressesbylabel", label])
    if not isinstance(result, dict) or not result:
        raise VerificationError(f"wallet {wallet!r} has no stable address for label {label!r}")
    return sorted(result)[0]


def _get_or_create_labeled_address(cli: "BitcoinCli", wallet: str) -> str:
    label = f"delftclaw:{wallet}:primary"
    result = cli.run([f"-rpcwallet={wallet}", "getaddressesbylabel", label], check=False)
    if result.stdout.strip():
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            data = {}
        if isinstance(data, dict) and data:
            return sorted(data)[0]
    return cli.text([f"-rpcwallet={wallet}", "getnewaddress", label, "bech32"])


def _confirmed_received_sats(cli: "BitcoinCli", wallet: str, txid: str) -> int:
    txs = cli.json([f"-rpcwallet={wallet}", "listtransactions", "*", "100", "0", "true"])
    if not isinstance(txs, list):
        raise VerificationError("listtransactions did not return a list")
    total = 0
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        if tx.get("txid") != txid or tx.get("category") != "receive":
            continue
        if int(tx.get("confirmations") or 0) <= 0:
            continue
        amount = tx.get("amount", 0)
        if Decimal(str(amount)) > 0:
            total += _btc_to_sats(amount)
    return total


class BitcoinCli:
    def __init__(self, bitcoin_cli: str, datadir: Path) -> None:
        self.bitcoin_cli = bitcoin_cli
        self.datadir = datadir

    def run(self, args: list[str], *, timeout_s: float = 60.0, check: bool = True) -> CommandResult:
        return _run(
            [
                self.bitcoin_cli,
                f"-datadir={self.datadir}",
                "-regtest",
                *args,
            ],
            timeout_s=timeout_s,
            check=check,
        )

    def json(self, args: list[str], *, timeout_s: float = 60.0) -> Any:
        return _json_cli(self.run(args, timeout_s=timeout_s))

    def text(self, args: list[str], *, timeout_s: float = 60.0) -> str:
        return self.run(args, timeout_s=timeout_s).stdout.strip()


def _wait_for_rpc(cli: BitcoinCli, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_error = ""
    while time.monotonic() < deadline:
        result = cli.run(["getblockcount"], timeout_s=5.0, check=False)
        if result.stdout.strip().isdigit():
            return
        last_error = (result.stderr or result.stdout).strip()
        time.sleep(1)
    raise VerificationError(f"bitcoind RPC did not become ready: {last_error}")


def _run_setup(
    *,
    setup_script: Path,
    datadir: Path,
    rpc_port: int,
    bitcoin_cli: str,
    bitcoind: str,
) -> None:
    bash = _which("bash")
    path_style = _bash_path_style(bash)
    env = os.environ.copy()
    env["BITCOIN_CLI"] = _to_bash_path(bitcoin_cli, style=path_style)
    env["BITCOIND"] = _to_bash_path(bitcoind, style=path_style)
    env["PYTHON_BIN"] = _to_bash_path(sys.executable, style=path_style)
    env["BOB_TARGET_BALANCE_SATS"] = str(BOB_TARGET_SATS)

    command = [
        bash,
        _to_bash_path(setup_script, style=path_style),
        "--bitcoin-data",
        _to_bash_path(datadir, style=path_style),
        "--rpc-port",
        str(rpc_port),
        "--rpc-bind",
        "127.0.0.1",
        "--bitcoin-cli",
        _to_bash_path(bitcoin_cli, style=path_style),
        "--bitcoind",
        _to_bash_path(bitcoind, style=path_style),
        "--python-bin",
        _to_bash_path(sys.executable, style=path_style),
    ]
    try:
        _run(command, env=env, timeout_s=180.0)
    except VerificationError as exc:
        message = str(exc)
        if path_style != "wsl" or (
            "cannot execute binary file" not in message
            and "command not found" not in message
        ):
            raise
        print("[*] Bash is WSL without Windows binary interop; using native Python setup fallback")
        _setup_regtest_with_python(
            datadir=datadir,
            rpc_port=rpc_port,
            bitcoin_cli=bitcoin_cli,
            bitcoind=bitcoind,
        )


def _write_bitcoin_conf(datadir: Path, rpc_port: int) -> None:
    (datadir / "regtest").mkdir(parents=True, exist_ok=True)
    (datadir / "bitcoin.conf").write_text(
        f"""# DelftClaw Bitcoin Regtest Configuration
# Generated by verify_regtest_donation_flow.py

server=1
rpcallowip=127.0.0.1
rpcallowip=0.0.0.0/0

[regtest]
rpcport={rpc_port}
rpcbind=127.0.0.1
rpcuser={RPC_USER}
rpcpassword={RPC_PASSWORD}

disablewallet=0
keypool=0
txindex=1
blockfilterindex=1
debug=rpc
debug=walletdb
datadir={datadir}
""",
        encoding="utf-8",
    )


def _ensure_wallet(cli: BitcoinCli, wallet: str) -> None:
    loaded = cli.json(["listwallets"])
    if isinstance(loaded, list) and wallet in loaded:
        return

    cli.run(["loadwallet", wallet], check=False)
    loaded = cli.json(["listwallets"])
    if isinstance(loaded, list) and wallet in loaded:
        return

    cli.run(["createwallet", wallet])


def _setup_regtest_with_python(
    *,
    datadir: Path,
    rpc_port: int,
    bitcoin_cli: str,
    bitcoind: str,
) -> None:
    _write_bitcoin_conf(datadir, rpc_port)
    cli = BitcoinCli(bitcoin_cli, datadir)
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        [bitcoind, f"-datadir={datadir}", "-regtest"],
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )
    try:
        _wait_for_rpc(cli)
    except Exception:
        proc.terminate()
        raise

    for wallet in ("alice", "bob", "charlie", "dave"):
        _ensure_wallet(cli, wallet)

    block_count = int(cli.text(["getblockcount"]))
    if block_count < 101:
        alice_address = _get_or_create_labeled_address(cli, "alice")
        cli.text(["generatetoaddress", str(101 - block_count), alice_address])

    bob_balance = _btc_to_sats(cli.text([f"-rpcwallet=bob", "getbalance"]))
    if bob_balance < BOB_TARGET_SATS:
        fund_sats = BOB_TARGET_SATS - bob_balance
        bob_address = _get_or_create_labeled_address(cli, "bob")
        cli.text(
            [
                f"-rpcwallet=alice",
                "-named",
                "sendtoaddress",
                f"address={bob_address}",
                f"amount={_sats_to_btc(fund_sats)}",
                "fee_rate=1",
            ]
        )
        alice_address = _get_or_create_labeled_address(cli, "alice")
        cli.text(["generatetoaddress", "1", alice_address])


def _raw_cli_donation(cli: BitcoinCli, alice_address: str) -> str:
    return cli.text(
        [
            f"-rpcwallet=bob",
            "-named",
            "sendtoaddress",
            f"address={alice_address}",
            f"amount={_sats_to_btc(DONATION_SATS)}",
            "fee_rate=1",
        ],
        timeout_s=60.0,
    )


async def _agent_layer_donation(
    *,
    rpc_url: str,
    datadir: Path,
    alice_address: str,
    agent_dir: Path,
) -> dict[str, Any]:
    sys.path.insert(0, str(REPO_ROOT))

    from agent import AgentConfig, OpenClawAgent, build_tools
    from agent.bitcoin_rpc import RegtestClient
    from agent.regtest_wallet import RegtestWallet
    from identity.agent_identity import AgentIdentity
    from identity.seed import MnemonicSeedSource
    from protocol import StubLLMClient

    alice_seed = MnemonicSeedSource(
        "army van defense carry jealous true garbage claim echo media make crunch"
    ).load()
    bob_seed = MnemonicSeedSource(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ).load()

    alice = OpenClawAgent(
        identity=AgentIdentity.from_seed(alice_seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(port=0, save_dir=agent_dir / "alice"),
    )
    bob = OpenClawAgent(
        identity=AgentIdentity.from_seed(bob_seed, network="TESTNET"),
        llm=StubLLMClient(sources={}),
        config=AgentConfig(
            port=0,
            save_dir=agent_dir / "bob",
            btc_network="regtest",
            community_log_path=agent_dir / "bob" / "community.log",
            peer_log_dir=agent_dir / "bob" / "peer_logs",
        ),
    )

    rpc = RegtestClient(
        rpc_url,
        username=RPC_USER,
        password=RPC_PASSWORD,
        datadir=str(datadir),
        wallet_name="bob",
    )
    bob.wallet = RegtestWallet(bob.wallet, rpc_client=rpc, use_onchain=True)  # type: ignore[assignment]

    manifest_md = f"""\
# Identity

- name: regtest_donation_verify
- version: 1.0.0
- description: Live regtest donation verification.

# Admission

- gatekeeper_address: {alice_address}
- min_sats: {DONATION_SATS}
- min_confirmations: 0
- bootstrap_cap_sats: 100000
- max_agents_per_seedbox: 3
- seedbox_cost_sats: 50000

# Genesis Peers

| host | port | pubkey_hex |
|------|------|------------|
| 127.0.0.1 | 8200 | {alice.pubkey_hex} |

# Default Overlays

- sha1: a3455e9cec3b78bc281f1c495b0a08baa733833a
"""
    bob.load_manifest(manifest_md)
    result = await build_tools(bob).dispatch(
        "community_donate_and_join",
        {"amount_sats": DONATION_SATS},
    )
    if not isinstance(result, dict) or "error" in result:
        raise VerificationError(f"agent donation tool failed: {result}")

    entry = next(
        (
            entry
            for entry in bob.community_log.read_entries()
            if entry.get("entry_hash") == result.get("entry_hash")
        ),
        None,
    )
    if not isinstance(entry, dict):
        raise VerificationError("agent donation entry was not written to community log")
    details = entry.get("details") or {}
    if details.get("donation_txid") != result.get("donation_txid"):
        raise VerificationError("community log donation_txid does not match tool result")
    if details.get("amount_sats") != DONATION_SATS:
        raise VerificationError("community log donation amount does not match expected sats")

    return {
        "txid": result["donation_txid"],
        "entry_hash": result["entry_hash"],
        "community_log": str(agent_dir / "bob" / "community.log"),
    }


def _verify_transaction(
    *,
    cli: BitcoinCli,
    txid: str,
    alice_address: str,
    bob_start_sats: int,
) -> dict[str, Any]:
    cli.text(["generatetoaddress", "1", alice_address])
    alice_tx = cli.json([f"-rpcwallet=alice", "gettransaction", txid])
    bob_tx = cli.json([f"-rpcwallet=bob", "gettransaction", txid])

    confirmations = int(alice_tx.get("confirmations") or 0)
    if confirmations < 1:
        raise VerificationError(f"transaction has insufficient confirmations: {confirmations}")

    received_sats = _confirmed_received_sats(cli, "alice", txid)
    if received_sats < DONATION_SATS:
        raise VerificationError(
            f"Alice received {received_sats} sats for {txid}, expected >= {DONATION_SATS}"
        )

    bob_end_sats = _btc_to_sats(cli.text([f"-rpcwallet=bob", "getbalance"]))
    if bob_start_sats < BOB_TARGET_SATS:
        raise VerificationError(
            f"Bob was funded with {bob_start_sats} sats, expected >= {BOB_TARGET_SATS}"
        )
    if bob_start_sats - bob_end_sats < DONATION_SATS:
        raise VerificationError(
            "Bob balance did not decrease by at least the donation amount "
            f"({bob_start_sats} -> {bob_end_sats})"
        )

    return {
        "txid": txid,
        "confirmations": confirmations,
        "alice_received_sats": received_sats,
        "bob_start_sats": bob_start_sats,
        "bob_end_sats": bob_end_sats,
        "bob_wallet_tx_amount_btc": bob_tx.get("amount"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoin-data", type=Path, help="Regtest datadir to create or reuse.")
    parser.add_argument("--rpc-port", type=int, default=18443, help="RPC port, default 18443.")
    parser.add_argument("--bitcoin-cli", default=None, help="Path to bitcoin-cli.")
    parser.add_argument(
        "--setup-script",
        type=Path,
        default=REPO_ROOT / "deploy" / "setup_bitcoin_regtest.sh",
        help="Path to setup_bitcoin_regtest.sh.",
    )
    parser.add_argument("--keep-running", action="store_true", help="Leave bitcoind running.")
    parser.add_argument(
        "--skip-agent-layer",
        action="store_true",
        help="Only verify raw Bitcoin Core wallet transaction.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    bitcoin_cli = str(Path(args.bitcoin_cli or _which("bitcoin-cli")).resolve())
    bitcoind = str(Path(_default_bitcoind_for_cli(bitcoin_cli)).resolve())
    setup_script = args.setup_script.resolve()
    if not setup_script.exists():
        raise VerificationError(f"setup script not found: {setup_script}")

    rpc_port = _choose_rpc_port(args.rpc_port)
    rpc_url = f"http://127.0.0.1:{rpc_port}"
    temp_ctx: tempfile.TemporaryDirectory[str] | None = None
    if args.bitcoin_data is None:
        temp_ctx = tempfile.TemporaryDirectory(prefix=".regtest_verify_", dir=REPO_ROOT)
        datadir = Path(temp_ctx.name).resolve()
    else:
        datadir = args.bitcoin_data.resolve()
        datadir.mkdir(parents=True, exist_ok=True)

    cli = BitcoinCli(bitcoin_cli, datadir)
    summary: dict[str, Any] = {
        "datadir": str(datadir),
        "rpc_url": rpc_url,
        "bitcoin_cli": bitcoin_cli,
        "bitcoind": bitcoind,
    }
    bitcoind_started = False

    try:
        print(f"[*] Running regtest setup in {datadir}")
        _run_setup(
            setup_script=setup_script,
            datadir=datadir,
            rpc_port=rpc_port,
            bitcoin_cli=bitcoin_cli,
            bitcoind=bitcoind,
        )
        bitcoind_started = True
        _wait_for_rpc(cli)

        alice_address = _stable_labeled_address(cli, "alice")
        bob_address = _stable_labeled_address(cli, "bob")
        bob_start_sats = _btc_to_sats(cli.text([f"-rpcwallet=bob", "getbalance"]))

        if not alice_address.startswith("bcrt1") or not bob_address.startswith("bcrt1"):
            raise VerificationError(
                f"expected regtest bech32 addresses, got alice={alice_address}, bob={bob_address}"
            )

        summary.update(
            {
                "alice_address": alice_address,
                "bob_address": bob_address,
                "bob_funded_sats": bob_start_sats,
            }
        )

        if args.skip_agent_layer:
            print("[*] Sending donation with bitcoin-cli")
            txid = _raw_cli_donation(cli, alice_address)
            summary["agent_layer"] = "skipped"
        else:
            print("[*] Sending donation through community_donate_and_join")
            agent_result = asyncio.run(
                _agent_layer_donation(
                    rpc_url=rpc_url,
                    datadir=datadir,
                    alice_address=alice_address,
                    agent_dir=datadir / "agent_layer",
                )
            )
            txid = str(agent_result["txid"])
            summary["agent_layer"] = agent_result

        if len(txid) != 64:
            raise VerificationError(f"expected 64-char txid, got {txid!r}")

        print("[*] Mining confirmation block and verifying wallet history")
        summary["transaction"] = _verify_transaction(
            cli=cli,
            txid=txid,
            alice_address=alice_address,
            bob_start_sats=bob_start_sats,
        )

        print("\n[+] Regtest donation verification passed")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    finally:
        if bitcoind_started and not args.keep_running:
            print("[*] Stopping isolated bitcoind")
            cli.run(["stop"], timeout_s=15.0, check=False)
            time.sleep(2)
        if temp_ctx is not None and not args.keep_running:
            temp_ctx.cleanup()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        print(f"\n[!] Regtest donation verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
