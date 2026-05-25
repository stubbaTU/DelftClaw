# regtest_transfer scenario

Two-agent scenario that performs a **real Bitcoin Core regtest** on-chain transfer via JSON-RPC:

- **bob** joins via the normal signed-log admission flow, with the admission donation broadcast through Bitcoin Core regtest RPC.
- **alice** mines regtest blocks, then sends **20,000 sats** to bob's advertised on-chain regtest address.

## Preconditions (on the host/VPS running the scenario)

1. A `bitcoind` node running with `-regtest` and RPC enabled.
2. RPC reachable from the scenario services (default: `http://127.0.0.1:18443`).

Minimal `bitcoin.conf` example:

```ini
regtest=1
server=1
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=18443
# Either cookie auth (default) OR explicit user/pass:
# rpcuser=rpcuser
# rpcpassword=rpcpass
```

## How it's wired

- `deploy/scenario_boot.py` writes per-agent env files that include:
  - `BITCOIN_RPC_URL` (defaults to `http://127.0.0.1:18443`)
  - `BITCOIN_RPC_WALLET` (defaults to the agent name: `alice` / `bob`)
  - `BITCOIN_RPC_USER` / `BITCOIN_RPC_PASSWORD` (optional; cookie auth works too)
  - `REDTEAM_PORT` / `PEER_LOG_URLS` so each agent serves and pulls signed community-log entries
- `agent/cli.py` wraps the agent's synthetic wallet with `RegtestWallet(..., use_onchain=True)` when RPC env is present.
- `agent/tools.py` conditionally exposes the real RPC tools from `agent/bitcoin_tools.py`:
  - `btc_get_balance`, `btc_get_address`, `btc_list_utxos`, `btc_list_transactions`, `btc_send`, `btc_transaction_status`, `btc_mine_blocks`

As of the current implementation, the RPC client auto-creates/loads the configured wallet (`alice` / `bob`) on first use when running against a fresh regtest datadir. Creation/loading is automatic; funding is not.

## Funding

Before starting the scenario, start `bitcoind` and fund the named RPC wallets. Bob should only receive the admission minimum.

```bash
bitcoind -regtest -daemon
bitcoin-cli -regtest ping

bitcoin-cli -regtest createwallet alice 2>/dev/null || bitcoin-cli -regtest loadwallet alice
bitcoin-cli -regtest createwallet bob 2>/dev/null || bitcoin-cli -regtest loadwallet bob

ALICE_ADDR=$(bitcoin-cli -regtest -rpcwallet=alice getnewaddress)
bitcoin-cli -regtest generatetoaddress 101 "$ALICE_ADDR"

BOB_ADDR=$(bitcoin-cli -regtest -rpcwallet=bob getnewaddress)
bitcoin-cli -regtest -rpcwallet=alice -named sendtoaddress \
  address="$BOB_ADDR" amount=0.0001 fee_rate=1
bitcoin-cli -regtest generatetoaddress 1 "$(bitcoin-cli -regtest -rpcwallet=alice getnewaddress)"
```

## Run

From your laptop (after configuring `VPS_HOST`/`VPS_USER` in the repo `Makefile`):

```bash
make scenario NAME=regtest_transfer
make tools NAME=regtest_transfer
```

To stop:

```bash
make stop NAME=regtest_transfer
```

## Notes

- Both Bob's admission donation and Alice's later payment use your local `bitcoind -regtest`.
- Bob's stop predicate uses confirmed incoming wallet transactions when available, not net balance, so the admission spend cannot mask the later payment.
