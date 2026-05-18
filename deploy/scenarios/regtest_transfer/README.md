# regtest_transfer scenario

Two-agent scenario that performs a **real Bitcoin Core regtest** on-chain transfer via JSON-RPC:

- **bob** joins via the normal signed-log admission flow (kept in `BTC_NETWORK=mock` mode so admission stays synthetic).
- **alice** mines regtest blocks, then sends **10,000 sats** to bob’s advertised on-chain regtest address.

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

## How it’s wired

- `deploy/scenario_boot.py` writes per-agent env files that include:
  - `BITCOIN_RPC_URL` (defaults to `http://127.0.0.1:18443`)
  - `BITCOIN_RPC_WALLET` (defaults to the agent name: `alice` / `bob`)
  - `BITCOIN_RPC_USER` / `BITCOIN_RPC_PASSWORD` (optional; cookie auth works too)
- `agent/cli.py` wraps the agent’s synthetic wallet with `RegtestWallet(..., use_onchain=True)` when RPC env is present.
- `agent/tools.py` conditionally exposes the real RPC tools from `agent/bitcoin_tools.py`:
  - `btc_get_balance`, `btc_get_address`, `btc_list_utxos`, `btc_send`, `btc_transaction_status`, `btc_mine_blocks`

As of the current implementation, the RPC client auto-creates/loads the configured wallet (`alice` / `bob`) on first use when running against a fresh regtest datadir.

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

- Admission is kept in `btc_network: mock` mode in `scenario.yaml` because `admission/donation_verifier.py` does not support `regtest` verification.
- The *on-chain transfer* is still real regtest: it uses the `btc_*` tools and your local `bitcoind -regtest`.

