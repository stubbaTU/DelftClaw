# Bitcoin Regtest Setup for DelftClaw Demo

This guide walks through setting up a real Bitcoin Regtest environment for the DelftClaw agents to perform actual on-chain transactions.

## Overview

The Regtest environment allows agents to:
- **Send real transactions** to a local Bitcoin network
- **Query balances** from actual UTXOs
- **Mine blocks** to confirm transactions
- **Validate spends** with real cryptographic signatures

This replaces the synthetic (mock) wallet system with a functional blockchain, perfect for testing transaction workflows, fee calculations, and admission gates that verify on-chain donations.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Process                             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  OpenClawAgent (agent/runtime.py)                      │ │
│  │  ├─ identity: AgentIdentity                           │ │
│  │  ├─ wallet: RegtestWallet (agent/regtest_wallet.py)  │ │
│  │  └─ tools: ToolRegistry                              │ │
│  │     ├─ wallet_balance, wallet_send (synthetic)       │ │
│  │     ├─ btc_get_balance, btc_send (on-chain)         │ │
│  │     └─ ... community, overlay, torrent tools         │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
              │
              │ JSON-RPC
              ▼
┌─────────────────────────────────────────────────────────────┐
│              Bitcoin Regtest Node (bitcoind)                │
│  ├─ Daemon: bitcoind -regtest -datadir=/path -rpcport=18443│
│  ├─ Wallets: alice, bob, charlie, dave                     │
│  ├─ ChainState: /path/.bitcoin/regtest                     │
│  └─ RPC: http://127.0.0.1:18443                            │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

### Requirements

1. **Bitcoin Core** installed on VPS
   ```bash
   # Ubuntu/Debian
   sudo apt-get install bitcoind
   
   # Or build from source
   # https://github.com/bitcoin/bitcoin/blob/master/doc/build-unix.md
   ```

2. **Python dependencies** (already in requirements.txt)
   ```bash
   pip install httpx>=0.27 bitcoinlib>=0.6.0
   ```

3. **Free disk space**: ~100MB for Regtest chain

### Directory Structure

```
/var/lib/delftclaw/                          (data directory)
├── scenarios/
│   └── seek_cc/
│       └── agents/
│           ├── alice/
│           │   ├── community.log
│           │   └── peer_logs/
│           ├── bob/
│           └── ...
└── bitcoin/
    ├── bitcoin.conf
    └── regtest/
        ├── blocks/
        ├── chainstate/
        ├── wallets/
        └── ...
```

## Setup Steps

### Step 1: Initialize Bitcoin Regtest Node

Run the setup script on your VPS:

```bash
cd /path/to/repo
chmod +x deploy/setup_bitcoin_regtest.sh

# Initialize with defaults
./deploy/setup_bitcoin_regtest.sh

# Or specify custom paths
./deploy/setup_bitcoin_regtest.sh \
    --bitcoin-data /var/lib/delftclaw/bitcoin \
    --rpc-port 18443 \
    --rpc-bind 127.0.0.1
```

What this script does:
- Creates Bitcoin config file (`bitcoin.conf`)
- Starts `bitcoind` in `-regtest` mode
- Creates named wallets for each agent
- Mines enough blocks for coinbase rewards to mature and become spendable
- Outputs wallet addresses to stdout

**Expected output:**
```
[*] Bitcoin config written to /home/user/.bitcoin/bitcoin.conf
[*] Starting bitcoind in -regtest mode...
[+] bitcoind is ready
[*] Creating agent wallets...
  ✓ Wallet 'alice' already exists
  ✓ Wallet 'bob' already exists
  ...

Wallets:
  alice:
    Address: mi...
    Balance: non-zero BTC
  ...
```

### Step 2: Fund Wallets

Use the Python initialization script:

```bash
cd /path/to/repo
python deploy/init_regtest_wallets.py \
    --agents alice bob charlie dave \
    --rpc-url http://127.0.0.1:18443 \
    --initial-balance 500000 \
    --output /var/lib/delftclaw/regtest_config.json
```

What this script does:
- Verifies RPC connectivity
- Creates wallets if they don't exist
- Mines enough blocks to fund each wallet and mature the rewards
- Verifies final balances
- Writes config JSON with addresses and RPC endpoints

**Expected output:**
```
--- Setting up alice ---
[+] Created wallet: alice
Mining 101 blocks to mi... for alice...
Mined 101 blocks
Wallet alice now has a spendable on-chain balance

...

Regtest Wallet Initialization Summary
======================================
RPC URL: http://127.0.0.1:18443
Network: regtest

Agents:
  alice:
    Address:       mi...
    Balance:       5,000,000,000 sats
    Blocks Mined:  101
  ...
```

### Step 3: Update Agent Configuration

Update systemd environment files or Docker compose to pass RPC details used by your deployment:

```bash
# /etc/delftclaw/instances/seek_cc-alice.env
OPENCLAW_RPC_URL=http://127.0.0.1:18443
OPENCLAW_RPC_WALLET=alice
OPENCLAW_USE_ONCHAIN=1
OPENCLAW_BTC_NETWORK=regtest
```

Or in the scenario boot script (deploy/scenario_boot.py):

```python
# Pass RPC config to agent
config = AgentConfig(
    port=8190,
    btc_network="regtest",
    # The agent's RegtestWallet will use these
    initial_balance_sats=500_000,  # Still used for max-spend cap
)
```

### Step 4: Launch Agent with Regtest Wallet

The agent runtime will detect the configured RPC endpoint and use `RegtestWallet` instead of synthetic wallet:

```python
from agent.runtime import OpenClawAgent, AgentConfig
from agent.regtest_wallet import RegtestWallet
from identity.agent_identity import AgentIdentity

# Create identity from seed
identity = AgentIdentity(network="REGTEST", agent_index=0)

# Create Regtest wallet instead of synthetic
wallet = RegtestWallet.from_seed(
    identity._seed,
    network="REGTEST",
    agent_index=0,
    rpc_url="http://127.0.0.1:18443",
    wallet_name="alice",
    use_onchain=True,  # Enable real Regtest operations
)

# Create agent with custom wallet
config = AgentConfig(
    port=8190,
    btc_network="regtest",
)
agent = OpenClawAgent(identity, llm, config, use_regtest_wallet=wallet)
await agent.start()
```

## Available Tools

### Synthetic wallet tools (unchanged)

- `wallet_address()` → Returns the synthetic `dclaw1...` address
- `wallet_balance()` → Returns synthetic balance (demo budget)
- `wallet_send(to_address, sats)` → Generates deterministic synthetic txid

### New Regtest tools (on-chain)

- `btc_get_balance()` → Query real Regtest balance from UTXOs
- `btc_get_address()` → Derive new Bitcoin address for this wallet
- `btc_list_utxos(min_confirmations=0)` → List unspent outputs
- `btc_send(to_address, amount_sat)` → Broadcast a real transaction
- `btc_transaction_status(txid)` → Check confirmations and status
- `btc_mine_blocks(num_blocks=1)` → Mine blocks (testing utility)

**Tool availability:**

- Agents without a configured RPC endpoint use **synthetic tools only**
- Agents with a `RegtestWallet` can use **both synthetic and Regtest tools**
- LLMs can mix and match: e.g., use synthetic `wallet_send` for a test, then `btc_send` for real

## Testing Transaction Flow

### Manual smoke test via bitcoin-cli

```bash
# Check alice's balance
bitcoin-cli -regtest -rpcwallet=alice getbalance
# => 5 (in BTC, which is 500,000,000 satoshis)

# Send 10,000 sats from alice to bob
ALICE_ADDR=$(bitcoin-cli -regtest -rpcwallet=alice getnewaddress)
BOB_ADDR=$(bitcoin-cli -regtest -rpcwallet=bob getnewaddress)
bitcoin-cli -regtest -rpcwallet=alice sendtoaddress $BOB_ADDR 0.0001  # 10,000 sats
# => txid: 1234...abcd

# Check bob's balance (should not update until mined)
bitcoin-cli -regtest -rpcwallet=bob getbalance
# => 0

# Mine a block
bitcoin-cli -regtest generatetoaddress 1 $ALICE_ADDR

# Check again
bitcoin-cli -regtest -rpcwallet=bob getbalance
# => 0.0001 (10,000 sats)

# Query transaction status
bitcoin-cli -regtest gettransaction 1234...abcd
```

### Agent tool test

The LLM can use tools in a script-like scenario:

```
Agent (alice):
1. Query balance: btc_get_balance() → 500000 sats
2. Get address: btc_get_address() → mi...
3. Send to bob: btc_send(bob_addr, 50000) → txid: abc...
4. Check status: btc_transaction_status(abc...) → unconfirmed
5. Mine blocks: btc_mine_blocks(1) → 1 block mined
6. Check again: btc_transaction_status(abc...) → 1 confirmation
7. Verify spend: btc_get_balance() → 449999 sats (minus 1 sat fee)
```

## Troubleshooting

### bitcoind fails to start

```bash
# Check config syntax
bitcoind -regtest -datadir=/path -printtoconsole 2>&1 | head -20

# Try resetting chain (WARNING: deletes all blocks)
rm -rf /path/.bitcoin/regtest/blocks
rm -rf /path/.bitcoin/regtest/chainstate
bitcoind -regtest -datadir=/path -daemon
```

### RPC connection refused

```bash
# Check if daemon is running
bitcoin-cli -regtest ping
# If error: no error code was returned

# Start manually in foreground to see errors
bitcoind -regtest -datadir=/path -printtoconsole
```

### High transaction fees

On Regtest, the default fee estimation may be high. Override in code:

```python
await wallet.send_onchain(addr, sats, fee_rate_sat_per_vb=1)  # 1 sat/vB
```

### Wallet not found

```bash
# List loaded wallets
bitcoin-cli -regtest listwallets

# Manually load if missing
bitcoin-cli -regtest loadwallet alice
```

### Insufficient funds

Regtest only generates 50 BTC per block. If agents spend faster than you mine:

```bash
# Mine more blocks
bitcoin-cli -regtest generatetoaddress 100 <address>

# Or increase initial funding in init_regtest_wallets.py
python deploy/init_regtest_wallets.py --initial-balance 10000000
```

## Integration with Demo Scenarios

To run the `seek_cc` scenario with Regtest:

### 1. Update scenario.yaml

```yaml
agents:
  alice:
    initial_balance_sats: 500000  # Demo budget cap
    # ... other config
```

### 2. Update scenario_boot.py

```python
from agent.regtest_wallet import RegtestWallet

# After creating identity:
if use_regtest:
    agent_wallet = RegtestWallet.from_seed(
        identity._seed,
        network="REGTEST",
        agent_index=agent_index,
        rpc_url="http://127.0.0.1:18443",
        wallet_name=agent_name,
        use_onchain=True,
    )
    agent.wallet = agent_wallet
```

### 3. Update environment file

```bash
/etc/delftclaw/scenarios/seek_cc/alice.env:
OPENCLAW_RPC_URL=http://127.0.0.1:18443
OPENCLAW_RPC_WALLET=alice
OPENCLAW_USE_ONCHAIN=1
```

## Key Differences from Synthetic Mode

| Feature | Synthetic | Regtest |
|---------|-----------|---------|
| **Balance** | Demo budget (fixed) | Real UTXOs (dynamic) |
| **Transactions** | Deterministic hash | Real txid from network |
| **Confirmations** | Instant (0) | Requires mining |
| **Fees** | Zero | Real fee calc |
| **Verification** | Ceremonial | Cryptographically valid |
| **Speed** | Sub-second | Seconds to minutes |

## Architecture Notes

### RegtestWallet Design

The `RegtestWallet` class (agent/regtest_wallet.py) wraps the synthetic `Wallet` and layers RPC calls:

```python
# Graceful fallback: tries RPC first, falls back to synthetic
balance = await wallet.balance_sats()  # Real if RPC OK, synthetic otherwise
```

This allows:
- **Gradual migration**: Switch individual tools to on-chain
- **Hybrid demos**: Some agents on Regtest, others synthetic
- **Fault tolerance**: If RPC goes down, agents keep working (synthetically)

### Tool Integration

New tools (agent/bitcoin_tools.py) follow the standard pattern:

```python
async def btc_send(to_address: str, amount_sat: int) -> dict:
    """Tool function returns JSON-serializable dict"""
    try:
        txid = await wallet.send_onchain(to_address, amount_sat)
        return {"txid": txid, "amount_sat": amount_sat}
    except Exception as exc:
        return {"error": str(exc)}
```

Tools are registered with `ToolRegistry` just like any other:

```python
tools = build_tools(agent)
tools.add(btc_tools)  # Extend registry
```

## Production Considerations

⚠️ **IMPORTANT**: Regtest is for testing only. For production:

- Use **Testnet** (requires real testnet coins)
- Use **Mainnet** (with real Bitcoin)
- Implement proper RPC authentication (username/password in bitcoin.conf)
- Use **hardware wallets** for key management
- Run bitcoind on a **separate machine** from agents
- Monitor **disk space** (mainnet blockchain is ~600GB)
- Implement **transaction broadcasting** verification
- Add **multi-sig** for treasuries
- Use **fee estimation** for real networks

See `/docs/` for security architecture.

## References

- [Bitcoin Core RPC API](https://developer.bitcoin.org/reference/rpc/)
- [Bitcoin Regtest Mode](https://developer.bitcoin.org/reference/command-line-arguments#regtest)
- [BIP-32 HD Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [agent/bitcoin_rpc.py](../agent/bitcoin_rpc.py) - RPC client implementation
- [agent/regtest_wallet.py](../agent/regtest_wallet.py) - Hybrid wallet wrapper
- [agent/bitcoin_tools.py](../agent/bitcoin_tools.py) - LLM tool definitions

