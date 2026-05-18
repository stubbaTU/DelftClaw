# Quick Start: Running Agents on Bitcoin Regtest

Get a local Bitcoin Regtest environment and agents working in **15 minutes**.

## Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install bitcoind python3 python3-pip

# Or macOS
brew install bitcoin
```

## Step 1: Set Up Bitcoin (2 minutes)

> If you already have `bitcoind --regtest` running, skip this step and continue with wallet initialization.

```bash
cd /path/to/delftclaw/repo

# Make setup script executable
chmod +x deploy/setup_bitcoin_regtest.sh

# Run setup
./deploy/setup_bitcoin_regtest.sh

# Expected output:
# [+] bitcoind is ready
# [*] Creating agent wallets...
# Wallets: alice, bob, charlie, dave ✓
```

That's it! Bitcoin is now running in Regtest mode.

## Step 2: Fund the Wallets (3 minutes)

```bash
# Install Python deps if needed
pip install -r requirements.txt

# Initialize wallets and mine blocks
python deploy/init_regtest_wallets.py \
    --agents alice bob charlie dave \
    --initial-balance 500000

# Expected output:
# --- Setting up alice ---
# Mining 101 blocks...
# Wallet alice now has a spendable on-chain balance ✓
# ... (repeat for bob, charlie, dave)
```

**Now all four agents have spendable on-chain balances.**

## Step 3: Verify Connectivity (2 minutes)

```bash
# Check Bitcoin is running
bitcoin-cli -regtest getblockcount
# => 101 (or higher)

# Check alice's balance
bitcoin-cli -regtest -rpcwallet=alice getbalance
# => a positive BTC balance (for example, 5.00000000 on a freshly mined wallet)

# Get an address for alice
bitcoin-cli -regtest -rpcwallet=alice getnewaddress
# => mi8c... (a Regtest address)
```

## Step 4: Run an Agent (5 minutes)

```bash
# Test the agent with Regtest wallet
python -m agent.example_regtest_setup \
    --agent alice \
    --mnemonic "$(python -c 'from identity.seed import Seed; print(Seed.generate_mnemonic())')" \
    --use-regtest \
    --rpc-url http://127.0.0.1:18443

# Expected output:
# [alice] Agent ready
# [alice] Wallet address (synthetic): dclaw1...
# [alice] Balance: <synthetic balance in sats>
# [alice] On-chain balance: <current regtest balance in sats>
```

**Your agent is now connected to Regtest!**

## Step 5: Use Regtest Tools (3 minutes)

The agent can now use real Bitcoin tools:

```python
# In agent code or LLM prompts:

# Get balance from Regtest
btc_get_balance()
# => {"balance_sat": <current wallet balance in sats>, "balance_btc": "<current BTC value>"}

# Get address
btc_get_address()
# => {"address": "mi8...", "network": "regtest"}

# Send satoshis
btc_send(to_address="mi...", amount_sat=10000)
# => {"txid": "abc123...", "amount_sat": 10000}

# Check transaction status
btc_transaction_status(txid="abc123...")
# => {"status": "unconfirmed", "confirmations": 0}

# Mine blocks to confirm
btc_mine_blocks(num_blocks=1)
# => {"blocks_mined": 1, "new_block_height": 103}

# Check again
btc_transaction_status(txid="abc123...")
# => {"status": "confirmed", "confirmations": 1}
```

## Next: Run Full Scenario

To run the `seek_cc` scenario with real Bitcoin:

```bash
# Update environment variables
export BITCOIN_RPC_URL=http://127.0.0.1:18443
export BITCOIN_REGTEST=1

# Launch scenario (see deploy/scenario_boot.py for full integration)
python deploy/scenario_boot.py \
    --scenario deploy/scenarios/seek_cc/scenario.yaml \
    --use-regtest

# Watch agents donate and transact on-chain!
# All donations appear in blockchain, not just mocked.
```

## Common Commands

### Mine more blocks
```bash
bitcoin-cli -regtest generatetoaddress 50 $(bitcoin-cli -regtest getnewaddress)
```

### Send Bitcoin manually
```bash
ALICE=$(bitcoin-cli -regtest -rpcwallet=alice getnewaddress)
BOB=$(bitcoin-cli -regtest -rpcwallet=bob getnewaddress)
bitcoin-cli -regtest -rpcwallet=alice sendtoaddress $BOB 0.001  # 100,000 sats
bitcoin-cli -regtest generatetoaddress 1 $ALICE  # Confirm
```

### Check all wallets
```bash
for w in alice bob charlie dave; do
    echo "$w: $(bitcoin-cli -regtest -rpcwallet=$w getbalance) BTC"
done
```

### Cleanly reset regtest blockchain and wallets
```bash
# Stop bitcoind and delete regtest chain state / wallets
chmod +x deploy/cleanup_bitcoin_regtest.sh
./deploy/cleanup_bitcoin_regtest.sh --yes

# To also remove bitcoin.conf:
./deploy/cleanup_bitcoin_regtest.sh --yes --remove-config
```

### Stop Bitcoin
```bash
bitcoin-cli -regtest stop
# Or force: pkill bitcoind
```

### Restart Bitcoin
```bash
bitcoind -regtest -daemon
sleep 2
bitcoin-cli -regtest ping
```

### View blockchain logs
```bash
tail -f ~/.bitcoin/debug.log
```

## Troubleshooting

**Q: "Connection refused"**
```bash
# Bitcoind not running?
ps aux | grep bitcoind
bitcoind -regtest -daemon  # Start it
```

**Q: "Wallet not initialized"**
```bash
bitcoin-cli -regtest loadwallet alice
```

**Q: Agent shows balance 0**
```bash
# Agent may be querying with high min_confirmations
# Tell it to use 0 confirma, or mine more blocks
bitcoin-cli -regtest generatetoaddress 10 $(bitcoin-cli -regtest getnewaddress)
```

**Q: "too_many_inputs" error**
```bash
# Wallet has too many UTXOs; consolidate
python deploy/consolidate_utxos.py --wallet alice
```

## What's Running?

| Component | Port | PID | Check |
|-----------|------|-----|-------|
| bitcoind (RPC) | 18443 | $(pgrep bitcoind) | `bitcoin-cli -regtest ping` |
| Bitcoin P2P | 18444 | (same) | `bitcoin-cli -regtest getpeerinfo` |
| Agent (IPv8) | 8190+ | (your_agent) | `netstat -tlnp \| grep 8190` |

## Cleanup

```bash
# Stop daemon
bitcoin-cli -regtest stop

# Delete chain (start fresh next time)
rm -rf ~/.bitcoin/regtest

# Stop agents
pkill -f "agent.example_regtest"
```

## Advanced Usage

See `/deploy/REGTEST_SETUP.md` for:
- Running scenario boot with Regtest
- Integration with systemd services
- Production configuration
- Security best practices

## Architecture Overview

```
Agent (Python)
    ↓
RegtestWallet (wrapper)
    ├─ Synthetic fallback
    └─ Bitcoin RPC calls
        ↓
bitcoind (Regtest node)
    ├─ Named wallets (alice, bob, charlie, dave)
    ├─ Block generation
    ├─ Transaction signing
    └─ Chain state
```

## Next Steps

1. ✅ Bitcoin running (`getblockcount` works)
2. ✅ Wallets funded (`alice` has 500k sats)
3. ✅ Agent connected (example_regtest_setup works)
4. 🚀 Run scenario (`seek_cc` with real Bitcoin)
5. 🚀 Deploy on VPS (production Regtest)
6. 🚀 Migrate to Testnet (real Bitcoin testnet coins)

---

**Total time: 15 minutes to first on-chain transaction!**

Questions? See the full guide: `/deploy/REGTEST_SETUP.md`

