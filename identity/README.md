# Identity Layer

Cryptographic identity stack for autonomous OpenClaw agents. One
BIP-39 seed derives, via a BIP-32 chain, three independent keys:

```
m/44'/0'/0'/0/0   ->  Ed25519 IPv8 transport key (LibNaCLSK)
m/44'/0'/0'/1/0   ->  Ed25519 application-layer signing key
                  ->  secp256k1 Bitcoin HD wallet (bitcoinlib BIP-32, separate)
```

`agent_id = sha256(ipv8_raw_pubkey || network)`.

## Public surface

- `AgentIdentity.from_seed(seed, network) -> AgentIdentity` — the
  multi-key bundle. Consumed by `agent/runtime.py:OpenClawAgent`.
- `Seed` + four loaders: `MnemonicSeedSource` (BIP-39),
  `EnvSeedSource` (env var), `KeyringSeedSource` (OS keyring),
  `KeyfileSeedSource` (hex file, auto-generates on first run; VPS
  production default).
- `Wallet.from_seed(seed, btc_network)` — thin `bitcoinlib.HDWallet`
  wrapper. CLI: `python -m identity.wallet --mnemonic '…'
  {address,balance,send}`. Also runs at scenario boot to materialise
  per-agent seed files.

## Tests

```bash
pytest identity/tests -q
```

## Notes

`OpenClawIdentity` (`openclaw_identity.py`) is a thin compatibility
shim around `AgentIdentity`, kept because the colleague's
`security/integration/openclaw_bridge.py` and the redteam signed-log
test suite import it directly. v5.1 production code uses
`AgentIdentity` everywhere else.
