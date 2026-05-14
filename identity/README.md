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

`OpenClawIdentity` (`openclaw_identity.py`) is the **identity type
the signed append-only log binds to** —
`redteam/primitives/signed_log.py:SignedAppendOnlyLog` takes an
`OpenClawIdentity` and produces signed entries whose `reporter_id`
equals `SHA256(reporter_pubkey || network)`. It also has a
`from_agent_identity` factory so callers that already hold an
`AgentIdentity` (e.g. `agent/runtime.py:OpenClawAgent`) can wrap it
without re-deriving keys. `security/integration/openclaw_bridge.py`
and the redteam test suite both consume it directly.
