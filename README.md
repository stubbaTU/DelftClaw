# DelftClaw

DelftClaw is a peer-to-peer network infrastructure for autonomous AI (OpenClaw) agents.

This project is developed as part of the CSE3000 Research Project.

## Features

- **P2P Agent Architecture**: Decentralized agent communication using an asynchronous, IPv8-style UDP stack.
- **Cryptographic Identity**: Agent identities and structured message verification built on the `identity/` package, including IPv8, MLS, and wallet keys.
- **Append-Only Action Log**: A public action history for post-factum accountability (`security/subq2_accountability/append_log.py`).
- **Game-Theoretic Reputation**: Reputation scoring and expulsion based on logged malicious behavior (`security/subq2_accountability/reputation.py`).
- **System-Level Isolation**: Proxy-based isolation intended to pair with sandboxing such as gVisor (`security/subq2_accountability/proxy.py`).

## Project Structure

```text
DelftClaw/
|-- agent.py                      # Core P2PAgent prototype using AgentIdentity
|-- network.py                    # Legacy async UDP endpoint prototype
|-- test_auth.py                  # Authentication/signature tests
|-- identity/                     # Agent identity, seed, wallet, and key derivation
|   |-- agent_identity.py
|   |-- derivation.py
|   |-- ipv8_key.py
|   |-- mls_key.py
|   |-- seed.py
|   `-- wallet.py
|-- communication/                # Transport, payloads, channels, messaging, replay, and trustroom logic
|   |-- admission/                # Join/admission protocol helpers
|   |-- channel/                  # Agent channels and inbox
|   |-- messaging/                # Group state, MLS/ratchet sessions, and envelopes
|   |-- payload/                  # Application and payment payloads
|   |-- replay/                   # Nonce cache and timestamp freshness checks
|   |-- transport/                # IPv8 runtime and peer model
|   |-- trustroom/                # Trustroom lifecycle, community, policy, and advertisement
|   `-- wire/                     # Wire frames and codecs
|-- replication/                  # Agent replication, provisioning, funding, and child-seed helpers
|   |-- child_seed.py
|   |-- funding.py
|   |-- provisioning.py
|   `-- replica.py
|-- shared/                       # Shared IDs, envelopes, credentials, threats, and errors
|-- security/                     # Security research components
|   |-- contracts.py              # Shared security protocol contracts and schemas
|   |-- subq1_preventative/       # Baseline ASR and privilege-separation experiments
|   |   |-- privilege.py
|   |   `-- testing_privilege.py
|   |-- subq2_accountability/     # Reputation, append-only logs, and harm-until-expulsion
|   |   |-- accountability.py
|   |   |-- append_log.py
|   |   |-- proxy.py
|   |   |-- reputation.py
|   |   `-- testing_reputation.py
|   `-- subq3_integrity/          # Log integrity and isolation experiments
|       |-- integrity.py
|       `-- testing_integrity.py
|-- trust/                        # Trust stores, revocation, and wire-format helpers
|   |-- formats/
|   |   `-- base.py
|   |-- revocation.py
|   `-- store.py
|-- libsodium.dll                 # Local crypto runtime dependency
|-- requirements.txt
`-- README.md
```

## P2PAgent Overview

The `P2PAgent` class (`agent.py`) is the current prototype that integrates the new `identity/` package, UDP communication, and security mechanisms. It provides:

- **Identity Management**: Uses `AgentIdentity` to derive IPv8, MLS, and wallet keys from one seed.
- **Communication**: Relies on `UDPEndpoint` for asynchronous peer-to-peer message exchange.
- **Message Integrity**: Ensures authenticity and integrity of messages using the IPv8 signing key.
- **Security Features**:
  - **Append-Only Logs**: Tracks agent actions for accountability.
  - **Isolation Proxy**: Provides a narrow logging interface for sandboxed code.
  - **Reputation Engine**: Manages peer trust and penalizes malicious behavior.

The security layer now uses the raw IPv8 Ed25519 verify key bytes as its stable `reporter_id` / `subject_id`, which matches the shared `AgentId` wrapper.

## OpenClaw Proof of Concept

The barebones real OpenClaw agent lives in `communication/claw/openclaw_agent.py` and is exercised by `examples/openclaw_poc.py`.

- It uses `identity.openclaw_identity.OpenClawIdentity` for a persistent local key file.
- It starts the real IPv8 runtime via `communication.transport.ipv8_runtime.IPv8Runtime`.
- It loads the minimal `ClawPoCCommunity` only to announce the identity hash; no search, donation, or seedbox features are enabled yet.

### Network Messaging Layer

The `ClawPoCCommunity` in `communication/claw/community.py` implements:

- **`IdentityAnnouncementPayload`** (msg_id=1): IPv8 packet format containing:
  - `identity_hash`: 32-byte SHA-256 network-bound identity digest
  - `public_key`: serialized IPv8 public key
  - `network`: network label (MAINNET, TESTNET, etc.)
  - `timestamp`: Unix epoch seconds (uint64)

- **Peer Registry**: in-memory `PeerIdentityRecord` dataclass tracking:
  - `mid`: IPv8 20-byte member ID
  - `identity_hash`: peer's identity hash
  - `public_key`: peer's serialized public key
  - `network`: peer's network label
  - `last_seen`: timestamp of last announcement

- **Message Flow**:
  - When a new peer joins, `peer_added()` sends an identity announcement
  - `announce_identity()` broadcasts the local identity to all current peers
  - `register_task("periodic_announce", ...)` re-announces every 60 seconds
  - `_on_identity_announcement()` validates and stores incoming announcements

- **Public API**:
  - `peer_identities`: property returning a copy of the peer registry dict
  - `get_peer_identity(mid)`: lookup a peer's identity record by IPv8 mid

Run it with:

```powershell
python examples\openclaw_poc.py
```

## OpenClaw Identity

For the OpenClaw-specific identity flow, use `identity.openclaw_identity.OpenClawIdentity`.

- The private IPv8 key is stored locally as a hex-encoded text file, defaulting to `%APPDATA%\OpenClaw\identity\openclaw_priv.pem` on Windows.
- The network-bound identifier is `SHA256(IPv8_Public_Key | NETWORK)` where `IPv8_Public_Key` is the raw 32-byte Ed25519 verify key.
- The supported network labels are normalized to uppercase, e.g. `MAINNET`, `TESTNET`, or `REGTEST`.

Example:

```python
from identity.openclaw_identity import OpenClawIdentity

identity = OpenClawIdentity(network="MAINNET")
print(identity.get_identity_hash())
```
