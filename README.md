# DelftClaw

DelftClaw is a peer-to-peer network infrastructure for autonomous AI (OpenClaw) agents.

This project is developed as part of the CSE3000 Research Project.

## Features

- **P2P Agent Architecture**: Decentralized agent communication using an asynchronous, IPv8-style UDP stack.
- **Cryptographic Identity**: Agent identities and structured message verification built on wallet-derived keys and deterministic signatures.
- **Append-Only Action Log**: A public action history for post-factum accountability (`security/subq2_accountability/append_log.py`).
- **Game-Theoretic Reputation**: Reputation scoring and expulsion based on logged malicious behavior (`security/subq2_accountability/reputation.py`).
- **System-Level Isolation**: Proxy-based isolation intended to pair with sandboxing such as gVisor (`security/subq2_accountability/proxy.py`).

## Project Structure

```text
DelftClaw/
|-- agent.py                      # Core P2PAgent prototype
|-- hdwallet.py                   # Legacy HD wallet prototype
|-- network.py                    # Legacy async UDP endpoint prototype
|-- identity/                     # Agent identity, seed, wallet, and key derivation
|-- communication/                # Transport, payloads, channels, messaging, and trust-room logic
|-- trust/                        # Credential issuance, revocation, storage, and formats
|-- replication/                  # Agent replication and child-seed helpers
|-- integration/                  # RPC, sidecar lifecycle, and OpenClaw tool adapters
|-- shared/                       # Shared IDs, envelopes, credentials, threats, and errors
|-- skills/openclaw-trustroom/    # OpenClaw skill package
|-- security/                     # Security research components
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
|-- requirements.txt
`-- README.md
```

## P2PAgent Overview

The `P2PAgent` class (`agent.py`) is the current prototype that integrates cryptographic identity, UDP communication, and security mechanisms. It provides:

- **Identity Management**: Uses `HDWallet` to generate and manage cryptographic keys and addresses.
- **Communication**: Relies on `UDPEndpoint` for asynchronous peer-to-peer message exchange.
- **Message Integrity**: Ensures authenticity and integrity of messages using ECDSA signatures.
- **Security Features**:
  - **Append-Only Logs**: Tracks agent actions for accountability.
  - **Isolation Proxy**: Provides a narrow logging interface for sandboxed code.
  - **Reputation Engine**: Manages peer trust and penalizes malicious behavior.

The new package directories under `identity/`, `communication/`, `trust/`, `replication/`, and `integration/` contain the broader DelftClaw infrastructure as it is being split out of the original prototype files.
