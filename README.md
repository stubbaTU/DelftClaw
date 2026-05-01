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

The security layer currently uses the IPv8 public key hex as its stable `reporter_id` / `subject_id` until the shared `AgentId` wrapper is fully implemented.
