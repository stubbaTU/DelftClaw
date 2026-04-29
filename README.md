# DelftClaw

DelftClaw is a peer-to-peer network infrastructure for autonomous AI (OpenClaw) agents.

This project is developed as part of the CSE3000 Research Project.

## Features

- **P2P Agent Architecture**: Decentralized agent communication using an asynchronous, IPv8-style UDP stack (`network.py`).
- **Cryptographic Identity**: Agent identities and structured message verifications built on BIP-32 HD wallets and ECDSA deterministic signatures (`hdwallet.py`).
- **Append-Only Action Log**: An irrefutable public ledger of past agent operations enabling post-factum accountability (`security/subq2_accountability/append_log.py`).
- **Game-Theoretic Reputation**: A reputation engine that parses the distributed log, punishing and expelling nodes automatically based on malicious behavior (`security/subq2_accountability/reputation.py`).
- **System-Level Isolation**: Proxy-based structural isolation intended to pair with gVisor, preventing a successfully compromised LLM from altering its local append-only log (`security/subq2_accountability/proxy.py`).

## Project Structure

```text
DelftClaw/
├── agent.py               # Core P2PAgent implementation
├── hdwallet.py            # BIP-32 hierarchical deterministic wallet implementation
├── network.py             # Asynchronous Datagram (UDP) endpoint
├── security/              # Defense-in-depth components
│   ├── subq1_preventative/
│   │   ├── privilege.py         # Privilege separation and constraint mechanisms 
│   │   └── testing_privilege.py # Evaluation and testing tools for privileges
│   ├── subq2_accountability/
│   │   ├── accountability.py    # Core accountability mechanisms
│   │   ├── append_log.py        # Irrefutable log operations
│   │   ├── proxy.py             # Isolation logic filtering actions and calls
│   │   ├── reputation.py        # Trust mechanism to implement the "shadow of the future"
│   │   └── testing_reputation.py # Evaluation for accountability & reputation
│   └── subq3_integrity/
│       ├── integrity.py         # Data and system integrity protection
│       └── testing_integrity.py # Tests for integrity modules
└── README.md

```

## P2PAgent Overview

The `P2PAgent` class (`agent.py`) is the core component of DelftClaw, integrating cryptographic identity, UDP communication, and security mechanisms. It provides:

- **Identity Management**: Uses `HDWallet` to generate and manage cryptographic keys and addresses.
- **Communication**: Relies on `UDPEndpoint` for asynchronous peer-to-peer message exchange.
- **Message Integrity**: Ensures authenticity and integrity of messages using ECDSA signatures.
- **Security Features**:
  - **Append-Only Logs**: Tracks agent actions for accountability.
  - **Isolation Proxy**: Enforces security policies and prevents unauthorized actions.
  - **Reputation Engine**: Manages peer trust and penalizes malicious behavior.

The `P2PAgent` is designed for secure and verifiable peer-to-peer communication, making it suitable for decentralized AI systems.
