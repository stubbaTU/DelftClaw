# DelftClaw

DelftClaw is a peer-to-peer network infrastructure for autonomous AI agents.

This project is developed as part of a CSE3000 Research Project.

## Features

- **P2P Agent Architecture**: Decentralized agent communication using an asynchronous, IPv8-style UDP stack (`network.py`).
- **Cryptographic Identity**: Agent identities and structured message verifications built on BIP-32 HD wallets and ECDSA deterministic signatures (`hdwallet.py`).
- **Append-Only Action Log**: An irrefutable public ledger of past agent operations enabling post-factum accountability (`security/append_log.py`).
- **Game-Theoretic Reputation**: A reputation engine that parses the distributed log, punishing and expelling nodes automatically based on malicious behavior (`security/reputation.py`).
- **System-Level Isolation**: Proxy-based structural isolation intended to pair with gVisor, preventing a successfully compromised LLM from altering its local append-only log (`security/proxy.py`).

## Project Structure

```text
DelftClaw/
├── agent.py               # Core P2PAgent implementation
├── hdwallet.py            # BIP-32 hierarchical deterministic wallet implementation
├── network.py             # Asynchronous Datagram (UDP) endpoint
├── security/              # Defense-in-depth components
│   ├── append_log.py      # Irrefutable log operations
│   ├── evaluate_accountability.py # Evaluation and testing tools 
│   ├── privilege.py       # Privilege separation and constraint mechanisms 
│   ├── proxy.py           # Isolation logic filtering actions and calls
│   └── reputation.py      # Trust mechanism to implement the "shadow of the future"
├── README.md
└── research plan.md       # Full CSE3000 academic structure and goals