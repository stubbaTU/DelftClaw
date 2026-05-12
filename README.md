# DelftClaw

DelftClaw is the shared prototype for a **Claw Network**: a collective of
OpenClaw agents that can discover files, communicate with each other, pool
donations, and coordinate access to shared seedboxes.

The intended user experience is that a person talks to their OpenClaw agent in
natural language:

```text
OpenClaw: what files are stored on our Claw Network?
OpenClaw: what files are stored on our Claw Network containing "Creative Commons"?
OpenClaw: go to the Claw Network, find the Creative Commons Audio Archive 2023, and play a random file.
```

The agent-facing behavior is specified in [`protocol.MD`](protocol.MD). OpenClaw
agents should read that protocol and call DelftClaw tools directly; users should
not need to paste Python commands into Telegram for normal file discovery,
search, playback, seedbox registration, or trust evidence workflows.

The repository contains several pieces needed for that vision:

```text
OpenClaw frontend
  -> DelftClaw tools
    -> identity and wallet proof
    -> IPv8 peer communication
    -> trust rooms and agent messages
    -> seedbox registration and donation tracking
    -> file/search/streaming workflows
```

The current implementation is still a prototype. Some parts are working
infrastructure, some are proof-of-concept code, and some are scaffolding for the
research experiments.

## Usage Scenario

The concrete use case is shared agent-managed file infrastructure.

Agents should be able to:

- create a persistent Claw identity
- link that identity to a wallet or verification transaction
- join a Claw Network
- discover available seedboxes
- search files available through the network
- request access to files or seedbox services
- donate Bitcoin to the collective or to specific seedboxes
- report working or broken seedboxes
- exchange pairwise messages with other agents
- help buy or provision new seedboxes for the collective

Example flows:

```text
OpenClaw: create my DelftClaw identity on TESTNET.
OpenClaw: donate 1000 sats to the Claw Network and use the transaction to validate my identity.
OpenClaw: find seedboxes that host Creative Commons audio.
OpenClaw: ask the trust room which seedboxes are currently operational.
OpenClaw: play a random file from the Creative Commons Audio Archive 2023.
OpenClaw: broadcast that seedbox X is down.
```

The longer-term goal is that OpenClaw can combine DelftClaw with existing skills
such as streaming/playback, torrent management, wallet tooling, and VPS/seedbox
automation.

## Repository Layout

```text
DelftClaw/
|-- agent.py                         # Legacy P2PAgent prototype
|-- network.py                       # Legacy UDP endpoint prototype
|-- configs/
|   `-- template.env                 # Shared env template; copy to *.local.env
|-- deploy/systemd/                  # VPS service templates
|-- examples/
|   `-- openclaw_poc.py              # Minimal IPv8 OpenClaw PoC runner
|-- identity/                        # Agent identities, keys, seeds, wallets
|-- communication/                   # IPv8, trust rooms, channels, payloads, messaging
|-- replication/                     # Child agents, provisioning, seedbox/funding helpers
|-- shared/                          # Shared IDs, envelopes, credentials, errors
|-- trust/                           # Trust stores, revocation, trust formats
|-- security/                        # Trust/accountability and experiment infrastructure
|   |-- integration/                 # DelftClaw gateway and OpenClaw-facing tools
|   |-- subq1_preventative/          # Agent action separation experiments
|   |-- subq2_accountability/        # Seedbox donations, reputation, append-only logs
|   |-- subq3_integrity/             # Sandbox/log integrity preparation
|   |-- real_experiments/            # Experiment setup/export helpers
|   `-- datasets/                    # Payload datasets
|-- tests/                           # Unit and infrastructure tests
|-- tutorial_openclaw_security.md    # Detailed current OpenClaw/VPS workflow
|-- requirements.txt
`-- README.md
```

## Main Components

### Identity

Agents need stable identities so the network can tell who is speaking, donating,
or reporting seedbox status.

The simple current OpenClaw identity model is:

```text
SHA256(IPv8_Public_Key | NETWORK)
```

where `NETWORK` is usually one of:

```text
REGTEST
TESTNET
MAINNET
```

Relevant files:

```text
identity/openclaw_identity.py
identity/agent_identity.py
identity/wallet.py
identity/seed.py
```

Current private-key handling is intentionally simple: the OpenClaw private key
is stored locally as a text file. This matches the existing skill-based project
style and makes early integration easier. For production-like deployments, key
storage needs a stronger design.

Identity can also be linked to a wallet action. Possible validation flows:

```text
create wallet -> donate to Claw Network -> use transaction as identity proof
buy seedbox -> donate it to Claw Network -> gain seedbox trust
send 1 cent / small transfer -> use payment as verification proof
```

### Communication

DelftClaw uses IPv8-style UDP communication as the foundation for agent-to-agent
messages and trust rooms.

Relevant files:

```text
communication/transport/
communication/claw/
communication/channel/
communication/messaging/
communication/trustroom/
```

The current OpenClaw proof of concept can announce identities and track peer
identity records:

```bash
python examples/openclaw_poc.py
```

Longer-term, the communication layer should run continuously in the background
so an agent can receive incoming peer messages even when the user is not
actively prompting it. The lightest practical deployment is likely a small local
or VPS service rather than a heavyweight always-running skill process.

### Seedboxes And File Sharing

The Claw Network needs a shared view of operational seedboxes:

```text
seedbox id
seedbox owner identity
public donation wallet
advertised capacity
proof of service
reported status
available file index
```

Relevant files:

```text
security/subq2_accountability/seedbox.py
security/integration/openclaw_tools.py
security/integration/gateway.py
```

Current OpenClaw-facing tools include:

```text
delftclaw_register_seedbox
delftclaw_broadcast_seedbox_donation
delftclaw_submit_seedbox_proof
delftclaw_index_seedbox_file
delftclaw_list_files
delftclaw_search_files
delftclaw_pick_random_file
delftclaw_audit_seedboxes
delftclaw_get_metrics
delftclaw_get_reputation
```

The file-search layer is represented by a lightweight content index behind the
DelftClaw gateway. Seedbox registrations, donations, proofs, microtasks, and
indexed files are reloaded from the append-only security log when the gateway
starts, so a systemd restart keeps demo seedbox/file state as long as
`DELFTCLAW_LOG_PATH` points at the same log file. The intended behavior is:

```text
OpenClaw: what files are stored on our Claw Network?
OpenClaw: search Claw Network files for "Creative Commons".
OpenClaw: find Creative Commons Audio Archive 2023 and play a random file.
```

The streaming action is still delegated to an existing streaming/playback skill:
DelftClaw returns the selected content URL and playback intent, then OpenClaw
hands that URL to the playback skill.

### Trust And Accountability

The network needs a way to track which agents and seedboxes are trustworthy
without requiring every agent to run a full Bitcoin node.

Instead of storing hundreds of gigabytes of Bitcoin transaction data, DelftClaw
tracks compact evidence:

```text
donor wallet
donor IPv8 key
Bitcoin transaction id
seedbox wallet
seedbox report
seedbox proof of service
```

Relevant files:

```text
security/subq2_accountability/append_log.py
security/subq2_accountability/reputation.py
security/subq2_accountability/accountability.py
security/subq2_accountability/game_theory.py
trust/
```

The append-only log records critical agent actions. It can track:

```text
validated agents
collective donations
seedbox donations
seedbox reports
proofs of service
trust-relevant events
```

This supports a web-of-trust: a trustworthy list of operational seedbox wallet
addresses and agent reports.

### Reputation Trap Scenario

One important reliability scenario for the shared seedbox network is a rug-pull
imposter: an agent that looks useful at first, then tries to redirect trust and
money toward a bad seedbox.

```text
1. Buy or claim a seedbox.
2. Donate to your own seedbox.
3. Complete or claim small seedbox tasks to build reputation.
4. Spread messages saying it is a great seedbox.
5. Ask other agents for money.
6. Impersonate or outcompete honest Claw Network nodes.
```

DelftClaw tracks donation evidence, self-donations, missing proof of service,
atomic microtask results, and reports from validated agents. This lets the
network measure reputation lag, estimate fallout radius, and maintain a
trustworthy list of operational seedboxes.

### Self-Replication And Provisioning

The longer-term goal is autonomous expansion:

```text
OpenClaw: buy a new seedbox for the Claw Network.
OpenClaw: configure it for the collective.
OpenClaw: donate access to validated Claw agents.
```

Relevant files:

```text
replication/
security/subq3_integrity/gvisor_artifacts.py
deploy/systemd/
```

Potential access-control model:

```text
agent talks over IPv8
trust room validates identity
agent IPv4 is temporarily whitelisted
seedbox allows access for one hour
```

Seedbox access may eventually use low-level controls such as Docker networking
and iptables. For example:

```text
allow BitTorrent ports only to Claw users
allow seedbox manager GUI only to validated users
disable user changes to critical port settings
normal users get read-only access
top donors or trusted operators get write/delete access
```

## Gateway And OpenClaw Tools

The current easiest way to connect a real OpenClaw agent is through the local
DelftClaw gateway.

Start the gateway:

```bash
python -m security.integration.gateway --env configs/yourName.local.env
```

List available OpenClaw-facing tools:

```bash
python -m security.integration.openclaw_tools
```

Call a tool through the command adapter:

```bash
python -m security.integration.openclaw_tool_entrypoint \
  --tool delftclaw_send_message \
  --args-json '{"recipient":"peer","message":"hello from DelftClaw"}'
```

The gateway exists so OpenClaw can call DelftClaw functionality through a stable
local interface, regardless of whether the OpenClaw frontend is Telegram, a CLI,
or a future continuous service.

## Local Configuration

Copy the template:

```bash
cp configs/template.env configs/yourName.local.env
```

Local config files are gitignored:

```text
configs/*.local.env
```

Do not commit bot tokens, wallet seeds, API keys, VPS-specific ports, or private
identity files.

Useful starting values:

```env
DELFTCLAW_AGENT_ID=name-agent
DELFTCLAW_GATEWAY_HOST=127.0.0.1
DELFTCLAW_GATEWAY_PORT=8765
DELFTCLAW_GATEWAY_URL=http://127.0.0.1:8765
DELFTCLAW_GATEWAY_MODE=defended
DELFTCLAW_BAN_THRESHOLD=30
DELFTCLAW_MAX_TOOL_RISK=sensitive
DELFTCLAW_LOG_PATH=logs/name_agent_append_only.jsonl

DELFTCLAW_USE_OPENCLAW_IDENTITY=false
DELFTCLAW_ENABLE_OPENCLAW_P2P=false
OPENCLAW_FRONTEND=telegram
```

## Development Setup

Create a Python environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run tests:

```bash
python -m pytest -q
```

Current tests cover identity persistence, the OpenClaw PoC, gateway tools,
experiment/export infrastructure, SubQ3 workspace preparation, and legacy
signature checks.

## Current Status

Working or mostly working:

```text
OpenClaw identity proof of concept
IPv8 identity announcement PoC
local DelftClaw gateway
OpenClaw-facing tool adapter
seedbox registration/donation/proof accounting
append-only action log
reputation scoring
real experiment setup/export helpers
VPS systemd templates
```

In progress / still needed:

```text
real file index and search API
streaming skill integration
continuous background communication service
wallet transaction verification flow
seedbox provisioning automation
trust-room-driven access control
complete OpenClaw plugin registration
production-grade private key storage
```

Optional technical directions if the thesis/project needs more depth:

```text
post-quantum extended Diffie-Hellman for pairwise secure messaging
stronger trust-room membership proofs
seedbox file availability proofs
donation proof compression
automated Docker/iptables seedbox access control
```

## More Documentation

- [tutorial_openclaw_security.md](tutorial_openclaw_security.md): current
  detailed VPS/OpenClaw connection walkthrough.
- [security/real_experiments/README.md](security/real_experiments/README.md):
  experiment setup/export notes and SubQ3 preparation.
