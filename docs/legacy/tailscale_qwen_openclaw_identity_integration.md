> ## ⚠ Legacy v4.0 document — withdrawn 2026-05-08
>
> This document references trust rooms, credential issuance, and the
> standalone identity MCP integration as if they're the primary
> integration path. The v5.1 architecture uses the unified agent MCP
> (see `agent/mcp_server.py`) and `make scenario` for autonomous
> orchestration; the identity MCP described here still exists but is
> one of three coexisting MCP servers, not the primary contract.
>
> Tailscale + remote Qwen guidance below is still broadly applicable
> as networking advice. The trust-room / credential workflows are
> obsolete — for current architecture see
> [`PROJECT_DESIGN.md`](../../PROJECT_DESIGN.md).

---

# Connecting DelftClaw Identity + OpenClaw MCP to a Tailscale GPU Node Running Qwen

You now have:

- A working cryptographic identity layer
- An MCP server exposing identity tools on port `7701`
- OpenClaw-compatible MCP integration
- A remote GPU machine running Qwen
- Tailscale networking between machines

The next step is wiring the systems together so:

1. OpenClaw agents can use the identity MCP tools
2. The agents can securely talk to the remote Qwen model
3. Multiple agents can communicate across the Tailscale network
4. Identity verification and signing can happen autonomously

---

# Recommended Architecture

## Local Machine (Agent Host)

Runs:

- OpenClaw agent runtime
- Identity MCP server
- Trustroom community
- AgentChannel
- Wallet + verification logic

Example:

- Laptop
- Raspberry Pi
- Edge node
- Desktop

---

## Remote GPU Machine (Tailscale Node)

Runs:

- Qwen inference server
- vLLM or Ollama
- Optional embedding models
- Optional vector DB

Example:

- RTX 4090 machine
- Cloud GPU VM
- Home server

---

## Network

Tailscale provides:

- Encrypted mesh networking
- Stable hostnames
- Private IPs
- NAT traversal
- Secure RPC between nodes

---

# Step 1 — Install Tailscale on Both Machines

## Agent machine

Install:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

Start:

```bash
sudo tailscale up
```

---

## GPU machine

Install:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

Start:

```bash
sudo tailscale up
```

---

## Verify Connectivity

On either machine:

```bash
tailscale status
```

You should see:

```text
100.x.x.x   gpu-node
100.x.x.x   agent-node
```

Test:

```bash
ping gpu-node
```

or:

```bash
ping 100.x.x.x
```

---

# Step 2 — Run Qwen on the GPU Node

The cleanest setup is:

- vLLM for OpenAI-compatible serving
- Qwen2.5 or Qwen3 instruct models

---

# Option A — vLLM (Recommended)

Install:

```bash
pip install vllm
```

Launch:

```bash
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-7B-Instruct \
  --host 0.0.0.0 \
  --port 8000
```

This exposes:

```text
http://gpu-node:8000/v1
```

Accessible across Tailscale.

---

# Option B — Ollama

Install:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Run:

```bash
ollama run qwen2.5:7b
```

Expose externally:

```bash
OLLAMA_HOST=0.0.0.0 ollama serve
```

Endpoint:

```text
http://gpu-node:11434
```

---

# Step 3 — Restrict Access to Tailscale Only

Do NOT expose Qwen publicly.

On the GPU node:

## UFW Example

```bash
sudo ufw allow in on tailscale0 to any port 8000
sudo ufw deny 8000
```

This ensures only Tailscale peers can reach the model.

---

# Step 4 — Connect OpenClaw to the Remote Qwen Server

Your OpenClaw runtime likely has:

- OpenAI-compatible provider support
- HTTP model backend config
- Environment-variable based model selection

Point it to the Tailscale endpoint.

---

# Example Environment Variables

```bash
export OPENAI_API_BASE="http://gpu-node:8000/v1"
export OPENAI_API_KEY="dummy"
export OPENAI_MODEL="Qwen/Qwen2.5-7B-Instruct"
```

or:

```bash
export OPENAI_BASE_URL="http://100.x.x.x:8000/v1"
```

---

# Example Python Client

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://gpu-node:8000/v1",
    api_key="dummy"
)

response = client.chat.completions.create(
    model="Qwen/Qwen2.5-7B-Instruct",
    messages=[
        {"role": "user", "content": "Hello"}
    ]
)

print(response.choices[0].message.content)
```

---

# Step 5 — Start the Identity MCP Server

On the agent machine:

```bash
python -m identity.start_identity_server \
  --network regtest \
  --port 7701
```

Expected output:

```text
Agent ID: <agent_id>
Wallet:   <wallet_address>
Network:  regtest
MCP:      http://localhost:7701/mcp
```

---

# Step 6 — Load MCP into OpenClaw

You already generated:

```text
identity/openclaw_mcp_config.json
```

Point OpenClaw to this config.

Example:

```json
{
  "mcpServers": {
    "agent-identity": {
      "url": "http://localhost:7701/mcp",
      "description": "Cryptographic identity, wallet, and verification tools for this OpenClaw agent."
    }
  }
}
```

Now Qwen can autonomously call:

- get_identity
- sign_message
- verify_message
- issue_credential
- verify_credential
- create_verification_challenge
- submit_verification

through OpenClaw tool calls.

---

# Step 7 — Full Autonomous Flow

Once connected, a natural language interaction becomes:

```text
User:
"Prove your identity to the trustroom and issue a seedbox credential."
```

Execution chain:

1. Qwen receives prompt
2. OpenClaw selects MCP tools
3. MCP tool calls identity layer
4. Identity layer signs/verifies
5. TrustroomCommunity distributes proof
6. Other agents validate credentials
7. Verification records stored locally

No manual cryptographic handling is required.

---

# Step 8 — Enable Multi-Agent Networking

Each agent machine can run:

- Its own AgentIdentity
- Its own MCP server
- Its own TrustroomCommunity
- Its own wallet

All connected over Tailscale.

Example topology:

```text
agent-alpha  -> Qwen GPU
agent-beta   -> Qwen GPU
agent-gamma  -> Qwen GPU
```

All authenticated through:

- IPv8 identity keys
- Wallet ownership
- Verifiable credentials
- Trustroom verification

---

# Step 9 — Recommended Production Layout

## GPU Node

Services:

```text
vLLM        :8000
Vector DB   :6333
Redis       :6379
```

---

## Agent Nodes

Services:

```text
Identity MCP     :7701
OpenClaw runtime :local
Trustroom        :local
IPv8             :local
```

---

# Step 10 — Optional: Run Identity MCP Over Tailscale

If agents need to remotely query another agent's identity tools:

Bind MCP to:

```python
host="0.0.0.0"
```

Then access:

```text
http://agent-alpha:7701/mcp
```

Only Tailscale peers can reach it.

---

# Step 11 — Recommended Security Hardening

## 1. Use Tailscale ACLs

Restrict which nodes can reach:

- port 8000 (Qwen)
- port 7701 (MCP)

---

## 2. Encrypt AgentIdentity at Rest

Your implementation already supports:

```python
identity.save(path, passphrase="...")
```

Use it.

---

## 3. Never Expose Wallet xpriv

Only expose:

- xpub
- address
- signatures

Never tool-expose xpriv.

---

## 4. Separate Model and Identity Machines

Do not colocate:

- public model serving
- private wallet storage

unless necessary.

---

# Step 12 — Suggested OpenClaw Agent Prompt

Your system prompt should explicitly teach Qwen how to use the identity tools.

Example:

```text
You are an autonomous OpenClaw agent.

You possess a cryptographic identity accessible through MCP tools.

Use:
- get_identity when asked about your identity
- sign_message to prove authorship
- issue_credential for trustroom membership
- verify_credential before trusting peers
- create_verification_challenge when asked to prove wallet ownership
- check_verification_status before interacting with unknown agents
```

This dramatically improves tool selection quality.

---

# Step 13 — Example End-to-End Boot Sequence

## GPU Node

```bash
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-7B-Instruct \
  --host 0.0.0.0 \
  --port 8000
```

---

## Agent Node

```bash
python -m identity.start_identity_server
```

---

## OpenClaw Runtime

```bash
python run_openclaw.py
```

OpenClaw now:

- uses remote Qwen inference over Tailscale
- calls local identity MCP tools
- signs messages autonomously
- issues credentials autonomously
- verifies peers autonomously
- performs Bitcoin identity verification autonomously

---

# Recommended Next Step

The strongest next upgrade is:

## Add a Trustroom MCP Server

Expose:

- join_trustroom
- publish_credential
- verify_peer
- broadcast_signed_message
- discover_agents

Then Qwen can coordinate decentralized agent swarms autonomously using:

- cryptographic identity
- verifiable credentials
- trust negotiation
- Bitcoin-backed proof-of-agenthood
- MLS-secured messaging

across your Tailscale mesh.

---

## Repo Implementation Status

The DelftClaw repo now includes a concrete Qwen connectivity layer under `security/integration/`:

- `security/integration/model_config.py`
  - Resolves model runtime settings from env vars and `~/.openclaw/openclaw.json`
  - Honors `OPENAI_API_BASE` / `OPENAI_BASE_URL` and `OPENAI_MODEL`
- `security/integration/qwen_client.py`
  - OpenAI-compatible HTTP client (`/v1/models`, `/v1/chat/completions`)
  - Intended for Tailscale-only model endpoints
- `security/integration/model_doctor.py`
  - Diagnostic CLI to validate endpoint reachability, model listing, and a smoke prompt

Run the diagnostic from repo root:

```bash
python -m security.integration.model_doctor
```

Or with explicit environment overrides:

```bash
export OPENAI_API_BASE="http://gpu-node:8000/v1"
export OPENAI_MODEL="Qwen/Qwen2.5-7B-Instruct"
export OPENAI_API_KEY="dummy"
python -m security.integration.model_doctor
```
