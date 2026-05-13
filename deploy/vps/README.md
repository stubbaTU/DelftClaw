# DelftClaw VPS Security + Identity Runbook

This runbook starts the shared identity MCP, the DelftClaw security gateway, and
the security MCP facade used by OpenClaw.

## Fresh clone

```bash
cd /root
rm -rf DelftClaw
git clone <YOUR_REPO_URL> DelftClaw
cd /root/DelftClaw
```

If you need a specific branch:

```bash
git checkout <BRANCH_NAME>
```

## Bootstrap

```bash
bash deploy/vps/bootstrap_security_identity.sh
```

What it does:

- creates `.venv`
- installs `requirements.txt`
- creates `configs/vuk.local.env` if missing
- creates the shared identity file at `identity/agent_identity.json`
- creates `/root/delftclaw_real_experiment`
- creates canary files for security experiments
- writes `configs/openclaw_security_identity_mcp_config.json`

## Run manually

```bash
bash deploy/vps/run_security_identity_stack.sh
```

What it starts:

- identity MCP on `http://127.0.0.1:7701/mcp`
- DelftClaw gateway on `http://127.0.0.1:8765`
- security MCP on `http://127.0.0.1:7702/mcp`

Logs are written to:

```text
logs/identity_mcp.log
logs/gateway.log
logs/security_mcp.log
```

## Smoke test

In another SSH session:

```bash
cd /root/DelftClaw
bash deploy/vps/smoke_test_security_identity.sh
```

What it checks:

- gateway health
- identity MCP health
- security MCP health
- identity tool call
- seedbox registration
- file indexing
- file listing
- gateway metrics

## OpenClaw MCP config

Use this generated file in OpenClaw:

```text
configs/openclaw_security_identity_mcp_config.json
```

It registers:

```text
agent-identity    -> http://127.0.0.1:7701/mcp
delftclaw-security -> http://127.0.0.1:7702/mcp
```

## Optional systemd install

After the manual smoke test passes:

```bash
cd /root/DelftClaw
bash deploy/vps/install_security_identity_services.sh
```

What it does:

- installs identity MCP, gateway, and security MCP as systemd services
- enables them at boot
- starts them immediately

Check:

```bash
systemctl status delftclaw-identity-mcp --no-pager
systemctl status delftclaw-gateway --no-pager
systemctl status delftclaw-security-mcp --no-pager
```

Stop:

```bash
systemctl stop delftclaw-security-mcp delftclaw-gateway delftclaw-identity-mcp
```

Disable autostart:

```bash
systemctl disable delftclaw-security-mcp delftclaw-gateway delftclaw-identity-mcp
```
