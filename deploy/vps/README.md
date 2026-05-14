# DelftClaw VPS Security + Identity Runbook

This runbook brings up the templated identity + security MCP units for a
single VPS instance. As of v5.1, identity-mcp and security-mcp are
**templated** like the rest of the DelftClaw fleet — they run as the
`delftclaw` system user from `/opt/delftclaw`, read a per-instance env
file from `/etc/delftclaw/instances/<instance>.env`, and are started
with `systemctl enable --now delftclaw-{identity,security}-mcp@<instance>`.

The colleagues' non-templated gateway + seedbox-audit units are still
shipped as `*.service.template` for now; they are independent of the
two MCPs and stay where they are.

## Prerequisites

`deploy/setup_vps.sh` has already run on this VPS. That created the
`delftclaw` user, `/opt/delftclaw` venv, and installed all four
templated systemd units:

```
delftclaw-mcp@.service
delftclaw-watchdog@.service
delftclaw-identity-mcp@.service     # new in v5.1
delftclaw-security-mcp@.service     # new in v5.1
```

## Bootstrap

```bash
sudo bash deploy/vps/bootstrap_security_identity.sh
```

What it does:

- creates the persistent identity JSON at
  `/var/lib/delftclaw/identity/agent_identity.json`
- writes the per-instance env file
  `/etc/delftclaw/instances/<instance>.env` (consumed by both templated
  MCP units)
- prepares the canary experiment workspace under
  `/var/lib/delftclaw/experiments`
- writes the OpenClaw MCP-config JSON pointing at the two MCPs at
  `/opt/delftclaw/configs/openclaw_security_identity_mcp_config.json`

`<instance>` defaults to `hostname -s`; override with
`INSTANCE=my-vps sudo bash deploy/vps/bootstrap_security_identity.sh`.

## Start

```bash
sudo bash deploy/vps/run_security_identity_stack.sh
```

This is a thin `systemctl` wrapper. It enables and starts the two
templated MCP units for `<instance>` plus the colleagues' optional
gateway / seedbox-audit units (when their non-templated unit files are
installed).

Endpoints:

- identity MCP on `http://127.0.0.1:7701/mcp`
- security MCP on `http://127.0.0.1:7702/mcp`
- gateway       on `http://127.0.0.1:8765` (when the legacy unit is up)

Tail logs:

```bash
journalctl -u 'delftclaw-identity-mcp@<instance>' -f
journalctl -u 'delftclaw-security-mcp@<instance>' -f
```

## Smoke test

In another SSH session:

```bash
bash deploy/vps/smoke_test_security_identity.sh
```

The smoke test reads ports + endpoints from the same per-instance env
file. Set `INSTANCE=<name>` if it differs from `hostname -s`.

What it checks:

- gateway health
- identity MCP health
- security MCP health
- identity tool call
- identity ↔ security agent-id consistency
- seedbox registration / file indexing / listing / metrics

## OpenClaw MCP config

`configs/openclaw_security_identity_mcp_config.json` registers:

```
agent-identity    -> http://127.0.0.1:7701/mcp
delftclaw-security -> http://127.0.0.1:7702/mcp
```

## Stop / disable

```bash
sudo systemctl disable --now delftclaw-identity-mcp@<instance>.service
sudo systemctl disable --now delftclaw-security-mcp@<instance>.service
```

## Migrating from the pre-v5.1 layout

If your VPS still has the old non-templated units installed
(`delftclaw-identity-mcp.service`, `delftclaw-security-mcp.service`),
`deploy/setup_vps.sh:step_systemd_templates` automatically stops and
removes them when re-run; the new templated unit files take over.

The colleagues' non-templated gateway + seedbox-audit units are
unchanged and are still installed by
`deploy/vps/install_security_identity_services.sh` (which no longer
touches identity-mcp/security-mcp).
