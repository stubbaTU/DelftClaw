# `configs/`

Two distinct files live here. They are easy to confuse but serve
different purposes:

| File | What it holds | Who reads it | Tracked? |
|---|---|---|---|
| `host.env` | **Per-host overrides** — Tailscale IPs, `LLM_BASE_URL`/`LLM_MODEL`, `BTC_NETWORK`. Machine-specific values that differ across dev VPSes. | `deploy/scenario_boot.py`, `deploy/vps/bootstrap_security_identity.sh`. Loaded if present; ignored otherwise. | **NO** (gitignored). Copy from `host.env.example` and edit. |
| `template.env` (or its `*.local.env` derivative) | **Experiment knobs** — gateway mode, ban threshold, run id, subq3 condition, log paths. The colleagues' gateway + seedbox-audit modules read these. | `security/integration/gateway.py`, `security/subq*` code, the legacy `*.service.template` units. | **YES** (`template.env` is tracked as the canonical example; copies named `*.local.env` are gitignored). |

In short:

- `host.env` answers **"where am I running?"** — Tailscale IP of the
  GPU box, which Qwen model to call, what BTC network to use.
- `template.env` answers **"what experiment am I running?"** — defended
  vs undefended gateway, which run id, which canary set.

Both can coexist; nothing reads both files into the same process today.
The scenario / templated-MCP path uses `host.env`; the colleagues'
gateway path uses `*.local.env`.

## First-time setup

```bash
cp configs/host.env.example configs/host.env
$EDITOR configs/host.env       # set TAILSCALE_GPU_IP, LLM_*, etc.
```

After editing, `make scenario NAME=…` and
`bash deploy/vps/bootstrap_security_identity.sh` automatically pick up
`configs/host.env` if it exists. `LLM_BASE_URL` / `LLM_MODEL` env
vars passed on the command line still win over the file (handy for one-
off overrides).
