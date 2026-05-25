# `configs/`

Two distinct files live here. They are easy to confuse but serve
different purposes:

| File | What it holds | Who reads it | Tracked? |
|---|---|---|---|
| `host.env` | **Per-host overrides** — Tailscale IPs, `QWEN_BASE_URL`/`QWEN_MODEL`, `BTC_NETWORK`. Machine-specific values that differ across dev VPSes. | `deploy/scenario_boot.py`. Loaded if present; ignored otherwise. | **NO** (gitignored). Copy from `host.env.example` and edit. |
| `template.env` (or its `*.local.env` derivative) | **Experiment knobs** — gateway mode, ban threshold, run id, subq3 condition, log paths. | Standalone security tools under `security/integration` and `security/subq*`. | **YES** (`template.env` is tracked as the canonical example; copies named `*.local.env` are gitignored). |

In short:

- `host.env` answers **"where am I running?"** — Tailscale IP of the
  GPU box, which Qwen model to call, what BTC network to use.
- `template.env` answers **"what experiment am I running?"** — defended
  vs undefended gateway, which run id, which canary set.

Both can coexist; nothing reads both files into the same process today.
The scenario path uses `host.env`; standalone security experiments use
`*.local.env`.

## First-time setup

```bash
cp configs/host.env.example configs/host.env
$EDITOR configs/host.env       # set TAILSCALE_GPU_IP, QWEN_*, etc.
```

After editing, `make scenario NAME=…` automatically picks up
`configs/host.env` if it exists. `QWEN_BASE_URL` / `QWEN_MODEL` env
vars passed on the command line still win over the file (handy for
one-off overrides).
