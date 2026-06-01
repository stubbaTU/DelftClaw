# `configs/`

This directory now contains only per-host deployment configuration.

| File | What it holds | Who reads it | Tracked? |
|---|---|---|---|
| `host.env` | Per-host overrides: Tailscale IPs, `QWEN_BASE_URL`/`QWEN_MODEL`, `BTC_NETWORK`. Machine-specific values that differ across dev VPSes. | `deploy/scenario_boot.py`. Loaded if present; ignored otherwise. | No. Copy from `host.env.example` and edit. |

`host.env` answers "where am I running?" The thesis security experiments keep
their own CLI flags and result folders instead of using a shared tracked
experiment template.

## First-time setup

```bash
cp configs/host.env.example configs/host.env
$EDITOR configs/host.env
```

After editing, `make scenario NAME=seek_cc` automatically picks up
`configs/host.env` if it exists. `QWEN_BASE_URL` / `QWEN_MODEL` env vars
passed on the command line still win over the file for one-off overrides.
