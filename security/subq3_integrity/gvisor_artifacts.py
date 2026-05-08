from __future__ import annotations

import argparse
from pathlib import Path


DOCKERFILE = """\
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app
ENV PYTHONPATH=/app
CMD ["python3", "-m", "security.integration.doctor", "--base-url", "http://127.0.0.1:8765", "--agent-id", "sandbox-agent"]
"""


IPTABLES_SCRIPT = """\
#!/usr/bin/env bash
set -euo pipefail

# Allow loopback for local gateway access, deny outbound traffic by default.
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow DNS only if explicitly needed by an experiment.
# iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

echo "iptables sandbox policy installed"
"""


RUNBOOK = """\
# gVisor Sandbox Runbook

This directory contains generated artifacts for the log-integrity/sandbox part
of the research plan.

## Build Image

```bash
docker build -f Dockerfile.gvisor -t delftclaw-openclaw-sandbox .
```

## Run With gVisor

Install gVisor/runsc first, then:

```bash
docker run --rm --runtime=runsc \\
  --network=none \\
  --read-only \\
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \\
  -e DELFTCLAW_GATEWAY_URL=http://127.0.0.1:8765 \\
  delftclaw-openclaw-sandbox
```

For the real integrity experiment, keep the append-only log and host canary
secrets outside the container. The container should only receive the gateway URL
and any explicitly mounted read-only prompt/input files.

## Host Firewall

Review `iptables_sandbox.sh` before running it. Apply only on a disposable VPS
or test VM because it changes host firewall policy.
"""


def generate_artifacts(output_dir: str | Path) -> None:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    (target / "Dockerfile.gvisor").write_text(DOCKERFILE, encoding="utf-8")
    script = target / "iptables_sandbox.sh"
    script.write_text(IPTABLES_SCRIPT, encoding="utf-8")
    (target / "README.md").write_text(RUNBOOK, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate gVisor/iptables sandbox experiment artifacts.")
    parser.add_argument("--output-dir", default="sandbox_artifacts")
    args = parser.parse_args()
    generate_artifacts(args.output_dir)
    print(f"wrote sandbox artifacts to {args.output_dir}")


if __name__ == "__main__":
    main()
