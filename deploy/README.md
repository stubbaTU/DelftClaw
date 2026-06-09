# DelftClaw Deploy Runbook

The deploy tree keeps the canonical `seek_cc` scenario and the operational
helpers needed to run it on the VPS.

## First Deploy

```bash
make deploy
```

This rsyncs the repo, installs VPS dependencies, configures the OpenClaw CLI,
creates the Python venv, installs systemd templates, and prepares the firewall
ranges used by `seek_cc`.

## Seek CC Scenario

```bash
make scenario NAME=seek_cc
make watch NAME=seek_cc
make trace NAME=seek_cc
make stop NAME=seek_cc
```

The helper script exposes the same flow:

```bash
bash deploy/vps/demo_seek_cc.sh start
bash deploy/vps/demo_seek_cc.sh status
bash deploy/vps/demo_seek_cc.sh probe
bash deploy/vps/demo_seek_cc.sh stop
```

## SQ3 VPS Checks

```bash
make sq3-containment-prepare
make sq3-containment-preflight
make sq3-containment-smoke
make sq3-containment-official
```

The prepare target installs and configures the VPS dependencies. Preflight
then verifies Docker runtimes, gVisor/runsc, nftables enforcement, the custom
seccomp profile, AppArmor, and host metadata. The official target runs
preflight and a six-condition smoke before launching the complete factorial
experiment from `security/containment_layer`.
