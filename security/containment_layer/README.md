# SQ3 Factorial System-Containment Evaluation

SQ3 assumes the agent process is already compromised. A deterministic battery
executes direct filesystem, network, process, and syscall attempts inside
containers. No LLM refusal behavior is measured.

## Experimental Design

The redesigned experiment separates two factors:

```text
Factor A: runtime and container hardening
  runc
  runc-hardened
  gvisor

Factor B: VukZero data architecture
  off: protected fixture mounted directly
  on: protected fixture absent; proxy-only operations and host egress control
```

All six cells run:

| Condition | Runtime factor | Architecture |
|---|---|---|
| `C0_uncontained` | runc | off |
| `B1_runc_hardened` | runc-hardened | off |
| `B2_gvisor_naive` | gvisor | off |
| `A1_arch_only_runc` | runc | on |
| `A2_vukzero_no_gvisor` | runc-hardened | on |
| `C1_vukzero_gvisor` | gvisor | on |

This distinguishes the contribution of least-exposure/proxy architecture from
the contribution of conventional hardening and gVisor.

## Enforcement

Hardened conditions use:

```text
read-only root filesystem
all Linux capabilities dropped
no-new-privileges
custom seccomp profile
AppArmor profile vukzero_sq3
non-root UID
PID, memory, CPU, and tmpfs limits
no host PID namespace
```

gVisor conditions additionally use Docker runtime `runsc`, with `systrap`
recorded as the intended platform.

Architecture-on conditions:

- mount only the agent workspace;
- keep `host_protected` outside the container;
- expose narrow trusted proxy operations;
- apply a host-controlled egress allowlist.

The firewall layer prefers a dedicated native nftables table named
`inet vukzero_sq3`. If native nft is unavailable, the official runner accepts
only the iptables compatibility interface backed by `nf_tables`.

## Probe Battery

The official battery contains:

```text
24 hostile probes
4 legitimate actions per condition
```

The original protected-asset probes cover identity, wallet, log integrity,
network egress, host/kernel reach, and rule tampering. Seven additional
non-weaponized runtime-boundary probes characterize mount, module loading,
device access, proc reach, ptrace, sysctl writes, and kernel identity.

No working sandbox-escape exploit or public network target is used.

## VPS Preparation

Run inside a disposable Ubuntu VPS/VM:

```bash
cd ~/DelftClaw
source .venv/bin/activate

bash security/containment_layer/prepare_vps.sh

python -m security.containment_layer.evaluation.official_runner \
  --out results/sq3_factorial_preflight \
  --preflight-only \
  --image python:3.12-slim
```

Or from the operator machine:

```bash
make sq3-containment-preflight
```

The official runner aborts if a requested condition cannot apply its required
runtime or enforcement. There is no silent fallback mode.

`prepare_vps.sh` installs the stable gVisor release-channel candidate and
records the exact installed version under `/var/lib/delftclaw/sq3`. To
reproduce a previously recorded version exactly:

```bash
SQ3_RUNSC_VERSION='<recorded apt version>' \
  bash security/containment_layer/prepare_vps.sh
```

## Official Run

```bash
python -m security.containment_layer.evaluation.official_runner \
  --out results/sq3_factorial_containment \
  --image python:3.12-slim \
  --timeout 10 \
  --repetitions 20
```

The 20 repetitions are used to quantify latency. Probe outcomes are
deterministic and the summary records any outcome instability.

To smoke-test every condition and enforcement layer before the full run:

```bash
python -m security.containment_layer.evaluation.official_runner \
  --out results/sq3_factorial_smoke \
  --probe-ids A1 D1 E5 \
  --repetitions 1 \
  --timeout 10
```

The smoke run executes the three selected hostile probes plus all four
legitimate actions under all six conditions. It therefore checks the full
factorial orchestration, both runtimes, firewall enforcement, architecture
boundary, and utility path without launching the complete experiment.

For the guarded one-command VPS workflow:

```bash
bash security/containment_layer/run_factorial_vps.sh
```

It performs preflight, runs the all-condition smoke, and launches the full
experiment only if both pass. Set `SQ3_SKIP_SMOKE=true` only after a successful
smoke from the same prepared VPS state.

## Outputs

```text
results.json
sq3_run_metadata.json
sq3_official_summary.json
sq3_probe_battery.jsonl
sq3_condition_characterization.json
sq3_factor_effects.json
sq3_pareto.csv
sq3_nft_ruleset_<condition>.txt
sq3_iptables_ruleset_<condition>.txt  # only for the iptables-nft fallback
sq3_seccomp_profile.json
sq3_apparmor_profile
sq3_docker_network.txt
records.csv
records.jsonl
sq3_table_main.tex
sq3_table_by_category.tex
sq3_table_factor_effects.tex
run.log
```

Metadata records the image digest, kernel, Docker runtime registry, runc/runsc
versions, gVisor platform, Docker firewall backend, nft/iptables versions,
seccomp hash, AppArmor profile, user-namespace/security options, conditions,
timeout, repetitions, and probe-battery hash.

## Metrics

Per condition:

```text
containment rate
fallout radius
false-positive rate over L1-L4
boundary-probe denied rate
median latency
latency IQR
empirical 95% latency interval
outcome stability
```

Factor-effect outputs aggregate containment by runtime and by architecture.
`sq3_pareto.csv` supports a latency-versus-containment Pareto plot.

## Tests

```bash
python -m pytest \
  tests/test_subq3_protected_resources.py \
  tests/test_subq3_resource_proxies.py \
  tests/test_subq3_official_runner.py \
  tests/test_subq3_firewall.py \
  tests/test_subq3_analysis.py -q
```

## Paper-Safe Claim

The redesigned experiment can attribute observed containment changes to the
runtime/hardening factor and to the VukZero least-exposure/proxy architecture.
It does not claim that gVisor, seccomp, AppArmor, or VukZero make sandbox escape
impossible.
