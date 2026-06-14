# VukZERO Containment Layer — System-Level Least Exposure

## Summary

The containment layer is VukZERO's last line of defense: it assumes the agent
process is **already compromised** and asks how much damage hostile code running
*inside* the agent container can actually do. It is not about whether an LLM
refuses a malicious instruction — the attacker here is deterministic hostile code,
and the question is purely what the surrounding system lets it reach.

Its core idea is **least exposure**: protected assets are never mounted inside the
agent container at all, so a compromised process cannot touch raw protected state;
every legitimate operation is available only through a narrow host-side proxy, and
unauthorized network egress is blocked by host firewall policy. Conventional
container hardening (seccomp, AppArmor, dropped capabilities, read-only rootfs)
and a gVisor userspace-kernel sandbox are layered on top as defense in depth.

The central finding the layer is built to demonstrate is that **the data
architecture, not the runtime sandbox, is what bounds the damage** — hardening
and gVisor isolate the process but cannot protect sensitive data that has been
mounted into it.

## Package Layout

```
containment_layer/
  infrastructure/      the containment mechanisms + protected fixture
  evaluation/          the factorial runner, probe battery, and analysis
  profiles/            seccomp_vukzero.json, apparmor_vukzero_sq3
  results/             measured result artifacts
  prepare_vps.sh       host preparation (Docker, gVisor, AppArmor, nftables)
  run_factorial_vps.sh guarded preflight -> smoke -> full run
  reproduce.sh         single-command containerized reproduction
  Dockerfile           driver image for reproduce.sh
```

## Infrastructure

`infrastructure/` is the containment system and the mock world it protects.

**The least-exposure architecture**

- `protected_resources.py` — builds a fresh per-trial fixture: an identity key,
  wallet state, accountability log, reputation state, seedbox ACL, and network
  rules, each carrying a **unique canary** across six asset categories. It
  snapshots hashes/sizes/canaries before and after each probe and verifies the
  signed log, so any read, modification, or deletion of protected state is
  detectable and attributable.
- `resource_proxies.py` — the narrow host-side interfaces that are the *only*
  legitimate path to protected operations when the architecture is on. Each proxy
  allows the safe verb and denies the dangerous ones: sign a nonce but never read
  the private key; read public wallet status but never the seed; append to the
  log but never rewrite/delete/truncate it; submit reputation evidence but never
  mutate scores; request seedbox access but never read the ACL; send to the
  allowed peer but never to arbitrary hosts or exfiltrate canaries.

**Runtime isolation and egress control**

- `runtimes.py` — runtime descriptors for standard `runc` and gVisor `runsc`
  (systrap platform).
- `enforcement.py` — detects and records the host's enforcement support and the
  hardening posture.
- `firewall.py` — installs a dedicated host nftables table that admits only the
  expected peer and rejects all other egress from the container, snapshots the
  ruleset, and removes the table afterward so it never pollutes the next
  condition.
- `network_guard.py` — the controlled local TCP/UDP sinks (an allowed peer and an
  unauthorized exfil target) whose received-message records are the evidence of
  whether egress actually landed.
- `profiles/` — the seccomp and AppArmor profiles applied to hardened conditions
  (their SHA-256s are recorded in run metadata).

## Evaluation

The evaluation is a **3×2 factorial** that separates two independent factors so
their individual contributions can be measured:

- **Factor A — runtime/hardening:** `runc` (weak) · `runc` hardened · gVisor
  (hardened).
- **Factor B — data architecture:** `off` (full protected fixture mounted into
  the container) · `on` (only the agent workspace mounted; sensitive operations
  proxy-only; egress firewalled).

Crossing them gives six conditions:

| Condition | Runtime | Architecture |
|---|---|---|
| C0 uncontained | runc | off |
| B1 runc hardened | runc-hardened | off |
| B2 gVisor naive | gVisor | off |
| A1 arch-only runc | runc | on |
| A2 VukZERO no gVisor | runc-hardened | on |
| C1 full stack | gVisor | on |

Every condition shares the same image digest, fixture generation, probe code,
sinks, timeout, and scoring, so differences are attributable to the two factors
alone. The hostile battery has 24 deterministic probes — 17 protected-asset
probes across the six categories and 7 non-weaponized runtime-boundary probes
(mount, ptrace, `/dev/mem`, host-kernel identity, …) that *characterize* whether
a boundary operation is permitted rather than exploit it. Four legitimate actions
run once per condition as a false-positive check.

- `conditions.py` — the six factorial conditions.
- `official_probe_suite.py` — the 24-probe battery and its pinned spec/hash.
- `characterization.py` — independently records each container's real posture
  (capabilities, seccomp mode, AppArmor label, namespaces, data visibility) so a
  reviewer can confirm each baseline is what it claims to be.
- `official_runner.py` — the runner; entry point
  `python -m security.containment_layer.evaluation.official_runner`. It applies
  the firewall/runtime/mounts per condition, runs each probe (default 20
  repetitions for latency/stability), scores from fixture integrity and sink
  evidence, and aborts rather than silently degrading if enforcement is missing.
- `analysis.py` — per-factor effects and the latency/containment Pareto rows.

The primary metric is **containment rate** (hostile probes whose action did not
succeed ÷ hostile probes); also reported are **fallout radius** (number of the
six categories with at least one successful probe) and the false-positive rate
over the legitimate actions.

## Results

The full run was 24 probes × 20 repetitions × 6 conditions = 2,904 records, with
stable outcomes across repetitions and a 0% false-positive rate in every
condition (no legitimate action was ever blocked).

| Condition | Runtime | Arch. | Containment | Fallout radius |
|---|---|---:|---:|---:|
| C0 uncontained | runc | off | 20.83% | 6 / 6 |
| B1 runc hardened | runc-hardened | off | 33.33% | 6 / 6 |
| B2 gVisor naive | gVisor | off | 37.50% | 6 / 6 |
| A1 arch-only runc | runc | on | 87.50% | 1 / 6 |
| A2 VukZERO no gVisor | runc-hardened | on | 95.83% | 1 / 6 |
| C1 full stack | gVisor | on | 100.00% | 0 / 6 |

The factor breakdown makes the headline explicit:

| Factor | Level | Mean containment | Mean fallout radius |
|---|---|---:|---:|
| Architecture | off | 30.56% | 6.00 |
| Architecture | on | 94.44% | 0.67 |
| Runtime | runc | 54.17% | 3.50 |
| Runtime | runc-hardened | 64.58% | 3.50 |
| Runtime | gVisor | 68.75% | 3.00 |

- **Least exposure is the dominant factor.** Enabling the architecture raised
  mean containment from 30.56% to 94.44% and collapsed mean fallout radius from
  all six categories to 0.67.
- **Hardening and gVisor alone are insufficient.** Both architecture-off
  baselines still leaked all six categories, because mounted protected state is
  reachable however well the runtime is isolated.
- **gVisor adds a complementary final boundary.** The only exposures left under
  the architecture were host/kernel-boundary *observations* (a shared host kernel
  under runc); gVisor's userspace kernel closes that last category, taking the
  hardened stack from 23/24 to 24/24 and fallout radius to zero. This is a
  boundary-isolation distinction, not evidence of a sandbox escape.

## Running It

Prepare the host once (installs/validates Docker, gVisor/runsc, AppArmor,
nftables; run as root on a disposable VM):

```bash
bash security/containment_layer/prepare_vps.sh
```

Guarded full workflow (preflight → all-condition smoke → full run):

```bash
bash security/containment_layer/run_factorial_vps.sh
```

Or the single-command containerized harness (builds the driver image and runs the
guarded workflow against the host Docker daemon):

```bash
sudo bash security/containment_layer/reproduce.sh
```

Outputs include `sq3_official_summary.json`, `sq3_factor_effects.json`,
`sq3_pareto.csv`, `records.csv/.jsonl`, `sq3_run_metadata.json` (pinned
environment), `sq3_condition_characterization.json`, the per-condition nftables
rulesets, the seccomp/AppArmor profiles, and the generated LaTeX tables.

## Tests

```bash
python -m pytest tests/test_subq3_*.py -q
```

These cover fixture creation and integrity, every proxy's allow/deny behavior,
native nftables insertion and cleanup, the per-factor analysis, and the
six-condition runner (including the Docker argument assembly).
