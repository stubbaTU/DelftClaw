# DelftClaw Security Infrastructure

This package owns the security side of the research architecture. Identity and
communication are deliberately treated as external services for now.

## Security-owned responsibilities

- SQ1 preventative layer: Brain vs Hands permission checks.
- SQ2 accountability layer: append-only evidence, reputation lag, fallout radius,
  seedbox donations, service proofs, and atomic microtasks.
- SQ3 impact layer: gVisor/iptables artifacts, protected-path manifests, and
  sandbox readiness checks.
- OpenClaw tool surface for security actions through `security.integration`.

## External responsibilities

- Identity must eventually provide a stable agent id and public-key bundle.
- Communication must eventually publish append-only evidence to peers.

Until those are ready, security code uses the adapter contracts in
`security.integration.ports` and can run with static/no-op adapters.

## Readiness check

```bash
python -m security.integration.security_readiness --artifact-dir sandbox_artifacts
```

This does not run experiments. It verifies that the security infrastructure is
ready to be wired into OpenClaw, identity, and communication.
