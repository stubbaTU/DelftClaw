# Vendored provenance

All vendored sources come from the DelftClaw repository at the pinned commit:

```
DelftClaw vendor commit: 156ce74e3d1af71009b83f3212ad67238e23eaa2
```

(Captured with `git -C <DelftClaw> rev-parse HEAD` during the scaffold phase.)

| Local path | Source (DelftClaw) | Treatment |
|---|---|---|
| `redteam_ablation/contracts.py` | `security/contracts.py` | Copy + trim. Kept `ToolRisk`, `RedTeamPayload`, `ToolDecision`, `ExecutionResult`, `ToolPolicy`, `attack_success_rate`. Dropped unused symbols (`SecurityAction`, `AccountabilityMetrics`, `SeedboxDonationEvidence`, `AtomicMicrotaskEvidence`, `TamperAttemptResult`, `LogIntegrityExperimentResult`). Stdlib only; no logic changes to the kept symbols. |
| `redteam_ablation/primitives/signed_log.py` | `redteam/primitives/signed_log.py` | Vendored with exactly two import swaps; all other logic byte-for-byte verbatim. |
| `redteam_ablation/primitives/verify.py` | `redteam/primitives/verify.py` | Vendored verbatim (no internal imports; stdlib + cryptography only). Added a provenance comment only. |
| `redteam_ablation/primitives/identity.py` | replaces `identity/openclaw_identity.py` (`OpenClawIdentity`) | New local Ed25519 adapter. Not a copy — re-implements the minimal identity port the vendored `signed_log.py` consumes. |

## Exact import swaps in `signed_log.py`

1. `from identity.openclaw_identity import OpenClawIdentity`
   → `from .identity import Ed25519Identity as OpenClawIdentity`
   (the local adapter is aliased to the original name so every annotation and
   constructor reference in the file stays verbatim).

2. `from shared.logging import get_logger`
   → a local `get_logger(name)` built on stdlib `logging.getLogger`, wrapped in
   a `_StructuredLoggerAdapter` whose `.debug(event, **fields)` swallows the
   structured keyword fields. This keeps the two `_logger.debug("signed_log.…",
   reporter_id=…, subject_id=…, action=…, previous_hash=…, entry_hash=…)` call
   sites byte-for-byte verbatim; under raw `logging.Logger.debug` those keyword
   fields would raise `TypeError`.

No other lines of `signed_log.py` or `verify.py` were modified.

## Local extension to `contracts.py` (2026-06-10)

`ExecutionResult` gained a field the DelftClaw original does not have:
`flagged_by: tuple[str, ...] = ()` — the names of interceptors whose verdict
carried `flagged=True` during `Dispatcher.dispatch`'s inspect loop (the
enforcement-ladder audit-mode detections, plan 2026-06-10 §1.2). The default
keeps every original call site valid; no other kept symbol was changed.

## Identity port the adapter had to satisfy

The vendored `signed_log.py` consumes the identity object only through:

* `identity.public_key` — must be **raw 32 bytes** (used as `.public_key.hex()`
  for `reporter_pubkey`, and concatenated with the network in the binding hash).
* `identity.network` — `str` (binding hash + the witness-path
  `self._identity.network`).
* `identity.sign(canonical_bytes) -> bytes` — raw 64-byte Ed25519 signature
  (`.sign(...).hex()` is stored as the entry `signature`).

The `Ed25519Identity.reporter_id` property is **not** required by `signed_log.py`
(the log derives `reporter_id` from the caller-supplied argument), but is part of
the seam spec and is exercised by `tests/test_identity.py`.
