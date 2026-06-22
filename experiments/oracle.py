"""SQ3 reference oracle — drive overlays through scripted scenarios and read a
canonicalized, identity-aware state trace.

This is the model-independent ground truth of the redesigned SQ3 study (Step 1).
A *scenario* is an ordered list of steps — ``Seed`` (populate runtime state
before the run), ``Send`` (deliver a message built with the sender's payload
class into the other node's live handler), and ``Checkpoint`` (assert an
observable runtime-state attribute equals an expected value). ``run_scenario``
runs two overlays as two live ``MockIPv8`` nodes (reusing the proven
``sq3.live_interop.TwoNodeNetwork``) and returns a ``Trace`` of per-checkpoint
results.

Conformance/interop metrics (Steps 4+) are defined on top of this:
``golden_trace`` runs the hand-written reference against itself to obtain the
expected behaviour; a compiled overlay is conformant iff it reproduces that
behaviour. Because the oracle is hand-written and the checkpoints are
hand-specified, the measurement is non-circular (invariant **I3**).

Two state-comparison rules are load-bearing (invariant **I4**):

  * peer identity is canonicalized — a runtime-state dict keyed by a peer's mid
    hex (e.g. ``pending_requests``) has its keys remapped to stable role labels
    (``A`` / ``B``) so two runs with different ephemeral keys still compare; and
  * values are compared in full (no ``len()`` reduction), with msgpack-decoded
    dicts/lists normalized recursively.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any, Callable

from ipv8.community import Community

from protocol.compiler import ParsedOverlay
from experiments.driver import ProgrammableNetwork
from experiments.fixtures import get_spec
from experiments.live_interop import LoadedOverlay

__all__ = [
    "Seed", "Send", "Checkpoint", "CheckResult", "Trace",
    "reference_overlay", "run_scenario", "golden_trace", "canonicalize",
    "state_delta", "LoadedOverlay", "ROLE_TO_IDX",
]

# Role labels map to node indices. A two-node run uses A/B; multi-peer scenarios
# (e.g. a payment payer keyed by two distinct requesters) add C.
ROLE_TO_IDX: dict[str, int] = {"A": 0, "B": 1, "C": 2}

_REFERENCE_MODULES: dict[str, str] = {
    "echo": "sq3.references.echo_ref",
    "content_community": "sq3.references.content_ref",
    "payment": "sq3.references.payment_ref",
    "file_transfer": "sq3.references.file_transfer_ref",
}


# ---------------------------------------------------------------------------
# Loading a reference module as a LoadedOverlay
# ---------------------------------------------------------------------------

def _community_in(namespace: dict[str, Any], module_name: str) -> type:
    """The single ``Community`` subclass *defined in* ``module_name``.

    Filters by ``__module__`` so the imported ``Community`` base (and any other
    imported community) is excluded, leaving the reference class.
    """
    found = [
        v for v in namespace.values()
        if isinstance(v, type)
        and issubclass(v, Community)
        and v is not Community
        and getattr(v, "__module__", None) == module_name
    ]
    if len(found) != 1:
        raise ValueError(
            f"{module_name} must define exactly one Community subclass, found {len(found)}"
        )
    return found[0]


def reference_overlay(spec_name: str) -> LoadedOverlay:
    """Load a hand-written reference as a ``LoadedOverlay`` (community class +
    module namespace), ready to run on the two-node harness exactly like a
    compiled overlay. The namespace exposes the payload classes so
    ``_payload_class_for`` resolves them by ``msg_id``."""
    if spec_name not in _REFERENCE_MODULES:
        known = ", ".join(sorted(_REFERENCE_MODULES))
        raise KeyError(f"no reference for {spec_name!r}; known: {known}")
    module = importlib.import_module(_REFERENCE_MODULES[spec_name])
    namespace = vars(module)
    return LoadedOverlay(
        community_cls=_community_in(namespace, module.__name__),
        namespace=namespace,
    )


# ---------------------------------------------------------------------------
# Scenario step types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Seed:
    """Populate a runtime-state attribute on a node before the exchange (the
    out-of-band seeding the deployed seeder does at boot: ``served`` /
    ``local_index``). Excluded from the verdict — only handler-driven deltas are
    judged (invariant **I5**)."""
    role: str
    attr: str
    value: Any


@dataclass(frozen=True)
class Send:
    """Deliver ``message`` from ``src_role`` to ``dst_role``, built with the
    sender's own payload class (cross-compile dispatch), and settle delivery.
    ``dst_role`` may be omitted in a two-node run (the other node is implied);
    it is required once a third role is present."""
    src_role: str
    message: str
    fields: dict[str, Any]
    dst_role: str | None = None


@dataclass(frozen=True)
class Checkpoint:
    """Assert that ``role``'s runtime-state ``attr`` equals ``expected`` after
    canonicalization. ``project`` optionally reduces the raw state to the
    comparable shape (e.g. pull ``complete``/``ok`` out of a transfer entry)
    before the comparison."""
    role: str
    attr: str
    expected: Any
    project: Callable[[Any], Any] | None = None


Step = Seed | Send | Checkpoint


# ---------------------------------------------------------------------------
# Trace
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CheckResult:
    role: str
    attr: str
    expected: Any
    actual: Any
    passed: bool


@dataclass
class Trace:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.checks)

    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]


# ---------------------------------------------------------------------------
# Identity-aware, full-value canonicalization (I4) + append-only delta (I5)
# ---------------------------------------------------------------------------

def canonicalize(value: Any, *, mid_to_role: dict[str, str]) -> Any:
    """Recursively normalize a runtime-state value for comparison.

    Normalization is deliberately *minimal* — only the differences that are pure
    serialization / Python-representation artifacts are erased, so that genuine
    behavioural divergence still shows:

      * peer-mid-hex dict keys are remapped to stable role labels (``A`` / ``B`` /
        ``C``) so two runs with different ephemeral peer ids compare;
      * ``bytearray`` collapses to ``bytes`` and ``tuple`` to ``list`` (the
        serializer/handler may produce either; they are never semantically
        distinct here);
      * collections keep their full value (no ``len()`` reduction), and list
        order is preserved — declared result order is part of the spec.

    What is *not* normalized: ``bytes`` is left distinct from ``str``. The
    descriptors declare text fields as ``str`` and the agent runtime polls them
    as ``str``; a compilation that stores a raw ``bytes`` memo (skipping the
    documented ``.decode("utf-8")``) is a real conformance defect, and the
    comparator surfaces it rather than papering over it."""
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            key = bytes(k) if isinstance(k, bytearray) else k
            if isinstance(key, str):
                key = mid_to_role.get(key, key)
            out[key] = canonicalize(v, mid_to_role=mid_to_role)
        return out
    if isinstance(value, (list, tuple)):
        return [canonicalize(v, mid_to_role=mid_to_role) for v in value]
    if isinstance(value, bytearray):
        return bytes(value)
    return value


def state_delta(baseline: Any, current: Any) -> Any:
    """The additions in ``current`` relative to ``baseline`` (invariant **I5**).

    Every DelftClaw runtime-state slot is an append-only accumulator — handlers
    add dict keys or append list items, never rewrite history — so the delta is
    well defined: for a dict, the keys present now but absent (or changed) in the
    baseline; for a list whose baseline is a prefix, the appended suffix. This is
    what excludes harness-seeded data (``served`` / ``local_index``) and any
    ``__init__`` / ``started()`` writes from a handler-behaviour checkpoint.
    Both arguments must already be canonicalized."""
    if isinstance(baseline, dict) and isinstance(current, dict):
        return {k: v for k, v in current.items() if k not in baseline or baseline[k] != v}
    if isinstance(baseline, list) and isinstance(current, list):
        if current[: len(baseline)] == baseline:
            return current[len(baseline):]
        return current
    return current


# ---------------------------------------------------------------------------
# Running a scenario
# ---------------------------------------------------------------------------

def _role_idx(role: str) -> int:
    try:
        return ROLE_TO_IDX[role]
    except KeyError as exc:
        raise ValueError(f"unknown role {role!r}; known: {sorted(ROLE_TO_IDX)}") from exc


async def run_scenario(
    impl_a: LoadedOverlay,
    impl_b: LoadedOverlay,
    steps: list[Step],
    *,
    spec: ParsedOverlay,
    extra: list[LoadedOverlay] | None = None,
) -> Trace:
    """Run ``impl_a`` as role A and ``impl_b`` as role B (plus any ``extra`` as
    C, D, …) through ``steps`` on the mock network, returning the checkpoint
    ``Trace``. All overlays must share a ``community_id`` (the reference
    guarantees this via **I2**)."""
    msg_by_name = {m.name: m for m in spec.messages}
    overlays = [impl_a, impl_b, *(extra or [])]
    community_id = impl_a.community_cls.community_id
    n_nodes = len(overlays)
    trace = Trace()

    state_names = [s.name for s in spec.runtime_state]

    async with ProgrammableNetwork(overlays, community_id) as net:
        mid_to_role = {
            net.nodes[idx].my_peer.mid.hex(): role
            for role, idx in ROLE_TO_IDX.items()
            if idx < len(net.nodes)
        }
        # Baseline: each node's canonicalized runtime state at the seed→send
        # transition (after Seeds + started(), before the first message). A
        # checkpoint judges the delta from here, so seeded/init state is excluded
        # (invariant I5). canonicalize() deep-copies, so later in-place mutation
        # of the live state does not disturb the baseline.
        baselines: dict[tuple[int, str], Any] = {}

        def snapshot_baseline() -> None:
            for idx in range(n_nodes):
                for attr in state_names:
                    baselines[(idx, attr)] = canonicalize(
                        net.state(idx, attr), mid_to_role=mid_to_role)

        for step in steps:
            if isinstance(step, Seed):
                setattr(net.overlay(_role_idx(step.role)), step.attr, step.value)
            elif isinstance(step, Send):
                if not baselines:
                    snapshot_baseline()
                src = _role_idx(step.src_role)
                if step.dst_role is not None:
                    dst = _role_idx(step.dst_role)
                elif n_nodes == 2:
                    dst = 1 - src
                else:
                    raise ValueError(
                        f"Send needs dst_role in a {n_nodes}-node run: {step!r}")
                if step.message not in msg_by_name:
                    raise KeyError(f"scenario sends unknown message {step.message!r}")
                await net.send(src, dst, msg_by_name[step.message], step.fields)
            elif isinstance(step, Checkpoint):
                idx = _role_idx(step.role)
                current = canonicalize(net.state(idx, step.attr), mid_to_role=mid_to_role)
                base = baselines.get((idx, step.attr))
                effect = state_delta(base, current) if base is not None else current
                actual = step.project(effect) if step.project is not None else effect
                expected = canonicalize(step.expected, mid_to_role=mid_to_role)
                trace.checks.append(CheckResult(
                    role=step.role, attr=step.attr,
                    expected=expected, actual=actual, passed=actual == expected,
                ))
            else:  # pragma: no cover - defensive
                raise TypeError(f"unknown scenario step: {step!r}")
    return trace


async def golden_trace(spec_name: str, steps: list[Step]) -> Trace:
    """The expected behaviour for ``spec_name``: the reference run against itself.
    Used by Steps 4+ to score compiled overlays; in Step 1 the gate compares the
    reference run against hand-written ``Checkpoint`` expectations directly."""
    spec = get_spec(spec_name).parsed
    return await run_scenario(
        reference_overlay(spec_name), reference_overlay(spec_name), steps, spec=spec,
    )
