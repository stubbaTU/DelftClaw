"""Named stop predicates the watchdog uses to decide a scenario is done.

A ``Predicate`` is a pure function ``StateSnapshot -> bool``. The
registry maps a scenario-yaml name (possibly with simple keyword arguments
in parentheses, e.g. ``peer_count_gte_N(n=2)``) to a concrete predicate.

The LLM never evaluates these — the watchdog does, deterministically.
"""

from __future__ import annotations

import re
from typing import Any, Callable

StateSnapshot = dict[str, Any]
Predicate = Callable[[StateSnapshot], bool]


# Track wallet balance at scenario start so ``wallet_received_sats`` is a
# delta-based predicate. The watchdog seeds this via ``set_baseline``.
_baseline_wallet: dict[str, int] = {}


def set_baseline(agent_id: str, snapshot: StateSnapshot) -> None:
    """Record the wallet baseline so wallet_received_sats can measure deltas."""
    sats = snapshot.get("wallet", {}).get("balance_sats")
    if isinstance(sats, int):
        _baseline_wallet[agent_id] = sats


# ---------------------------------------------------------------------------
# Predicate implementations
# ---------------------------------------------------------------------------

def _never(_: StateSnapshot) -> bool:
    return False


def _torrent_progress_gte_1(snapshot: StateSnapshot) -> bool:
    for t in snapshot.get("torrents", []):
        if isinstance(t.get("progress"), (int, float)) and float(t["progress"]) >= 1.0:
            return True
    return False


def _peer_count_gte_N(n: int = 1) -> Predicate:
    def pred(snapshot: StateSnapshot) -> bool:
        return len(snapshot.get("peers", [])) >= n
    pred.__name__ = f"peer_count_gte_{n}"
    return pred


def _wallet_received_sats(min_sats: int = 1) -> Predicate:
    def pred(snapshot: StateSnapshot) -> bool:
        agent_id = snapshot.get("agent", {}).get("agent_id")
        sats = snapshot.get("wallet", {}).get("balance_sats")
        if agent_id is None or not isinstance(sats, int):
            return False
        baseline = _baseline_wallet.get(agent_id, sats)
        return (sats - baseline) >= min_sats
    pred.__name__ = f"wallet_received_sats_{min_sats}"
    return pred


def _community_seedbox_count_gte_N(n: int = 1) -> Predicate:
    def pred(snapshot: StateSnapshot) -> bool:
        community = snapshot.get("community") or {}
        seedbox_count = community.get("seedbox_count")
        return isinstance(seedbox_count, int) and seedbox_count >= n
    pred.__name__ = f"community_seedbox_count_gte_{n}"
    return pred


def _community_member_count_gte_N(n: int = 1) -> Predicate:
    def pred(snapshot: StateSnapshot) -> bool:
        community = snapshot.get("community") or {}
        member_count = community.get("member_count")
        return isinstance(member_count, int) and member_count >= n
    pred.__name__ = f"community_member_count_gte_{n}"
    return pred


def _security_layer_done(layer: str | int = "") -> Predicate:
    key = {
        "1": "layer1",
        "2": "layer2",
        "3": "layer3",
        "preventative": "layer1",
        "accountability": "layer2",
        "impact": "layer3",
    }.get(str(layer), str(layer))

    def pred(snapshot: StateSnapshot) -> bool:
        security = snapshot.get("security") or {}
        checklist = security.get("checklist") or {}
        return bool(checklist.get(key))

    pred.__name__ = f"security_layer_done_{key}"
    return pred


def _security_all_done(snapshot: StateSnapshot) -> bool:
    security = snapshot.get("security") or {}
    return bool(security.get("ok"))


def _integrated_security_done(snapshot: StateSnapshot) -> bool:
    security = snapshot.get("security") or {}
    checklist = security.get("checklist") or {}
    return bool(checklist.get("integrated"))


# ---------------------------------------------------------------------------
# Registry + resolver
# ---------------------------------------------------------------------------

# Predicates with no arguments resolve directly. Parameterised predicates
# accept keyword args from inside ``name(k=v, ...)``.
_REGISTRY: dict[str, Predicate | Callable[..., Predicate]] = {
    "never": _never,
    "torrent_progress_gte_1": _torrent_progress_gte_1,
    "peer_count_gte_N": _peer_count_gte_N,
    "wallet_received_sats": _wallet_received_sats,
    "community_seedbox_count_gte_N": _community_seedbox_count_gte_N,
    "community_member_count_gte_N": _community_member_count_gte_N,
    "security_layer_done": _security_layer_done,
    "security_all_done": _security_all_done,
    "integrated_security_done": _integrated_security_done,
}


_CALL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\s*(.*?)\s*\))?\s*$")
_KV_RE = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^,]+?)\s*(?:,|$)")


class UnknownPredicate(KeyError):
    """Raised when a manifest references a predicate not in the registry."""


def resolve(spec: str) -> Predicate:
    """Resolve a ``spec`` like ``"never"`` or ``"peer_count_gte_N(n=2)"`` into a predicate."""
    m = _CALL_RE.match(spec)
    if not m:
        raise UnknownPredicate(f"malformed predicate spec: {spec!r}")
    name = m.group(1)
    kwargs_text = m.group(2) or ""

    if name not in _REGISTRY:
        raise UnknownPredicate(f"unknown predicate {name!r} (available: {sorted(_REGISTRY)})")

    entry = _REGISTRY[name]
    if not kwargs_text:
        # Bare names: either a predicate (zero-arg) or a factory we call with no args.
        if callable(entry) and _looks_like_factory(entry):
            return entry()
        return entry  # plain predicate

    kwargs = _parse_kwargs(kwargs_text)
    if not callable(entry) or not _looks_like_factory(entry):
        raise UnknownPredicate(
            f"predicate {name!r} does not accept arguments; got {kwargs!r}"
        )
    return entry(**kwargs)


def known_predicate_names() -> list[str]:
    return sorted(_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _looks_like_factory(obj: Any) -> bool:
    """``True`` if ``obj`` is a factory that returns a predicate when called.

    Convention: factory names end with ``_N`` (parameter count slot) or have
    explicit defaults; bare predicates are leaf functions. We probe with
    ``__name__``.
    """
    name = getattr(obj, "__name__", "")
    return (
        name.startswith("_peer_count_gte_N")
        or name.startswith("_wallet_received_sats")
        or name.startswith("_community_seedbox_count_gte_N")
        or name.startswith("_community_member_count_gte_N")
        or name.startswith("_security_layer_done")
    )


def _parse_kwargs(text: str) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    for m in _KV_RE.finditer(text + ","):
        key = m.group(1)
        raw = m.group(2)
        try:
            kwargs[key] = int(raw)
            continue
        except ValueError:
            pass
        try:
            kwargs[key] = float(raw)
            continue
        except ValueError:
            pass
        if raw.lower() in ("true", "false"):
            kwargs[key] = raw.lower() == "true"
            continue
        kwargs[key] = raw.strip('"\'')
    return kwargs
