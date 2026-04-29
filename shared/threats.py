"""Threat enumeration used by SQ1 (requirements) and SQ3 (lying-agent experiments)."""

from __future__ import annotations

from enum import StrEnum


class Threat(StrEnum):
    """Threat scenarios the channel must address. Each maps to one or more layers."""

    IDENTITY_LIE = "identity_lie"
    # Peer claims a public key it does not actually control.

    CREDENTIAL_LIE = "credential_lie"
    # Peer presents a VC it is not the rightful subject of.

    INTENT_LIE = "intent_lie"
    # Peer's message reflects an intent its prompt did not authorise.

    PROVENANCE_LIE = "provenance_lie"
    # Peer falsely claims a message originated upstream from another agent.

    REPLAY = "replay"
    # An old ciphertext or VC presentation is replayed by an adversary.

    NETWORK_OBSERVER = "network_observer"
    # Passive eavesdropper records traffic for offline analysis.

    PAST_KEY_COMPROMISE = "past_key_compromise"
    # Forward-secrecy violation: yesterday's key leaks and exposes today's traffic.

    FUTURE_KEY_COMPROMISE = "future_key_compromise"
    # Post-compromise: takeover today must not let the attacker read tomorrow's traffic.

    PROMPT_INJECTION = "prompt_injection"
    # Adversary alters the producing agent's prompt to manipulate its outgoing messages.

    ROGUE_REPLICA = "rogue_replica"
    # A child replica uses keys derived from its parent outside its delegated scope.
